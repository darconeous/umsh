//! The bridge server: listeners, per-client tunnels, and the one task
//! that copies frames between them.
//!
//! A client is a configured name with a pinned identity, so the
//! interface set is fixed for the run and a disconnected client is an
//! interface that is down rather than one that has gone away. That is
//! what lets the hub hold a stable interface index and lets a
//! reconnecting client resume its own identity rather than acquire a new
//! one.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;

use crate::config::{Config, ServerConfig};
use crate::device::DeviceRelay;
use crate::hub::Hub;
use crate::identity::BridgeIdentity;
use crate::iface::{Ingress, InterfaceId, Interfaces};
use crate::lan::LanRelay;
use crate::policy::Policy;
use crate::tls::{self, Address, Credential};
use crate::tunnel::{TunnelQueue, TunnelReader, TunnelWriter, pump_writer};

/// Frames waiting for the hub before an interface's reader blocks. The
/// hub's work per frame is bounded and small, so this only ever absorbs
/// a burst.
const HUB_BACKLOG: usize = 64;

/// How long a new connection has to complete its TLS handshake. A peer
/// that opens a socket and says nothing must not hold it indefinitely.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections allowed to be mid-handshake at once, across every
/// listener. Past this, accepting waits for a handshake to finish, so a
/// flood of silent sockets queues in the kernel rather than here.
const MAX_HANDSHAKES: usize = 256;

/// The kernel's queue of not-yet-accepted connections, matching what
/// [`TcpListener::bind`] asks for.
const LISTEN_BACKLOG: i32 = 1024;

/// A bridge server ready to serve: everything that can refuse the
/// configuration has run, and every listener it names is open.
pub struct BoundServer {
    identity: BridgeIdentity,
    server: ServerConfig,
    interfaces: Arc<Interfaces>,
    policy: Policy,
    acceptor: TlsAcceptor,
    by_address: HashMap<Address, usize>,
    tunnel_listeners: Vec<TcpListener>,
    /// One per [`ServerConfig::hosts`] entry, in the same order.
    host_listeners: Vec<TcpListener>,
}

/// Check a server configuration and open its listeners.
///
/// Every socket is bound here, before anything is served, so a port the
/// server cannot have stops it at startup.
pub async fn bind(identity: BridgeIdentity, config: Config) -> Result<BoundServer> {
    let server = config.server.expect("validated as a server configuration");
    let credential =
        Credential::for_identity(&identity).context("minting the server's TLS credential")?;

    // A configured client with this server's own address would let the
    // hub attribute the server's traffic to a client—and it can only
    // be a mistake, because no client can hold this server's key.
    for client in &server.clients {
        if client.address.0 == *identity.public_key() {
            anyhow::bail!(
                "client \"{}\" lists this bridge's own identity as its address",
                client.name
            );
        }
    }

    let interfaces = Arc::new(Interfaces::build(&server));
    let policy = Policy::build(&server, &interfaces)?;

    // An identity names exactly one client; the configuration
    // guarantees no two share one.
    let by_address: HashMap<Address, usize> = server
        .clients
        .iter()
        .enumerate()
        .map(|(index, client)| (client.address, index))
        .collect();
    let accepted: Vec<Address> = by_address.keys().copied().collect();
    let acceptor = TlsAcceptor::from(tls::server_config(&credential, accepted)?);

    let mut tunnel_listeners = Vec::new();
    for address in &server.listen {
        let listener = listen(*address).with_context(|| format!("listening on {address}"))?;
        tunnel_listeners.push(listener);
    }
    if tunnel_listeners.is_empty() {
        return Err(anyhow!("no listener could be opened"));
    }
    let mut host_listeners = Vec::new();
    for entry in &server.hosts {
        host_listeners.push(crate::host::bind(entry).await?);
    }

    Ok(BoundServer {
        identity,
        server,
        interfaces,
        policy,
        acceptor,
        by_address,
        tunnel_listeners,
        host_listeners,
    })
}

/// Open a tunnel listener.
///
/// An IPv6 socket is made v6-only, so the default pair of `0.0.0.0:P`
/// and `[::]:P` are two listeners rather than a collision: where the
/// system default is dual-stack, as on Linux, the v6 bind would
/// otherwise claim the v4 port too.
fn listen(address: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // What tokio's own bind does, so a restart is not refused over the
    // previous run's connections in TIME_WAIT.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    TcpListener::from_std(socket.into())
}

impl BoundServer {
    /// Where the tunnel listeners are, in configuration order. A
    /// configured port of 0 reads as the port the system chose.
    pub fn tunnel_addrs(&self) -> Vec<SocketAddr> {
        self.tunnel_listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Where the host interface named `name` listens.
    pub fn host_addr(&self, name: &str) -> Option<SocketAddr> {
        let index = self
            .server
            .hosts
            .iter()
            .position(|host| host.name == name)?;
        self.host_listeners[index].local_addr().ok()
    }

    /// Serve until the process ends.
    pub async fn run(self) -> Result<()> {
        let Self {
            identity,
            mut server,
            interfaces,
            policy,
            acceptor,
            by_address,
            tunnel_listeners,
            host_listeners,
        } = self;

        tracing::info!(
            address = %identity.public_key(),
            exit_clamp = server
                .limits
                .exit_clamp
                .map_or_else(|| "off".to_string(), |clamp| clamp.to_string()),
            "bridge server starting"
        );
        for iface in &interfaces.all {
            tracing::info!(
                iface = %iface.name,
                fan_out = %policy.describe_fan_out(iface.id),
                "interface"
            );
        }

        let (ingress_tx, ingress_rx) = mpsc::channel(HUB_BACKLOG);

        if let Some(radio) = interfaces.radio {
            let iface = interfaces.get(radio).clone();
            let inbound = Arc::new(TunnelQueue::new(
                server.tunnel.queue_depth,
                Duration::from_secs(server.tunnel.max_frame_age_secs),
            ));
            let relay = DeviceRelay::new(
                std::mem::take(&mut server.radio),
                inbound.clone(),
                iface.egress.clone(),
            );
            tokio::task::spawn_local(async move { relay.run().await });
            spawn_ingress(inbound, radio, ingress_tx.clone());
        }

        if let (Some(lan), Some(entry)) = (interfaces.lan, &server.lan) {
            let iface = interfaces.get(lan).clone();
            let inbound = Arc::new(TunnelQueue::new(
                server.tunnel.queue_depth,
                Duration::from_secs(server.tunnel.max_frame_age_secs),
            ));
            let relay = LanRelay::new(entry.socket_config(), inbound.clone(), iface.egress.clone());
            tokio::task::spawn_local(async move { relay.run().await });
            spawn_ingress(inbound, lan, ingress_tx.clone());
        }

        // Host interfaces need no credential and no radio: each is a socket
        // presenting a simulated device whose radio is this hub.
        for (index, (entry, listener)) in server.hosts.iter().zip(host_listeners).enumerate() {
            let iface = interfaces
                .by_host(index)
                .ok_or_else(|| anyhow!("host {index} has no interface"))?
                .clone();
            let relay = crate::host::HostRelay::new(entry, listener, iface, ingress_tx.clone());
            tokio::task::spawn_local(relay.run());
        }

        let hub = Hub::new(interfaces.clone(), policy, server.limits.exit_clamp);
        tokio::task::spawn_local(hub.run(ingress_rx));

        let shared = Arc::new(Shared {
            interfaces,
            by_address,
            tunnel: server.tunnel,
            client_names: server
                .clients
                .iter()
                .map(|client| client.name.clone())
                .collect(),
            ingress: ingress_tx,
            handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
        });

        for listener in tunnel_listeners {
            if let Ok(address) = listener.local_addr() {
                tracing::info!(%address, "listening");
            }
            let acceptor = acceptor.clone();
            let shared = shared.clone();
            tokio::task::spawn_local(async move { accept_loop(listener, acceptor, shared).await });
        }

        std::future::pending().await
    }
}

struct Shared {
    interfaces: Arc<Interfaces>,
    by_address: HashMap<Address, usize>,
    tunnel: crate::config::TunnelConfig,
    client_names: Vec<String>,
    ingress: mpsc::Sender<Ingress>,
    /// Permits for connections still in their TLS handshake.
    handshakes: Arc<Semaphore>,
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    loop {
        // Taken before accepting, so at the limit the next connection
        // waits in the kernel's backlog rather than holding a socket here.
        let Ok(permit) = shared.handshakes.clone().acquire_owned().await else {
            return;
        };
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // A per-connection accept failure (a descriptor limit, a
                // connection reset between accept and return) must not
                // take the listener down with it.
                tracing::warn!("accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::task::spawn_local(async move {
            if let Err(error) = serve(stream, acceptor, shared, permit).await {
                tracing::info!(%peer, "connection ended: {error:#}");
            }
        });
    }
}

async fn serve(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    shared: Arc<Shared>,
    handshake: OwnedSemaphorePermit,
) -> Result<()> {
    let peer = stream.peer_addr().ok();
    let handshaken = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
    drop(handshake);
    let stream = handshaken
        .map_err(|_| anyhow!("no TLS handshake within {HANDSHAKE_TIMEOUT:?}"))?
        .context("TLS handshake")?;

    // The handshake already proved the peer holds a pinned identity's
    // key, and proved it for the key its certificate names; this is
    // only working out *which* client that was.
    let address = {
        let (_, connection) = stream.get_ref();
        let certificate = connection
            .peer_certificates()
            .and_then(<[_]>::first)
            .ok_or_else(|| anyhow!("the client presented no certificate"))?;
        tls::certificate_key(certificate)
            .ok_or_else(|| anyhow!("the client's certificate carries no key"))?
    };
    let client = *shared
        .by_address
        .get(&address)
        .ok_or_else(|| anyhow!("no client is configured for {address}"))?;
    let iface = shared
        .interfaces
        .by_client(client)
        .ok_or_else(|| anyhow!("client {client} has no interface"))?
        .clone();
    let name = shared.client_names[client].clone();

    // A second connection for the same credential displaces the first:
    // the newer one is the live client, and the older is a session that
    // has already lost its network path. Clearing the egress queue ends
    // the old writer and discards its backlog in one move; the
    // generation that clear establishes is this connection's claim on
    // the interface.
    if iface.is_connected() {
        tracing::info!(client = %name, "displacing an earlier connection");
    }
    iface.egress.clear();
    let session = iface.egress.generation();
    iface.set_connected(true);
    tracing::info!(client = %name, ?peer, "client attached");

    let idle_timeout = Duration::from_secs(shared.tunnel.idle_timeout_secs);
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = TunnelReader::new(read_half, idle_timeout);
    let mut writer = TunnelWriter::new(
        write_half,
        Duration::from_secs(shared.tunnel.keepalive_secs),
    );

    let egress = iface.egress.clone();
    let mut pump = tokio::task::spawn_local(async move {
        pump_writer(&mut writer, &egress, session, idle_timeout).await
    });

    let read_loop = async {
        loop {
            match reader.read_frame().await {
                Ok(frame) => {
                    let ingress = Ingress {
                        iface: iface.id,
                        frame,
                    };
                    if shared.ingress.send(ingress).await.is_err() {
                        break Err(anyhow!("the hub stopped"));
                    }
                }
                Err(error) => break Err(anyhow!("{error}")),
            }
        }
    };
    // Either half ending ends the session: a writer that failed or
    // stalled leaves a connection that can no longer deliver anything,
    // and one whose session was ended by a successor's clear has been
    // displaced.
    let outcome = tokio::select! {
        outcome = read_loop => outcome,
        ended = &mut pump => writer_ended(ended),
    };

    // Only tear the interface down if this connection is still the one
    // holding it. A displaced session's writer ends at once, but a
    // successor already owns the interface—marking it down here would
    // silence the live session until *its* idle timer noticed. The
    // successor's clear bumped the generation, which is how this
    // connection knows its claim has lapsed.
    if iface.egress.generation() == session {
        iface.set_connected(false);
        iface.egress.clear();
    }
    pump.abort();
    tracing::info!(
        client = %name,
        malformed = reader.malformed(),
        "client detached"
    );
    outcome
}

/// The session outcome for a writer task that ended first.
pub(crate) fn writer_ended(
    ended: std::result::Result<std::io::Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match ended {
        Ok(Ok(())) => Err(anyhow!("the session was displaced")),
        Ok(Err(error)) => Err(anyhow!("tunnel write failed: {error}")),
        Err(error) => Err(anyhow!("tunnel writer stopped: {error}")),
    }
}

/// Move an interface's received frames into the hub.
fn spawn_ingress(inbound: Arc<TunnelQueue>, iface: InterfaceId, ingress: mpsc::Sender<Ingress>) {
    tokio::task::spawn_local(async move {
        loop {
            match inbound.pop().await {
                crate::tunnel::Dequeued::Frame(frame) => {
                    if ingress.send(Ingress { iface, frame }).await.is_err() {
                        return;
                    }
                }
                crate::tunnel::Dequeued::SessionEnded => return,
            }
        }
    });
}

/// Wire a validated configuration to whichever role it describes.
pub async fn run_config(mut config: Config) -> Result<()> {
    let identity = load_identity(&mut config)?;
    match config.client {
        Some(client) => crate::client::run(identity, client).await,
        None => bind(identity, config).await?.run().await,
    }
}

/// [`bind`] a validated server configuration, loading the identity it
/// names.
pub async fn bind_config(mut config: Config) -> Result<BoundServer> {
    let identity = load_identity(&mut config)?;
    bind(identity, config).await
}

fn load_identity(config: &mut Config) -> Result<BridgeIdentity> {
    BridgeIdentity::load(
        &config
            .identity
            .take()
            .expect("validated: every role has an identity")
            .key_file,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_v4_and_v6_wildcards_bind_the_same_port_side_by_side() {
        let v4 = listen(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
        let port = v4.local_addr().unwrap().port();
        match listen(SocketAddr::from(([0u16; 8], port))) {
            Ok(v6) => assert_eq!(v6.local_addr().unwrap().port(), port),
            // A host with no IPv6 at all has nothing to collide with.
            Err(error) if error.kind() != std::io::ErrorKind::AddrInUse => {
                eprintln!("no IPv6 here: {error}");
            }
            Err(error) => panic!("the v6 wildcard collided with the v4 one: {error}"),
        }
    }
}
