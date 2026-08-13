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
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::device::DeviceRelay;
use crate::hub::Hub;
use crate::identity::BridgeIdentity;
use crate::iface::{Ingress, InterfaceId, Interfaces};
use crate::policy::Policy;
use crate::tls::{self, Address, Credential};
use crate::tunnel::{TunnelQueue, TunnelReader, TunnelWriter, pump_writer};

/// Frames waiting for the hub before an interface's reader blocks. The
/// hub's work per frame is bounded and small, so this only ever absorbs
/// a burst.
const HUB_BACKLOG: usize = 64;

pub async fn run(identity: BridgeIdentity, config: Config) -> Result<()> {
    let mut server = config.server.expect("validated as a server configuration");
    let credential =
        Credential::for_identity(&identity).context("minting the server's TLS credential")?;

    // A configured client with this server's own address would let the
    // hub attribute the server's traffic to a client — and it can only
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
            fan_out = %policy.describe_fan_out(&interfaces, iface.id),
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

    let hub = Hub::new(interfaces.clone(), policy, server.limits.exit_clamp);
    tokio::task::spawn_local(hub.run(ingress_rx));

    // An identity names exactly one client; the configuration
    // guarantees no two share one.
    let by_address: HashMap<Address, usize> = server
        .clients
        .iter()
        .enumerate()
        .map(|(index, client)| (client.address, index))
        .collect();
    let accepted: Vec<Address> = by_address.keys().copied().collect();

    let tls_config = tls::server_config(&credential, accepted)?;
    let acceptor = TlsAcceptor::from(tls_config);
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
    });

    let mut listeners = Vec::new();
    for address in &server.listen {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("listening on {address}"))?;
        tracing::info!(%address, "listening");
        listeners.push(listener);
    }
    if listeners.is_empty() {
        return Err(anyhow!("no listener could be opened"));
    }

    for listener in listeners {
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::task::spawn_local(async move { accept_loop(listener, acceptor, shared).await });
    }

    std::future::pending().await
}

struct Shared {
    interfaces: Arc<Interfaces>,
    by_address: HashMap<Address, usize>,
    tunnel: crate::config::TunnelConfig,
    client_names: Vec<String>,
    ingress: mpsc::Sender<Ingress>,
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    loop {
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
            if let Err(error) = serve(stream, acceptor, shared).await {
                tracing::info!(%peer, "connection ended: {error:#}");
            }
        });
    }
}

async fn serve(stream: TcpStream, acceptor: TlsAcceptor, shared: Arc<Shared>) -> Result<()> {
    let peer = stream.peer_addr().ok();
    let stream = acceptor.accept(stream).await.context("TLS handshake")?;

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

    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = TunnelReader::new(
        read_half,
        Duration::from_secs(shared.tunnel.idle_timeout_secs),
    );
    let mut writer = TunnelWriter::new(
        write_half,
        Duration::from_secs(shared.tunnel.keepalive_secs),
    );

    let egress = iface.egress.clone();
    let pump =
        tokio::task::spawn_local(async move { pump_writer(&mut writer, &egress, session).await });

    let outcome = loop {
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
    };

    // Only tear the interface down if this connection is still the one
    // holding it. A displaced session lingers until its idle timeout
    // fires, and by then a successor owns the interface — marking it
    // down here would silence the live session until *its* idle timer
    // noticed. The successor's clear bumped the generation, which is how
    // this connection knows its claim has lapsed.
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
    let identity = BridgeIdentity::load(
        &config
            .identity
            .take()
            .expect("validated: every role has an identity")
            .key_file,
    )?;
    match config.client {
        Some(client) => crate::client::run(identity, client).await,
        None => run(identity, config).await,
    }
}
