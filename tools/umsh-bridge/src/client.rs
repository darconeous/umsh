//! The bridge client: a byte-faithful relay between the server and its
//! radio, its LAN bearer group, or both. With both, each frame from one
//! of the three is copied to the other two.
//!
//! There is no forwarding logic here, deliberately—nor anywhere else
//! in the bridge. A client does not parse what it carries, does not
//! suppress duplicates, and does not decide anything about a frame. The
//! node behind its radio does all of that, to bridged traffic as to
//! anything else it hears.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::TcpStream;

use crate::config::ClientConfig;
use crate::device::DeviceRelay;
use crate::identity::BridgeIdentity;
use crate::lan::LanRelay;
use crate::tls::{self, Credential};
use crate::tunnel::{Dequeued, TunnelQueue, TunnelReader, TunnelWriter, pump_writer};

/// How long one connection attempt, or the TLS handshake that follows
/// it, may take before the client gives up on it and backs off.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(identity: BridgeIdentity, mut config: ClientConfig) -> Result<()> {
    let credential =
        Credential::for_identity(&identity).context("minting this client's TLS credential")?;
    let tls_config = tls::client_config(&credential, config.server_address)?;
    let connector = tokio_rustls::TlsConnector::from(tls_config);

    let max_age = Duration::from_secs(config.tunnel.max_frame_age_secs);
    let queue = || Arc::new(TunnelQueue::new(config.tunnel.queue_depth, max_age));
    let to_server = queue();

    // Each local side's inbound and outbound queues, for whichever are
    // configured.
    let radio = (!config.radio.is_none()).then(|| (queue(), queue()));
    let lan = config.lan.as_ref().map(|_| (queue(), queue()));
    if let Some((inbound, outbound)) = &radio {
        let relay = DeviceRelay::new(
            std::mem::take(&mut config.radio),
            inbound.clone(),
            outbound.clone(),
        );
        tokio::task::spawn_local(async move { relay.run().await });
    }
    if let (Some((inbound, outbound)), Some(entry)) = (&lan, &config.lan) {
        let relay = LanRelay::new(entry.socket_config(), inbound.clone(), outbound.clone());
        tokio::task::spawn_local(async move { relay.run().await });
    }
    if let Some((inbound, _)) = &radio {
        let mut targets = vec![to_server.clone()];
        targets.extend(lan.as_ref().map(|(_, outbound)| outbound.clone()));
        spawn_fan_out(inbound.clone(), targets);
    }
    if let Some((inbound, _)) = &lan {
        let mut targets = vec![to_server.clone()];
        targets.extend(radio.as_ref().map(|(_, outbound)| outbound.clone()));
        spawn_fan_out(inbound.clone(), targets);
    }
    let to_local: Vec<Arc<TunnelQueue>> = radio
        .iter()
        .chain(&lan)
        .map(|(_, outbound)| outbound.clone())
        .collect();

    tracing::info!(
        server = %config.server,
        address = %credential.address,
        "bridge client starting"
    );

    let min = Duration::from_secs(config.tunnel.reconnect_min_secs.max(1));
    let max = Duration::from_secs(config.tunnel.reconnect_max_secs.max(1));
    let mut backoff = min;
    loop {
        let started = tokio::time::Instant::now();
        match session(&connector, &config, &to_server, &to_local).await {
            Ok(()) => tracing::info!("tunnel closed by the server"),
            Err(error) => tracing::warn!("tunnel: {error:#}"),
        }

        // A connection that lived a while was working; the next failure
        // deserves a fresh, short retry rather than the last one's
        // accumulated patience.
        if started.elapsed() > max {
            backoff = min;
        }
        let delay = jittered(backoff);
        tracing::debug!(?delay, "reconnecting");
        tokio::time::sleep(delay).await;
        backoff = (backoff * 2).min(max);
    }
}

async fn session(
    connector: &tokio_rustls::TlsConnector,
    config: &ClientConfig,
    to_server: &Arc<TunnelQueue>,
    to_local: &[Arc<TunnelQueue>],
) -> Result<()> {
    let stream = connect_any(&config.server).await?;
    stream.set_nodelay(true).ok();
    let peer = stream.peer_addr().ok();

    let name = match &config.server_name {
        Some(name) => tls::server_name(name)?,
        None => tls::server_name(host_of(&config.server))?,
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| anyhow!("no TLS handshake within {CONNECT_TIMEOUT:?}"))?
        .context("TLS handshake")?;
    tracing::info!(?peer, "tunnel established");

    let idle_timeout = Duration::from_secs(config.tunnel.idle_timeout_secs);
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = TunnelReader::new(read_half, idle_timeout);
    let mut writer = TunnelWriter::new(
        write_half,
        Duration::from_secs(config.tunnel.keepalive_secs),
    );

    // A re-established connection starts empty rather than flushing the
    // old one's backlog: anything that waited through a reconnection has
    // outlived every confirmation retry that could have wanted it. This
    // is the last moment before the new session's writer starts, so it
    // also covers whatever queued during the handshake.
    to_server.clear();
    let session = to_server.generation();

    let queue = to_server.clone();
    let mut pump = tokio::task::spawn_local(async move {
        pump_writer(&mut writer, &queue, session, idle_timeout).await
    });

    let read_loop = async {
        loop {
            match reader.read_frame().await {
                Ok(frame) => {
                    // Passed on unmodified—to the device as the body of a
                    // CMD_STR_SEND: the server composed it and the client
                    // has no business editing it.
                    for queue in to_local {
                        if queue.push(frame.clone()) {
                            tracing::warn!(
                                "a local side is not keeping up; dropped the oldest frame"
                            );
                        }
                    }
                }
                Err(error) => break Err(anyhow!("{error}")),
            }
        }
    };
    // A writer that failed or stalled ends the session as surely as a
    // reader that did: the tunnel can no longer carry this side's
    // traffic, and reconnecting is how it gets a working one.
    let outcome = tokio::select! {
        outcome = read_loop => outcome,
        ended = &mut pump => crate::server::writer_ended(ended),
    };

    // Ending the writer's session unparks it whether or not it is
    // waiting on a frame.
    to_server.clear();
    pump.abort();
    if reader.malformed() > 0 {
        tracing::warn!(
            malformed = reader.malformed(),
            "the server sent frames this client could not read"
        );
    }
    outcome
}

/// Copy each frame from `source` to every queue in `targets`.
fn spawn_fan_out(source: Arc<TunnelQueue>, targets: Vec<Arc<TunnelQueue>>) {
    tokio::task::spawn_local(async move {
        loop {
            // Nothing clears a local side's inbound queue, so a session
            // ending here is only ever a spurious wake.
            let Dequeued::Frame(frame) = source.pop().await else {
                continue;
            };
            for target in &targets {
                if target.push(frame.clone()) {
                    tracing::warn!("a queue is not keeping up; dropped the oldest frame");
                }
            }
        }
    });
}

/// Try every address the name resolves to, in the order the resolver
/// gave them—which is how a dual-stacked server is reached over
/// whichever family actually works from here.
async fn connect_any(server: &str) -> Result<TcpStream> {
    let addresses: Vec<_> = tokio::net::lookup_host(server)
        .await
        .with_context(|| format!("resolving {server}"))?
        .collect();
    if addresses.is_empty() {
        bail!("{server} resolved to no addresses");
    }

    let mut last = None;
    for address in &addresses {
        let error = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => error,
            Err(_elapsed) => std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no connection within {CONNECT_TIMEOUT:?}"),
            ),
        };
        tracing::debug!(%address, "connect failed: {error}");
        last = Some(error);
    }
    Err(anyhow!(last.expect("at least one address was tried"))
        .context(format!("connecting to {server}")))
}

/// The host part of a `host:port`, including a bracketed IPv6 literal.
fn host_of(server: &str) -> &str {
    if let Some(rest) = server.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(server);
    }
    server
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(server)
}

/// Spread reconnections so a server coming back does not meet every
/// client it lost at the same instant.
fn jittered(base: Duration) -> Duration {
    let millis = base.as_millis() as u64;
    base + Duration::from_millis(rand::random_range(0..=millis / 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sni_name_comes_from_the_host_part_of_any_address_form() {
        assert_eq!(host_of("bridge.example.net:21837"), "bridge.example.net");
        assert_eq!(host_of("192.0.2.10:21837"), "192.0.2.10");
        assert_eq!(host_of("[2001:db8::1]:21837"), "2001:db8::1");
        // And every form yields a name rustls will accept.
        for server in [
            "bridge.example.net:21837",
            "192.0.2.10:21837",
            "[2001:db8::1]:21837",
        ] {
            tls::server_name(host_of(server)).unwrap();
        }
    }

    #[test]
    fn jitter_only_ever_adds() {
        let base = Duration::from_secs(4);
        for _ in 0..64 {
            let delay = jittered(base);
            assert!(
                delay >= base && delay <= base + Duration::from_secs(2),
                "{delay:?}"
            );
        }
    }
}
