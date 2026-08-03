//! A whole bridge in one process.
//!
//! Server and client both run on the test's `LocalSet`, joined by a real
//! TLS tunnel over loopback and fronted by the UDP-multicast fake radio
//! on two different groups — one "segment" each. Injecting a frame on
//! one segment and watching what appears on the other exercises the
//! tunnel, the relay, and the forwarding procedure together, which is
//! the only way to catch the places where those three disagree.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use umsh::tokio_support::UdpMulticastRadio;
use umsh_bridge::config::Config;
use umsh_bridge::tls::Credential;
use umsh_core::{FloodHops, NodeHint, OptionNumber, PacketBuilder, PacketHeader, ParsedOptions};
use umsh_hal::{CadPolicy, Radio, TxOptions};

/// Multicast groups for the two segments. Distinct so the two radios
/// hear only their own.
const SEGMENT_A: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 61);
const SEGMENT_B: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 62);

struct Deployment {
    server: String,
    client: String,
    server_port: u16,
    client_port: u16,
}

/// Issue everything a deployment needs and write both configurations.
fn deployment(dir: &Path, extra_forwarding: &str) -> Deployment {
    umsh_bridge::keygen::write_identity(&dir.join("identity.key"), false).unwrap();
    umsh_bridge::keygen::write_certificate(
        "server",
        &dir.join("server.crt"),
        &dir.join("server.key"),
        false,
    )
    .unwrap();
    umsh_bridge::keygen::write_certificate(
        "cabin",
        &dir.join("cabin.crt"),
        &dir.join("cabin.key"),
        false,
    )
    .unwrap();

    let server_fp = Credential::load(&dir.join("server.crt"), &dir.join("server.key"))
        .unwrap()
        .fingerprint;
    let cabin_fp = Credential::load(&dir.join("cabin.crt"), &dir.join("cabin.key"))
        .unwrap()
        .fingerprint;

    let tunnel_port = free_port();
    let server_port = free_port();
    let client_port = free_port();
    let d = dir.display();

    Deployment {
        server: format!(
            "[identity]\nkey_file = \"{d}/identity.key\"\n\
             [server]\nlisten = [\"127.0.0.1:{tunnel_port}\"]\n\
             [server.tls]\ncert_file = \"{d}/server.crt\"\nkey_file = \"{d}/server.key\"\n\
             [server.radio]\ntype = \"udp-multicast\"\ngroup = \"{SEGMENT_A}\"\n\
             port = {server_port}\n\
             [server.forwarding]\nflood_contention_ms = 0\n{extra_forwarding}\
             [[server.clients]]\nname = \"cabin\"\nfingerprint = \"{cabin_fp}\"\n"
        ),
        client: format!(
            "[client]\nserver = \"127.0.0.1:{tunnel_port}\"\n\
             [client.tls]\ncert_file = \"{d}/cabin.crt\"\nkey_file = \"{d}/cabin.key\"\n\
             server_fingerprint = \"{server_fp}\"\n\
             [client.radio]\ntype = \"udp-multicast\"\ngroup = \"{SEGMENT_B}\"\n\
             port = {client_port}\n"
        ),
        server_port,
        client_port,
    }
}

/// A port nothing is listening on, by asking the OS for one and letting
/// it go again.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.local_addr().unwrap().port()
}

fn parse(text: &str) -> Config {
    let config: Config = toml::from_str(text).unwrap();
    config.validate().unwrap();
    config
}

/// Start both ends and give them a moment to attach.
async fn start(deployment: &Deployment) {
    let server = parse(&deployment.server);
    let client = parse(&deployment.client);
    tokio::task::spawn_local(async move {
        if let Err(error) = umsh_bridge::server::run_config(server).await {
            eprintln!("server: {error:#}");
        }
    });
    tokio::task::spawn_local(async move {
        if let Err(error) = umsh_bridge::server::run_config(client).await {
            eprintln!("client: {error:#}");
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// A flood broadcast as a node on one segment would send it.
fn broadcast(remaining: u8, source: u8, options: &[(OptionNumber, Vec<u8>)]) -> Vec<u8> {
    let mut buf = [0u8; 255];
    let mut builder = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_hint(NodeHint([source, 0x22, 0x33]))
        .flood_hops(remaining);
    for (number, value) in options {
        builder = builder.option(*number, value);
    }
    builder
        .payload(b"across the bridge")
        .build()
        .unwrap()
        .to_vec()
}

/// Wait for a frame on `radio`, or give up.
async fn expect_frame(radio: &mut UdpMulticastRadio) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let received = tokio::time::timeout(Duration::from_secs(3), async {
        core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf)).await
    })
    .await
    .ok()?
    .ok()?;
    Some(buf[..received.len].to_vec())
}

async fn expect_no_frame(radio: &mut UdpMulticastRadio) {
    let mut buf = vec![0u8; 512];
    let outcome = tokio::time::timeout(Duration::from_millis(500), async {
        core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf)).await
    })
    .await;
    if let Ok(Ok(received)) = outcome {
        panic!("unexpected frame: {:02x?}", &buf[..received.len]);
    }
}

/// Run `body` on a `LocalSet`, which is what the bridge's `!Send` tasks
/// need.
fn with_local<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(body()));
}

#[test]
fn a_flood_frame_crosses_the_bridge_clamped_traced_and_confirmed() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");
        // Both segments' peers join before the bridge does, so nothing
        // is missed while the tunnel comes up.
        let mut segment_a = UdpMulticastRadio::bind_v4(SEGMENT_A, deployment.server_port)
            .await
            .unwrap();
        let mut segment_b = UdpMulticastRadio::bind_v4(SEGMENT_B, deployment.client_port)
            .await
            .unwrap();
        start(&deployment).await;

        // A node on the client's segment floods a traced broadcast.
        let sent = broadcast(3, 0x11, &[(OptionNumber::TraceRoute, Vec::new())]);
        segment_b
            .transmit(
                &sent,
                TxOptions {
                    cad: CadPolicy::Skip,
                },
            )
            .await
            .unwrap();

        // It comes out on the server's segment, rewritten.
        let arrived = expect_frame(&mut segment_a)
            .await
            .expect("the frame should have crossed the bridge");
        let header = PacketHeader::parse(&arrived).unwrap();
        let hops = header.flood_hops.unwrap();
        assert_eq!(hops.remaining(), 1, "clamped to the exit maximum");
        assert_eq!(hops.accumulated(), 1, "one hop, through the bridge");

        let options = ParsedOptions::extract(&arrived, header.options_range.clone()).unwrap();
        let trace = options.trace_route.clone().expect("the trace survives");
        let identity =
            umsh_bridge::identity::BridgeIdentity::load(&dir.path().join("identity.key")).unwrap();
        assert_eq!(
            &arrived[trace],
            &identity.router_hint().0,
            "the bridge's hint is prepended, which is what makes the reversed trace routable"
        );
        assert_eq!(
            &arrived[header.body_range.clone()],
            b"across the bridge",
            "the body is untouched"
        );

        // And the previous hop's segment gets the confirmation copy: the
        // same packet with no flood budget left.
        let confirmation = expect_frame(&mut segment_b)
            .await
            .expect("a confirmation copy should come back");
        let header = PacketHeader::parse(&confirmation).unwrap();
        assert_eq!(
            header.flood_hops.unwrap().remaining(),
            0,
            "the copy confirms without recruiting forwarders"
        );
        assert_eq!(header.flood_hops.unwrap().accumulated(), 1);
    });
}

#[test]
fn the_bridge_does_not_carry_a_frame_back_to_where_it_came_from() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");
        let mut segment_a = UdpMulticastRadio::bind_v4(SEGMENT_A, deployment.server_port)
            .await
            .unwrap();
        let mut segment_b = UdpMulticastRadio::bind_v4(SEGMENT_B, deployment.client_port)
            .await
            .unwrap();
        start(&deployment).await;

        let sent = broadcast(3, 0x44, &[]);
        segment_b
            .transmit(
                &sent,
                TxOptions {
                    cad: CadPolicy::Skip,
                },
            )
            .await
            .unwrap();
        expect_frame(&mut segment_a).await.expect("fanned out");
        // The confirmation copy, and then nothing more: the frame the
        // bridge put on segment A must not come back through it.
        expect_frame(&mut segment_b).await.expect("confirmed");
        expect_no_frame(&mut segment_a).await;
        expect_no_frame(&mut segment_b).await;
    });
}

#[test]
fn a_spent_flood_budget_does_not_cross() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");
        let mut segment_a = UdpMulticastRadio::bind_v4(SEGMENT_A, deployment.server_port)
            .await
            .unwrap();
        let mut segment_b = UdpMulticastRadio::bind_v4(SEGMENT_B, deployment.client_port)
            .await
            .unwrap();
        start(&deployment).await;

        let mut spent = broadcast(1, 0x55, &[]);
        spent[1] = FloodHops::new(0, 4).unwrap().0;
        segment_b
            .transmit(
                &spent,
                TxOptions {
                    cad: CadPolicy::Skip,
                },
            )
            .await
            .unwrap();
        expect_no_frame(&mut segment_a).await;
    });
}

/// A raw pinned tunnel connection with the cabin client's credential,
/// for tests that need to hold more than one at a time.
async fn connect_pinned(
    client: &umsh_bridge::config::ClientConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let credential = Credential::load(&client.tls.cert_file, &client.tls.key_file).unwrap();
    let tls = umsh_bridge::tls::client_config(&credential, client.tls.server_fingerprint).unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let stream = tokio::net::TcpStream::connect(client.server.as_str())
        .await
        .unwrap();
    connector
        .connect(umsh_bridge::tls::server_name("127.0.0.1").unwrap(), stream)
        .await
        .unwrap()
}

#[test]
fn a_reconnecting_client_displaces_its_predecessor_without_being_torn_down() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");
        let mut segment_a = UdpMulticastRadio::bind_v4(SEGMENT_A, deployment.server_port)
            .await
            .unwrap();
        let server = parse(&deployment.server);
        tokio::task::spawn_local(async move {
            let _ = umsh_bridge::server::run_config(server).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The first connection attaches, silently loses its network
        // path, and the reconnection displaces it.
        let client = parse(&deployment.client).client.unwrap();
        let stale = connect_pinned(&client).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let live = connect_pinned(&client).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The stale session's teardown runs now — it must not mark the
        // interface down or end the writer its successor is using.
        drop(stale);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A frame from the server's segment still reaches the live
        // session.
        segment_a
            .transmit(
                &broadcast(3, 0x77, &[]),
                TxOptions {
                    cad: CadPolicy::Skip,
                },
            )
            .await
            .unwrap();
        let mut reader = umsh_bridge::tunnel::TunnelReader::new(live, Duration::from_secs(30));
        let frame = tokio::time::timeout(Duration::from_secs(3), reader.read_frame())
            .await
            .expect("the displaced session's teardown silenced its successor")
            .expect("tunnel read");
        let header = PacketHeader::parse(&frame.data).unwrap();
        assert_eq!(
            header.source,
            umsh_core::SourceAddrRef::Hint(NodeHint([0x77, 0x22, 0x33])),
            "the frame that crossed is the one the radio heard"
        );
    });
}

#[test]
fn a_client_the_server_does_not_pin_is_refused_at_the_handshake() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");

        // A credential the server has never heard of.
        umsh_bridge::keygen::write_certificate(
            "stranger",
            &dir.path().join("stranger.crt"),
            &dir.path().join("stranger.key"),
            false,
        )
        .unwrap();
        let stranger = deployment
            .client
            .replace("cabin.crt", "stranger.crt")
            .replace("cabin.key", "stranger.key");

        let server = parse(&deployment.server);
        tokio::task::spawn_local(async move {
            let _ = umsh_bridge::server::run_config(server).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let config = parse(&stranger);
        let client = config.client.unwrap();
        let credential = Credential::load(&client.tls.cert_file, &client.tls.key_file).unwrap();
        let tls =
            umsh_bridge::tls::client_config(&credential, client.tls.server_fingerprint).unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls);
        let stream = tokio::net::TcpStream::connect(client.server.as_str())
            .await
            .unwrap();
        // In TLS 1.3 the client finishes before the server has looked at
        // its certificate, so the refusal arrives as an alert on the
        // first exchange rather than as a handshake error. What matters
        // is that the session never carries a frame.
        let mut stream = connector
            .connect(umsh_bridge::tls::server_name("127.0.0.1").unwrap(), stream)
            .await
            .expect("the client half of a 1.3 handshake completes early");

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let _ = stream.write_all(&[0x7E]).await;
        let mut buf = [0u8; 16];
        let outcome = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
        match outcome {
            Ok(Err(_)) => {}
            Ok(Ok(0)) => {}
            Ok(Ok(read)) => panic!("an unpinned client was served {read} bytes"),
            Err(_) => panic!("an unpinned client's connection was left open"),
        }
    });
}

#[test]
fn a_server_whose_fingerprint_does_not_match_is_refused_by_the_client() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");

        let server = parse(&deployment.server);
        tokio::task::spawn_local(async move {
            let _ = umsh_bridge::server::run_config(server).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let config = parse(&deployment.client);
        let client = config.client.unwrap();
        let credential = Credential::load(&client.tls.cert_file, &client.tls.key_file).unwrap();
        let wrong = "sha256:00000000000000000000000000000000000000000000000000000000000000ff"
            .parse()
            .unwrap();
        let tls = umsh_bridge::tls::client_config(&credential, wrong).unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls);
        let stream = tokio::net::TcpStream::connect(client.server.as_str())
            .await
            .unwrap();
        let outcome = connector
            .connect(umsh_bridge::tls::server_name("127.0.0.1").unwrap(), stream)
            .await;
        assert!(outcome.is_err(), "the pin is the whole trust decision");
    });
}
