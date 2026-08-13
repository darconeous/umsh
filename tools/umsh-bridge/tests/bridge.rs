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
use umsh_bridge::identity::BridgeIdentity;
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
    umsh_bridge::keygen::write_identity(&dir.join("cabin.key"), false).unwrap();

    let server_address = BridgeIdentity::load(&dir.join("identity.key"))
        .unwrap()
        .public_key()
        .to_string();
    let cabin_address = BridgeIdentity::load(&dir.join("cabin.key"))
        .unwrap()
        .public_key()
        .to_string();

    let tunnel_port = free_port();
    let server_port = free_port();
    let client_port = free_port();
    let d = dir.display();

    Deployment {
        server: format!(
            "[identity]\nkey_file = \"{d}/identity.key\"\n\
             [server]\nlisten = [\"127.0.0.1:{tunnel_port}\"]\n\
             [server.radio]\ntype = \"udp-multicast\"\ngroup = \"{SEGMENT_A}\"\n\
             port = {server_port}\n\
             [server.forwarding]\nflood_contention_ms = 0\n{extra_forwarding}\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{cabin_address}\"\n"
        ),
        client: format!(
            "[identity]\nkey_file = \"{d}/cabin.key\"\n\
             [client]\nserver = \"127.0.0.1:{tunnel_port}\"\n\
             server_address = \"{server_address}\"\n\
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
        let sent = broadcast(
            3,
            0x11,
            &[
                (OptionNumber::TraceRoute, Vec::new()),
                (OptionNumber::TraceSignal, Vec::new()),
            ],
        );
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
        let signal = options
            .trace_signal
            .clone()
            .expect("the trace signal survives");
        assert_eq!(
            &arrived[signal],
            // What the client's radio is configured to report: -40 dBm
            // at 10 dB. The reading belongs to the radio that heard the
            // frame, which for this crossing is the client's, not the
            // server's.
            &umsh_core::options::TraceSignalEntry::new(-40, 100).as_bytes(),
            "the entry pairs with the hint above it"
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

/// A raw pinned tunnel connection with the configured client's
/// identity, for tests that need to hold more than one at a time.
async fn connect_pinned(config: &Config) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let identity = BridgeIdentity::load(&config.identity.as_ref().unwrap().key_file).unwrap();
    let credential = Credential::for_identity(&identity).unwrap();
    let client = config.client.as_ref().unwrap();
    let tls = umsh_bridge::tls::client_config(&credential, client.server_address).unwrap();
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
        let config = parse(&deployment.client);
        let stale = connect_pinned(&config).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let live = connect_pinned(&config).await;
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

/// Expect the server to refuse the session: in TLS 1.3 the client
/// finishes before the server has looked at its certificate, so the
/// refusal arrives as an alert on the first exchange rather than as a
/// handshake error. What matters is that the session never carries a
/// frame.
async fn expect_refusal(stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>, who: &str) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = stream;
    let _ = stream.write_all(&[0x7E]).await;
    let mut buf = [0u8; 16];
    let outcome = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
    match outcome {
        Ok(Err(_)) => {}
        Ok(Ok(0)) => {}
        Ok(Ok(read)) => panic!("{who} was served {read} bytes"),
        Err(_) => panic!("{who}'s connection was left open"),
    }
}

#[test]
fn a_client_the_server_does_not_pin_is_refused_at_the_handshake() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");

        // An identity the server has never heard of.
        umsh_bridge::keygen::write_identity(&dir.path().join("stranger.key"), false).unwrap();
        let stranger = deployment.client.replace("cabin.key", "stranger.key");

        let server = parse(&deployment.server);
        tokio::task::spawn_local(async move {
            let _ = umsh_bridge::server::run_config(server).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let config = parse(&stranger);
        let identity = BridgeIdentity::load(&config.identity.as_ref().unwrap().key_file).unwrap();
        let credential = Credential::for_identity(&identity).unwrap();
        let client = config.client.unwrap();
        let tls = umsh_bridge::tls::client_config(&credential, client.server_address).unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls);
        let stream = tokio::net::TcpStream::connect(client.server.as_str())
            .await
            .unwrap();
        let stream = connector
            .connect(umsh_bridge::tls::server_name("127.0.0.1").unwrap(), stream)
            .await
            .expect("the client half of a 1.3 handshake completes early");
        expect_refusal(stream, "an unpinned client").await;
    });
}

#[test]
fn a_client_cannot_wear_a_pinned_address_without_holding_its_key() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");

        let server = parse(&deployment.server);
        tokio::task::spawn_local(async move {
            let _ = umsh_bridge::server::run_config(server).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The attacker presents cabin's certificate — public material —
        // but holds only its own key. rustls's own builder refuses a
        // mismatched pair, so the forgery needs a resolver that skips
        // the consistency check; a real attacker gets to skip it too.
        umsh_bridge::keygen::write_identity(&dir.path().join("stranger.key"), false).unwrap();
        let cabin = BridgeIdentity::load(&dir.path().join("cabin.key")).unwrap();
        let stranger = BridgeIdentity::load(&dir.path().join("stranger.key")).unwrap();
        let cabin_cred = Credential::for_identity(&cabin).unwrap();
        let stranger_cred = Credential::for_identity(&stranger).unwrap();

        use std::sync::Arc;
        use tokio_rustls::rustls;

        #[derive(Debug)]
        struct Forged(Arc<rustls::sign::CertifiedKey>);
        impl rustls::client::ResolvesClientCert for Forged {
            fn resolve(
                &self,
                _hints: &[&[u8]],
                _schemes: &[rustls::SignatureScheme],
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
            fn has_certs(&self) -> bool {
                true
            }
        }

        /// The attacker does not bother verifying the server.
        #[derive(Debug)]
        struct TrustAnything;
        impl rustls::client::danger::ServerCertVerifier for TrustAnything {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &rustls::pki_types::CertificateDer<'_>,
                _d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &rustls::pki_types::CertificateDer<'_>,
                _d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::ED25519]
            }
        }

        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&stranger_cred.key).unwrap();
        let forged = rustls::sign::CertifiedKey::new(cabin_cred.chain.clone(), signing_key);
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnything))
        .with_client_cert_resolver(Arc::new(Forged(Arc::new(forged))));
        tls.alpn_protocols = vec![umsh_bridge::tls::ALPN.to_vec()];

        let client = parse(&deployment.client).client.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
        let stream = tokio::net::TcpStream::connect(client.server.as_str())
            .await
            .unwrap();
        let stream = connector
            .connect(umsh_bridge::tls::server_name("127.0.0.1").unwrap(), stream)
            .await
            .expect("the client half of a 1.3 handshake completes early");
        expect_refusal(stream, "an impostor wearing a pinned address").await;
    });
}

#[test]
fn a_server_whose_identity_does_not_match_is_refused_by_the_client() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "");

        let server = parse(&deployment.server);
        tokio::task::spawn_local(async move {
            let _ = umsh_bridge::server::run_config(server).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let config = parse(&deployment.client);
        let identity = BridgeIdentity::load(&config.identity.as_ref().unwrap().key_file).unwrap();
        let credential = Credential::for_identity(&identity).unwrap();
        let client = config.client.unwrap();
        // Pin some identity that is not the server's.
        umsh_bridge::keygen::write_identity(&dir.path().join("wrong.key"), false).unwrap();
        let wrong = umsh_bridge::tls::Address(
            *BridgeIdentity::load(&dir.path().join("wrong.key"))
                .unwrap()
                .public_key(),
        );
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
