//! A whole bridge in one process.
//!
//! Server and client both run on the test's `LocalSet`, joined by a real
//! TLS tunnel over loopback and fronted by the UDP-multicast fake radio
//! on two different groups — one "segment" each. Injecting a frame on
//! one segment and watching what appears on the other exercises the
//! tunnel, the relay, and the hub together, which is the only way to
//! catch the places where those three disagree.
//!
//! The fake radio has no node behind it, and so no repeater: what
//! crosses here crosses exactly as the bridge carried it. That is the
//! point of these tests — they pin what the *bridge* does, which is very
//! nearly nothing. Hop accounting, duplicate suppression, and trace
//! prepending belong to the repeaters on either side, and are tested
//! where they live.

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
fn deployment(dir: &Path, extra_limits: &str) -> Deployment {
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
             port = {server_port}\n{extra_limits}\
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
fn a_frame_crosses_the_bridge_exactly_as_it_was_heard() {
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

        let arrived = expect_frame(&mut segment_a)
            .await
            .expect("the frame should have crossed the bridge");
        assert_eq!(
            arrived, sent,
            "the bridge carries frames; it does not rewrite them"
        );

        // Spelled out, because these are the rewrites the bridge used to
        // make and now leaves to the repeaters on either side.
        let header = PacketHeader::parse(&arrived).unwrap();
        let hops = header.flood_hops.unwrap();
        assert_eq!(hops.remaining(), 3, "no hop was spent at the bridge");
        assert_eq!(hops.accumulated(), 0);
        let options = ParsedOptions::extract(&arrived, header.options_range.clone()).unwrap();
        assert!(
            arrived[options.trace_route.clone().expect("the trace survives")].is_empty(),
            "the bridge is nobody's hop, so it writes no trace entry"
        );
        assert!(
            arrived[options.trace_signal.clone().expect("the signal survives")].is_empty(),
            "and no signal entry to pair with one"
        );
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
        // Nothing comes back. Confirming the previous hop is the ingress
        // repeater's ordinary re-transmission, which happens on the
        // segment and never reaches the bridge as something to send.
        expect_no_frame(&mut segment_b).await;
        expect_no_frame(&mut segment_a).await;
    });
}

#[test]
fn a_spent_flood_budget_is_the_repeaters_business_not_the_bridges() {
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

        // It crosses. A real deployment's ingress repeater would never
        // have transmitted it — a spent budget is refused at the node,
        // before the bridge is offered anything — but the bridge itself
        // does not read hop counts, and a fake radio has no repeater to
        // stop it.
        let arrived = expect_frame(&mut segment_a).await.expect("crossed");
        assert_eq!(arrived, spent);
    });
}

#[test]
fn the_exit_clamp_lowers_a_budget_on_the_way_through() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(dir.path(), "[server.limits]\nexit_clamp = 1\n");
        let mut segment_a = UdpMulticastRadio::bind_v4(SEGMENT_A, deployment.server_port)
            .await
            .unwrap();
        let mut segment_b = UdpMulticastRadio::bind_v4(SEGMENT_B, deployment.client_port)
            .await
            .unwrap();
        start(&deployment).await;

        let sent = broadcast(7, 0x66, &[]);
        segment_b
            .transmit(
                &sent,
                TxOptions {
                    cad: CadPolicy::Skip,
                },
            )
            .await
            .unwrap();

        let arrived = expect_frame(&mut segment_a).await.expect("crossed");
        let hops = PacketHeader::parse(&arrived).unwrap().flood_hops.unwrap();
        assert_eq!(hops.remaining(), 1, "held closer to home by the operator");
        assert_eq!(hops.accumulated(), 0, "the clamp spends no hop of its own");
        assert_eq!(
            arrived[2..],
            sent[2..],
            "the hop byte is the only thing the bridge ever writes"
        );
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

// ---------------------------------------------------------------------
// Host interfaces
// ---------------------------------------------------------------------

/// A server that is nothing but host interfaces: no radio, no clients,
/// no hardware anywhere. Two hosts on it are a two-node mesh on one
/// machine, which is what host interfaces exist for.
fn host_only_deployment(dir: &Path, ports: (u16, u16), limits: (u32, u32)) -> String {
    umsh_bridge::keygen::write_identity(&dir.join("identity.key"), false).unwrap();
    let d = dir.display();
    format!(
        "[identity]\nkey_file = \"{d}/identity.key\"\n\
         [server]\nlisten = [\"127.0.0.1:{}\"]\n\
         [[server.hosts]]\nname = \"alice\"\nlisten = \"127.0.0.1:{}\"\n\
         max_frames_per_minute = {}\n\
         [[server.hosts]]\nname = \"bob\"\nlisten = \"127.0.0.1:{}\"\n\
         max_frames_per_minute = {}\n",
        free_port(),
        ports.0,
        limits.0,
        ports.1,
        limits.1,
    )
}

/// Attach to a host interface exactly as `umshctl --tcp` does: the same
/// HDLC framing a serial link carries, over a socket.
async fn attach_host(
    port: u16,
) -> umsh::ulcp::UlcpDevice<umsh::ulcp::SerialFrameLink<tokio::net::TcpStream>> {
    let stream = tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .expect("connecting to the host interface");
    stream.set_nodelay(true).unwrap();
    let link = umsh::ulcp::SerialFrameLink::new(stream);
    let mut device = umsh::ulcp::UlcpDevice::attach_existing(
        link,
        umsh::ulcp::UlcpDeviceConfig::new(910_525, 62_500, 7, 5),
    )
    .await
    .expect("attaching to the host interface");
    // A host on the medium drives its own PHY; nothing is heard or sent
    // until it switches the radio on, simulated or not.
    device
        .set_prop(umsh_ulcp::ids::prop::PHY_ENABLED, &[1])
        .await
        .expect("enabling the simulated PHY");
    device
}

/// Wait for a raw frame from a host interface's device.
async fn expect_host_frame(
    device: &mut umsh::ulcp::UlcpDevice<umsh::ulcp::SerialFrameLink<tokio::net::TcpStream>>,
) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        core::future::poll_fn(|cx| device.poll_receive_raw(cx)).await
    })
    .await
    .ok()?
    .ok()
    .map(|raw| raw.data)
}

async fn transmit_from_host(
    device: &mut umsh::ulcp::UlcpDevice<umsh::ulcp::SerialFrameLink<tokio::net::TcpStream>>,
    frame: &[u8],
) {
    let mut meta = [0u8; umsh_ulcp::meta::TxMeta::WIRE_LEN];
    umsh_ulcp::meta::TxMeta::default()
        .encode(&mut meta)
        .unwrap();
    device
        .transmit_raw_with_meta(frame, &meta)
        .await
        .expect("the simulated PHY accepts a transmit");
}

#[test]
fn two_hosts_reach_each_other_with_no_radio_anywhere() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let ports = (free_port(), free_port());
        let config = parse(&host_only_deployment(dir.path(), ports, (600, 600)));
        tokio::task::spawn_local(async move {
            if let Err(error) = umsh_bridge::server::run_config(config).await {
                eprintln!("server: {error:#}");
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut alice = attach_host(ports.0).await;
        let mut bob = attach_host(ports.1).await;

        let sent = broadcast(3, 0x11, &[]);
        transmit_from_host(&mut alice, &sent).await;

        let arrived = expect_host_frame(&mut bob)
            .await
            .expect("the frame should have reached the other host");
        assert_eq!(
            arrived, sent,
            "a host interface carries frames; it does not rewrite them"
        );
    });
}

#[test]
fn a_hosts_frames_stop_at_the_hub_once_its_budget_is_spent() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let ports = (free_port(), free_port());
        // One frame a minute for alice: the second is refused by the
        // hub, not by her device.
        let config = parse(&host_only_deployment(dir.path(), ports, (1, 600)));
        tokio::task::spawn_local(async move {
            if let Err(error) = umsh_bridge::server::run_config(config).await {
                eprintln!("server: {error:#}");
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut alice = attach_host(ports.0).await;
        let mut bob = attach_host(ports.1).await;

        transmit_from_host(&mut alice, &broadcast(3, 0x11, &[])).await;
        assert!(
            expect_host_frame(&mut bob).await.is_some(),
            "the first frame is within budget"
        );

        // A second frame is accepted by the device — a host's own duty
        // ledger has nothing to say about simulated airtime — and then
        // discarded by the hub.
        transmit_from_host(&mut alice, &broadcast(3, 0x22, &[])).await;
        let starved = tokio::time::timeout(Duration::from_millis(500), async {
            core::future::poll_fn(|cx| bob.poll_receive_raw(cx)).await
        })
        .await;
        assert!(starved.is_err(), "the spent budget should stop the frame");
    });
}

#[test]
fn a_host_that_reconnects_finds_the_device_where_it_left_it() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let ports = (free_port(), free_port());
        let config = parse(&host_only_deployment(dir.path(), ports, (600, 600)));
        tokio::task::spawn_local(async move {
            if let Err(error) = umsh_bridge::server::run_config(config).await {
                eprintln!("server: {error:#}");
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The device outlives the host, as a radio outlives whoever
        // unplugs from it: a name set through one attachment is still
        // there for the next.
        let mut alice = attach_host(ports.0).await;
        alice
            .set_prop(umsh_ulcp::ids::prop::DEV_NAME, b"named by the first host")
            .await
            .unwrap();
        drop(alice);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut again = attach_host(ports.0).await;
        let name = again
            .get_prop(umsh_ulcp::ids::prop::DEV_NAME)
            .await
            .unwrap();
        assert_eq!(
            name.strip_suffix(&[0]).unwrap_or(&name),
            b"named by the first host",
            "device-domain state should survive a host detaching"
        );
    });
}

/// The safety claim in one assertion: the device a host interface
/// presents does not advertise a node, so a participant's own
/// `CAP_MAC_BACKHAUL` check refuses to bridge through it.
#[test]
fn a_host_interface_does_not_pretend_to_have_a_node() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let ports = (free_port(), free_port());
        let config = parse(&host_only_deployment(dir.path(), ports, (600, 600)));
        tokio::task::spawn_local(async move {
            if let Err(error) = umsh_bridge::server::run_config(config).await {
                eprintln!("server: {error:#}");
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut device = attach_host(ports.0).await;
        let capabilities = device.capabilities().await.unwrap();
        assert!(!capabilities.contains(&umsh_ulcp::ids::cap::MAC_BACKHAUL));
        assert!(!capabilities.contains(&umsh_ulcp::ids::cap::REPEATER));
        assert!(
            capabilities.contains(&umsh_ulcp::ids::cap::WRITABLE_RAW_STREAM),
            "a host still has to be able to transmit"
        );
    });
}

/// A host that connects while another holds the interface takes it over,
/// rather than waiting behind a socket nobody may ever close. Same rule
/// as a tunnel client, and for the same reason: the newer connection is
/// the live host.
#[test]
fn a_second_host_displaces_the_first() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let ports = (free_port(), free_port());
        let config = parse(&host_only_deployment(dir.path(), ports, (600, 600)));
        tokio::task::spawn_local(async move {
            if let Err(error) = umsh_bridge::server::run_config(config).await {
                eprintln!("server: {error:#}");
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The first host attaches and is deliberately left holding its
        // socket open, as a wedged simulator would.
        let first = attach_host(ports.0).await;
        let mut bob = attach_host(ports.1).await;

        // A second host on the same interface takes it over.
        let mut second = attach_host(ports.0).await;
        transmit_from_host(&mut second, &broadcast(3, 0x33, &[])).await;
        assert!(
            expect_host_frame(&mut bob).await.is_some(),
            "the displacing host should own the interface"
        );

        drop(first);
    });
}
