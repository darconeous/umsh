//! A bridge with a LAN interface, in one process.
//!
//! The LAN is a bearer group confined to the loopback interface, and the
//! participant on it is a bare [`LanSocket`]: what it sends is what a
//! radio or endpoint on the LAN would send, and what it hears is what the
//! bridge put there.

use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use umsh::tokio_support::{LanConfig, LanSocket, UdpMulticastRadio};
use umsh_bridge::config::Config;
use umsh_bridge::identity::BridgeIdentity;
use umsh_bridge::lan::LanRelay;
use umsh_bridge::tunnel::{Dequeued, TunnelQueue};
use umsh_core::{NodeHint, PacketBuilder};
use umsh_hal::{CadPolicy, Radio, TxOptions};

const SEGMENT: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 71);
const LAN: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 72);

/// Where each end's radio and LAN membership go, as TOML.
struct Sides {
    server: &'static str,
    client: &'static str,
}

struct Deployment {
    server: String,
    /// The client's configuration, for a server whose tunnel listener
    /// ended up at the given address.
    client: Box<dyn Fn(SocketAddr) -> String>,
    segment_port: u16,
    lan_port: u16,
}

/// Write both configurations, putting a `radio` (the simulated segment)
/// or a `lan` (the loopback group) on each side as `sides` asks.
fn deployment(dir: &Path, sides: Sides) -> Deployment {
    umsh_bridge::keygen::write_identity(&dir.join("server.key"), false).unwrap();
    umsh_bridge::keygen::write_identity(&dir.join("client.key"), false).unwrap();
    let address = |name: &str| {
        BridgeIdentity::load(&dir.join(name))
            .unwrap()
            .public_key()
            .to_string()
    };
    let (server_address, client_address) = (address("server.key"), address("client.key"));

    let segment_port = free_udp_port();
    let lan_port = free_udp_port();
    let d = dir.display();
    let tables = |role: &str, sides: &str| {
        let mut out = String::new();
        if sides.contains("radio") {
            out += &format!(
                "[{role}.radio]\ntype = \"udp-multicast\"\ngroup = \"{SEGMENT}\"\n\
                 port = {segment_port}\n"
            );
        }
        if sides.contains("lan") {
            out +=
                &format!("[{role}.lan]\ngroup = \"{LAN}:{lan_port}\"\ninterface = \"127.0.0.1\"\n");
        }
        out
    };

    let client_key = format!("{d}/client.key");
    let client_tables = tables("client", sides.client);
    Deployment {
        server: format!(
            "[identity]\nkey_file = \"{d}/server.key\"\n\
             [server]\nlisten = [\"127.0.0.1:0\"]\n{}\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{client_address}\"\n",
            tables("server", sides.server)
        ),
        client: Box::new(move |tunnel| {
            format!(
                "[identity]\nkey_file = \"{client_key}\"\n\
                 [client]\nserver = \"{tunnel}\"\n\
                 server_address = \"{server_address}\"\n{client_tables}"
            )
        }),
        segment_port,
        lan_port,
    }
}

/// A UDP port nothing holds. The groups' ports are UDP, and a free TCP
/// port says nothing about them.
fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
    socket.local_addr().unwrap().port()
}

fn parse(text: &str) -> Config {
    let config: Config = toml::from_str(text).unwrap();
    config.validate().unwrap();
    config
}

/// Start both ends. The server's tunnel listener binds port 0 and the
/// client is pointed at whatever port it got, so tests running side by
/// side cannot be handed the same one.
async fn start(deployment: &Deployment) {
    let server = umsh_bridge::server::bind_config(parse(&deployment.server))
        .await
        .expect("binding the server");
    let tunnel = server.tunnel_addrs()[0];
    let client = parse(&(deployment.client)(tunnel));
    tokio::task::spawn_local(async move {
        if let Err(error) = server.run().await {
            eprintln!("bridge: {error:#}");
        }
    });
    tokio::task::spawn_local(async move {
        if let Err(error) = umsh_bridge::server::run_config(client).await {
            eprintln!("bridge: {error:#}");
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
}

fn broadcast(source: u8) -> Vec<u8> {
    let mut buf = [0u8; 255];
    PacketBuilder::new(&mut buf)
        .broadcast()
        .source_hint(NodeHint([source, 0x22, 0x33]))
        .flood_hops(3)
        .payload(b"across the lan")
        .build()
        .unwrap()
        .to_vec()
}

fn lan_participant(port: u16) -> LanSocket {
    LanSocket::bind(LanConfig::host_local(LAN, port)).unwrap()
}

/// Every frame the participant hears within `wait`, less its own.
async fn heard_on_lan(socket: &LanSocket, own: &[Vec<u8>], wait: Duration) -> Vec<Vec<u8>> {
    let mut heard = Vec::new();
    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok((len, _))) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
        let frame = buf[..len].to_vec();
        if !own.contains(&frame) {
            heard.push(frame);
        }
    }
    heard
}

async fn heard_on_segment(radio: &mut UdpMulticastRadio) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let received = tokio::time::timeout(Duration::from_secs(3), async {
        core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf)).await
    })
    .await
    .ok()?
    .ok()?;
    Some(buf[..received.len].to_vec())
}

async fn transmit(radio: &mut UdpMulticastRadio, frame: &[u8]) {
    radio
        .transmit(
            frame,
            TxOptions {
                cad: CadPolicy::Skip,
                power_dbm: None,
            },
        )
        .await
        .unwrap();
}

fn with_local<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(body()));
}

/// A pair of frames, one each way, between the LAN and a segment.
async fn exchange(mut segment: UdpMulticastRadio, lan: LanSocket) {
    let from_lan = broadcast(0x11);
    lan.send(&from_lan).await.unwrap();
    assert_eq!(heard_on_segment(&mut segment).await, Some(from_lan.clone()));

    let from_segment = broadcast(0x22);
    transmit(&mut segment, &from_segment).await;
    assert_eq!(
        heard_on_lan(&lan, &[from_lan], Duration::from_millis(500)).await,
        [from_segment]
    );
}

#[test]
fn a_server_joins_its_lan_to_a_client_segment() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(
            dir.path(),
            Sides {
                server: "lan",
                client: "radio",
            },
        );
        let segment = UdpMulticastRadio::bind_v4(SEGMENT, deployment.segment_port)
            .await
            .unwrap();
        let lan = lan_participant(deployment.lan_port);
        start(&deployment).await;
        exchange(segment, lan).await;
    });
}

#[test]
fn a_client_with_no_radio_joins_its_lan_to_the_server_segment() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(
            dir.path(),
            Sides {
                server: "radio",
                client: "lan",
            },
        );
        let segment = UdpMulticastRadio::bind_v4(SEGMENT, deployment.segment_port)
            .await
            .unwrap();
        let lan = lan_participant(deployment.lan_port);
        start(&deployment).await;
        exchange(segment, lan).await;
    });
}

/// Two participants on one LAN would carry every frame back and forth
/// between them forever, with no repeater in the way to stop it. Each
/// carries a frame across once.
#[test]
fn two_participants_on_one_lan_do_not_circulate_a_frame() {
    with_local(|| async {
        let dir = tempfile::tempdir().unwrap();
        let deployment = deployment(
            dir.path(),
            Sides {
                server: "lan",
                client: "lan",
            },
        );
        let lan = lan_participant(deployment.lan_port);
        start(&deployment).await;

        // The participant hears its own datagram once, as loopback hands
        // it back; any further copy is the frame coming round again.
        let frame = broadcast(0x33);
        lan.send(&frame).await.unwrap();
        assert_eq!(
            heard_on_lan(&lan, &[], Duration::from_secs(1)).await,
            [frame]
        );
    });
}

/// Whether a frame the participant sends to the group comes out of the
/// relay's inbound queue.
async fn relayed(lan: &LanSocket, inbound: &TunnelQueue, frame: &[u8]) -> bool {
    lan.send(frame).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Ok(Dequeued::Frame(heard)) = tokio::time::timeout_at(deadline, inbound.pop()).await {
        if heard.data == frame {
            return true;
        }
    }
    false
}

/// A relay on the routed interface keeps asking the routing table, and
/// when the address under its membership changes it rejoins on the new
/// one, rather than staying joined on an address that hears nothing.
#[test]
fn a_relay_follows_its_routed_interface_to_a_new_address() {
    const RECHECK: Duration = Duration::from_millis(100);
    with_local(|| async {
        let port = free_udp_port();
        let config = LanConfig {
            group: SocketAddrV4::new(LAN, port),
            interface: Ipv4Addr::UNSPECIFIED,
            loopback: true,
        };
        let routed = Rc::new(Cell::new(Ipv4Addr::LOCALHOST));
        let resolver = {
            let routed = routed.clone();
            Box::new(move |_| Ok(routed.get()))
        };
        let inbound = Arc::new(TunnelQueue::new(16, Duration::from_secs(60)));
        let outbound = Arc::new(TunnelQueue::new(16, Duration::from_secs(60)));
        let relay = LanRelay::with_resolver(config, inbound.clone(), outbound, resolver, RECHECK);
        let lan = lan_participant(port);
        tokio::task::spawn_local(async move { relay.run().await });
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(relayed(&lan, &inbound, &broadcast(0x41)).await);

        // The routed address moves to one this host does not hold. A relay
        // that never looked again would still be joined on loopback, and
        // still hear the group there; this one follows the address, where
        // the join fails.
        routed.set(Ipv4Addr::new(192, 0, 2, 1));
        tokio::time::sleep(RECHECK * 3).await;
        assert!(!relayed(&lan, &inbound, &broadcast(0x42)).await);

        // The address comes back to loopback: the relay's next attempt
        // joins there, and it hears the group again.
        routed.set(Ipv4Addr::LOCALHOST);
        let mut tag = 0x43;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        while !relayed(&lan, &inbound, &broadcast(tag)).await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the relay never rejoined"
            );
            tag += 1;
        }
    });
}
