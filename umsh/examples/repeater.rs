use std::cell::RefCell;
use std::rc::Rc;

use embassy_executor::Spawner;
use embedded_hal_async::delay::DelayNs;
use rand::rngs::ThreadRng;
use umsh::{
    crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    embassy_support::{
        EmbassyClock, EmbassyDelay, EmbassyPlatform, MemoryCounterStore, MemoryKeyValueStore,
    },
    mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, test_support::SimulatedNetwork},
    node::{Host, UnicastTextChatWrapper},
};

const IDENTITIES: usize = 4;
const PEERS: usize = 16;
const CHANNELS: usize = 8;
const ACKS: usize = 16;
const TX: usize = 16;
const FRAME: usize = 256;
const DUP: usize = 64;

type RepeaterPlatform = EmbassyPlatform<
    umsh::mac::test_support::SimulatedRadio,
    ThreadRng,
    MemoryCounterStore<4, 32>,
    MemoryKeyValueStore<4, 32, 128>,
>;

type RepeaterMac = Mac<RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type RepeaterHost<'a> = Host<'a, RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let network = SimulatedNetwork::new();
    let alice_radio = network.add_radio();
    let repeater_radio = network.add_radio();
    let bob_radio = network.add_radio();
    network.connect_bidirectional(alice_radio.id(), repeater_radio.id());
    network.connect_bidirectional(repeater_radio.id(), bob_radio.id());

    let alice_identity = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
    let repeater_identity = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);
    let bob_identity = SoftwareIdentity::from_secret_bytes(&[0x33; 32]);
    let alice_key = *alice_identity.public_key();
    let bob_key = *bob_identity.public_key();

    let alice_mac = RefCell::new(build_mac(alice_radio, false));
    let repeater_mac = RefCell::new(build_mac(repeater_radio, true));
    let bob_mac = RefCell::new(build_mac(bob_radio, false));

    let alice_handle = MacHandle::new(&alice_mac);
    let repeater_handle = MacHandle::new(&repeater_mac);
    let bob_handle = MacHandle::new(&bob_mac);

    let alice_id = alice_handle
        .add_identity(alice_identity)
        .expect("alice identity should fit");
    let _repeater_id = repeater_handle
        .add_identity(repeater_identity)
        .expect("repeater identity should fit");
    let bob_id = bob_handle
        .add_identity(bob_identity)
        .expect("bob identity should fit");

    let mut alice_host = RepeaterHost::new(alice_handle);
    let mut bob_host = RepeaterHost::new(bob_handle);
    let alice_node = alice_host.add_node(alice_id);
    let bob_node = bob_host.add_node(bob_id);
    let bob = bob_node.peer(alice_key).expect("alice peer should fit");
    let bob_chat = UnicastTextChatWrapper::from_peer(&bob);
    let delivered = Rc::new(RefCell::new(false));
    {
        let delivered = delivered.clone();
        bob_chat.on_text(move |body| {
            println!(
                "repeater delivered {} -> {}",
                hex_encode(&alice_key.0[..4]),
                body
            );
            *delivered.borrow_mut() = true;
        });
    }

    let alice = alice_node.peer(bob_key).expect("bob peer should fit");
    let alice_chat = UnicastTextChatWrapper::from_peer(&alice);
    alice_chat
        .send_text(
            "hello through the embassy repeater",
            &umsh::mac::SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(5),
        )
        .await
        .expect("alice send should queue successfully");

    let mut delay = EmbassyDelay;
    for _ in 0..64 {
        alice_host.pump_once().await.expect("alice pump should succeed");
        repeater_mac
            .borrow_mut()
            .poll_cycle(|_, _| {})
            .await
            .expect("repeater poll should succeed");
        bob_host.pump_once().await.expect("bob pump should succeed");

        if *delivered.borrow() {
            return;
        }

        delay.delay_ns(10_000_000).await;
    }

    panic!("repeater example timed out before delivery");
}

fn build_mac(radio: umsh::mac::test_support::SimulatedRadio, repeater: bool) -> RepeaterMac {
    let mut repeater_config = RepeaterConfig::default();
    repeater_config.enabled = repeater;
    Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        EmbassyClock,
        rand::rng(),
        MemoryCounterStore::<4, 32>::default(),
        repeater_config,
        OperatingPolicy::default(),
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
