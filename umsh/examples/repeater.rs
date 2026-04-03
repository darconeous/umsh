use std::cell::RefCell;

use embassy_executor::Spawner;
use embedded_hal_async::delay::DelayNs;
use rand::rngs::ThreadRng;
use umsh::{
    crypto::{
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
        CryptoEngine, NodeIdentity,
    },
    embassy_support::{EmbassyClock, EmbassyDelay, EmbassyPlatform, MemoryCounterStore, MemoryKeyValueStore},
    mac::{test_support::SimulatedNetwork, Mac, MacHandle, OperatingPolicy, RepeaterConfig},
    node::{Endpoint, EndpointConfig, EndpointEvent, EventAction},
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

type RepeaterMac = Mac<
    RepeaterPlatform,
    IDENTITIES,
    PEERS,
    CHANNELS,
    ACKS,
    TX,
    FRAME,
    DUP,
>;

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
    let shared = CryptoEngine::new(SoftwareAes, SoftwareSha256)
        .derive_pairwise_keys(&alice_identity.shared_secret_with(&bob_key).expect("valid shared secret"));

    let alice_mac = RefCell::new(build_mac(alice_radio, false));
    let repeater_mac = RefCell::new(build_mac(repeater_radio, true));
    let bob_mac = RefCell::new(build_mac(bob_radio, false));

    let alice_handle = MacHandle::new(&alice_mac);
    let repeater_handle = MacHandle::new(&repeater_mac);
    let bob_handle = MacHandle::new(&bob_mac);

    let alice_id = alice_handle.add_identity(alice_identity).expect("alice identity should fit");
    let _repeater_id = repeater_handle.add_identity(repeater_identity).expect("repeater identity should fit");
    let bob_id = bob_handle.add_identity(bob_identity).expect("bob identity should fit");

    let bob_peer = alice_handle.add_peer(bob_key).expect("bob peer should fit");
    let alice_peer = bob_handle.add_peer(alice_key).expect("alice peer should fit");
    alice_handle
        .install_pairwise_keys(alice_id, bob_peer, shared.clone())
        .expect("alice pairwise keys should install");
    bob_handle
        .install_pairwise_keys(bob_id, alice_peer, shared)
        .expect("bob pairwise keys should install");

    let alice = Endpoint::new(alice_id, alice_handle, EndpointConfig::default());
    let mut bob = Endpoint::new(bob_id, bob_handle, EndpointConfig::default())
        .with_kv_store(MemoryKeyValueStore::<4, 32, 128>::default());

    alice
        .send_text(&bob_key, "hello through the embassy repeater")
        .expect("alice send should queue successfully");

    let mut delay = EmbassyDelay;
    for _ in 0..64 {
        alice_mac.borrow_mut().poll_cycle(|_, _| {}).await.expect("alice poll should succeed");
        repeater_mac.borrow_mut().poll_cycle(|_, _| {}).await.expect("repeater poll should succeed");

        let mut delivered = false;
        bob_mac.borrow_mut().poll_cycle(|_, event| {
            if let EventAction::Handled(Some(EndpointEvent::TextReceived { from, message })) = bob.handle_event(event) {
                println!("repeater delivered {} -> {}", hex_encode(&from.0[..4]), message.body);
                delivered = true;
            }
        }).await.expect("bob poll should succeed");

        if delivered {
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