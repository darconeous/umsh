use std::cell::RefCell;

use embassy_executor::Spawner;
use rand::rngs::ThreadRng;
use umsh::{
    crypto::{
        CryptoEngine,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    embassy_support::{
        EmbassyClock, EmbassyPlatform, MemoryCounterStore, MemoryKeyValueStore,
    },
    mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, test_support::SimulatedNetwork},
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

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let network = SimulatedNetwork::new();
    let repeater_radio = network.add_radio();
    let repeater_identity = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);

    let repeater_mac = RefCell::new(build_mac(repeater_radio));
    let repeater_handle = MacHandle::new(&repeater_mac);
    let repeater_id = repeater_handle
        .add_identity(repeater_identity)
        .expect("repeater identity should fit");

    let repeater_key = repeater_mac
        .borrow()
        .identity(repeater_id)
        .expect("repeater identity should exist")
        .identity()
        .public_key()
        .0;
    println!(
        "repeater running in simulated-radio mode as {}",
        hex_encode(&repeater_key[..4])
    );
    println!("forwarding loop active; attach traffic with a separate simulated harness");

    repeater_handle
        .run_quiet()
        .await
        .expect("repeater run loop should succeed");
}

fn build_mac(radio: umsh::mac::test_support::SimulatedRadio) -> RepeaterMac {
    let mut repeater_config = RepeaterConfig::default();
    repeater_config.enabled = true;
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
