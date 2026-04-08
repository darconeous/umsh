use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::Poll;

use embassy_executor::Spawner;
use rand::rngs::ThreadRng;
use umsh::{
    crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    embassy_support::{EmbassyClock, EmbassyPlatform, MemoryCounterStore, MemoryKeyValueStore},
    mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, test_support::SimulatedNetwork},
    node::Host,
    text::UnicastTextChatWrapper,
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
type RepeaterHost<'a> =
    Host<'a, RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // This example is intentionally a simulation/demo, not the minimal repeater surface.
    // It shows an end-to-end forwarding topology with Alice -> repeater -> Bob while still
    // using the current Host/LocalNode/text-wrapper layering at the application edge.
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
    let _delivery_subscription = {
        let delivered = delivered.clone();
        bob_chat.on_text(move |_packet, text| {
            println!(
                "repeater delivered {} -> {}",
                hex_encode(&alice_key.0[..4]),
                text.body
            );
            *delivered.borrow_mut() = true;
        })
    };

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

    for _ in 0..64 {
        // Wait for whichever participant actually has work ready next rather than polling
        // each MAC/Host on a fixed interval.
        match wait_for_any_activity(
            alice_host.pump_once(),
            repeater_handle.next_event(|_, _| {}),
            bob_host.pump_once(),
        )
        .await
        {
            WakeResult::Alice(result) => result.expect("alice pump should succeed"),
            WakeResult::Repeater(result) => result.expect("repeater wake should succeed"),
            WakeResult::Bob(result) => result.expect("bob pump should succeed"),
        }

        if *delivered.borrow() {
            return;
        }
    }

    panic!("simulated repeater delivery timed out before arrival");
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

enum WakeResult<A, B, C> {
    Alice(A),
    Repeater(B),
    Bob(C),
}

async fn wait_for_any_activity<A, B, C>(
    alice: A,
    repeater: B,
    bob: C,
) -> WakeResult<A::Output, B::Output, C::Output>
where
    A: Future,
    B: Future,
    C: Future,
{
    // Embassy does not offer a standard-library-style select helper here, so we build the
    // smallest possible "wake on whichever future becomes ready first" adapter.
    let mut alice = core::pin::pin!(alice);
    let mut repeater = core::pin::pin!(repeater);
    let mut bob = core::pin::pin!(bob);

    poll_fn(|cx| {
        if let Poll::Ready(output) = alice.as_mut().poll(cx) {
            return Poll::Ready(WakeResult::Alice(output));
        }
        if let Poll::Ready(output) = repeater.as_mut().poll(cx) {
            return Poll::Ready(WakeResult::Repeater(output));
        }
        if let Poll::Ready(output) = bob.as_mut().poll(cx) {
            return Poll::Ready(WakeResult::Bob(output));
        }
        Poll::Pending
    })
    .await
}
