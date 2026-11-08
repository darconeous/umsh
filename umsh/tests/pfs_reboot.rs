//! A session with forward secrecy outlives a reboot at one end only as long
//! as the other end goes on using it: the rebooted node recognizes the
//! traffic from its records, ends the session, and both ends fall back to
//! their long-term keys.

#![cfg(feature = "tokio-support")]

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use tokio::task::{JoinHandle, LocalSet, spawn_local};
use umsh::core::PublicKey;
use umsh::crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh::crypto::{CryptoEngine, NodeIdentity};
use umsh::mac::test_support::{SimulatedNetwork, SimulatedRadio};
use umsh::mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh::node::{Host, LocalNode, PfsStatus};
use umsh::tokio_support::{MemoryCounterStore, MemoryKeyValueStore, StdClock, TokioPlatform};
use umsh_sync::AsyncRefCell;

type Platform = TokioPlatform<SimulatedRadio, MemoryCounterStore, MemoryKeyValueStore>;
/// Room for the long-term identity and a session's ephemeral one.
type TestMac = Mac<Platform, 4, 8, 1, 8, 8, 255, 32>;
type Node = LocalNode<MacHandle<'static, Platform, 4, 8, 1, 8, 8, 255, 32>>;

const ALICE: [u8; 32] = [0x11; 32];
const BOB: [u8; 32] = [0x22; 32];

/// A test that stops making progress fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(20);

fn key(secret: &[u8; 32]) -> PublicKey {
    *SoftwareIdentity::from_secret_bytes(secret).public_key()
}

/// Brings a node up on `radio` as `secret`, its frame counters kept in
/// `counters` across reboots, with a pump polling it until aborted.
async fn boot(
    radio: SimulatedRadio,
    secret: [u8; 32],
    counters: MemoryCounterStore,
) -> (Node, JoinHandle<()>) {
    let mac: &'static AsyncRefCell<TestMac> = Box::leak(Box::new(AsyncRefCell::new(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rand::rng(),
        counters,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    ))));
    let handle = MacHandle::new(mac);
    let id = handle
        .add_identity(SoftwareIdentity::from_secret_bytes(&secret))
        .await
        .unwrap();
    handle.load_persisted_counter(id).await.unwrap();
    let mut host = Host::new(handle);
    let node = host.add_node(id);
    // The data pump, as its own task until the node loses power: never
    // raced, never timed out. Its frame counters are kept after each cycle,
    // as a board keeps them.
    let pump = spawn_local(async move {
        host.run_with(async || {
            handle.service_counter_persistence().await.unwrap();
        })
        .await
        .unwrap();
    });
    (node, pump)
}

async fn until(
    what: &str,
    mut done: impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = bool>>>,
) {
    tokio::time::timeout(PATIENCE, async {
        while !done().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
}

fn active(node: &Node, peer: PublicKey) -> std::pin::Pin<Box<dyn Future<Output = bool>>> {
    let node = node.clone();
    Box::pin(async move { matches!(node.pfs_status(&peer).await, Ok(PfsStatus::Active { .. })) })
}

#[tokio::test]
async fn a_rebooted_node_ends_the_session_its_peer_still_uses() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let alice_radio = network.add_radio_with_config(255, 20);
            let bob_radio = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(alice_radio.id(), bob_radio.id());
            let (alice_id, bob_id) = (alice_radio.id(), bob_radio.id());

            let (alice, _alice_pump) =
                boot(alice_radio, ALICE, MemoryCounterStore::default()).await;
            let bob_counters = MemoryCounterStore::default();
            let (bob, bob_pump) = boot(bob_radio, BOB, bob_counters.clone()).await;
            alice.peer(key(&BOB)).await.unwrap();
            bob.peer(key(&ALICE)).await.unwrap();

            let options = SendOptions::default().with_ack_requested(true);
            alice.request_pfs(&key(&BOB), 60, &options).await.unwrap();
            until("Alice holds the session", || active(&alice, key(&BOB))).await;
            // Bob sends nothing under the session until Alice's first frame
            // under it shows she holds it too.
            alice
                .send_with_secrecy(&key(&BOB), b"hello", &options, true)
                .await
                .unwrap();
            until("Bob holds the session", || active(&bob, key(&ALICE))).await;

            // Bob keeps his records, then loses power.
            let records = bob.pfs_session_records(None).await;
            assert_eq!(records.len(), 1);
            bob_pump.abort();
            drop(bob);

            // He comes back on a new radio at the same place, holding only
            // the public half of the session.
            let reborn_radio = network.add_radio_with_config(255, 20);
            network.disconnect(alice_id, bob_id);
            network.connect_bidirectional(alice_id, reborn_radio.id());
            let (bob, _bob_pump) = boot(reborn_radio, BOB, bob_counters).await;
            bob.peer(key(&ALICE)).await.unwrap();
            let bob_ended = Rc::new(Cell::new(false));
            let ended = bob_ended.clone();
            std::mem::forget(bob.on_pfs_ended(move |_| ended.set(true)));
            bob.restore_pfs_session_records(&records, None).await;
            assert_eq!(bob.pfs_session_records(None).await, records);

            let alice_ended = Rc::new(Cell::new(false));
            let ended = alice_ended.clone();
            std::mem::forget(alice.on_pfs_ended(move |_| ended.set(true)));

            // Alice, none the wiser, says something under the session. It
            // is lost, and Bob ends the session.
            alice
                .send_with_secrecy(&key(&BOB), b"lost", &options, true)
                .await
                .unwrap();
            until("both ends have ended the session", || {
                let both = alice_ended.get() && bob_ended.get();
                Box::pin(async move { both })
            })
            .await;
            assert_eq!(
                alice.pfs_status(&key(&BOB)).await.unwrap(),
                PfsStatus::Inactive
            );
            assert!(bob.pfs_session_records(None).await.is_empty());

            // What she says next goes under the long-term keys, and arrives.
            let heard = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
            let into = heard.clone();
            std::mem::forget(bob.on_receive(move |packet| {
                into.borrow_mut().push(packet.payload().to_vec());
                false
            }));
            alice
                .peer(key(&BOB))
                .await
                .unwrap()
                .send(b"heard", &options)
                .await
                .unwrap();
            until("Bob hears what Alice says next", || {
                let arrived = heard
                    .borrow()
                    .iter()
                    .any(|payload| payload.ends_with(b"heard"));
                Box::pin(async move { arrived })
            })
            .await;
        })
        .await;
}
