//! Frames sent under a session with forward secrecy are acknowledged like
//! any other: the ack is sealed under the session's keys and completes the
//! send at its origin, in both directions.

#![cfg(feature = "tokio-support")]

use std::future::Future;
use std::time::Duration;

use tokio::task::{JoinHandle, LocalSet, spawn_local};
use umsh::core::PublicKey;
use umsh::crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh::crypto::{CryptoEngine, NodeIdentity};
use umsh::mac::test_support::{SimulatedNetwork, SimulatedRadio};
use umsh::mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh::node::{Host, LocalNode, PfsStatus, SendProgressTicket};
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

/// Brings a node up on `radio` as `secret`, with a pump polling it until
/// the test ends.
async fn boot(radio: SimulatedRadio, secret: [u8; 32]) -> (Node, JoinHandle<()>) {
    let mac: &'static AsyncRefCell<TestMac> = Box::leak(Box::new(AsyncRefCell::new(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rand::rng(),
        MemoryCounterStore::default(),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    ))));
    let handle = MacHandle::new(mac);
    let id = handle
        .add_identity(SoftwareIdentity::from_secret_bytes(&secret))
        .await
        .unwrap();
    let mut host = Host::new(handle);
    let node = host.add_node(id);
    let pump = spawn_local(async move {
        host.run().await.unwrap();
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

/// Waits for `ticket` to finish, and requires that it was acknowledged.
async fn acked(what: &str, ticket: &SendProgressTicket) {
    until(what, || {
        let finished = ticket.is_finished();
        Box::pin(async move { finished })
    })
    .await;
    assert!(
        ticket.was_acked(),
        "{what}: the send finished unacknowledged"
    );
}

#[tokio::test]
async fn sends_under_a_session_are_acknowledged_both_ways() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let alice_radio = network.add_radio_with_config(255, 20);
            let bob_radio = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(alice_radio.id(), bob_radio.id());

            let (alice, _alice_pump) = boot(alice_radio, ALICE).await;
            let (bob, _bob_pump) = boot(bob_radio, BOB).await;
            alice.peer(key(&BOB)).await.unwrap();
            bob.peer(key(&ALICE)).await.unwrap();

            let options = SendOptions::default().with_ack_requested(true);
            alice.request_pfs(&key(&BOB), 60, &options).await.unwrap();
            until("Alice holds the session", || active(&alice, key(&BOB))).await;

            let ticket = alice
                .send_with_secrecy(&key(&BOB), b"first", &options, true)
                .await
                .unwrap();
            acked("Bob acknowledges Alice's first frame", &ticket).await;
            until("Bob holds the session", || active(&bob, key(&ALICE))).await;

            let ticket = bob
                .send_with_secrecy(&key(&ALICE), b"reply", &options, true)
                .await
                .unwrap();
            acked("Alice acknowledges Bob's frame", &ticket).await;

            for n in 0..3 {
                let ticket = alice
                    .send_with_secrecy(&key(&BOB), format!("more {n}").as_bytes(), &options, true)
                    .await
                    .unwrap();
                acked("Bob acknowledges Alice's next frame", &ticket).await;
            }
            // Every send was delivered, so the session is still held.
            assert!(active(&alice, key(&BOB)).await);
            assert!(active(&bob, key(&ALICE)).await);
        })
        .await;
}
