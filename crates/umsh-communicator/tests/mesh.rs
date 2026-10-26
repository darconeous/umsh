//! Two communicators on a simulated radio link, each over a real MAC and
//! its own soft device, as two boards would run: what one sends, the other
//! keeps, and the sender sees acknowledged.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use tokio::task::{LocalSet, spawn_local};
use umsh::crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh::crypto::{CryptoEngine, NodeIdentity};
use umsh::mac::test_support::{SimulatedNetwork, SimulatedRadio};
use umsh::mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig};
use umsh::node::{Host, LocalNode, PfsStatus};
use umsh::tokio_support::{MemoryCounterStore, MemoryKeyValueStore, StdClock, TokioPlatform};
use umsh_communicator::task::{self, Inbox};
use umsh_communicator::{
    ChannelCrypto, Clock, CommunicatorNode, MemoryStore, Seeds, WellKnownChannels,
};
use umsh_core::PublicKey;
use umsh_sync::AsyncRefCell;
use umsh_ulcp::ids::prop;
use umsh_ulcp_simdev::SimulatedDevice;
use umsh_ux_communicator::model::{
    ChatKind, Chats, Delivery, Exchange, ExchangeEnd, MeetState, Member, MessageId, NearbyDevice,
    Node, NodeEvent, Peers, Via,
};
use umsh_ux_communicator::models;

mod support;

use support::{Port, device, phone_inserts, provision};

type Platform = TokioPlatform<SimulatedRadio, MemoryCounterStore, MemoryKeyValueStore>;
/// Room for the board's identity and the ephemeral ones its sessions with
/// forward secrecy take, as the device node has.
type MeshMac = Mac<Platform, 5, 16, 4, 8, 8, 255, 32>;

/// A test that stops making progress fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(20);

/// How long one turn of a device node's pump waits for its radio.
const TURN: Duration = Duration::from_millis(5);

/// The board's clock, from when the test started.
struct Since(Instant);

impl Clock for Since {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }

    fn wall(&self) -> Option<u32> {
        Some(1_792_247_520 + self.0.elapsed().as_secs() as u32)
    }
}

/// One board: its communicator's node, the soft device it holds its
/// settings on, the device node, and the device identity's key.
struct Board {
    node: &'static CommunicatorNode<Port>,
    sim: Rc<RefCell<SimulatedDevice>>,
    mesh: LocalNode<MacHandle<'static, Platform, 5, 16, 4, 8, 8, 255, 32>>,
    key: PublicKey,
}

/// Brings a board up on `radio` as the identity `secret` makes: the soft
/// device holds it, and the device node's MAC runs as it.
async fn board(radio: SimulatedRadio, secret: [u8; 32]) -> Board {
    let sim = device();
    provision(&sim, Some(&secret));
    let clock: &'static Since = Box::leak(Box::new(Since(Instant::now())));
    let node: &'static CommunicatorNode<Port> = Box::leak(Box::new(CommunicatorNode::new(
        Port(sim.clone()),
        MemoryStore::new(),
        ChannelCrypto::software(),
        &std::alloc::System,
        clock,
        Seeds {
            session_id: u64::from(secret[0]),
            jitter_seed: 2,
        },
    )));
    node.pump();
    assert!(node.started());

    let identity = SoftwareIdentity::from_secret_bytes(&secret);
    let key = *identity.public_key();
    let mac: &'static AsyncRefCell<MeshMac> = Box::leak(Box::new(AsyncRefCell::new(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rand::rng(),
        MemoryCounterStore::default(),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    ))));
    let handle = MacHandle::new(mac);
    handle.set_auto_register_full_key_peers(true).await;
    let id = handle.add_identity(identity).await.unwrap();
    let mut host = Host::new(handle);
    let mesh = host.add_node(id);

    let inbox: &'static Inbox<NoopRawMutex> = Box::leak(Box::new(Inbox::new()));
    std::mem::forget(task::listen(&mesh, inbox, key, WellKnownChannels::derive()));
    // The simulated radio wakes no one when a frame reaches it, so the
    // pump is polled again every few milliseconds.
    spawn_local(async move {
        loop {
            if let Ok(pumped) = tokio::time::timeout(TURN, host.pump_once()).await {
                pumped.unwrap();
            }
            handle.service_counter_persistence().await.unwrap();
        }
    });
    let board = Board {
        node,
        sim,
        mesh: mesh.clone(),
        key,
    };
    spawn_local(async move {
        task::run(
            node,
            &mesh,
            inbox,
            |at| tokio::time::sleep(Duration::from_millis(at.saturating_sub(clock.now_ms()))),
            || {},
        )
        .await;
    });
    board
}

/// Brings a repeater up on `radio` as the identity `secret` makes: a MAC
/// that forwards and does nothing else. Returns its key.
async fn repeater(radio: SimulatedRadio, secret: [u8; 32]) -> PublicKey {
    let identity = SoftwareIdentity::from_secret_bytes(&secret);
    let key = *identity.public_key();
    let mut config = RepeaterConfig::default();
    config.enabled = true;
    let mac: &'static AsyncRefCell<MeshMac> = Box::leak(Box::new(AsyncRefCell::new(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rand::rng(),
        MemoryCounterStore::default(),
        config,
        OperatingPolicy::default(),
    ))));
    let handle = MacHandle::new(mac);
    handle.add_identity(identity).await.unwrap();
    spawn_local(async move {
        loop {
            if let Ok(served) = tokio::time::timeout(TURN, handle.next_event(|_, _| {})).await {
                served.unwrap();
            }
        }
    });
    key
}

/// Who carried `message` in `chat`, sent by `board`, and how far it got,
/// as its row shows them.
fn how_sent(board: &Board, chat: u32, message: MessageId) -> (Delivery, Option<Via>) {
    let message = board.node.message(chat, message).unwrap();
    (message.delivery, message.via)
}

fn address(key: &PublicKey) -> String {
    umsh_core::base58::encode(&key.0)
        .iter()
        .map(|&digit| char::from(digit))
        .collect()
}

/// Waits until `done` holds, failing the test if it never does.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The first direct message to a node that has never heard of us arrives
/// and is acknowledged, and so does the answer.
#[tokio::test(flavor = "current_thread")]
async fn a_direct_message_is_delivered() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let bob = board(far, [0x22; 32]).await;
            while bob.node.next_event().is_some() {}

            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            let sent = alice
                .node
                .send(chat.id, "Meet at the ridge", None, false)
                .unwrap();
            let mut arrived = None;
            let settled = NodeEvent::Settled {
                chat: chat.id,
                message: sent.id,
            };
            let mut settlings = 0;
            until("the message was not delivered", || {
                while let Some(event) = bob.node.next_event() {
                    if let NodeEvent::Arrived { chat, message } = event {
                        arrived = Some((chat, message));
                    }
                }
                while let Some(event) = alice.node.next_event() {
                    settlings += usize::from(event == settled);
                }
                let delivery = alice.node.message(chat.id, sent.id).unwrap().delivery;
                arrived.is_some() && delivery == Delivery::Delivered
            })
            .await;
            // Its acknowledgment is announced as how it came out, once.
            tokio::time::sleep(Duration::from_millis(200)).await;
            while let Some(event) = alice.node.next_event() {
                settlings += usize::from(event == settled);
            }
            assert_eq!(settlings, 1);
            let latest = alice.node.latest_sent(chat.id);
            assert_eq!(latest.sent, Some(sent.id));
            assert_eq!(latest.delivered, Some(sent.id));
            let (chat, message) = arrived.unwrap();
            let message = bob.node.message(chat, message).unwrap();
            assert_eq!(&*message.text, "Meet at the ridge");
            assert_eq!(
                bob.node.chat(chat).unwrap().kind,
                ChatKind::Peer { hops: Some(1) }
            );

            // The answer goes back the same way.
            while alice.node.next_event().is_some() {}
            let answer = bob.node.send(chat, "On my way", None, false).unwrap();
            let mut answered = false;
            until("the answer was not delivered", || {
                while let Some(event) = alice.node.next_event() {
                    answered |= matches!(event, NodeEvent::Arrived { .. });
                }
                let delivery = bob.node.message(chat, answer.id).unwrap().delivery;
                answered && delivery == Delivery::Delivered
            })
            .await;
        })
        .await;
}

/// A message too long for one frame is announced as having come out once,
/// when its last fragment is acknowledged, not as each one is.
#[tokio::test(flavor = "current_thread")]
async fn a_long_message_settles_once_all_of_it_is_acknowledged() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let bob = board(far, [0x22; 32]).await;

            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            while alice.node.next_event().is_some() {}
            let text = "Meet at the ridge, then the saddle, then down the far side. ".repeat(8);
            let sent = alice.node.send(chat.id, &text, None, false).unwrap();
            let settled = NodeEvent::Settled {
                chat: chat.id,
                message: sent.id,
            };
            let mut settlings = 0;
            let mut changes = 0;
            until("the message was not delivered", || {
                while bob.node.next_event().is_some() {}
                while let Some(event) = alice.node.next_event() {
                    settlings += usize::from(event == settled);
                    changes += usize::from(matches!(
                        event,
                        NodeEvent::MessageChanged { message, .. } if message == sent.id
                    ));
                }
                alice.node.message(chat.id, sent.id).unwrap().delivery == Delivery::Delivered
            })
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            while let Some(event) = alice.node.next_event() {
                settlings += usize::from(event == settled);
            }
            assert!(changes > 0, "its fragments were heard of on the way");
            assert_eq!(settlings, 1);
        })
        .await;
}

/// Waits until `alice` and `bob` both hold a session with forward secrecy
/// with each other, or neither does.
async fn until_secrecy(alice: &Board, bob: &Board, held: bool) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let alice_holds = alice.mesh.pfs_status(&bob.key).await.unwrap();
        let bob_holds = bob.mesh.pfs_status(&alice.key).await.unwrap();
        let active = |status: &PfsStatus| matches!(status, PfsStatus::Active { .. });
        let inactive = |status: &PfsStatus| matches!(status, PfsStatus::Inactive);
        let done = if held {
            active(&alice_holds) && active(&bob_holds)
        } else {
            inactive(&alice_holds) && inactive(&bob_holds)
        };
        if done {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "forward secrecy held: {alice_holds:?} and {bob_holds:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A saved peer who prefers forward secrecy is asked for a session, which
/// both boards then hold, the chat shows, and what is said goes through
/// under; it ends when they no longer prefer one. Only what was sent while
/// the chat showed the session says it went under one.
#[tokio::test(flavor = "current_thread")]
async fn forward_secrecy_is_held_with_a_peer_who_prefers_it() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let bob = board(far, [0x22; 32]).await;

            phone_inserts(&alice.sim, prop::DEV_PEERS, &bob.key.0);
            alice.node.pump();
            let mut peers = Peers::new();
            alice.node.peers(&mut peers);
            let peer = peers[0].id;
            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            let shown = || alice.node.chat(chat.id).unwrap().forward_secret;
            let say = async |text| {
                let sent = alice.node.send(chat.id, text, None, shown()).unwrap();
                until("the message was not delivered", || {
                    alice.node.message(chat.id, sent.id).unwrap().delivery == Delivery::Delivered
                })
                .await;
                sent.id
            };
            let secret = |id| alice.node.message(chat.id, id).unwrap().forward_secret;

            let before = say("Leaving now").await;
            assert!(!secret(before));

            alice.node.set_forward_secrecy(peer, true);
            until_secrecy(&alice, &bob, true).await;
            until("the chat does not show the session", shown).await;
            let during = say("Meet at the ridge").await;
            assert!(secret(during));

            alice.node.set_forward_secrecy(peer, false);
            assert!(!shown(), "the chat shows the session ended at once");
            until_secrecy(&alice, &bob, false).await;
            let after = say("Almost there").await;
            assert!(!secret(after));
            assert!(!secret(before) && secret(during), "each keeps its own");
        })
        .await;
}

/// What is said under a session with forward secrecy lands in the same
/// chat as what was said before it, on both ends: the session's addresses
/// are its own, but the people in it are not new.
#[tokio::test(flavor = "current_thread")]
async fn what_is_said_under_forward_secrecy_lands_in_the_same_chat() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let bob = board(far, [0x22; 32]).await;

            phone_inserts(&alice.sim, prop::DEV_PEERS, &bob.key.0);
            alice.node.pump();
            let mut peers = Peers::new();
            alice.node.peers(&mut peers);
            let peer = peers[0].id;
            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            while bob.node.next_event().is_some() {}

            // Says `text` from `from` in `chat` and returns the chat it
            // arrives in at `to`.
            let say = async |from: &Board, to: &Board, chat, text| {
                let secret = from.node.chat(chat).unwrap().forward_secret;
                let sent = from.node.send(chat, text, None, secret).unwrap();
                let mut arrived = None;
                until("the message did not arrive", || {
                    while let Some(event) = to.node.next_event() {
                        if let NodeEvent::Arrived { chat, message } = event
                            && &*to.node.message(chat, message).unwrap().text == text
                        {
                            arrived = Some(chat);
                        }
                    }
                    arrived.is_some()
                        && from.node.message(chat, sent.id).unwrap().delivery == Delivery::Delivered
                })
                .await;
                arrived.unwrap()
            };

            let bobs_chat = say(&alice, &bob, chat.id, "Leaving now").await;
            // Alice saved Bob; Bob did not save Alice.
            assert_eq!(alice.node.chat_peer(chat.id), Some(peer));
            assert_eq!(bob.node.chat_peer(bobs_chat), None);
            let alice_to_bob = bob.node.chat_member(bobs_chat).unwrap();
            assert_eq!(
                alice_to_bob.address.as_deref(),
                Some(address(&alice.key).as_str())
            );
            assert!(!alice_to_bob.saved);
            assert!(alice.node.chat_member(chat.id).unwrap().saved);

            alice.node.set_forward_secrecy(peer, true);
            until_secrecy(&alice, &bob, true).await;
            until("the chat does not show the session", || {
                alice.node.chat(chat.id).unwrap().forward_secret
            })
            .await;
            assert_eq!(
                say(&alice, &bob, chat.id, "Meet at the ridge").await,
                bobs_chat
            );
            assert_eq!(say(&bob, &alice, bobs_chat, "On my way").await, chat.id);

            // Each side's details say which messages had forward secrecy.
            let secrecy = |board: &Board, chat| {
                (0..board.node.rows(chat))
                    .filter_map(|row| board.node.row_message(chat, row))
                    .map(|m| {
                        let details = board.node.details(chat, m.id).unwrap();
                        (m.text.to_string(), details.forward_secret)
                    })
                    .collect::<Vec<_>>()
            };
            let expected = [
                ("Leaving now".to_string(), false),
                ("Meet at the ridge".to_string(), true),
                ("On my way".to_string(), true),
            ];
            assert_eq!(secrecy(&alice, chat.id), expected);
            assert_eq!(secrecy(&bob, bobs_chat), expected);
        })
        .await;
}

/// A message I delete is gone for everyone: a stand-in takes its place on
/// both sides.
#[tokio::test(flavor = "current_thread")]
async fn a_message_i_delete_is_deleted_for_my_peer_too() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let bob = board(far, [0x22; 32]).await;
            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            while bob.node.next_event().is_some() {}

            let sent = alice
                .node
                .send(chat.id, "Wrong ridge", None, false)
                .unwrap();
            let mut arrived = None;
            until("the message did not arrive", || {
                while let Some(event) = bob.node.next_event() {
                    if let NodeEvent::Arrived { chat, message } = event {
                        arrived = Some((chat, message));
                    }
                }
                arrived.is_some()
            })
            .await;
            let (bobs_chat, theirs) = arrived.unwrap();

            alice.node.delete_message(chat.id, sent.id);
            assert!(alice.node.message(chat.id, sent.id).unwrap().deleted);
            until("the deletion did not arrive", || {
                while bob.node.next_event().is_some() {}
                bob.node
                    .message(bobs_chat, theirs)
                    .is_some_and(|m| m.deleted)
            })
            .await;
        })
        .await;
}

/// A deleted chat is gone with its messages, and what its peer says next
/// starts a new one holding only that.
#[tokio::test(flavor = "current_thread")]
async fn a_deleted_chat_starts_over_with_the_next_message() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let bob = board(far, [0x22; 32]).await;
            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            while bob.node.next_event().is_some() {}

            let say = async |text| {
                let sent = alice.node.send(chat.id, text, None, false).unwrap();
                let mut arrived = None;
                until("the message did not arrive", || {
                    while let Some(event) = bob.node.next_event() {
                        if let NodeEvent::Arrived { chat, .. } = event {
                            arrived = Some(chat);
                        }
                    }
                    arrived.is_some()
                        && alice.node.message(chat.id, sent.id).unwrap().delivery
                            == Delivery::Delivered
                })
                .await;
                arrived.unwrap()
            };

            let first = say("Leaving now").await;
            bob.node.delete_chat(first);
            let mut removed = false;
            while let Some(event) = bob.node.next_event() {
                removed |= event == NodeEvent::ChatRemoved(first);
            }
            assert!(removed);
            assert!(bob.node.chat(first).is_none());

            let second = say("Meet at the ridge").await;
            assert_eq!(bob.node.rows(second), 1);
            let message = bob.node.row_message(second, 0).unwrap();
            assert_eq!(&*message.text, "Meet at the ridge");
        })
        .await;
}

/// What Add peer on `board` shows now, with the device's answers taken in.
fn meet(board: &Board) -> MeetState {
    board.node.pump();
    let mut state = MeetState::new();
    board.node.meet(&mut state);
    state
}

/// Names `board`'s device `name`.
fn named(board: &Board, name: &str) {
    board.node.set_name(name);
    board.node.pump();
    while board.node.next_event().is_some() {}
}

/// Two boards in range of each other and of a third radio that only
/// listens, named Alice and Bob, both on Add peer, each listing the other.
async fn on_nearby() -> (Board, Board, Tap, NearbyDevice, NearbyDevice) {
    let network = SimulatedNetwork::new();
    let near = network.add_radio_with_config(255, 20);
    let far = network.add_radio_with_config(255, 20);
    let tap = network.add_radio_with_config(255, 20);
    network.connect_bidirectional(near.id(), far.id());
    network.connect(near.id(), tap.id());
    network.connect(far.id(), tap.id());
    let alice = board(near, [0x11; 32]).await;
    let bob = board(far, [0x22; 32]).await;
    named(&alice, "Alice");
    named(&bob, "Bob");
    // Of two devices of one model with colors alike, one draws a new key,
    // and a row read just before then names a key gone. Two models never
    // do.
    alice.node.set_model(models::LILYGO_T_LORA_PAGER);
    bob.node.set_model(models::LILYGO_T_DECK);
    alice.node.open_meet();
    bob.node.open_meet();
    let mut listed = (None, None);
    until("the boards did not list each other", || {
        listed = (
            meet(&alice).devices.first().copied(),
            meet(&bob).devices.first().copied(),
        );
        listed.0.is_some() && listed.1.is_some()
    })
    .await;
    let (bob_listed, alice_listed) = (listed.0.unwrap(), listed.1.unwrap());
    (alice, bob, Tap(tap, Vec::new()), bob_listed, alice_listed)
}

/// A radio that keeps every frame it hears.
struct Tap(SimulatedRadio, Vec<Vec<u8>>);

impl Tap {
    /// Takes in what reached the tap, and returns whether any of it
    /// carries `key`.
    fn heard(&mut self, key: &PublicKey) -> bool {
        use std::task::{Context, Poll, Waker};
        use umsh::hal::Radio as _;

        let mut buf = [0u8; 255];
        let mut cx = Context::from_waker(Waker::noop());
        while let Poll::Ready(Ok(rx)) = self.0.poll_receive(&mut cx, &mut buf) {
            self.1.push(buf[..rx.len].to_vec());
        }
        self.1
            .iter()
            .any(|frame| frame.windows(key.0.len()).any(|window| window == key.0))
    }
}

/// Alice asks Bob, Bob agrees, and both come to the same code.
async fn comparing(alice: &Board, bob: &Board, bob_listed: NearbyDevice) -> u32 {
    assert!(alice.node.ask_to_exchange(bob_listed.id));
    until("Bob was not asked", || {
        matches!(meet(bob).exchange, Exchange::Asked(_))
    })
    .await;
    bob.node.answer_exchange(true);
    let code = |board: &Board| match meet(board).exchange {
        Exchange::Comparing { code, .. } => Some(code),
        _ => None,
    };
    let mut codes = (None, None);
    until("the codes did not show", || {
        codes = (code(alice), code(bob));
        codes.0.is_some() && codes.1.is_some()
    })
    .await;
    assert_eq!(codes.0, codes.1);
    codes.0.unwrap()
}

async fn until_exchanged(board: &Board) -> Member {
    let mut member = None;
    until("the contacts did not cross", || {
        if let Exchange::Exchanged(theirs) = meet(board).exchange {
            member = Some(theirs);
        }
        member.is_some()
    })
    .await;
    member.unwrap()
}

/// Once both holders find the codes the same, each board holds the
/// other's address and name, and neither has saved anything.
#[tokio::test(flavor = "current_thread")]
async fn contacts_are_exchanged_after_both_confirm() {
    LocalSet::new()
        .run_until(async {
            let (alice, bob, _tap, bob_listed, alice_listed) = on_nearby().await;
            assert_eq!(bob_listed.model, models::LILYGO_T_DECK);
            assert_eq!(alice_listed.model, models::LILYGO_T_LORA_PAGER);
            comparing(&alice, &bob, bob_listed).await;
            alice.node.confirm_code(true);
            bob.node.confirm_code(true);

            let at_alice = until_exchanged(&alice).await;
            let at_bob = until_exchanged(&bob).await;
            assert_eq!(at_alice.address.as_deref(), Some(&*address(&bob.key)));
            assert_eq!(at_alice.sender.name.as_str(), "Bob");
            assert!(!at_alice.saved);
            assert_eq!(at_bob.address.as_deref(), Some(&*address(&alice.key)));
            assert_eq!(at_bob.sender.name.as_str(), "Alice");
            assert!(!at_bob.saved);
            for board in [&alice, &bob] {
                let mut peers = Peers::new();
                board.node.peers(&mut peers);
                assert!(peers.is_empty());
            }
        })
        .await;
}

/// No frame carries a board's long-term key until its holder presses Same.
#[tokio::test(flavor = "current_thread")]
async fn nothing_long_term_is_sent_before_its_own_same() {
    LocalSet::new()
        .run_until(async {
            let (alice, bob, mut tap, bob_listed, _) = on_nearby().await;
            comparing(&alice, &bob, bob_listed).await;
            alice.node.confirm_code(true);
            // Alice's contact is on its way: give it time to air.
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(!tap.heard(&alice.key));
            assert!(!tap.heard(&bob.key));
            assert!(matches!(
                meet(&alice).exchange,
                Exchange::Comparing { sent: true, .. }
            ));
            bob.node.confirm_code(true);
            until_exchanged(&alice).await;
            until_exchanged(&bob).await;
            assert!(!tap.heard(&alice.key));
            assert!(!tap.heard(&bob.key));
        })
        .await;
}

/// A holder who finds the codes different ends the exchange for both, and
/// what the other side sent is dropped.
#[tokio::test(flavor = "current_thread")]
async fn different_after_one_same_discards_the_identity() {
    LocalSet::new()
        .run_until(async {
            let (alice, bob, _tap, bob_listed, _) = on_nearby().await;
            comparing(&alice, &bob, bob_listed).await;
            alice.node.confirm_code(true);
            tokio::time::sleep(Duration::from_millis(500)).await;
            bob.node.confirm_code(false);
            until("the exchange did not end for both", || {
                [&alice, &bob]
                    .iter()
                    .all(|board| meet(board).exchange == Exchange::Ended(ExchangeEnd::Different))
            })
            .await;
            let known = bob.node.known_member(&address(&alice.key)).unwrap();
            assert_ne!(known.sender.name.as_str(), "Alice");
        })
        .await;
}

/// Leaving Add peer mid-exchange ends it for the other side too.
#[tokio::test(flavor = "current_thread")]
async fn leaving_cancels() {
    LocalSet::new()
        .run_until(async {
            let (alice, bob, _tap, bob_listed, _) = on_nearby().await;
            comparing(&alice, &bob, bob_listed).await;
            alice.node.close_meet();
            assert_eq!(meet(&alice).exchange, Exchange::Closed);
            until("Bob did not hear Alice leave", || {
                meet(&bob).exchange == Exchange::Ended(ExchangeEnd::Left)
            })
            .await;
        })
        .await;
}

/// Each attempt draws a key of its own: opening Add peer again after an
/// exchange ends shows a new color, and the boards list each other anew.
#[tokio::test(flavor = "current_thread")]
async fn try_again_uses_a_fresh_session() {
    LocalSet::new()
        .run_until(async {
            let (alice, bob, _tap, bob_listed, _) = on_nearby().await;
            let before = meet(&alice).own_color;
            let first = comparing(&alice, &bob, bob_listed).await;
            alice.node.confirm_code(false);
            until("the exchange did not end", || {
                meet(&bob).exchange == Exchange::Ended(ExchangeEnd::Different)
            })
            .await;
            alice.node.open_meet();
            bob.node.open_meet();
            let mut listed = None;
            until("the boards did not list each other again", || {
                let state = meet(&alice);
                listed = state.devices.first().copied();
                state.exchange == Exchange::Idle
                    && listed.is_some()
                    && !meet(&bob).devices.is_empty()
            })
            .await;
            let again = comparing(&alice, &bob, listed.unwrap()).await;
            // A new pair of keys and nonces: the colors and the code are
            // drawn anew, and match only by chance.
            assert!(meet(&alice).own_color != before || again != first);
        })
        .await;
}

/// A message to a peer two hops away says the repeater between carried it,
/// then that it was delivered; its details list the repeater.
#[tokio::test(flavor = "current_thread")]
async fn a_direct_message_names_the_repeater_that_carried_it() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let middle = network.add_radio_with_config(255, 20);
            let far = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), middle.id());
            network.connect_bidirectional(middle.id(), far.id());
            let alice = board(near, [0x11; 32]).await;
            let ridge = repeater(middle, [0x33; 32]).await;
            let bob = board(far, [0x22; 32]).await;

            let chat = alice
                .node
                .direct_chat(&address(&bob.key), "Bob", &alice.node.avatar())
                .unwrap();
            let sent = alice
                .node
                .send(chat.id, "Meet at the ridge", None, false)
                .unwrap();
            let mut carried = None;
            until("the message was not delivered", || {
                let (delivery, via) = how_sent(&alice, chat.id, sent.id);
                carried = carried.take().or(via);
                delivery == Delivery::Delivered
            })
            .await;
            let carried = carried.expect("the repeater was heard carrying it");
            assert_eq!(carried.count, 1);
            let details = alice.node.details(chat.id, sent.id).unwrap();
            assert_eq!(details.repeaters.len() + usize::from(details.anonymous), 1);
            if let Some(named) = details.repeaters.first() {
                assert_eq!(named.hint, [ridge.0[0], ridge.0[1]]);
                assert_eq!(named.address, None, "the repeater is not known yet");
                assert_eq!(carried.lead.as_deref(), Some(&*named.name));
            }
        })
        .await;
}

/// A message to a peer no one hears goes on naming the repeater that
/// carried it until that goes quiet, then waits on its acknowledgment.
#[tokio::test(flavor = "current_thread")]
async fn a_direct_message_waits_on_its_acknowledgment_once_its_repeaters_go_quiet() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            // Frames slow enough that the acknowledgment is waited on for
            // longer than the repeaters take to go quiet.
            let near = network.add_radio_with_config(255, 400);
            let middle = network.add_radio_with_config(255, 400);
            network.connect_bidirectional(near.id(), middle.id());
            let alice = board(near, [0x11; 32]).await;
            repeater(middle, [0x33; 32]).await;
            let nowhere = *SoftwareIdentity::from_secret_bytes(&[0x44; 32]).public_key();

            let chat = alice
                .node
                .direct_chat(&address(&nowhere), "Nowhere", &alice.node.avatar())
                .unwrap();
            let sent = alice
                .node
                .send(chat.id, "Anyone out there?", None, false)
                .unwrap();
            until("the repeater was not heard carrying it", || {
                matches!(
                    how_sent(&alice, chat.id, sent.id),
                    (Delivery::Sent, Some(_))
                )
            })
            .await;
            until("it never settled into waiting", || {
                how_sent(&alice, chat.id, sent.id).0 == Delivery::Confirming
            })
            .await;
        })
        .await;
}

/// A channel's message, which no one acknowledges, ends at Sent, naming
/// the repeater that carried it.
#[tokio::test(flavor = "current_thread")]
async fn a_channel_message_ends_at_sent_via_its_repeater() {
    LocalSet::new()
        .run_until(async {
            let network = SimulatedNetwork::new();
            let near = network.add_radio_with_config(255, 20);
            let middle = network.add_radio_with_config(255, 20);
            network.connect_bidirectional(near.id(), middle.id());
            let alice = board(near, [0x11; 32]).await;
            repeater(middle, [0x33; 32]).await;
            let key = WellKnownChannels::derive().public;
            alice
                .mesh
                .join(&umsh::node::Channel::private(key, ""))
                .await
                .unwrap();

            let mut chats = Chats::new();
            alice.node.chats(&mut chats);
            let public = chats
                .iter()
                .find(|chat| &*chat.name == "Public")
                .expect("the public channel")
                .id;
            let sent = alice.node.send(public, "Radio check", None, false).unwrap();
            until("the repeater was not heard carrying it", || {
                matches!(how_sent(&alice, public, sent.id), (Delivery::Sent, Some(_)))
            })
            .await;
            tokio::time::sleep(Duration::from_millis(3_000)).await;
            assert_eq!(how_sent(&alice, public, sent.id).0, Delivery::Sent);
            // Nothing came of it to announce.
            while let Some(event) = alice.node.next_event() {
                assert!(!matches!(event, NodeEvent::Settled { .. }), "{event:?}");
            }
        })
        .await;
}
