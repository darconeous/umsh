#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Application-facing node layer built on top of [`umsh-mac`](umsh_mac).
//!
//! `umsh-node` sits between the radio-facing MAC coordinator in `umsh-mac` and the
//! application. Where `umsh-mac` thinks in raw frames, keys, replay windows, and transmit
//! queues, `umsh-node` provides composable abstractions for sending and receiving messages,
//! tracking in-flight sends, and managing channel membership.
//!
//! This crate requires `alloc` (heap allocation for `String`, `Vec`, etc.). It is
//! otherwise `no_std` compatible.
//!
//! # Architecture overview
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  Application                                                  │
//! │  TextSession · PeerConnection · BoundChannel                  │
//! └──────────────────────┬───────────────────────────────────────┘
//!                        │  Transport trait
//! ┌──────────────────────┴───────────────────────────────────────┐
//! │  LocalNode<M>                                                 │
//! │    ├── sends down through MacBackend                          │
//! │    └── reads events from EventDispatcher                      │
//! │                                                               │
//! │  NodeRuntime (owns dispatcher, drives MAC event dispatch)     │
//! └──────────────────────┬───────────────────────────────────────┘
//!                        │  MacBackend trait
//! ┌──────────────────────┴───────────────────────────────────────┐
//! │  MacHandle → Mac<P>  (no_std, heapless)                       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key types
//!
//! - [`NodeRuntime`] — owns the event dispatcher and creates [`LocalNode`] handles.
//! - [`LocalNode`] — per-identity application handle. Implements [`Transport`] (unicast /
//!   broadcast). Manages channel membership via `join`/`leave`/`bound_channel`.
//! - [`BoundChannel`] — a channel bound to a `LocalNode`. Implements [`Transport`]
//!   (blind unicast / multicast). Available with the `software-crypto` feature.
//! - [`PeerConnection`] — relationship with one remote peer, generic over transport context.
//! - [`Transport`] — shared send interface (`send` / `send_all`).
//! - [`SendProgressTicket`] — lightweight polling handle for observing in-flight send
//!   progress (`was_transmitted`, `was_acked`, `is_finished`).
//! - [`NodeEvent`] — typed event enum delivered to registered [`EventSink`] instances.
//! - [`MacBackend`] — pluggable MAC backend trait for testability.
//!
//! # Owned payload types
//!
//! [`OwnedTextMessage`], [`OwnedNodeIdentityPayload`], [`OwnedMacCommand`] are heap-allocated
//! equivalents of the zero-copy borrowed types from `umsh-app`, suitable for storing and
//! cloning across async task boundaries.
//!
//! # MAC abstraction
//!
//! [`MacBackend`] exposes the public send/configure surface of the MAC coordinator.
//! [`MacBackendInternal`] (crate-private, requires `unsafe-advanced`) extends it with operations
//! that can corrupt protocol state if misused (`install_pairwise_keys`,
//! `cancel_pending_ack`). Safe PFS session management is available with
//! `software-crypto` and builds on the public `MacBackend` surface.
//!
//! [`MacHandle`](umsh_mac::MacHandle) implements `MacBackend`, and test code can provide
//! a fake implementation to drive the node layer deterministically.
//!
//! # Typical usage
//!
//! ```rust,ignore
//! let runtime = NodeRuntime::new(mac_handle.clone());
//! let node = runtime.create_node(identity_id, Box::new(my_sink));
//!
//! // Send a raw payload via the Transport trait:
//! let ticket = node.send(&peer_key, &payload, &SendOptions::default()).await?;
//!
//! // Dispatch MAC events from the event loop:
//! mac.poll_cycle(|identity_id, event| {
//!     runtime.dispatch(identity_id, &event);
//! }).await?;
//!
//! // Poll ticket progress:
//! if ticket.was_acked() { /* ... */ }
//! ```

#[cfg(not(feature = "alloc"))]
compile_error!("umsh-node currently requires the alloc feature");

extern crate alloc;

#[cfg(feature = "software-crypto")]
mod channel;
mod dispatch;
mod events;
mod mac;
mod node;
mod owned;
mod peer;
#[cfg(feature = "software-crypto")]
mod pfs;
mod runtime;
mod ticket;
mod transport;

#[cfg(feature = "software-crypto")]
pub use channel::Channel;
pub use dispatch::EventSink;
pub use events::NodeEvent;
pub use mac::{MacBackend, MacBackendError};
#[cfg(feature = "software-crypto")]
pub use node::BoundChannel;
pub use node::{LocalNode, NodeError};
pub use owned::{OwnedMacCommand, OwnedNodeIdentityPayload, OwnedTextMessage};
pub use peer::PeerConnection;
pub use runtime::NodeRuntime;
pub use ticket::{SendToken, SendProgressTicket};
pub use transport::Transport;
#[cfg(feature = "software-crypto")]
pub use pfs::{PfsSession, PfsSessionManager, PfsState};

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        rc::Rc,
        task::{Context, Poll},
    };
    #[cfg(feature = "unsafe-advanced")]
    use std::{
        future::Future,
        pin::pin,
        task::{RawWaker, RawWakerVTable, Waker},
    };
    use core::convert::Infallible;

    use rand::{Rng, TryCryptoRng, TryRng};
    use umsh_core::PublicKey;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_crypto::software::SoftwareIdentity;
    use umsh_crypto::{AesCipher, AesProvider, CryptoEngine, NodeIdentity, Sha256Provider, SharedSecret};
    use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, TxError, TxOptions};
    use umsh_mac::{Mac, MacEventRef, MacHandle, OperatingPolicy, Platform, RepeaterConfig};
    #[cfg(feature = "unsafe-advanced")]
    use umsh_mac::{CapacityError, LocalIdentityId, PeerCryptoState, PeerId, SendError, SendOptions, SendReceipt};
    #[cfg(all(feature = "std", feature = "unsafe-advanced"))]
    use umsh_mac::test_support::{make_test_mac, DummyClock as SimClock, DummyDelay as SimDelay, DummyIdentity as SimIdentity, SimulatedNetwork};
    #[cfg(all(feature = "std", not(feature = "unsafe-advanced")))]
    use umsh_mac::test_support::DummyDelay as SimDelay;

    use crate::{NodeEvent, NodeRuntime};
    use crate::dispatch::EventSink;
    #[cfg(feature = "unsafe-advanced")]
    use crate::{MacBackend, MacBackendError, OwnedMacCommand, OwnedTextMessage};
    #[cfg(feature = "unsafe-advanced")]
    use crate::mac::MacBackendInternal;
    #[cfg(feature = "unsafe-advanced")]
    use umsh_crypto::PairwiseKeys;
    #[cfg(feature = "unsafe-advanced")]
    use umsh_core::ChannelId;

    /// Simple EventSink that collects events into a shared Vec.
    struct VecEventSink {
        events: Rc<RefCell<Vec<NodeEvent>>>,
    }

    impl VecEventSink {
        fn new() -> (Self, Rc<RefCell<Vec<NodeEvent>>>) {
            let events = Rc::new(RefCell::new(Vec::new()));
            (Self { events: events.clone() }, events)
        }
    }

    impl EventSink for VecEventSink {
        fn send_event(&mut self, event: NodeEvent) {
            self.events.borrow_mut().push(event);
        }
    }

    #[test]
    fn dispatch_delivers_text_event_to_node_sink() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

        let runtime = NodeRuntime::new(handle);
        let (sink, events) = VecEventSink::new();
        let _node = runtime.create_node(local_id, Box::new(sink));

        let payload = [umsh_app::PayloadType::TextMessage as u8, 0xFF, b'h', b'i'];
        runtime.dispatch(local_id, &MacEventRef::Unicast {
            from: PublicKey([0x22; 32]),
            payload: &payload,
            ack_requested: false,
        });

        let received = events.borrow();
        assert_eq!(received.len(), 1);
        match &received[0] {
            NodeEvent::TextReceived { from, body } => {
                assert_eq!(*from, PublicKey([0x22; 32]));
                assert_eq!(body, "hi");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn dispatch_delivers_beacon_event() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

        let runtime = NodeRuntime::new(handle);
        let (sink, events) = VecEventSink::new();
        let _node = runtime.create_node(local_id, Box::new(sink));

        let from_hint = umsh_core::NodeHint([0xAA, 0xBB, 0xCC]);
        runtime.dispatch(local_id, &MacEventRef::Broadcast {
            from_hint,
            from_key: None,
            payload: &[],
        });

        let received = events.borrow();
        assert_eq!(received.len(), 1);
        assert!(matches!(&received[0], NodeEvent::BeaconReceived { from_key: None, .. }));
    }

    #[cfg(all(feature = "std", feature = "unsafe-advanced"))]
    #[test]
    fn nodes_exchange_text_over_simulated_network() {
        use crate::Transport;

        let network = SimulatedNetwork::new();
        let alice_radio = network.add_radio();
        let bob_radio = network.add_radio();
        network.connect_bidirectional(alice_radio.id(), bob_radio.id());

        let alice_clock = SimClock::new(1_000);
        let bob_clock = SimClock::new(1_000);
        let alice_mac = RefCell::new(make_test_mac::<4, 16, 8, 16, 16, 256, 64>(alice_radio, alice_clock));
        let bob_mac = RefCell::new(make_test_mac::<4, 16, 8, 16, 16, 256, 64>(bob_radio, bob_clock));
        let alice_handle = MacHandle::new(&alice_mac);
        let bob_handle = MacHandle::new(&bob_mac);

        let alice_key = PublicKey([0x11; 32]);
        let bob_key = PublicKey([0x22; 32]);
        let alice_id = alice_handle.add_identity(SimIdentity::new(alice_key.0)).unwrap();
        let bob_id = bob_handle.add_identity(SimIdentity::new(bob_key.0)).unwrap();
        let _bob_peer = alice_handle.add_peer(bob_key).unwrap();
        let _alice_peer = bob_handle.add_peer(alice_key).unwrap();

        let alice_runtime = NodeRuntime::new(alice_handle);
        let bob_runtime = NodeRuntime::new(bob_handle);
        let (alice_sink, alice_events) = VecEventSink::new();
        let (bob_sink, bob_events) = VecEventSink::new();
        let alice_node = alice_runtime.create_node(alice_id, Box::new(alice_sink));
        let _bob_node = bob_runtime.create_node(bob_id, Box::new(bob_sink));

        // Encode and send a text payload via the Transport trait.
        let payload = encode_text_payload("hello bob");
        let options = SendOptions::default()
            .with_ack_requested(true)
            .with_flood_hops(5);
        let ticket = block_on_ready(alice_node.send(&bob_key, &payload, &options)).unwrap();
        assert!(!ticket.was_transmitted());

        // Alice transmits.
        block_on_ready(alice_mac.borrow_mut().poll_cycle(|id, event| {
            alice_runtime.dispatch(id, &event);
        })).unwrap();

        // Bob receives.
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|id, event| {
            bob_runtime.dispatch(id, &event);
        })).unwrap();

        let received = bob_events.borrow();
        assert_eq!(received.len(), 1);
        match &received[0] {
            NodeEvent::TextReceived { from, body } => {
                assert_eq!(*from, alice_key);
                assert_eq!(body, "hello bob");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // Alice receives the ACK.
        block_on_ready(alice_mac.borrow_mut().poll_cycle(|id, event| {
            alice_runtime.dispatch(id, &event);
        })).unwrap();

        let alice_received = alice_events.borrow();
        assert!(alice_received.iter().any(|e| matches!(e, NodeEvent::AckReceived { peer, .. } if *peer == bob_key)));
        assert!(ticket.was_acked());
        assert!(ticket.is_finished());
    }

    #[cfg(all(feature = "std", feature = "unsafe-advanced"))]
    #[test]
    fn nodes_exchange_text_through_simulated_repeater() {
        use crate::Transport;

        let network = SimulatedNetwork::new();
        let alice_radio = network.add_radio();
        let repeater_radio = network.add_radio();
        let bob_radio = network.add_radio();
        network.connect_bidirectional(alice_radio.id(), repeater_radio.id());
        network.connect_bidirectional(repeater_radio.id(), bob_radio.id());

        let alice_clock = SimClock::new(1_000);
        let repeater_clock = SimClock::new(1_000);
        let bob_clock = SimClock::new(1_000);
        let alice_mac = RefCell::new(make_test_mac::<4, 16, 8, 16, 16, 256, 64>(alice_radio, alice_clock));
        let repeater_mac = RefCell::new(make_test_mac::<4, 16, 8, 16, 16, 256, 64>(repeater_radio, repeater_clock.clone()));
        let bob_mac = RefCell::new(make_test_mac::<4, 16, 8, 16, 16, 256, 64>(bob_radio, bob_clock));
        repeater_mac.borrow_mut().repeater_config_mut().enabled = true;

        let alice_handle = MacHandle::new(&alice_mac);
        let repeater_handle = MacHandle::new(&repeater_mac);
        let bob_handle = MacHandle::new(&bob_mac);

        let alice_key = PublicKey([0x31; 32]);
        let repeater_key = PublicKey([0x42; 32]);
        let bob_key = PublicKey([0x53; 32]);
        let alice_id = alice_handle.add_identity(SimIdentity::new(alice_key.0)).unwrap();
        let _repeater_id = repeater_handle.add_identity(SimIdentity::new(repeater_key.0)).unwrap();
        let bob_id = bob_handle.add_identity(SimIdentity::new(bob_key.0)).unwrap();

        let _bob_peer = alice_handle.add_peer(bob_key).unwrap();
        let _alice_peer = bob_handle.add_peer(alice_key).unwrap();

        let alice_runtime = NodeRuntime::new(alice_handle);
        let bob_runtime = NodeRuntime::new(bob_handle);
        let (bob_sink, bob_events) = VecEventSink::new();
        let alice_node = alice_runtime.create_node_without_sink(alice_id);
        let _bob_node = bob_runtime.create_node(bob_id, Box::new(bob_sink));

        let payload = encode_text_payload("via repeater");
        let options = SendOptions::default()
            .with_ack_requested(true)
            .with_flood_hops(5);
        block_on_ready(alice_node.send(&bob_key, &payload, &options)).unwrap();

        // Alice transmits.
        block_on_ready(alice_mac.borrow_mut().poll_cycle(|id, ev| alice_runtime.dispatch(id, &ev))).unwrap();

        // Bob doesn't see it yet (not directly connected).
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|id, ev| bob_runtime.dispatch(id, &ev))).unwrap();
        assert!(bob_events.borrow().is_empty());

        // Repeater forwards.
        block_on_ready(repeater_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();
        repeater_clock.advance_ms(1_000);
        block_on_ready(repeater_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();

        // Bob receives the forwarded frame.
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|id, ev| bob_runtime.dispatch(id, &ev))).unwrap();

        let received = bob_events.borrow();
        assert_eq!(received.len(), 1);
        match &received[0] {
            NodeEvent::TextReceived { from, body } => {
                assert_eq!(*from, alice_key);
                assert_eq!(body, "via repeater");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn pfs_session_manager_request_and_teardown() {
        use crate::pfs::PfsSessionManager;

        let mac = FakeMac::new(vec![[3u8; 32]]);
        let peer_long_term = PublicKey([0x55; 32]);
        let options = SendOptions::default().with_ack_requested(true);

        let mut pfs = PfsSessionManager::new();
        block_on_ready(pfs.request_session(
            &mac,
            LocalIdentityId(1),
            &peer_long_term,
            60,
            &options,
        ))
        .unwrap();

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, LocalIdentityId(1));
        assert_eq!(sent[0].to, peer_long_term);
        assert_eq!(parse_owned_mac_command(&sent[0].payload), OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: *SoftwareIdentity::from_secret_bytes(&[3u8; 32]).public_key(),
            duration_minutes: 60,
        });

        assert!(block_on_ready(pfs.end_session(
            &mac,
            LocalIdentityId(1),
            &peer_long_term,
            true,
            &options,
        ))
        .unwrap());
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(parse_owned_mac_command(&sent[0].payload), OwnedMacCommand::EndPfsSession);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn pfs_end_session_errors_when_missing() {
        use crate::pfs::PfsSessionManager;

        let mac = FakeMac::new(Vec::new());
        let options = SendOptions::default();
        let mut pfs = PfsSessionManager::new();

        let error = block_on_ready(pfs.end_session(
            &mac,
            LocalIdentityId(1),
            &PublicKey([0x77; 32]),
            true,
            &options,
        ))
        .unwrap_err();
        assert!(matches!(error, crate::NodeError::PfsSessionMissing));
    }

    #[cfg(feature = "unsafe-advanced")]
    fn encode_text_payload(text: &str) -> Vec<u8> {
        let message = OwnedTextMessage {
            message_type: umsh_app::MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body: String::from(text),
        };
        let mut body = [0u8; 512];
        let len = umsh_app::text_message::encode(&message.as_borrowed(), &mut body).unwrap();
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(umsh_app::PayloadType::TextMessage as u8);
        payload.extend_from_slice(&body[..len]);
        payload
    }

    fn make_mac() -> Mac<DummyPlatform, 4, 16, 8, 16, 16, 256, 64> {
        Mac::new(
            DummyRadio::default(),
            CryptoEngine::new(DummyAes, DummySha),
            DummyClock::default(),
            DummyRng::default(),
            DummyCounterStore,
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        )
    }

    struct DummyIdentity {
        public_key: PublicKey,
    }

    impl DummyIdentity {
        fn new(bytes: [u8; 32]) -> Self {
            Self { public_key: PublicKey(bytes) }
        }
    }

    impl NodeIdentity for DummyIdentity {
        type Error = ();

        fn public_key(&self) -> &PublicKey {
            &self.public_key
        }

        async fn sign(&self, _message: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok([0u8; 64])
        }

        async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error> {
            let mut out = [0u8; 32];
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = self.public_key.0[index] ^ peer.0[index];
            }
            Ok(SharedSecret(out))
        }
    }

    struct DummyCipher {
        key: [u8; 16],
    }

    impl AesCipher for DummyCipher {
        fn encrypt_block(&self, block: &mut [u8; 16]) {
            for (byte, key) in block.iter_mut().zip(self.key.iter()) {
                *byte ^= *key;
            }
        }

        fn decrypt_block(&self, block: &mut [u8; 16]) {
            self.encrypt_block(block);
        }
    }

    struct DummyAes;

    impl AesProvider for DummyAes {
        type Cipher = DummyCipher;

        fn new_cipher(&self, key: &[u8; 16]) -> Self::Cipher {
            DummyCipher { key: *key }
        }
    }

    struct DummySha;

    impl Sha256Provider for DummySha {
        fn hash(&self, data: &[&[u8]]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for chunk in data {
                for (index, byte) in chunk.iter().enumerate() {
                    out[index % 32] ^= *byte;
                }
            }
            out
        }

        fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (index, byte) in key.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
            for chunk in data {
                for (index, byte) in chunk.iter().enumerate() {
                    out[index % 32] ^= *byte;
                }
            }
            out
        }
    }

    #[derive(Default)]
    struct DummyRadio {
        transmitted: Vec<Vec<u8>>,
        received: VecDeque<Vec<u8>>,
    }

    impl Radio for DummyRadio {
        type Error = ();

        async fn transmit(&mut self, data: &[u8], _options: TxOptions) -> Result<(), TxError<Self::Error>> {
            self.transmitted.push(data.to_vec());
            Ok(())
        }

        fn poll_receive(&mut self, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<RxInfo, Self::Error>> {
            if let Some(frame) = self.received.pop_front() {
                let len = frame.len();
                buf[..len].copy_from_slice(&frame);
                Poll::Ready(Ok(RxInfo { len, rssi: -40, snr: 10 }))
            } else {
                Poll::Pending
            }
        }

        fn max_frame_size(&self) -> usize {
            256
        }

        fn t_frame_ms(&self) -> u32 {
            10
        }
    }

    #[derive(Default)]
    struct DummyClock {
        now_ms: Cell<u64>,
    }

    impl Clock for DummyClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.get()
        }
    }

    #[derive(Default)]
    struct DummyRng(u8);

    impl TryRng for DummyRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dest.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for DummyRng {}

    struct DummyCounterStore;

    impl CounterStore for DummyCounterStore {
        type Error = ();

        async fn load(&self, _context: &[u8]) -> Result<u32, Self::Error> {
            Ok(0)
        }

        async fn store(&self, _context: &[u8], _value: u32) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn flush(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct DummyKeyValueStore;

    impl KeyValueStore for DummyKeyValueStore {
        type Error = ();

        async fn load(&self, _key: &[u8], _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(None)
        }

        async fn store(&self, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn delete(&self, _key: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct DummyPlatform;

    impl Platform for DummyPlatform {
        type Identity = DummyIdentity;
        type Aes = DummyAes;
        type Sha = DummySha;
        type Radio = DummyRadio;
        type Delay = SimDelay;
        type Clock = DummyClock;
        type Rng = DummyRng;
        type CounterStore = DummyCounterStore;
        type KeyValueStore = DummyKeyValueStore;
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[derive(Clone, Default)]
    struct FakeMac {
        state: Rc<RefCell<FakeMacState>>,
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[derive(Default)]
    struct FakeMacState {
        random_blocks: VecDeque<[u8; 32]>,
        next_peer_id: u8,
        next_ephemeral_id: u8,
        now_ms: u64,
        unicasts: Vec<SentUnicast>,
        removed_ephemerals: Vec<LocalIdentityId>,
        peers: Vec<(PublicKey, PeerId)>,
        installed: Vec<(LocalIdentityId, PeerId, PairwiseKeys)>,
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SentUnicast {
        from: LocalIdentityId,
        to: PublicKey,
        payload: Vec<u8>,
        options: SendOptions,
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    impl FakeMac {
        fn new(random_blocks: Vec<[u8; 32]>) -> Self {
            Self {
                state: Rc::new(RefCell::new(FakeMacState {
                    random_blocks: random_blocks.into(),
                    next_peer_id: 0,
                    next_ephemeral_id: 10,
                    now_ms: 1_000,
                    ..FakeMacState::default()
                })),
            }
        }

        fn take_unicasts(&self) -> Vec<SentUnicast> {
            core::mem::take(&mut self.state.borrow_mut().unicasts)
        }

    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    impl MacBackend for FakeMac {
        type SendError = SendError;
        type CapacityError = CapacityError;

        fn add_peer(&self, key: PublicKey) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            if let Some((_, existing)) = state.peers.iter().find(|(existing_key, _)| *existing_key == key) {
                return Ok(*existing);
            }
            let peer_id = PeerId(state.next_peer_id);
            state.next_peer_id = state.next_peer_id.wrapping_add(1);
            state.peers.push((key, peer_id));
            Ok(peer_id)
        }

        fn add_private_channel(&self, _key: umsh_core::ChannelKey) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn add_named_channel(&self, _name: &str) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        async fn send_broadcast(
            &self,
            _from: LocalIdentityId,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(SendReceipt(99))
        }

        async fn send_multicast(
            &self,
            _from: LocalIdentityId,
            _channel: &ChannelId,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(SendReceipt(99))
        }

        async fn send_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().unicasts.push(SentUnicast {
                from,
                to: *dst,
                payload: payload.to_vec(),
                options: options.clone(),
            });
            Ok(Some(SendReceipt(42)))
        }

        async fn send_blind_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            _channel: &ChannelId,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>> {
            self.send_unicast(from, dst, payload, options).await
        }

        fn fill_random(&self, dest: &mut [u8]) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            let next = state.random_blocks.pop_front().expect("test rng exhausted");
            dest.copy_from_slice(&next[..dest.len()]);
            Ok(())
        }

        fn now_ms(&self) -> Result<u64, MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(self.state.borrow().now_ms)
        }

        fn register_ephemeral(
            &self,
            _parent: LocalIdentityId,
            _identity: SoftwareIdentity,
        ) -> Result<LocalIdentityId, MacBackendError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            let id = LocalIdentityId(state.next_ephemeral_id);
            state.next_ephemeral_id = state.next_ephemeral_id.wrapping_add(1);
            Ok(id)
        }

        fn remove_ephemeral(&self, id: LocalIdentityId) -> Result<bool, MacBackendError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().removed_ephemerals.push(id);
            Ok(true)
        }
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    impl MacBackendInternal for FakeMac {
        fn install_pairwise_keys(
            &self,
            identity_id: LocalIdentityId,
            peer_id: PeerId,
            pairwise_keys: PairwiseKeys,
        ) -> Result<Option<PeerCryptoState>, MacBackendError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().installed.push((identity_id, peer_id, pairwise_keys));
            Ok(None)
        }

        fn cancel_pending_ack(&self, _identity_id: LocalIdentityId, _receipt: SendReceipt) -> bool {
            false
        }
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn parse_owned_mac_command(payload: &[u8]) -> OwnedMacCommand {
        match umsh_app::parse_payload(umsh_core::PacketType::Unicast, payload).unwrap() {
            umsh_app::PayloadRef::MacCommand(command) => OwnedMacCommand::from(command),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[cfg(feature = "unsafe-advanced")]
    fn block_on_ready<F: Future>(future: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker { raw_waker() }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            RawWaker::new(core::ptr::null(), &RawWakerVTable::new(clone, wake, wake_by_ref, drop))
        }

        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly returned Poll::Pending"),
        }
    }
}
