#![cfg_attr(not(feature = "std"), no_std)]

//! Application-facing endpoint orchestration built on top of [`umsh-mac`](umsh_mac).
//!
//! `umsh-node` is the layer between the radio-facing MAC coordinator in `umsh-mac` and the
//! application that the user actually interacts with. Where `umsh-mac` thinks in raw frames,
//! keys, replay windows, and transmit queues, `umsh-node` thinks in text messages, node
//! identities, beacons, and PFS sessions. The two crates are intentionally separated: an
//! application that wants full control over the MAC surface can use `umsh-mac` directly;
//! `umsh-node` is the batteries-included entry point for most use cases.
//!
//! This crate requires `alloc` (heap allocation for `String`, `Vec`, etc.). It is
//! otherwise `no_std` compatible.
//!
//! # Architecture overview
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │  Application                                                  │
//! │  endpoint.send_text() / endpoint.handle_event() / …          │
//! └──────────────────────────┬────────────────────────────────────┘
//!                            │  EndpointEvent · DeferredAction
//!                            ▼
//! ┌───────────────────────────────────────────────────────────────┐
//! │  Endpoint<M>  (endpoint.rs)                                   │
//! │                                                               │
//! │  ┌────────────────────┐  ┌────────────────────────────────┐   │
//! │  │ EndpointConfig     │  │ PfsSessionManager (pfs.rs)     │   │
//! │  │  default_mic_size  │  │  PfsSession × N                │   │
//! │  │  beacon_interval   │  │  ephemeral MAC identity mgmt   │   │
//! │  │  UiAcceptancePolicy│  └────────────────────────────────┘   │
//! │  └────────────────────┘                                        │
//! └──────────────────────────┬────────────────────────────────────┘
//!                            │  NodeMac trait (mac.rs)
//!                            ▼
//! ┌───────────────────────────────────────────────────────────────┐
//! │  umsh_mac::MacHandle  →  umsh_mac::Mac<P>                     │
//! │  (radio, crypto, tx queue, dup cache, replay windows, …)      │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules and key types
//!
//! ## [`endpoint`] — the primary application interface
//!
//! [`Endpoint<M>`] is the top-level type most applications interact with. It wraps a
//! [`LocalIdentityId`](umsh_mac::LocalIdentityId) and a [`NodeMac`] handle, and provides:
//!
//! - **High-level send helpers** — `send_text`, `send_channel_text`, `send_blind_text`,
//!   `send_beacon`, `send_identity_beacon`, `request_path_discovery`. Each helper encodes
//!   the appropriate `umsh-app` payload type and calls through to the underlying MAC handle.
//! - **Event processing** — `handle_event` accepts a [`MacEventRef`](umsh_mac::MacEventRef)
//!   (produced by the `umsh-mac` event loop), parses the payload, applies the
//!   [`UiAcceptancePolicy`] filter, and returns an [`EventAction`] indicating whether the
//!   event was handled inline or requires deferred async follow-up work.
//! - **Scheduled beacons** — `send_scheduled_beacon` checks an internal timer and sends
//!   a beacon when the configured `beacon_interval_ms` has elapsed.
//! - **PFS session management** — when the `software-crypto` feature is enabled,
//!   `request_pfs_session`, `end_pfs_session`, and the deferred handling of PFS MAC
//!   commands are all routed through the endpoint. After a session is established,
//!   subsequent `send_text` calls to that peer are automatically redirected through the
//!   ephemeral identity and keyed to the peer's ephemeral public key.
//!
//! [`EndpointConfig`] holds the per-endpoint defaults (default MIC size, flood hops,
//! encryption flag, beacon interval, and the [`UiAcceptancePolicy`] filter).
//!
//! [`UiAcceptancePolicy`] is a compact set of boolean flags that suppress specific event
//! categories before they reach the application — for example, `allow_direct_text: false`
//! silently drops all incoming direct unicast text messages at the endpoint layer. All
//! flags default to `true`.
//!
//! ## [`owned`] — heap-allocated event and payload types
//!
//! The `umsh-app` crate uses zero-copy borrowed types (`TextMessage<'_>`,
//! `NodeIdentityPayload<'_>`, `MacCommand<'_>`) that borrow from the underlying frame
//! buffer. `umsh-node` provides owned heap-allocated equivalents that can be stored,
//! cloned, and sent across async task boundaries without lifetime constraints:
//!
//! - [`OwnedTextMessage`] — owned parsed text message with all optional fields.
//! - [`OwnedNodeIdentityPayload`] — owned node identity advertisement (role, caps, name,
//!   signature).
//! - [`OwnedMacCommand`] — owned MAC command variant, with `Vec<u8>` for variable-length
//!   fields like echo data.
//! - [`EndpointEvent`] — the top-level event enum emitted by `handle_event` and
//!   `handle_deferred`. Variants cover text received, channel text, node discovery, beacon
//!   received, ACK confirmation, ACK timeout, PFS session lifecycle, and surfaced MAC
//!   commands.
//! - [`EventAction`] — the return type of `handle_event`. Either `Handled(Option<EndpointEvent>)`
//!   for events resolved synchronously, or `NeedsAsync(DeferredAction)` for events that
//!   require async follow-up (e.g., PFS key derivation after receiving a session response).
//! - [`DeferredAction`] — the work item passed back to `handle_deferred` when follow-up is
//!   needed. Currently contains only MAC command handling, but is designed to accommodate
//!   future async event types.
//!
//! ## [`mac`] — MAC abstraction trait for testability
//!
//! [`NodeMac`] is the trait that `Endpoint` depends on instead of being generic over
//! `MacHandle` directly. It exposes the send/configure surface of the MAC coordinator:
//! `add_peer`, `install_pairwise_keys`, `send_broadcast`, `send_unicast`,
//! `send_multicast`, `send_blind_unicast`, `fill_random`, `now_ms`, and (with
//! `software-crypto`) the ephemeral identity lifecycle methods.
//!
//! [`MacHandle`](umsh_mac::MacHandle) implements `NodeMac`, and test code can provide a
//! fake implementation to drive `Endpoint` deterministically without a real radio or
//! cryptographic state — the pattern used throughout the integration tests in this file.
//!
//! [`NodeMacError`] normalizes the two error dimensions of a MAC handle — `Busy` (the
//! `RefCell` was already borrowed), `Send` (a `SendError`), and `Capacity` (a
//! `CapacityError`) — into a single error type that `EndpointError` can wrap.
//!
//! ## [`pfs`] — Perfect Forward Secrecy session management
//!
//! Available when the `software-crypto` feature is enabled. Implements the two-message
//! PFS handshake defined in the `umsh-app` MAC command layer:
//!
//! 1. The initiator generates a fresh [`SoftwareIdentity`](umsh_crypto::software::SoftwareIdentity)
//!    and sends a `PfsSessionRequest` MAC command carrying the ephemeral public key and a
//!    requested duration.
//! 2. The responder generates its own ephemeral identity, replies with a
//!    `PfsSessionResponse`, derives the shared pairwise keys from the two ephemeral keys
//!    via ECDH, and installs them into the MAC coordinator.
//! 3. The initiator receives the `PfsSessionResponse`, performs its own ECDH, installs the
//!    keys, and registers the ephemeral MAC identity via `register_ephemeral`.
//!
//! [`PfsSessionManager`] tracks all active sessions (up to `DEFAULT_MAX_PFS_SESSIONS`).
//! Each [`PfsSession`] records the peer's long-term key, both ephemeral keys, the mapped
//! [`LocalIdentityId`](umsh_mac::LocalIdentityId), an expiry timestamp, and the
//! [`PfsState`] (either `Requested` or `Active`). `Endpoint` consults the session manager
//! on every outbound unicast to transparently redirect traffic through the ephemeral
//! identity when a session exists.
//!
//! ## [`error`] — endpoint error type
//!
//! [`EndpointError`] is the single error type returned by all `Endpoint` methods. It wraps
//! `umsh-app` parse/encode errors, [`NodeMacError`], missing-identity / PFS-not-found
//! errors, and (with `software-crypto`) cryptographic failures. The variants mirror the
//! layers the operation touches: application parsing, payload encoding, MAC send, and
//! PFS crypto.
//!
//! # Typical usage
//!
//! ```rust,ignore
//! // After setting up mac + handle as in umsh-mac docs:
//! let endpoint = Endpoint::new(identity_id, mac_handle, EndpointConfig {
//!     beacon_interval_ms: Some(60_000),
//!     ..EndpointConfig::default()
//! });
//!
//! // Send a text message:
//! let receipt = endpoint.send_text(&peer_key, "hello")?;
//!
//! // In the mac event loop callback:
//! match endpoint.handle_event(mac_event) {
//!     EventAction::Handled(Some(EndpointEvent::TextReceived { from, message })) => {
//!         println!("{}: {}", from, message.body);
//!     }
//!     EventAction::NeedsAsync(deferred) => {
//!         let event = endpoint.handle_deferred(deferred).await;
//!         // ...
//!     }
//!     _ => {}
//! }
//!
//! // Periodically call from the event loop:
//! endpoint.send_scheduled_beacon(now_ms)?;
//! ```

#[cfg(not(feature = "alloc"))]
compile_error!("umsh-node currently requires the alloc feature");

extern crate alloc;

mod endpoint;
mod error;
mod mac;
mod owned;
#[cfg(feature = "software-crypto")]
mod pfs;

pub use endpoint::{Endpoint, EndpointConfig, UiAcceptancePolicy};
pub use error::EndpointError;
pub use mac::{NodeMac, NodeMacError};
pub use owned::{DeferredAction, EndpointEvent, EventAction, OwnedMacCommand, OwnedNodeIdentityPayload, OwnedTextMessage};
#[cfg(feature = "software-crypto")]
pub use pfs::{PfsSession, PfsSessionManager, PfsState};

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        future::Future,
        pin::pin,
        rc::Rc,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };
    use core::convert::Infallible;

    use rand::{Rng, TryCryptoRng, TryRng};
    use umsh_core::{ChannelId, PublicKey};
    #[cfg(feature = "software-crypto")]
    use umsh_crypto::software::SoftwareIdentity;
    use umsh_crypto::{AesCipher, AesProvider, CryptoEngine, NodeIdentity, PairwiseKeys, Sha256Provider, SharedSecret};
    use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, TxError, TxOptions};
    use umsh_mac::{CapacityError, LocalIdentityId, Mac, MacEventRef, MacHandle, OperatingPolicy, PeerCryptoState, PeerId, Platform, RepeaterConfig, SendError, SendOptions, SendReceipt};
    #[cfg(feature = "std")]
    use umsh_mac::test_support::{make_test_mac, DummyClock as SimClock, DummyDelay as SimDelay, DummyIdentity as SimIdentity, SimulatedNetwork};

    use crate::{Endpoint, EndpointConfig, EndpointEvent, EventAction, NodeMac, NodeMacError, OwnedMacCommand, OwnedTextMessage, UiAcceptancePolicy};

    #[test]
    fn endpoint_send_text_queues_unicast() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let peer_key = PublicKey([0xAB; 32]);
        let peer_id = handle.add_peer(peer_key).unwrap();
        handle.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

        let endpoint = Endpoint::new(local_id, handle, EndpointConfig::default());
        endpoint.send_text(&peer_key, "hello").unwrap();

        assert_eq!(mac.borrow().tx_queue().len(), 1);
    }

    #[test]
    fn endpoint_handle_event_parses_text_messages() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let mut endpoint = Endpoint::new(local_id, handle, EndpointConfig::default());
        let payload = [umsh_app::PayloadType::TextMessage as u8, 0xFF, b'h', b'i'];

        match endpoint.handle_event(MacEventRef::Unicast {
            from: PublicKey([0x22; 32]),
            payload: &payload,
            ack_requested: false,
        }) {
            EventAction::Handled(Some(EndpointEvent::TextReceived { from, message })) => {
                assert_eq!(from, PublicKey([0x22; 32]));
                assert_eq!(message.body, "hi");
            }
            other => panic!("unexpected event action: {other:?}"),
        }
    }

    #[test]
    fn endpoint_beacon_schedule_fires_once_due() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let mut endpoint = Endpoint::new(
            local_id,
            handle,
            EndpointConfig {
                beacon_interval_ms: Some(100),
                ..EndpointConfig::default()
            },
        );

        assert!(!endpoint.send_scheduled_beacon(50).unwrap());
        assert!(endpoint.send_scheduled_beacon(100).unwrap());
        assert_eq!(mac.borrow().tx_queue().len(), 1);
    }

    #[test]
    fn endpoint_sync_policy_can_filter_direct_text() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let mut endpoint = Endpoint::new(
            local_id,
            handle,
            EndpointConfig {
                ui_acceptance: UiAcceptancePolicy {
                    allow_direct_text: false,
                    ..UiAcceptancePolicy::default()
                },
                ..EndpointConfig::default()
            },
        );
        let payload = [umsh_app::PayloadType::TextMessage as u8, 0xFF, b'h', b'i'];

        match endpoint.handle_event(MacEventRef::Unicast {
            from: PublicKey([0x22; 32]),
            payload: &payload,
            ack_requested: false,
        }) {
            EventAction::Handled(None) => {}
            other => panic!("unexpected event action: {other:?}"),
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn endpoints_exchange_text_over_simulated_network() {
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
        let shared_keys = PairwiseKeys {
            k_enc: [7; 16],
            k_mic: [9; 16],
        };
        let bob_peer = alice_handle.add_peer(bob_key).unwrap();
        let alice_peer = bob_handle.add_peer(alice_key).unwrap();
        alice_handle.install_pairwise_keys(alice_id, bob_peer, shared_keys.clone()).unwrap();
        bob_handle.install_pairwise_keys(bob_id, alice_peer, shared_keys).unwrap();

        let alice = Endpoint::new(alice_id, alice_handle, EndpointConfig::default());
        let mut bob = Endpoint::new(bob_id, bob_handle, EndpointConfig::default());
        alice.send_text(&bob_key, "hello bob").unwrap();

        block_on_ready(alice_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();
        let mut bob_events = Vec::new();
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|_, event| match bob.handle_event(event) {
            EventAction::Handled(Some(endpoint_event)) => bob_events.push(endpoint_event),
            EventAction::Handled(None) => {}
            EventAction::NeedsAsync(_) => panic!("unexpected deferred action for text exchange"),
        }))
        .unwrap();
        assert_eq!(
            bob_events,
            vec![EndpointEvent::TextReceived {
                from: alice_key,
                message: OwnedTextMessage {
                    message_type: umsh_app::MessageType::Basic,
                    sender_handle: None,
                    sequence: None,
                    sequence_reset: false,
                    regarding: None,
                    editing: None,
                    bg_color: None,
                    text_color: None,
                    body: String::from("hello bob"),
                },
            }]
        );

        let mut alice = alice;
        bob.send_text(&alice_key, "hello alice").unwrap();
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();
        let mut alice_events = Vec::new();
        // Two poll_cycles: first receives the MAC ACK for "hello bob", second
        // receives Bob's "hello alice" text.
        for _ in 0..2 {
            block_on_ready(alice_mac.borrow_mut().poll_cycle(|_, event| match alice.handle_event(event) {
                EventAction::Handled(Some(endpoint_event)) => alice_events.push(endpoint_event),
                EventAction::Handled(None) => {}
                EventAction::NeedsAsync(_) => panic!("unexpected deferred action for text exchange"),
            }))
            .unwrap();
        }
        assert_eq!(
            alice_events,
            vec![
                EndpointEvent::AckReceived {
                    peer: bob_key,
                    receipt: umsh_mac::SendReceipt(0),
                },
                EndpointEvent::TextReceived {
                    from: bob_key,
                    message: OwnedTextMessage {
                        message_type: umsh_app::MessageType::Basic,
                        sender_handle: None,
                        sequence: None,
                        sequence_reset: false,
                        regarding: None,
                        editing: None,
                        bg_color: None,
                        text_color: None,
                        body: String::from("hello alice"),
                    },
                },
            ]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn endpoints_exchange_text_through_simulated_repeater() {
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

        let shared_keys = PairwiseKeys {
            k_enc: [5; 16],
            k_mic: [6; 16],
        };
        let bob_peer = alice_handle.add_peer(bob_key).unwrap();
        let alice_peer = bob_handle.add_peer(alice_key).unwrap();
        alice_handle.install_pairwise_keys(alice_id, bob_peer, shared_keys.clone()).unwrap();
        bob_handle.install_pairwise_keys(bob_id, alice_peer, shared_keys).unwrap();

        let alice = Endpoint::new(alice_id, alice_handle, EndpointConfig::default());
        let mut bob = Endpoint::new(bob_id, bob_handle, EndpointConfig::default());
        alice.send_text(&bob_key, "via repeater").unwrap();

        block_on_ready(alice_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();

        let mut premature_events = Vec::new();
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|_, event| match bob.handle_event(event) {
            EventAction::Handled(Some(endpoint_event)) => premature_events.push(endpoint_event),
            EventAction::Handled(None) => {}
            EventAction::NeedsAsync(_) => panic!("unexpected deferred action for repeater test"),
        }))
        .unwrap();
        assert!(premature_events.is_empty());

        block_on_ready(repeater_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();
        repeater_clock.advance_ms(1_000);
        block_on_ready(repeater_mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();

        let mut bob_events = Vec::new();
        block_on_ready(bob_mac.borrow_mut().poll_cycle(|_, event| match bob.handle_event(event) {
            EventAction::Handled(Some(endpoint_event)) => bob_events.push(endpoint_event),
            EventAction::Handled(None) => {}
            EventAction::NeedsAsync(_) => panic!("unexpected deferred action for repeater test"),
        }))
        .unwrap();
        assert_eq!(
            bob_events,
            vec![EndpointEvent::TextReceived {
                from: alice_key,
                message: OwnedTextMessage {
                    message_type: umsh_app::MessageType::Basic,
                    sender_handle: None,
                    sequence: None,
                    sequence_reset: false,
                    regarding: None,
                    editing: None,
                    bg_color: None,
                    text_color: None,
                    body: String::from("via repeater"),
                },
            }]
        );
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn endpoint_pfs_establishes_routes_and_tears_down() {
        let mac = FakeMac::new(vec![[3u8; 32]]);
        let peer_long_term = PublicKey([0x55; 32]);
        let peer_ephemeral = PublicKey([0x66; 32]);
        let mut endpoint = Endpoint::new(LocalIdentityId(1), mac.clone(), EndpointConfig::default());

        endpoint.request_pfs_session(&peer_long_term, 60).unwrap();

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, LocalIdentityId(1));
        assert_eq!(sent[0].to, peer_long_term);
        assert_eq!(parse_owned_mac_command(&sent[0].payload), OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: *SoftwareIdentity::from_secret_bytes(&[3u8; 32]).public_key(),
            duration_minutes: 60,
        });

        let response_payload = encode_mac_payload(umsh_app::MacCommand::PfsSessionResponse {
            ephemeral_key: peer_ephemeral,
            duration_minutes: 60,
        });
        let deferred = match endpoint.handle_event(MacEventRef::Unicast {
            from: peer_long_term,
            payload: &response_payload,
            ack_requested: false,
        }) {
            EventAction::NeedsAsync(deferred) => deferred,
            other => panic!("unexpected event action: {other:?}"),
        };
        let event = block_on_ready(endpoint.handle_deferred(deferred));
        assert_eq!(event, Some(EndpointEvent::PfsSessionEstablished { peer: peer_long_term }));

        endpoint.send_text(&peer_long_term, "secret").unwrap();
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, LocalIdentityId(10));
        assert_eq!(sent[0].to, peer_ephemeral);

        assert!(endpoint.end_pfs_session(&peer_long_term).unwrap());
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(parse_owned_mac_command(&sent[0].payload), OwnedMacCommand::EndPfsSession);
        assert_eq!(mac.take_removed_ephemerals(), vec![LocalIdentityId(10)]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn endpoint_end_pfs_session_errors_when_missing() {
        let mac = FakeMac::new(Vec::new());
        let mut endpoint = Endpoint::new(LocalIdentityId(1), mac, EndpointConfig::default());

        let error = endpoint.end_pfs_session(&PublicKey([0x77; 32])).unwrap_err();
        assert!(matches!(error, crate::EndpointError::PfsSessionMissing));
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

    #[cfg(feature = "software-crypto")]
    #[derive(Clone, Default)]
    struct FakeMac {
        state: Rc<RefCell<FakeMacState>>,
    }

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SentUnicast {
        from: LocalIdentityId,
        to: PublicKey,
        payload: Vec<u8>,
        options: SendOptions,
    }

    #[cfg(feature = "software-crypto")]
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

        fn take_removed_ephemerals(&self) -> Vec<LocalIdentityId> {
            core::mem::take(&mut self.state.borrow_mut().removed_ephemerals)
        }
    }

    #[cfg(feature = "software-crypto")]
    impl NodeMac for FakeMac {
        type SendError = SendError;
        type CapacityError = CapacityError;

        fn add_peer(&self, key: PublicKey) -> Result<PeerId, NodeMacError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            if let Some((_, existing)) = state.peers.iter().find(|(existing_key, _)| *existing_key == key) {
                return Ok(*existing);
            }
            let peer_id = PeerId(state.next_peer_id);
            state.next_peer_id = state.next_peer_id.wrapping_add(1);
            state.peers.push((key, peer_id));
            Ok(peer_id)
        }

        fn add_private_channel(&self, _key: umsh_core::ChannelKey) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn add_named_channel(&self, _name: &str) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn install_pairwise_keys(
            &self,
            identity_id: LocalIdentityId,
            peer_id: PeerId,
            pairwise_keys: PairwiseKeys,
        ) -> Result<Option<PeerCryptoState>, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().installed.push((identity_id, peer_id, pairwise_keys));
            Ok(None)
        }

        fn send_broadcast(
            &self,
            _from: LocalIdentityId,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn send_multicast(
            &self,
            _from: LocalIdentityId,
            _channel: &ChannelId,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn send_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().unicasts.push(SentUnicast {
                from,
                to: *dst,
                payload: payload.to_vec(),
                options: options.clone(),
            });
            Ok(Some(SendReceipt(42)))
        }

        fn send_blind_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            _channel: &ChannelId,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.send_unicast(from, dst, payload, options)
        }

        fn fill_random(&self, dest: &mut [u8]) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            let next = state.random_blocks.pop_front().expect("test rng exhausted");
            dest.copy_from_slice(&next[..dest.len()]);
            Ok(())
        }

        fn now_ms(&self) -> Result<u64, NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(self.state.borrow().now_ms)
        }

        fn register_ephemeral(
            &self,
            _parent: LocalIdentityId,
            _identity: SoftwareIdentity,
        ) -> Result<LocalIdentityId, NodeMacError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            let id = LocalIdentityId(state.next_ephemeral_id);
            state.next_ephemeral_id = state.next_ephemeral_id.wrapping_add(1);
            Ok(id)
        }

        fn remove_ephemeral(&self, id: LocalIdentityId) -> Result<bool, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().removed_ephemerals.push(id);
            Ok(true)
        }
    }

    #[cfg(feature = "software-crypto")]
    fn encode_mac_payload(command: umsh_app::MacCommand<'_>) -> Vec<u8> {
        let mut body = [0u8; 80];
        let len = umsh_app::mac_command::encode(&command, &mut body).unwrap();
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(umsh_app::PayloadType::MacCommand as u8);
        payload.extend_from_slice(&body[..len]);
        payload
    }

    #[cfg(feature = "software-crypto")]
    fn parse_owned_mac_command(payload: &[u8]) -> OwnedMacCommand {
        match umsh_app::parse_payload(umsh_core::PacketType::Unicast, payload).unwrap() {
            umsh_app::PayloadRef::MacCommand(command) => OwnedMacCommand::from(command),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

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