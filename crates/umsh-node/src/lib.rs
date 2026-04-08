#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Application-facing node layer built on top of [`umsh-mac`](umsh_mac).
//!
//! `umsh-node` sits between the radio-facing MAC coordinator in `umsh-mac` and the
//! application. Where `umsh-mac` thinks in raw frames, keys, replay windows, and transmit
//! queues, `umsh-node` provides composable abstractions for sending and receiving messages,
//! tracking in-flight sends, and managing channel membership.
//!
//! The receive boundary is intentionally low-level: raw subscriptions get a
//! [`ReceivedPacketRef`] that stays close to the accepted on-wire packet. Payload-specific
//! helpers such as those in the `umsh-text` crate live one layer up and are built on top of
//! those raw packet callbacks.
//!
//! This crate requires `alloc` (heap allocation for `String`, `Vec`, etc.). It is
//! otherwise `no_std` compatible.
//!
//! # Architecture overview
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  Application                                                 │
//! │  Host · LocalNode · PeerConnection · BoundChannel            │
//! ┌──────────────────────┴───────────────────────────────────────┐
//! │  Host                                                        │
//! │    ├── drives the shared MAC/runtime event loop              │
//! │    └── owns multiple LocalNode handles                       │
//! └──────────────────────┬───────────────────────────────────────┘
//!                        │
//! ┌──────────────────────┴───────────────────────────────────────┐
//! │  LocalNode<M>                                                │
//! │    ├── sends down through MacBackend                         │
//! │    ├── owns per-identity PFS state                           │
//! │    └── dispatches node/peer callback subscriptions           │
//! └──────────────────────┬───────────────────────────────────────┘
//!                        │  MacBackend trait
//! ┌──────────────────────┴───────────────────────────────────────┐
//! │  MacHandle → Mac<P>  (no_std, heapless)                      │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key types
//!
//! - [`Host`] — preferred multi-identity driver. Owns the shared MAC event loop and routes
//!   inbound traffic to the right [`LocalNode`].
//! - [`LocalNode`] — per-identity application handle. Implements [`Transport`] (unicast /
//!   broadcast), owns PFS state, and exposes raw packet plus control-side subscriptions.
//! - [`BoundChannel`] — a channel bound to a `LocalNode`. Implements [`Transport`]
//!   (blind unicast / multicast). Available with the `software-crypto` feature.
//! - [`PeerConnection`] — relationship with one remote peer, generic over transport context,
//!   with peer-scoped callback subscriptions.
//! - [`Transport`] — shared send interface (`send` / `send_all`).
//! - [`SendProgressTicket`] — lightweight polling handle for observing in-flight send
//!   progress (`was_transmitted`, `was_acked`, `is_finished`).
//! - [`Subscription`] — owned callback registration that auto-unsubscribes on drop.
//! - [`ReceivedPacketRef`] — borrowed receive view passed into low-level `on_receive(...)`
//!   handlers and wrappers, including local RX observations such as RSSI, SNR, LQI, and
//!   receive timestamp.
//! - [`MacBackend`] — pluggable MAC backend trait for testability.
//!
//! # Control payload types
//!
//! [`umsh_text::OwnedTextMessage`], [`OwnedNodeIdentityPayload`], and [`OwnedMacCommand`] are
//! optional heap-allocated conveniences for callers that need
//! to retain parsed payloads across task boundaries. Most receive-side code should prefer the
//! borrowed views from the payload crates and [`ReceivedPacketRef`].
//!
//! # MAC abstraction
//!
//! [`MacBackend`] exposes the public send/configure surface of the MAC coordinator.
//! Safe PFS session management is available with `software-crypto` and builds on
//! that public surface directly.
//!
//! [`MacHandle`](umsh_mac::MacHandle) implements `MacBackend`, and test code can provide
//! a fake implementation to drive the node layer deterministically.
//!
//! # Typical usage
//!
//! For most applications, register callbacks and then let [`Host::run`] own the shared
//! MAC event loop:
//!
//! ```rust,ignore
//! let mut host = Host::new(mac_handle);
//! let node = host.add_node(identity_id);
//! let peer = node.peer(peer_key)?;
//! let chat = umsh_text::UnicastTextChatWrapper::from_peer(&peer);
//!
//! let _messages = chat.on_text(|packet, text| {
//!     println!(
//!         "peer says: {} (hops={})",
//!         text.body,
//!         packet.flood_hops().map(|h| h.remaining()).unwrap_or(0),
//!     );
//! });
//!
//! let _ticket = chat.send_text("hello", &SendOptions::default()).await?;
//! host.run().await?;
//! ```
//!
//! If you need to multiplex UMSH progress with another async source such as user input, use
//! [`Host::pump_once`] as a single wake-driven step. It already waits on radio activity and
//! protocol deadlines; you should not add a manual poll/sleep loop around it.
//!
//! ```rust,ignore
//! loop {
//!     tokio::select! {
//!         line = stdin.next_line() => { /* handle input */ }
//!         result = host.pump_once() => result?,
//!     }
//! }
//! ```
//!
//! If you need protocol fidelity instead of a payload wrapper, subscribe directly on the node
//! or peer and inspect the raw packet view:
//!
//! ```rust,ignore
//! let _raw = peer.on_receive(|packet| {
//!     if packet.packet_family() == umsh::mac::PacketFamily::Unicast {
//!         println!(
//!             "from={:?} encrypted={} mic_len={}",
//!             packet.from_key(),
//!             packet.encrypted(),
//!             packet.mic_len(),
//!         );
//!     }
//!     false
//! });
//! ```

#[cfg(not(feature = "alloc"))]
compile_error!("umsh-node currently requires the alloc feature");

extern crate alloc;

mod app_error;
mod app_owned;
mod app_payload;
mod app_util;
#[cfg(feature = "software-crypto")]
mod channel;
mod dispatch;
mod host;
mod identity;
mod mac;
pub mod mac_command;
mod node;
mod peer;
#[cfg(feature = "software-crypto")]
mod pfs;
mod receive;
mod ticket;
mod transport;

#[cfg(feature = "software-crypto")]
pub use channel::Channel;
pub use host::{Host, HostError};
pub use mac::{MacBackend, MacBackendError};
#[cfg(feature = "software-crypto")]
pub use node::BoundChannel;
#[cfg(feature = "software-crypto")]
pub use node::PfsStatus;
pub use node::{LocalNode, NodeError, Subscription};
pub use peer::PeerConnection;
pub use receive::{ChannelInfoRef, PacketFamily, ReceivedPacketRef, RouteHops, RxMetadata, Snr};
pub use ticket::{SendProgressTicket, SendToken};
pub use transport::Transport;
pub use app_error::{AppEncodeError, AppParseError};
pub use app_owned::{OwnedMacCommand, OwnedNodeIdentityPayload};
pub use app_payload::{
    expect_payload_type, parse_mac_command_payload, parse_node_identity_payload, split_payload_type,
};
pub use identity::{Capabilities, NodeIdentityPayload, NodeRole};
pub use mac_command::{CommandId, MacCommand};

pub mod identity_payload {
    pub use crate::identity::{encode, parse};
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use std::{
        cell::RefCell,
        collections::VecDeque,
        future::Future,
        num::NonZeroU8,
        pin::pin,
        rc::Rc,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_core::{NodeHint, PublicKey};
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_crypto::NodeIdentity;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_crypto::software::SoftwareIdentity;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_hal::Snr;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_mac::MacEventRef;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_mac::{CapacityError, LocalIdentityId, PeerId, SendError, SendOptions, SendReceipt};

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use crate::ReceivedPacketRef;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use crate::{MacBackend, MacBackendError, OwnedMacCommand, SendToken};
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_text::OwnedTextMessage;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_core::ChannelId;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn peer_receive_handlers_precede_node_receive_handlers() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(LocalIdentityId(1), mac, dispatcher, membership, state);
        let peer = PublicKey([0x41; 32]);
        let peer_connection = node.peer(peer).unwrap();

        let call_order = Rc::new(RefCell::new(Vec::new()));
        let peer_call_order = call_order.clone();
        let _peer_subscription = peer_connection.on_receive(move |_| {
            peer_call_order.borrow_mut().push("peer");
            true
        });
        let node_call_order = call_order.clone();
        let _node_subscription = node.on_receive(move |_| {
            node_call_order.borrow_mut().push("node");
            true
        });

        assert!(node.dispatch_received_packet(&test_unicast_packet(peer, &[0x01, 0x02])));
        assert_eq!(call_order.borrow().as_slice(), ["peer"]);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn receive_callbacks_can_observe_rx_metadata() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(LocalIdentityId(1), mac, dispatcher, membership, state);
        let peer = PublicKey([0x44; 32]);

        let observed = Rc::new(RefCell::new(None));
        let observed_for_callback = observed.clone();
        let _subscription = node.on_receive(move |packet| {
            *observed_for_callback.borrow_mut() = Some((
                packet.rssi(),
                packet.snr(),
                packet.lqi(),
                packet.received_at_ms(),
            ));
            true
        });

        let payload = encode_text_payload("metadata");
        let packet = test_unicast_packet_with_rx(
            peer,
            &payload,
            umsh_mac::RxMetadata::new(
                Some(-73),
                Some(Snr::from_centibels(123)),
                NonZeroU8::new(200),
                Some(123_456),
            ),
        );

        assert!(node.dispatch_received_packet(&packet));
        assert_eq!(
            *observed.borrow(),
            Some((
                Some(-73),
                Some(Snr::from_centibels(123)),
                NonZeroU8::new(200),
                Some(123_456),
            ))
        );
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn subscription_guard_unregisters_on_drop() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(LocalIdentityId(1), mac, dispatcher, membership, state);
        let peer = PublicKey([0x33; 32]);

        let hits = Rc::new(RefCell::new(0u32));
        {
            let hits = hits.clone();
            let _subscription = node.on_receive(move |_| {
                *hits.borrow_mut() += 1;
                true
            });
            assert!(node.dispatch_received_packet(&test_unicast_packet(peer, &[0x01, 0x02])));
        }

        assert_eq!(*hits.borrow(), 1);
        assert!(!node.dispatch_received_packet(&test_unicast_packet(peer, &[0x01, 0x02])));
        assert_eq!(*hits.borrow(), 1);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn callbacks_observe_control_side_events_and_peer_ack_state() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(LocalIdentityId(1), mac, dispatcher, membership, state);

        let peer = PublicKey([0x42; 32]);
        let peer_connection = node.peer(peer).unwrap();
        let node_discovery = Rc::new(RefCell::new(Vec::new()));
        let beacons = Rc::new(RefCell::new(Vec::new()));
        let commands = Rc::new(RefCell::new(Vec::new()));
        let peer_acks = Rc::new(RefCell::new(Vec::new()));
        let peer_timeouts = Rc::new(RefCell::new(Vec::new()));

        let discovery_log = node_discovery.clone();
        let _discovered_subscription = node.on_node_discovered(move |key, name| {
            discovery_log
                .borrow_mut()
                .push((key, name.map(str::to_string)));
        });
        let beacon_log = beacons.clone();
        let _beacon_subscription = node.on_beacon(move |from_hint, from_key| {
            beacon_log.borrow_mut().push((from_hint, from_key));
        });
        let command_log = commands.clone();
        let _command_subscription = node.on_mac_command(move |from, command| {
            command_log.borrow_mut().push((from, command.clone()));
        });
        let peer_ack_log = peer_acks.clone();
        let _ack_subscription = peer_connection.on_ack_received(move |token| {
            peer_ack_log.borrow_mut().push(token);
        });
        let peer_timeout_log = peer_timeouts.clone();
        let _timeout_subscription = peer_connection.on_ack_timeout(move |token| {
            peer_timeout_log.borrow_mut().push(token);
        });

        let token = SendToken::new(LocalIdentityId(1), SendReceipt(12));
        let timeout_token = SendToken::new(LocalIdentityId(1), SendReceipt(13));
        let hint = NodeHint([1, 2, 3]);
        let command = OwnedMacCommand::EchoRequest {
            data: vec![9, 8, 7],
        };

        node.dispatch_node_discovered(peer, Some("alice"));
        node.dispatch_beacon(hint, Some(peer));
        node.dispatch_mac_command(peer, &command);
        node.dispatch_ack_received(peer, token);
        node.dispatch_ack_timeout(peer, timeout_token);

        assert_eq!(
            node_discovery.borrow().as_slice(),
            &[(peer, Some(String::from("alice")))]
        );
        assert_eq!(beacons.borrow().as_slice(), &[(hint, Some(peer))]);
        assert_eq!(commands.borrow().as_slice(), &[(peer, command)]);
        assert_eq!(peer_acks.borrow().as_slice(), &[token]);
        assert_eq!(peer_timeouts.borrow().as_slice(), &[timeout_token]);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn pfs_routed_send_tracks_ack_against_ephemeral_identity() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(vec![[7u8; 32], [9u8; 32]]);
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac.clone(),
            dispatcher.clone(),
            membership,
            state,
        );

        let peer = PublicKey([0x55; 32]);
        let peer_connection = node.peer(peer).unwrap();
        let options = SendOptions::default().with_ack_requested(true);

        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
        let request = mac.take_unicasts().pop().expect("request send");
        let request_command = parse_owned_mac_command(&request.payload);
        let request_ephemeral = match request_command {
            OwnedMacCommand::PfsSessionRequest { ephemeral_key, .. } => ephemeral_key,
            other => panic!("unexpected request payload: {other:?}"),
        };

        block_on_ready(node.handle_pfs_command(
            &peer,
            &OwnedMacCommand::PfsSessionResponse {
                ephemeral_key: PublicKey([0x44; 32]),
                duration_minutes: 60,
            },
            &options,
        ))
        .unwrap();

        let payload = encode_text_payload("hello over pfs");
        let ticket = block_on_ready(peer_connection.send(&payload, &options)).unwrap();
        let sent = mac.take_unicasts().pop().expect("pfs-routed send");
        assert_eq!(sent.from, LocalIdentityId(10));
        assert_eq!(sent.to, PublicKey([0x44; 32]));

        let pairwise_from_pfs = PublicKey([0x44; 32]);
        let _ = request_ephemeral; // Keeps the request path explicit in the test setup.
        dispatcher.borrow_mut().dispatch_ticket_state(
            sent.from,
            &MacEventRef::AckReceived {
                peer: pairwise_from_pfs,
                receipt: SendReceipt(42),
            },
        );
        assert!(ticket.was_acked());
        assert!(ticket.is_finished());
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
        assert_eq!(
            parse_owned_mac_command(&sent[0].payload),
            OwnedMacCommand::PfsSessionRequest {
                ephemeral_key: *SoftwareIdentity::from_secret_bytes(&[3u8; 32]).public_key(),
                duration_minutes: 60,
            }
        );

        assert!(
            block_on_ready(pfs.end_session(
                &mac,
                LocalIdentityId(1),
                &peer_long_term,
                true,
                &options,
            ))
            .unwrap()
        );
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            parse_owned_mac_command(&sent[0].payload),
            OwnedMacCommand::EndPfsSession
        );
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
            message_type: umsh_text::MessageType::Basic,
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
        let len = umsh_text::text_message::encode(&message.as_borrowed(), &mut body).unwrap();
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(umsh_core::PayloadType::TextMessage as u8);
        payload.extend_from_slice(&body[..len]);
        payload
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn test_unicast_packet<'a>(from: PublicKey, payload: &'a [u8]) -> ReceivedPacketRef<'a> {
        test_unicast_packet_with_rx(from, payload, umsh_mac::RxMetadata::default())
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn test_unicast_packet_with_rx<'a>(
        from: PublicKey,
        payload: &'a [u8],
        rx: umsh_mac::RxMetadata,
    ) -> ReceivedPacketRef<'a> {
        let wire = Box::leak(payload.to_vec().into_boxed_slice());
        let header = umsh_core::PacketHeader {
            fcf: umsh_core::Fcf::new(umsh_core::PacketType::Unicast, false, false, false),
            options_range: 0..0,
            flood_hops: None,
            dst: None,
            channel: None,
            ack_dst: None,
            source: umsh_core::SourceAddrRef::Hint(from.hint()),
            sec_info: None,
            body_range: 0..wire.len(),
            mic_range: wire.len()..wire.len(),
            total_len: wire.len(),
        };
        ReceivedPacketRef::new(
            wire,
            wire,
            header,
            umsh_core::ParsedOptions::default(),
            Some(from),
            Some(from.hint()),
            true,
            None,
            rx,
        )
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

        fn add_peer(
            &self,
            key: PublicKey,
        ) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            if let Some((_, existing)) = state
                .peers
                .iter()
                .find(|(existing_key, _)| *existing_key == key)
            {
                return Ok(*existing);
            }
            let peer_id = PeerId(state.next_peer_id);
            state.next_peer_id = state.next_peer_id.wrapping_add(1);
            state.peers.push((key, peer_id));
            Ok(peer_id)
        }

        fn add_private_channel(
            &self,
            _key: umsh_core::ChannelKey,
        ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn add_named_channel(
            &self,
            _name: &str,
        ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
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
        ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>>
        {
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
        ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>>
        {
            self.send_unicast(from, dst, payload, options).await
        }

        fn fill_random(
            &self,
            dest: &mut [u8],
        ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
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
        ) -> Result<LocalIdentityId, MacBackendError<Self::SendError, Self::CapacityError>>
        {
            let mut state = self.state.borrow_mut();
            let id = LocalIdentityId(state.next_ephemeral_id);
            state.next_ephemeral_id = state.next_ephemeral_id.wrapping_add(1);
            Ok(id)
        }

        fn remove_ephemeral(
            &self,
            id: LocalIdentityId,
        ) -> Result<bool, MacBackendError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().removed_ephemerals.push(id);
            Ok(true)
        }
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn parse_owned_mac_command(payload: &[u8]) -> OwnedMacCommand {
        OwnedMacCommand::from(
            crate::parse_mac_command_payload(umsh_core::PacketType::Unicast, payload).unwrap(),
        )
    }

    #[cfg(feature = "unsafe-advanced")]
    fn block_on_ready<F: Future>(future: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
            )
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
