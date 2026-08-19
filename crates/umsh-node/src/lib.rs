#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Application-facing node layer built on top of [`umsh-mac`](umsh_mac).
//!
//! > Note: This reference implementation is a work in progress and was developed
//! > with the assistance of an LLM. It should be considered experimental.
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
//! [`umsh_text::OwnedTextMessage`], [`NodeIdentityPayload`], and [`OwnedMacCommand`] are
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
mod app_payload;
mod app_util;
#[cfg(feature = "software-crypto")]
mod channel;
mod dispatch;
mod host;
mod identity;
pub mod identity_responder;
pub mod location;
mod mac;
pub mod mac_command;
mod node;
mod peer;
pub mod peer_repeaters;
#[cfg(feature = "software-crypto")]
mod pfs;
mod receive;
mod ticket;
mod transport;

pub use app_error::{AppEncodeError, AppParseError};
pub use app_payload::{
    expect_payload_type, parse_mac_command_payload, parse_node_identity_payload, split_payload_type,
};
#[cfg(feature = "software-crypto")]
pub use channel::Channel;
pub use host::{Host, HostError};
pub use identity::{NodeCapabilities, NodeIdentityPayload, NodeRole};
pub use identity_responder::{
    IdentityRequestContext, NodeIdentityProfile, RespondDecision, default_respond_policy,
    never_respond_policy,
};
pub use mac::{MacBackend, MacBackendError};
pub use mac_command::OwnedMacCommand;
pub use mac_command::{CommandId, MacCommand};
#[cfg(feature = "software-crypto")]
pub use node::BoundChannel;
#[cfg(feature = "software-crypto")]
pub use node::PfsStatus;
pub use node::{LocalNode, NodeError, PfsFailure, PongMetadata, Subscription};
pub use peer::{PING_MIC_SIZE, PeerConnection};
pub use peer_repeaters::{
    MAX_PEER_REPEATERS, MergedPeerRepeater, PeerRepeaterRecord, PeerRepeaterTable,
};
pub use receive::{ChannelInfoRef, PacketFamily, ReceivedPacketRef, RouteHops, RxMetadata, Snr};
pub use ticket::{SendProgressTicket, SendToken};
pub use transport::Transport;

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
    use umsh_core::ChannelId;
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    use umsh_text::OwnedTextMessage;
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
        let peer_connection = block_on_ready(node.peer(peer)).unwrap();

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
    fn test_node(mac: FakeMac) -> crate::node::LocalNode<FakeMac> {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        LocalNode::new(
            LocalIdentityId(1),
            mac,
            Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new())),
            Rc::new(RefCell::new(NodeMembership::new())),
            Rc::new(RefCell::new(LocalNodeState::new())),
        )
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn leaving_a_channel_unregisters_its_key_from_the_mac() {
        let mac = FakeMac::new(Vec::new());
        let node = test_node(mac.clone());
        let channel = crate::Channel::private(umsh_core::ChannelKey([0x11; 32]), "trail");

        block_on_ready(node.join(&channel)).unwrap();
        assert!(mac.holds_channel(channel.key()));

        block_on_ready(node.leave(&channel)).unwrap();
        assert!(!mac.holds_channel(channel.key()));
        assert!(node.bound_channel(&channel).is_none());
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn rejoining_after_leave_re_registers_the_key_with_the_mac() {
        let mac = FakeMac::new(Vec::new());
        let node = test_node(mac.clone());
        let channel = crate::Channel::private(umsh_core::ChannelKey([0x22; 32]), "camp");

        let first = block_on_ready(node.join(&channel)).unwrap();
        block_on_ready(node.leave(&channel)).unwrap();
        let second = block_on_ready(node.join(&channel)).unwrap();

        // The key is back in the MAC, the fresh handle is live, and the stale
        // one from before the leave is not.
        assert!(mac.holds_channel(channel.key()));
        assert!(second.is_active());
        assert!(!first.is_active());
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn leaving_a_channel_that_was_never_joined_is_a_no_op() {
        let mac = FakeMac::new(Vec::new());
        let node = test_node(mac.clone());
        let joined = crate::Channel::private(umsh_core::ChannelKey([0x33; 32]), "joined");
        let stranger = crate::Channel::private(umsh_core::ChannelKey([0x44; 32]), "stranger");

        block_on_ready(node.join(&joined)).unwrap();
        block_on_ready(node.leave(&stranger)).unwrap();

        assert!(mac.holds_channel(joined.key()));
        assert!(node.bound_channel(&joined).is_some());
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
        let peer_connection = block_on_ready(node.peer(peer)).unwrap();
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

    /// A ping must travel the way the traffic it is measuring would, so the
    /// caller's options carry through untouched. The one exception is the ack
    /// request: the echo response already acknowledges the ping, so asking
    /// for a MAC ack too would put a second frame on the air for nothing.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn ping_honours_caller_options_but_never_requests_a_mac_ack() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};
        use umsh_core::MicSize;

        let mac = FakeMac::new(vec![[7u8; 32], [9u8; 32]]);
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac.clone(),
            Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new())),
            Rc::new(RefCell::new(NodeMembership::new())),
            Rc::new(RefCell::new(LocalNodeState::new())),
        );
        let peer_connection = block_on_ready(node.peer(PublicKey([0x55; 32]))).unwrap();

        let options = SendOptions::default()
            .with_mic_size(MicSize::Mic4)
            .with_ack_requested(true)
            .with_trace_route()
            .with_flood_hops(3)
            .with_region_code([0x78, 0x53]);
        block_on_ready(peer_connection.ping(6, &options, 1_000)).unwrap();

        let sent = mac.take_unicasts().pop().expect("ping send");
        assert_eq!(sent.options.mic_size, MicSize::Mic4);
        assert!(sent.options.trace_route);
        assert_eq!(sent.options.flood_hops, Some(3));
        assert_eq!(sent.options.region_code, Some([0x78, 0x53]));
        assert!(!sent.options.ack_requested, "the echo response is the ack");

        // `no_flood` is a distinct state from an unset budget and must also
        // survive, rather than collapsing back to the wide default.
        block_on_ready(peer_connection.ping(0, &SendOptions::default().no_flood(), 1_000)).unwrap();
        let sent = mac.take_unicasts().pop().expect("ping send");
        assert_eq!(sent.options.flood_hops, None);
    }

    /// The MIC size pings are normally sent with. A ping frame is otherwise
    /// nearly half authenticator.
    #[test]
    fn ping_mic_size_is_eight_bytes() {
        assert_eq!(crate::PING_MIC_SIZE, umsh_core::MicSize::Mic8);
        assert_eq!(crate::PING_MIC_SIZE.byte_len(), 8);
    }

    /// How much echo data fits is a property of the frame the ping is sealed
    /// into—MIC size, source form, options—and the MAC builder is the only
    /// thing that knows all of it. A ping asks for the size it was told to and
    /// lets an oversize request fail at the builder, rather than being quietly
    /// shortened to a length that measures a different frame than the caller
    /// asked about.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn ping_data_is_not_capped_by_the_node_layer() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let peer_connection = block_on_ready(node.peer(PublicKey([0x55; 32]))).unwrap();

        block_on_ready(peer_connection.ping(120, &SendOptions::default(), 1_000)).unwrap();

        let sent = mac.take_unicasts().pop().expect("ping send");
        match parse_owned_mac_command(&sent.payload) {
            OwnedMacCommand::EchoRequest { data } => {
                assert_eq!(data.len(), 2 + 120, "2-byte nonce plus the requested fill");
            }
            other => panic!("unexpected ping payload: {other:?}"),
        }
    }

    /// A peer reached through a channel pings over that channel. The ping is
    /// measuring the path the channel's traffic takes, so it has to be carried
    /// the same way—and the reply that comes back on the channel matches the
    /// pending ping just as a unicast reply would.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn ping_over_a_bound_channel_sends_a_blind_unicast() {
        let mac = FakeMac::new(vec![[0x3c; 32]]);
        let node = test_node(mac.clone());
        let channel = crate::Channel::private(umsh_core::ChannelKey([0x66; 32]), "trail");
        let bound = block_on_ready(node.join(&channel)).unwrap();

        let peer = PublicKey([0x55; 32]);
        let pongs = Rc::new(RefCell::new(Vec::new()));
        let pong_log = pongs.clone();
        let peer_connection = bound.peer(peer);
        let _pong_subscription = peer_connection.on_pong(move |rtt_ms| {
            pong_log.borrow_mut().push(rtt_ms);
        });

        block_on_ready(peer_connection.ping(4, &SendOptions::default(), 1_000)).unwrap();

        let sent = mac.take_unicasts().pop().expect("ping send");
        assert_eq!(
            sent.channel,
            Some(*channel.channel_id()),
            "a channel-bound ping goes out blind on that channel"
        );
        assert!(!sent.options.ack_requested, "the echo response is the ack");
        let nonce = match parse_owned_mac_command(&sent.payload) {
            OwnedMacCommand::EchoRequest { data } => {
                assert_eq!(data.len(), 2 + 4);
                [data[0], data[1]]
            }
            other => panic!("unexpected ping payload: {other:?}"),
        };

        let packet = test_channel_packet(
            peer,
            umsh_core::PacketType::BlindUnicast,
            channel.key(),
            *channel.channel_id(),
            &nonce,
        );
        node.match_pong(peer, &nonce, &packet, 1_250);

        assert_eq!(pongs.borrow().as_slice(), &[250]);
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
        let peer_connection = block_on_ready(node.peer(peer)).unwrap();
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
            None,
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
        let message = OwnedTextMessage::basic(text);
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
            fcf: umsh_core::Fcf::new(umsh_core::PacketType::Unicast, false, false),
            options_range: 0..0,
            flood_hops: None,
            dst: None,
            channel: None,
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

    /// A received frame that arrived inside a channel—a blind unicast, or
    /// the multicast a solicitation can ride.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn test_channel_packet<'a>(
        from: PublicKey,
        packet_type: umsh_core::PacketType,
        channel_key: &'a umsh_core::ChannelKey,
        channel_id: umsh_core::ChannelId,
        payload: &'a [u8],
    ) -> ReceivedPacketRef<'a> {
        let wire = Box::leak(payload.to_vec().into_boxed_slice());
        let header = umsh_core::PacketHeader {
            fcf: umsh_core::Fcf::new(packet_type, false, false),
            options_range: 0..0,
            flood_hops: None,
            dst: None,
            channel: Some(channel_id),
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
            Some(crate::ChannelInfoRef {
                id: channel_id,
                key: channel_key,
            }),
            umsh_mac::RxMetadata::default(),
        )
    }

    /// A received broadcast frame, as a solicitation would arrive: optionally
    /// carrying an FHOPS byte and a Route option. Only the ranges matter, so
    /// the wire is just the route bytes.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn test_broadcast_packet(
        from: PublicKey,
        flood_hops: Option<u8>,
        route: Option<&'static [u8]>,
    ) -> ReceivedPacketRef<'static> {
        test_broadcast_packet_with_trace(from, flood_hops, route, None)
    }

    /// As above, plus an accumulated trace route — what a steered
    /// solicitation looks like once repeaters have prepended themselves to it.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn test_broadcast_packet_with_trace(
        from: PublicKey,
        flood_hops: Option<u8>,
        route: Option<&'static [u8]>,
        trace: Option<&'static [u8]>,
    ) -> ReceivedPacketRef<'static> {
        let route_len = route.map_or(0, <[u8]>::len);
        let trace_len = trace.map_or(0, <[u8]>::len);
        let mut bytes = route.map_or_else(Vec::new, <[u8]>::to_vec);
        bytes.extend_from_slice(trace.unwrap_or(&[]));
        let wire: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        let mut options = umsh_core::ParsedOptions::default();
        if route.is_some() {
            options.source_route = Some(0..route_len);
        }
        if trace.is_some() {
            options.trace_route = Some(route_len..route_len + trace_len);
        }
        let header = umsh_core::PacketHeader {
            fcf: umsh_core::Fcf::new(umsh_core::PacketType::Broadcast, false, false),
            options_range: 0..route_len + trace_len,
            flood_hops: flood_hops.map(umsh_core::FloodHops),
            dst: None,
            channel: None,
            source: umsh_core::SourceAddrRef::Hint(from.hint()),
            sec_info: None,
            body_range: route_len + trace_len..wire.len(),
            mic_range: wire.len()..wire.len(),
            total_len: wire.len(),
        };
        ReceivedPacketRef::new(
            wire,
            &wire[route_len + trace_len..],
            header,
            options,
            Some(from),
            Some(from.hint()),
            false,
            None,
            umsh_mac::RxMetadata::default(),
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
        channels: Vec<umsh_core::ChannelKey>,
        observations: Vec<umsh_mac::TransmitterObservation>,
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SentUnicast {
        from: LocalIdentityId,
        to: PublicKey,
        payload: Vec<u8>,
        options: SendOptions,
        /// The channel a blind unicast went out on; `None` for plain unicast.
        channel: Option<ChannelId>,
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

        fn holds_channel(&self, key: &umsh_core::ChannelKey) -> bool {
            self.state.borrow().channels.iter().any(|k| k.0 == key.0)
        }

        fn observe(&self, hint: umsh_core::RouterHint, rssi_dbm: i16, snr: umsh_hal::Snr) {
            let mut state = self.state.borrow_mut();
            let last_seen_ms = state.now_ms;
            state.observations.push(umsh_mac::TransmitterObservation {
                hint,
                rssi_dbm,
                snr,
                last_seen_ms,
            });
        }
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    impl MacBackend for FakeMac {
        type SendError = SendError;
        type CapacityError = CapacityError;
        type RunError = core::convert::Infallible;

        async fn next_event(
            &self,
            _on_event: impl FnMut(LocalIdentityId, umsh_mac::MacEventRef<'_>),
        ) -> Result<(), Self::RunError> {
            // FakeMac is used to drive LocalNode directly in tests, never as a
            // Host run loop, so this stub is never invoked.
            Ok(())
        }

        async fn add_peer(
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

        async fn add_private_channel(
            &self,
            key: umsh_core::ChannelKey,
        ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            if !state.channels.iter().any(|k| k.0 == key.0) {
                state.channels.push(key);
            }
            Ok(())
        }

        async fn add_named_channel(
            &self,
            _name: &str,
        ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        async fn remove_channel(&self, key: &umsh_core::ChannelKey) -> bool {
            let mut state = self.state.borrow_mut();
            let before = state.channels.len();
            state.channels.retain(|k| k.0 != key.0);
            state.channels.len() != before
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
                channel: None,
            });
            Ok(Some(SendReceipt(42)))
        }

        async fn send_blind_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            channel: &ChannelId,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>>
        {
            self.state.borrow_mut().unicasts.push(SentUnicast {
                from,
                to: *dst,
                payload: payload.to_vec(),
                options: options.clone(),
                channel: Some(*channel),
            });
            Ok(Some(SendReceipt(42)))
        }

        async fn fill_random(&self, dest: &mut [u8]) {
            let mut state = self.state.borrow_mut();
            let next = state.random_blocks.pop_front().expect("test rng exhausted");
            dest.copy_from_slice(&next[..dest.len()]);
        }

        async fn now_ms(&self) -> u64 {
            self.state.borrow().now_ms
        }

        async fn register_ephemeral(
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

        async fn remove_ephemeral(&self, id: LocalIdentityId) -> bool {
            self.state.borrow_mut().removed_ephemerals.push(id);
            true
        }

        async fn for_each_transmitter_observation(
            &self,
            f: &mut dyn FnMut(umsh_mac::TransmitterObservation),
        ) {
            let observations = self.state.borrow().observations.clone();
            for observation in observations {
                f(observation);
            }
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

    // --- Identity Request responder ---

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn responder_node(mac: &FakeMac) -> crate::LocalNode<FakeMac> {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        LocalNode::new(
            LocalIdentityId(1),
            mac.clone(),
            dispatcher,
            membership,
            state,
        )
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn test_profile(public_key: PublicKey) -> crate::NodeIdentityProfile {
        crate::NodeIdentityProfile::new(
            public_key,
            crate::NodeRole::Repeater,
            crate::NodeCapabilities::REPEATER | crate::NodeCapabilities::TEXT_MESSAGES,
        )
        .with_name("repeater-1")
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_answers_selected_request_with_unicast_identity() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        // Broadcast-style request that filters on our hint and carries a nonce.
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(0xCAFE_F00D)
            .unwrap()
            .filter_hint(&our_key.hint())
            .unwrap()
            .build();
        let packet = test_unicast_packet(requester, &[]);

        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 0)
            .expect("responder should produce a reply plan");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1, "exactly one unicast reply");
        let reply = &unicasts[0];
        assert_eq!(reply.to, requester, "reply is addressed to the requester");
        // test_unicast_packet is source_authenticated → requester already has
        // our key → hint source suffices.
        assert!(!reply.options.full_source);
        // A targeted request gets an immediate reply; only broadcast and
        // multicast solicitations are jittered.
        assert_eq!(reply.options.tx_delay_ms, None);

        assert_eq!(reply.payload[0], umsh_core::PayloadType::NodeIdentity as u8);
        let identity = crate::NodeIdentityPayload::from_bytes(&reply.payload[1..]).unwrap();
        assert_eq!(identity.role, crate::NodeRole::Repeater);
        assert_eq!(identity.name.as_deref(), Some("repeater-1"));
        assert_eq!(identity.nonce, Some(0xCAFE_F00D), "request nonce echoed");
        assert!(identity.signature.is_none(), "responses are unsigned");
    }

    /// A blind request concealed both endpoints behind the channel key. The
    /// identity reply follows it back onto that channel rather than naming the
    /// pair in the clear.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn identity_response_follows_a_blind_request_onto_its_channel() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let channel_key = umsh_core::ChannelKey([0x5A; 32]);
        let channel_id = umsh_core::ChannelId([0xC1, 0xD2]);
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint(&our_key.hint())
            .unwrap()
            .build();
        let packet = test_channel_packet(
            requester,
            umsh_core::PacketType::BlindUnicast,
            &channel_key,
            channel_id,
            &[],
        );

        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 0)
            .expect("responder should produce a reply plan");
        block_on_ready(node.send_identity_response(plan));

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].channel,
            Some(channel_id),
            "a blind request must not be answered off its channel"
        );
    }

    /// A multicast solicitation carries a channel too, but every node it
    /// selects answers the same frame; targeted unicast replies are what keep
    /// one solicitation from filling the channel with them.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn identity_response_to_a_multicast_solicitation_stays_unicast() {
        let mac = FakeMac::new(vec![[0x12; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let channel_key = umsh_core::ChannelKey([0x5A; 32]);
        let channel_id = umsh_core::ChannelId([0xC1, 0xD2]);
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint(&our_key.hint())
            .unwrap()
            .build();
        let packet = test_channel_packet(
            requester,
            umsh_core::PacketType::Multicast,
            &channel_key,
            channel_id,
            &[],
        );

        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 0)
            .expect("responder should produce a reply plan");
        block_on_ready(node.send_identity_response(plan));

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].channel, None);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_answers_broadcast_solicitation_with_delayed_full_source_reply() {
        let mac = FakeMac::new(vec![[0x12; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let options = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(0x0000_BEEF)
            .unwrap()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();
        let packet = test_broadcast_packet(requester, None, None);

        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 0)
            .expect("selected broadcast solicitation produces a plan");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        let reply = &unicasts[0];
        assert_eq!(reply.to, requester);
        // A broadcast is unauthenticated, so the requester may lack our key.
        assert!(reply.options.full_source);
        // The reply is held for a random slice of the 30-second window so the
        // selected nodes do not all answer the same frame at once.
        let delay = reply
            .options
            .tx_delay_ms
            .expect("broadcast replies are jittered");
        assert!((500..=30_000).contains(&delay));
        // No FILTER_NODE_HINT narrowed the solicitation, so the reply stays
        // inside the one hop the request was allowed: no FHOPS field.
        assert_eq!(reply.options.flood_hops, None);
    }

    /// A `FILTER_NODE_HINT` names one answering node, so the solicitation may
    /// be flood routed and the reply keeps its normal flood budget.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_answers_flood_routed_hint_filtered_solicitation() {
        let mac = FakeMac::new(vec![[0x12; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint(&our_key.hint())
            .unwrap()
            .build();
        // FHOPS_REM=2, FHOPS_ACC=1: repeated once, two hops of budget left.
        let repeated = test_broadcast_packet(requester, Some(0x21), None);

        let plan = node
            .evaluate_identity_request(&repeated, requester, &options, 0)
            .expect("a hint-filtered solicitation may be flood routed");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        assert!(
            unicasts[0].options.flood_hops.is_some(),
            "the reply may be flooded back to a requester that named us"
        );
        assert_eq!(
            unicasts[0].options.tx_delay_ms, None,
            "a whole hint names one node, so the reply goes out at once"
        );
    }

    /// A one-byte prefix keeps the hold: it selects a 256th of everything the
    /// request reaches, and a hint-filtered request may be flood routed, so
    /// that fraction is of the whole mesh rather than one neighborhood.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_holds_a_reply_to_a_one_byte_hint_prefix() {
        let mac = FakeMac::new(vec![[0x12; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint_prefix(&our_key.hint().0[..1])
            .unwrap()
            .build();
        let packet = test_broadcast_packet(requester, None, None);

        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 0)
            .expect("a one-byte prefix still selects the nodes it covers");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        let delay = unicasts[0]
            .options
            .tx_delay_ms
            .expect("a prefix this short may select a crowd, which is held");
        assert!((500..=30_000).contains(&delay));
    }

    /// The shape that identifies an intermediate hop: the requester knows only
    /// the two-byte router hint a route named it by, steers the ask to the hop
    /// before it so it arrives with an empty Route option, and gets an answer
    /// back down the trace the request accumulated on the way.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_answers_a_router_hint_prefix_and_replies_down_the_trace() {
        let mac = FakeMac::new(vec![[0x12; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        // Two bytes of our own hint — everything a route reveals about us.
        let router_hint = &our_key.hint().0[..2];
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint_prefix(router_hint)
            .unwrap()
            .build();
        // Steered here, so the Route option arrived emptied, and traced, so
        // the repeater that carried it prepended its own hint.
        let steered =
            test_broadcast_packet_with_trace(requester, Some(0x00), Some(&[]), Some(&[0x12, 0x34]));

        let plan = node
            .evaluate_identity_request(&steered, requester, &options, 0)
            .expect("a router-hint prefix selects the node it names");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        assert_eq!(
            unicasts[0].options.source_route.as_deref(),
            Some([umsh_core::RouterHint([0x12, 0x34])].as_slice()),
            "the reply retraces the path the question came by"
        );
        assert_eq!(
            unicasts[0].options.tx_delay_ms, None,
            "two bytes name one node, so there is no crowd of replies to spread"
        );

        // A hint that is a prefix of somebody else's is not a prefix of ours.
        let stranger = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint_prefix(&[router_hint[0], router_hint[1] ^ 0xFF])
            .unwrap()
            .build();
        assert!(
            node.evaluate_identity_request(&steered, requester, &stranger, 0)
                .is_none(),
            "a prefix naming another router selects nobody here"
        );
    }

    /// One solicitation gets one reply, however many copies of it arrive.
    ///
    /// A request is unauthenticated and carries no frame counter, so nothing
    /// below the node layer can recognize a repeat of one; a repeater that
    /// carried a copy it should have left alone used to buy the requester an
    /// extra reply from every node in earshot.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_answers_one_solicitation_once() {
        let mac = FakeMac::new(vec![[0x12; 32], [0x13; 32], [0x14; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let options = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(0x0000_BEEF)
            .unwrap()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();
        let packet = test_broadcast_packet(requester, None, None);

        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 1_000)
            .expect("the first copy is answered");
        block_on_ready(node.send_identity_response(plan));

        // A second copy arriving while the first reply is still held in the
        // transmit queue, and a third once it has aired.
        assert!(
            node.evaluate_identity_request(&packet, requester, &options, 3_000)
                .is_none(),
            "a copy arriving mid-hold must not queue a second reply"
        );
        assert!(
            node.evaluate_identity_request(&packet, requester, &options, 45_000)
                .is_none(),
            "nor one arriving after the first reply aired"
        );
        assert_eq!(mac.take_unicasts().len(), 1, "exactly one reply");

        // A fresh nonce is the requester asking again, and is answered.
        let asked_again = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(0x0000_F00D)
            .unwrap()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();
        let plan = node
            .evaluate_identity_request(&packet, requester, &asked_again, 46_000)
            .expect("a new solicitation is a new question");
        block_on_ready(node.send_identity_response(plan));
        assert_eq!(mac.take_unicasts().len(), 1);

        // So is the same nonce once the suppression window has passed.
        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 200_000)
            .expect("suppression is a window, not a permanent refusal");
        block_on_ready(node.send_identity_response(plan));
        assert_eq!(mac.take_unicasts().len(), 1);
    }

    /// Suppression names a solicitation, not a peer: two requesters asking at
    /// once both get an answer.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_answers_every_requester_that_asks() {
        let mac = FakeMac::new(vec![[0x12; 32], [0x13; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        let options = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(0x0000_BEEF)
            .unwrap()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();

        // Same nonce, different askers — a nonce is only unique to its sender.
        for requester in [PublicKey([0x41; 32]), PublicKey([0x42; 32])] {
            let packet = test_broadcast_packet(requester, None, None);
            let plan = node
                .evaluate_identity_request(&packet, requester, &options, 1_000)
                .expect("each requester is owed an answer");
            block_on_ready(node.send_identity_response(plan));
        }
        assert_eq!(mac.take_unicasts().len(), 2);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_drops_repeated_or_routed_broadcast_solicitations() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();

        // A nonzero FHOPS byte marks a request that was flood routed, and no
        // FILTER_NODE_HINT narrows this one to a single answering node.
        let repeated = test_broadcast_packet(requester, Some(0x21), None);
        assert!(
            node.evaluate_identity_request(&repeated, requester, &options, 0)
                .is_none()
        );

        // A non-empty Route option is a steered request. That holds whatever
        // the filters say, so check it with a hint filter too.
        let routed = test_broadcast_packet(requester, None, Some(&[0xAB, 0xCD]));
        assert!(
            node.evaluate_identity_request(&routed, requester, &options, 0)
                .is_none()
        );
        let hint_options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint(&our_key.hint())
            .unwrap()
            .build();
        assert!(
            node.evaluate_identity_request(&routed, requester, &hint_options, 0)
                .is_none()
        );

        // A zeroed FHOPS byte and a present-but-empty Route option are fine.
        let clean = test_broadcast_packet(requester, Some(0x00), Some(&[]));
        assert!(
            node.evaluate_identity_request(&clean, requester, &options, 0)
                .is_some()
        );
    }

    /// A steered solicitation arrives with its Route option emptied by the
    /// repeaters that spent it and a trace route they filled in on the way.
    /// That trace is the requester's only path home — the reply carries no
    /// flood budget, and receiving a broadcast teaches the MAC no route — so
    /// the reply must go back down it, copied verbatim rather than reversed.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_routes_its_reply_back_down_the_requests_trace() {
        let mac = FakeMac::new(vec![[0x00; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();

        // Two repeaters carried it: each consumed its own hint from the Route
        // option, leaving it empty, and prepended itself to the trace.
        let steered = test_broadcast_packet_with_trace(
            requester,
            Some(0x00),
            Some(&[]),
            Some(&[0x12, 0x34, 0xAB, 0xCD]),
        );
        let plan = node
            .evaluate_identity_request(&steered, requester, &options, 0)
            .expect("an emptied route is an arrived request, and we answer it");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        let reply = &unicasts[0];
        let route = reply
            .options
            .source_route
            .as_ref()
            .expect("the reply is steered back");
        // Same order as the trace: repeaters prepend, so an accumulated trace
        // already reads as the path back.
        assert_eq!(
            route.as_slice(),
            &[
                umsh_core::RouterHint([0x12, 0x34]),
                umsh_core::RouterHint([0xAB, 0xCD])
            ]
        );
        // And still no flood budget: routing it home must not also license
        // every repeater that hears it to flood it onward.
        assert_eq!(reply.options.flood_hops, None);
    }

    /// The ordinary in-range case is unchanged: no trace in, no route out,
    /// and above all no empty Route option on the wire.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_leaves_an_untraced_reply_unrouted() {
        let mac = FakeMac::new(vec![[0x00; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();

        let direct = test_broadcast_packet(requester, None, None);
        let plan = node
            .evaluate_identity_request(&direct, requester, &options, 0)
            .expect("a zero-hop solicitation is answered");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        assert!(unicasts[0].options.source_route.is_none());
        assert_eq!(unicasts[0].options.flood_hops, None);
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_ignores_request_that_filters_exclude() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        // Filter targets a different hint → we are not selected.
        let other_hint = PublicKey([0x99; 32]).hint();
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint(&other_hint)
            .unwrap()
            .build();
        let packet = test_unicast_packet(PublicKey([0x41; 32]), &[]);

        assert!(
            node.evaluate_identity_request(&packet, PublicKey([0x41; 32]), &options, 0)
                .is_none()
        );
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_respects_ignore_policy() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        node.enable_identity_responder(test_profile(our_key), |_ctx| {
            crate::RespondDecision::Ignore
        });

        // No filters → selects everyone, so only the policy can decline.
        let options = crate::mac_command::IdentityRequestBuilder::new().build();
        let packet = test_unicast_packet(PublicKey([0x41; 32]), &[]);

        assert!(
            node.evaluate_identity_request(&packet, PublicKey([0x41; 32]), &options, 0)
                .is_none()
        );
    }

    /// Advertisements are built from the installed profile, so a node that
    /// has opted out of being discovered must still be able to read it back.
    /// Silencing the responder with a policy rather than uninstalling it is
    /// what keeps the two independent.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn never_respond_policy_keeps_the_profile_readable() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        node.enable_identity_responder(test_profile(our_key), crate::never_respond_policy);

        let options = crate::mac_command::IdentityRequestBuilder::new().build();
        let packet = test_unicast_packet(PublicKey([0x41; 32]), &[]);
        assert!(
            node.evaluate_identity_request(&packet, PublicKey([0x41; 32]), &options, 0)
                .is_none(),
            "a silenced responder answers nothing"
        );
        assert_eq!(
            node.with_identity_profile(|profile| profile.public_key),
            Some(our_key),
            "yet the profile an advertisement is built from is still there"
        );
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn responder_disabled_yields_no_plan() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        let options = crate::mac_command::IdentityRequestBuilder::new().build();
        let packet = test_unicast_packet(PublicKey([0x41; 32]), &[]);
        assert!(
            node.evaluate_identity_request(&packet, PublicKey([0x41; 32]), &options, 0)
                .is_none()
        );
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn default_policy_full_source_tracks_authentication() {
        use crate::identity_responder::{IdentityRequestContext, default_respond_policy};
        use crate::mac_command::IdentityRequestFilters;

        let base = |source_authenticated: bool| IdentityRequestContext {
            from_key: PublicKey([0x41; 32]),
            from_hint: None,
            source_authenticated,
            has_full_source: false,
            channel: None,
            family: crate::PacketFamily::Unicast,
            filters: IdentityRequestFilters::new(&[]),
            rssi: None,
            snr: None,
            trace_route: &[],
        };

        // Authenticated request → sender already holds our key → hint reply.
        assert_eq!(
            default_respond_policy(&base(true)),
            crate::RespondDecision::Respond { full_source: false }
        );
        // Unauthenticated request → sender may lack our key → include it.
        assert_eq!(
            default_respond_policy(&base(false)),
            crate::RespondDecision::Respond { full_source: true }
        );
    }

    // --- Peer Repeaters responder ---

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn peer_identity(name: &str, regions: &[&str]) -> crate::NodeIdentityPayload {
        crate::NodeIdentityPayload {
            role: crate::NodeRole::Repeater,
            capabilities: crate::NodeCapabilities::REPEATER,
            name: Some(String::from(name)),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: Some(regions.iter().map(|text| String::from(*text)).collect()),
            nonce: None,
            signature: None,
        }
    }

    /// The request options a requester would put on the wire.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn peer_repeaters_request(nonce: Option<u16>, cursor: Option<&[u8]>) -> Vec<u8> {
        let mut builder = crate::mac_command::PeerRepeatersRequestBuilder::new();
        if let Some(nonce) = nonce {
            builder = builder.nonce(nonce).unwrap();
        }
        if let Some(cursor) = cursor {
            builder = builder.cursor(cursor).unwrap();
        }
        builder.build()
    }

    /// Pull the one response the responder sent back off the fake MAC and
    /// reparse it exactly as a receiver would.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    /// The peer-repeater listing names the neighborhood around this node. A
    /// request that arrived concealed on a channel is answered there, not in
    /// the open.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn peer_repeaters_response_follows_a_blind_request_onto_its_channel() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();
        let channel_id = umsh_core::ChannelId([0xC1, 0xD2]);

        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            Some(channel_id),
            &peer_repeaters_request(Some(7), None),
        ));

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].channel, Some(channel_id));
    }

    /// Pull the one response the responder sent back off the fake MAC and
    /// reparse it exactly as a receiver would.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    fn sent_response(mac: &FakeMac) -> (PublicKey, Vec<u8>) {
        let mut unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1, "exactly one response frame");
        let sent = unicasts.remove(0);
        assert_eq!(
            sent.payload[0],
            umsh_core::PayloadType::MacCommand as u8,
            "responses travel as MAC commands"
        );
        let body = match crate::mac_command::parse(&sent.payload[1..]).unwrap() {
            crate::mac_command::MacCommand::PeerRepeatersResponse { body } => body.to_vec(),
            other => panic!("expected a Peer Repeaters Response, got {other:?}"),
        };
        (sent.to, body)
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn a_disabled_responder_answers_nothing() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.observe_peer_identity(PublicKey([0xAA; 32]), &peer_identity("Ridge", &[]), 0);

        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            None,
            &peer_repeaters_request(None, None),
        ));
        assert!(mac.take_unicasts().is_empty());
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn a_response_echoes_the_nonce_and_reports_what_both_sources_know() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();

        let peer = PublicKey([0xAA; 32]);
        node.observe_peer_identity(peer, &peer_identity("Ridge", &["SJC", "0x1234"]), 0);
        // The same peer heard on the air: only this supplies signal.
        mac.observe(
            umsh_core::RouterHint([peer.0[0], peer.0[1]]),
            -95,
            umsh_hal::Snr::from_decibels(2),
        );
        // A hop nothing has an identity for still names itself in a trace.
        mac.observe(
            umsh_core::RouterHint([0x11, 0x22]),
            -70,
            umsh_hal::Snr::from_decibels(-4),
        );

        let requester = PublicKey([0x41; 32]);
        block_on_ready(node.answer_peer_repeaters_request(
            requester,
            None,
            &peer_repeaters_request(Some(0xBEEF), None),
        ));

        let (to, body) = sent_response(&mac);
        assert_eq!(to, requester);
        let view = crate::mac_command::PeerRepeatersResponseView::new(&body);
        assert_eq!(view.nonce(), Some(0xBEEF), "request nonce echoed");
        assert_eq!(view.total(), Some(2));
        assert_eq!(view.cursor(), None, "one page held everything");

        let entries: Vec<_> = view.entries().collect();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].hint(), Some(&peer.hint().0[..]));
        assert_eq!(entries[0].name(), Some("Ridge"));
        let (rssi, snr) = entries[0].rssi_snr().unwrap();
        assert_eq!(rssi, -95);
        assert_eq!(snr, umsh_hal::Snr::from_decibels(2));
        assert_eq!(
            entries[0].regions().collect::<Vec<_>>(),
            vec![[0x78, 0x53], [0x12, 0x34]],
            "the identity's region strings arrive as derived codes"
        );

        assert_eq!(
            entries[1].hint(),
            Some(&[0x11, 0x22][..]),
            "an unclaimed observation is named by its router hint alone"
        );
        assert_eq!(entries[1].name(), None);
        assert_eq!(entries[1].rssi_snr().unwrap().0, -70);
        assert!(entries[1].regions().next().is_none());
    }

    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn a_full_table_pages_and_the_cursor_resumes_where_it_stopped() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();

        // Long names, so the entries are large enough that one page cannot
        // hold the whole table.
        for seed in 0..crate::peer_repeaters::MAX_PEER_REPEATERS as u8 {
            node.observe_peer_identity(
                PublicKey([seed; 32]),
                &peer_identity(&format!("Repeater number {seed:08}"), &["Rogue Valley"]),
                0,
            );
        }

        let requester = PublicKey([0x41; 32]);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        let mut pages = 0;
        loop {
            block_on_ready(node.answer_peer_repeaters_request(
                requester,
                None,
                &peer_repeaters_request(Some(1), cursor.as_deref()),
            ));
            let (_, body) = sent_response(&mac);
            let view = crate::mac_command::PeerRepeatersResponseView::new(&body);
            assert_eq!(
                view.total(),
                Some(crate::peer_repeaters::MAX_PEER_REPEATERS as u8),
                "every page reports the whole listing's size"
            );
            seen.extend(
                view.entries()
                    .filter_map(|entry| entry.hint().map(Vec::from)),
            );
            pages += 1;
            assert!(pages < 10, "paging should terminate");
            match view.cursor() {
                Some(next) => cursor = Some(next.to_vec()),
                None => break,
            }
        }

        assert!(pages > 1, "the table did not fit one page");
        assert_eq!(seen.len(), crate::peer_repeaters::MAX_PEER_REPEATERS);
        for seed in 0..crate::peer_repeaters::MAX_PEER_REPEATERS as u8 {
            assert!(
                seen.contains(&Vec::from(&PublicKey([seed; 32]).hint().0[..])),
                "every repeater was listed exactly once across the pages"
            );
        }
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            seen.len(),
            "no entry was repeated across pages"
        );
    }

    /// A cursor names a place in a listing. If the listing has changed since,
    /// resuming into it would skip or repeat peers, so the walk restarts.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn a_cursor_from_a_changed_listing_restarts_the_walk() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();
        for seed in 0..3u8 {
            node.observe_peer_identity(PublicKey([seed; 32]), &peer_identity("Peer", &[]), 0);
        }

        // A cursor whose generation matches resumes; index 2 leaves one entry.
        let generation = 3u16.to_be_bytes();
        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            None,
            &peer_repeaters_request(None, Some(&[generation[0], generation[1], 2])),
        ));
        let (_, body) = sent_response(&mac);
        let view = crate::mac_command::PeerRepeatersResponseView::new(&body);
        assert_eq!(view.entries().count(), 1, "resumed at the third entry");

        // One more identity moves the generation on, and the same cursor is
        // now stale.
        node.observe_peer_identity(PublicKey([0x77; 32]), &peer_identity("Newcomer", &[]), 0);
        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            None,
            &peer_repeaters_request(None, Some(&[generation[0], generation[1], 2])),
        ));
        let (_, body) = sent_response(&mac);
        let view = crate::mac_command::PeerRepeatersResponseView::new(&body);
        assert_eq!(
            view.entries().count(),
            4,
            "the stale cursor restarted the walk"
        );
    }

    /// The listing is the answer even when it is empty — a repeater that
    /// knows of nobody says so rather than staying silent.
    #[cfg(all(feature = "software-crypto", feature = "unsafe-advanced"))]
    #[test]
    fn an_empty_neighborhood_still_answers() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();

        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            None,
            &peer_repeaters_request(None, None),
        ));
        let (_, body) = sent_response(&mac);
        let view = crate::mac_command::PeerRepeatersResponseView::new(&body);
        assert_eq!(view.total(), Some(0));
        assert_eq!(view.entries().count(), 0);
        assert_eq!(view.cursor(), None);
    }
}
