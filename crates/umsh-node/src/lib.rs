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
//! - [`Host`]—preferred multi-identity driver. Owns the shared MAC event loop and routes
//!   inbound traffic to the right [`LocalNode`].
//! - [`LocalNode`]—per-identity application handle. Implements [`Transport`] (unicast /
//!   broadcast), owns PFS state, and exposes raw packet plus control-side subscriptions.
//! - [`BoundChannel`]—a channel bound to a `LocalNode`. Implements [`Transport`]
//!   (blind unicast / multicast). Available with the `software-crypto` feature.
//! - [`PeerConnection`]—relationship with one remote peer, generic over transport context,
//!   with peer-scoped callback subscriptions.
//! - [`Transport`]—shared send interface (`send` / `send_all`).
//! - [`SendProgressTicket`]—lightweight polling handle for observing in-flight send
//!   progress (`was_transmitted`, `was_acked`, `is_finished`).
//! - [`Subscription`]—owned callback registration that auto-unsubscribes on drop.
//! - [`ReceivedPacketRef`]—borrowed receive view passed into low-level `on_receive(...)`
//!   handlers and wrappers, including local RX observations such as RSSI, SNR, LQI, and
//!   receive timestamp.
//! - [`MacBackend`]—pluggable MAC backend trait for testability.
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
#[cfg(feature = "software-crypto")]
pub mod meet;
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
pub use host::{Host, HostError, IdentityUpdate, identity_is_trustworthy};
pub use identity::{IdentitySignature, NodeCapabilities, NodeIdentityPayload, NodeRole, forwards};
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
pub use node::{IdentityFilter, LocalNode, NodeError, PfsFailure, PongMetadata, Subscription};
pub use peer::{PING_MIC_SIZE, PeerConnection};
pub use peer_repeaters::{
    MAX_PEER_REPEATERS, MergedPeerRepeater, PeerRepeaterRecord, PeerRepeaterTable,
};
pub use receive::{
    ChannelInfoRef, PacketFamily, ReceivedPacketRef, RepeaterHints, RxAcceptance, RxMetadata,
    SignatureStatus, Snr,
};
pub use ticket::{MAX_TALLIED_REPEATERS, RepeatTally, SendProgressTicket, SendToken};
pub use transport::Transport;

#[cfg(test)]
mod tests {
    #[cfg(feature = "software-crypto")]
    use std::{
        cell::RefCell,
        collections::VecDeque,
        future::Future,
        num::NonZeroU8,
        pin::pin,
        rc::Rc,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };
    #[cfg(feature = "software-crypto")]
    use umsh_core::{NodeHint, PublicKey};
    #[cfg(feature = "software-crypto")]
    use umsh_crypto::NodeIdentity;
    #[cfg(feature = "software-crypto")]
    use umsh_crypto::software::SoftwareIdentity;
    #[cfg(feature = "software-crypto")]
    use umsh_hal::Snr;
    #[cfg(feature = "software-crypto")]
    use umsh_mac::MacEventRef;
    #[cfg(feature = "software-crypto")]
    use umsh_mac::{
        CapacityError, LocalIdentityId, PeerHolder, PeerId, SendError, SendOptions, SendReceipt,
    };

    #[cfg(feature = "software-crypto")]
    use crate::ReceivedPacketRef;
    #[cfg(feature = "software-crypto")]
    use crate::{MacBackend, MacBackendError, OwnedMacCommand, SendToken};
    #[cfg(feature = "software-crypto")]
    use umsh_core::ChannelKey;
    #[cfg(feature = "software-crypto")]
    use umsh_text::OwnedTextMessage;
    #[cfg(feature = "software-crypto")]
    #[test]
    fn peer_receive_handlers_precede_node_receive_handlers() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac,
            dispatcher,
            membership,
            Rc::default(),
            state,
        );
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

    #[cfg(feature = "software-crypto")]
    fn test_node(mac: FakeMac) -> crate::node::LocalNode<FakeMac> {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        LocalNode::new(
            LocalIdentityId(1),
            mac,
            Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new())),
            Rc::new(RefCell::new(NodeMembership::new())),
            Rc::default(),
            Rc::new(RefCell::new(LocalNodeState::new())),
        )
    }

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_channel_stays_registered_until_its_last_node_leaves() {
        let mac = FakeMac::new(Vec::new());
        let mut host = crate::Host::new(mac.clone());
        let first = host.add_node(LocalIdentityId(1));
        let second = host.add_node(LocalIdentityId(2));
        let channel = crate::Channel::private(umsh_core::ChannelKey([0x55; 32]), "shared");

        block_on_ready(first.join(&channel)).unwrap();
        let bound = block_on_ready(second.join(&channel)).unwrap();

        block_on_ready(first.leave(&channel)).unwrap();
        assert!(mac.holds_channel(channel.key()));
        assert!(bound.is_active());

        // Leaving twice does not count as a second member leaving.
        block_on_ready(first.leave(&channel)).unwrap();
        assert!(mac.holds_channel(channel.key()));

        block_on_ready(second.leave(&channel)).unwrap();
        assert!(!mac.holds_channel(channel.key()));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn receive_callbacks_can_observe_rx_metadata() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac,
            dispatcher,
            membership,
            Rc::default(),
            state,
        );
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

    #[cfg(feature = "software-crypto")]
    #[test]
    fn subscription_guard_unregisters_on_drop() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac,
            dispatcher,
            membership,
            Rc::default(),
            state,
        );
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

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_handler_may_unsubscribe_itself_subscribe_another_and_reach_the_node() {
        let node = test_node(FakeMac::new(Vec::new()));
        let peer = PublicKey([0x55; 32]);
        let calls = Rc::new(RefCell::new(Vec::new()));
        let own = Rc::new(RefCell::new(None::<crate::Subscription>));
        let added = Rc::new(RefCell::new(None::<crate::Subscription>));

        let first = {
            let node = node.clone();
            let calls = calls.clone();
            let own = own.clone();
            let added = added.clone();
            node.clone().on_receive(move |_| {
                calls.borrow_mut().push("first");
                assert!(own.borrow_mut().take().unwrap().unsubscribe());
                let calls = calls.clone();
                *added.borrow_mut() = Some(node.on_receive(move |_| {
                    calls.borrow_mut().push("second");
                    true
                }));
                block_on_ready(node.peer(peer)).unwrap();
                true
            })
        };
        *own.borrow_mut() = Some(first);

        // The handler added during dispatch waits for the next packet.
        assert!(node.dispatch_received_packet(&test_unicast_packet(peer, &[0x01])));
        assert_eq!(calls.borrow().as_slice(), ["first"]);

        assert!(node.dispatch_received_packet(&test_unicast_packet(peer, &[0x02])));
        assert_eq!(calls.borrow().as_slice(), ["first", "second"]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_handler_unsubscribed_by_an_earlier_one_is_not_called() {
        let node = test_node(FakeMac::new(Vec::new()));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let later = Rc::new(RefCell::new(None::<crate::Subscription>));

        let _first = {
            let calls = calls.clone();
            let later = later.clone();
            node.on_beacon(move |_, _| {
                calls.borrow_mut().push("first");
                drop(later.borrow_mut().take());
            })
        };
        *later.borrow_mut() = Some({
            let calls = calls.clone();
            node.on_beacon(move |_, _| calls.borrow_mut().push("later"))
        });

        node.dispatch_beacon(NodeHint([1, 2, 3]), None);
        assert_eq!(calls.borrow().as_slice(), ["first"]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn callbacks_observe_control_side_events_and_peer_ack_state() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(Vec::new());
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac,
            dispatcher,
            membership,
            Rc::default(),
            state,
        );

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
    #[cfg(feature = "software-crypto")]
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
            Rc::default(),
            Rc::new(RefCell::new(LocalNodeState::new())),
        );
        let peer_connection = block_on_ready(node.peer(PublicKey([0x55; 32]))).unwrap();

        let options = SendOptions::default()
            .with_mic_size(MicSize::Mic4)
            .with_ack_requested(true)
            .with_trace()
            .with_flood_hops(3)
            .with_region_code([0x78, 0x53]);
        block_on_ready(peer_connection.ping(6, &options, 1_000)).unwrap();

        let sent = mac.take_unicasts().pop().expect("ping send");
        assert_eq!(sent.options.mic_size, MicSize::Mic4);
        assert!(sent.options.trace);
        assert_eq!(sent.options.flood_hops, Some(3));
        assert_eq!(sent.options.region_code, Some([0x78, 0x53]));
        assert!(!sent.options.ack_requested, "the echo response is the ack");

        // `no_flood` is a distinct state from an unset budget and must also
        // survive, rather than collapsing back to the wide default.
        block_on_ready(peer_connection.ping(0, &SendOptions::default().no_flood(), 1_000)).unwrap();
        let sent = mac.take_unicasts().pop().expect("ping send");
        assert_eq!(sent.options.flood_hops, None);
    }

    /// A ping the MAC refused to send is not waited for: its caller has the
    /// error, and it never times out.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn unsent_ping_never_times_out() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let peer_connection = block_on_ready(node.peer(PublicKey([0x55; 32]))).unwrap();
        let timeouts = Rc::new(RefCell::new(0u32));
        let counted = timeouts.clone();
        let _subscription = node.on_ping_timeout(move |_| *counted.borrow_mut() += 1);

        mac.state.borrow_mut().refuse_sends = true;
        assert!(
            block_on_ready(peer_connection.ping(0, &SendOptions::default(), u64::MAX)).is_err()
        );
        node.expire_pings(u64::MAX);

        assert_eq!(*timeouts.borrow(), 0);
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
    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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
            Some(*channel.key()),
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

    /// A new ping to a peer cancels the one still waiting: the old one's
    /// echo is ignored and its deadline never fires, while the new one is
    /// answered and timed on its own.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_new_ping_cancels_the_one_still_waiting() {
        let mac = FakeMac::new(vec![[7u8; 32], [9u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let peer_connection = block_on_ready(node.peer(peer)).unwrap();
        let pongs = Rc::new(RefCell::new(Vec::new()));
        let timeouts = Rc::new(RefCell::new(0));
        let pong_log = pongs.clone();
        let timeout_log = timeouts.clone();
        let _pong_subscription = node.on_pong(move |_, rtt_ms| pong_log.borrow_mut().push(rtt_ms));
        let _timeout_subscription = node.on_ping_timeout(move |_| *timeout_log.borrow_mut() += 1);
        let nonce_of = |mac: &FakeMac| match parse_owned_mac_command(
            &mac.take_unicasts().pop().unwrap().payload,
        ) {
            OwnedMacCommand::EchoRequest { data } => [data[0], data[1]],
            other => panic!("unexpected ping payload: {other:?}"),
        };

        block_on_ready(peer_connection.ping(4, &SendOptions::default(), 1_000)).unwrap();
        let old = nonce_of(&mac);
        block_on_ready(peer_connection.ping(4, &SendOptions::default(), 1_000)).unwrap();
        let new = nonce_of(&mac);
        let packet = test_broadcast_packet_with_traces(peer, None, None, None);

        node.match_pong(peer, &old, &packet, 250);
        assert!(
            pongs.borrow().is_empty(),
            "the canceled ping's echo is ignored"
        );
        node.match_pong(peer, &new, &packet, 250);
        assert_eq!(pongs.borrow().len(), 1, "the new ping is answered");
        node.expire_pings(10_000);
        assert_eq!(*timeouts.borrow(), 0, "neither ping is left to time out");
    }

    /// A traced reply reports how each repeater heard the hop beyond it,
    /// unless its trace lost the signal in transit.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_pong_reports_the_trace_signal_the_trace_kept() {
        use umsh_core::options::HopSignal;

        for (trace, expected) in [
            (
                &[0xAAu8, 0x01, 97, 65, 0xBB, 0x02, 0, 0][..],
                vec![HopSignal::new(-97, 65), HopSignal::POINT_TO_POINT],
            ),
            (&[0xFEu8, 0xAA, 0x01, 0xBB, 0x02][..], Vec::new()),
        ] {
            let mac = FakeMac::new(vec![[7u8; 32]]);
            let node = test_node(mac.clone());
            let peer = PublicKey([0x55; 32]);
            let peer_connection = block_on_ready(node.peer(peer)).unwrap();
            let seen = Rc::new(RefCell::new(None));
            let log = seen.clone();
            let _subscription = node.on_pong_with_metadata(move |_, pong| {
                *log.borrow_mut() = Some(pong.clone());
            });

            block_on_ready(peer_connection.ping(4, &SendOptions::default(), 1_000)).unwrap();
            let sent = mac.take_unicasts().pop().expect("ping send");
            let nonce = match parse_owned_mac_command(&sent.payload) {
                OwnedMacCommand::EchoRequest { data } => [data[0], data[1]],
                other => panic!("unexpected ping payload: {other:?}"),
            };

            let trace: &'static [u8] = Box::leak(trace.to_vec().into_boxed_slice());
            let packet = test_broadcast_packet_with_traces(peer, None, None, Some(trace));
            node.match_pong(peer, &nonce, &packet, 1_250);

            let pong = seen.borrow_mut().take().expect("pong");
            assert_eq!(pong.route_hints.len(), 2);
            assert_eq!(pong.trace_signal, expected);
            assert!(!pong.trace_truncated);
        }
    }

    #[cfg(feature = "software-crypto")]
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
            Rc::default(),
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
        // A requested session has no address yet: nothing is sent to it
        // until the response names the peer's half.
        assert!(node.pfs_local_keys().is_empty());

        block_on_ready(node.handle_pfs_command(
            &peer,
            frame(),
            &OwnedMacCommand::PfsSessionResponse {
                ephemeral_key: PublicKey([0x44; 32]),
                duration_minutes: 60,
            },
            &options,
        ))
        .unwrap();
        assert_eq!(node.pfs_local_keys(), vec![request_ephemeral]);

        let payload = encode_text_payload("hello over pfs");
        let ticket = block_on_ready(peer_connection.send(&payload, &options)).unwrap();
        let sent = mac.take_unicasts().pop().expect("pfs-routed send");
        assert_eq!(sent.from, LocalIdentityId(10));
        assert_eq!(sent.to, PublicKey([0x44; 32]));

        let pairwise_from_pfs = PublicKey([0x44; 32]);
        dispatcher.borrow_mut().dispatch_ticket_state(
            sent.from,
            &MacEventRef::AckReceived {
                peer: pairwise_from_pfs,
                receipt: SendReceipt(42),
                via_route_retry: false,
            },
        );
        assert!(ticket.was_acked());
        assert!(ticket.is_finished());
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_accepted_session_reports_its_local_address_until_it_ends() {
        use crate::node::{LocalNode, LocalNodeState, NodeMembership};

        let mac = FakeMac::new(vec![[7u8; 32]]);
        let dispatcher = Rc::new(RefCell::new(crate::dispatch::EventDispatcher::new()));
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            LocalIdentityId(1),
            mac.clone(),
            dispatcher,
            membership,
            Rc::default(),
            state,
        );

        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default().with_ack_requested(true);
        block_on_ready(node.peer(peer)).unwrap();
        block_on_ready(node.handle_pfs_command(
            &peer,
            frame(),
            &OwnedMacCommand::PfsSessionRequest {
                ephemeral_key: PublicKey([0x44; 32]),
                duration_minutes: 60,
            },
            &options,
        ))
        .unwrap();
        let response = mac.take_unicasts().pop().expect("response send");
        let local = match parse_owned_mac_command(&response.payload) {
            OwnedMacCommand::PfsSessionResponse { ephemeral_key, .. } => ephemeral_key,
            other => panic!("unexpected response payload: {other:?}"),
        };
        assert_eq!(node.pfs_local_keys(), vec![local]);

        block_on_ready(node.handle_pfs_command(
            &peer,
            frame(),
            &OwnedMacCommand::EndPfsSession,
            &options,
        ))
        .unwrap();
        assert!(node.pfs_local_keys().is_empty());
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_session_manager_request_and_teardown() {
        use crate::{node::LocalNodeState, pfs};

        let mac = FakeMac::new(vec![[3u8; 32]]);
        let peer_long_term = PublicKey([0x55; 32]);
        let options = SendOptions::default().with_ack_requested(true);

        let state = RefCell::new(LocalNodeState::new());
        block_on_ready(pfs::request_session(
            &state,
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
            block_on_ready(pfs::end_session(
                &state,
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

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_end_session_errors_when_missing() {
        use crate::{node::LocalNodeState, pfs};

        let mac = FakeMac::new(Vec::new());
        let options = SendOptions::default();
        let state = RefCell::new(LocalNodeState::new());

        let error = block_on_ready(pfs::end_session(
            &state,
            &mac,
            LocalIdentityId(1),
            &PublicKey([0x77; 32]),
            true,
            &options,
        ))
        .unwrap_err();
        assert!(matches!(error, crate::NodeError::PfsSessionMissing));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_responder_answers_with_a_finite_lifetime() {
        use crate::node::LocalNodeState;
        use crate::pfs::{self, MAX_PFS_SESSION_MINUTES};

        // Zero, which no node may send, and a request past the ceiling both
        // come back as the ceiling; anything else is accepted as asked.
        for (requested, accepted) in [
            (0u16, MAX_PFS_SESSION_MINUTES),
            (MAX_PFS_SESSION_MINUTES + 1, MAX_PFS_SESSION_MINUTES),
            (u16::MAX, MAX_PFS_SESSION_MINUTES),
            (MAX_PFS_SESSION_MINUTES, MAX_PFS_SESSION_MINUTES),
            (45, 45),
        ] {
            let mac = FakeMac::new(vec![[3u8; 32]]);
            let options = SendOptions::default();
            let state = RefCell::new(LocalNodeState::new());
            block_on_ready(mac.add_peer(PublicKey([0x55; 32]))).unwrap();
            block_on_ready(pfs::accept_request(
                &state,
                &mac,
                LocalIdentityId(1),
                PublicKey([0x55; 32]),
                PublicKey([0x44; 32]),
                requested,
                frame(),
                &options,
            ))
            .unwrap();

            let sent = mac.take_unicasts();
            let OwnedMacCommand::PfsSessionResponse {
                duration_minutes, ..
            } = parse_owned_mac_command(&sent[0].payload)
            else {
                panic!("expected a PFS response");
            };
            assert_eq!(duration_minutes, accepted, "requested {requested}");
            assert_eq!(
                state.borrow().pfs.sessions()[0].expires_ms - mac.state.borrow().now_ms,
                u64::from(accepted) * 60_000,
                "requested {requested}"
            );
        }
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_zero_duration_never_means_forever() {
        use crate::node::LocalNodeState;
        use crate::pfs::{self, MAX_PFS_SESSION_MINUTES};

        let mac = FakeMac::new(vec![[3u8; 32]]);
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        let state = RefCell::new(LocalNodeState::new());

        // The initiator never puts 0 on the wire.
        block_on_ready(pfs::request_session(
            &state,
            &mac,
            LocalIdentityId(1),
            &peer,
            0,
            &options,
        ))
        .unwrap();
        let sent = mac.take_unicasts();
        assert!(matches!(
            parse_owned_mac_command(&sent[0].payload),
            OwnedMacCommand::PfsSessionRequest {
                duration_minutes: MAX_PFS_SESSION_MINUTES,
                ..
            }
        ));

        // A response that names 0 anyway still yields a session that ends.
        block_on_ready(pfs::accept_response(
            &state,
            &mac,
            LocalIdentityId(1),
            peer,
            PublicKey([0x44; 32]),
            0,
            frame(),
            &options,
        ))
        .unwrap();
        let expires_ms = state.borrow().pfs.sessions()[0].expires_ms;
        assert_eq!(
            expires_ms - mac.state.borrow().now_ms,
            u64::from(MAX_PFS_SESSION_MINUTES) * 60_000
        );
        assert_eq!(
            block_on_ready(pfs::expire_sessions(&state, &mac, expires_ms)).unwrap(),
            vec![peer]
        );
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_session_ended_during_activation_stays_ended() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();

        // The response is underway when the user ends the session.
        mac.state.borrow_mut().hold_add_peer = true;
        let response = OwnedMacCommand::PfsSessionResponse {
            ephemeral_key: PublicKey([0x44; 32]),
            duration_minutes: 60,
        };
        let mut accepting = pin!(node.handle_pfs_command(&peer, frame(), &response, &options));
        assert!(parks(accepting.as_mut()));
        block_on_ready(node.end_pfs(&peer, &options)).unwrap();
        mac.state.borrow_mut().hold_add_peer = false;

        assert!(block_on_ready(accepting).unwrap().is_none());
        assert!(node.pfs_local_keys().is_empty());
        assert!(matches!(
            block_on_ready(node.pfs_status(&peer)).unwrap(),
            crate::PfsStatus::Inactive
        ));
        assert_eq!(
            mac.state.borrow().removed_ephemerals,
            vec![LocalIdentityId(10)]
        );
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_session_ended_while_answering_gets_no_response() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        block_on_ready(node.peer(peer)).unwrap();

        mac.state.borrow_mut().hold_add_peer = true;
        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([0x44; 32]),
            duration_minutes: 60,
        };
        let mut accepting = pin!(node.handle_pfs_command(&peer, frame(), &request, &options));
        assert!(parks(accepting.as_mut()));
        block_on_ready(node.end_pfs(&peer, &options)).unwrap();
        mac.state.borrow_mut().hold_add_peer = false;

        assert!(block_on_ready(accepting).unwrap().is_none());
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            parse_owned_mac_command(&sent[0].payload),
            OwnedMacCommand::EndPfsSession
        );
        assert!(node.pfs_local_keys().is_empty());
        assert_eq!(
            mac.state.borrow().removed_ephemerals,
            vec![LocalIdentityId(10)]
        );
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_session_being_answered_holds_its_place_in_the_table() {
        let mac = FakeMac::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]]);
        let node = test_node(mac.clone());
        let options = SendOptions::default();
        for peer in 1..=3 {
            block_on_ready(node.request_pfs(&PublicKey([peer; 32]), 60, &options)).unwrap();
        }

        let answered = PublicKey([0x44; 32]);
        block_on_ready(node.peer(answered)).unwrap();
        mac.state.borrow_mut().hold_add_peer = true;
        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([0x45; 32]),
            duration_minutes: 60,
        };
        let mut accepting = pin!(node.handle_pfs_command(&answered, frame(), &request, &options));
        assert!(parks(accepting.as_mut()));

        let refused = block_on_ready(node.request_pfs(&PublicKey([9; 32]), 60, &options));
        assert!(matches!(
            refused,
            Err(crate::NodeError::PfsSessionTableFull)
        ));

        mac.state.borrow_mut().hold_add_peer = false;
        assert!(block_on_ready(accepting).unwrap().is_some());
        assert_eq!(node.state().borrow().pfs.sessions().len(), 4);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_repeated_request_replaces_the_session_and_its_identity() {
        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        let request = |key: u8| OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([key; 32]),
            duration_minutes: 60,
        };

        block_on_ready(node.peer(peer)).unwrap();

        block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x44), &options)).unwrap();
        let first = node.pfs_local_keys();
        mac.state.borrow_mut().now_ms += 60_000;
        block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x45), &options)).unwrap();

        assert_eq!(node.pfs_local_keys().len(), 1);
        assert_ne!(node.pfs_local_keys(), first);
        assert_eq!(
            mac.state.borrow().removed_ephemerals,
            vec![LocalIdentityId(10)]
        );
        // The replaced session's peer slot went with it.
        let peers: Vec<PublicKey> = mac.state.borrow().peers.iter().map(|(k, _)| *k).collect();
        assert_eq!(peers, vec![peer, PublicKey([0x45; 32])]);
    }

    /// A repeat of the request that opened the session, under the same
    /// ephemeral key, gets the response it got before, on the carriage the
    /// repeat came on, and opens nothing.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_repeated_request_under_the_same_key_gets_the_same_response() {
        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let channel = ChannelKey([0x33; 32]);
        let options = SendOptions::default();
        let request = |duration_minutes| OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([0x44; 32]),
            duration_minutes,
        };
        block_on_ready(node.peer(peer)).unwrap();

        block_on_ready(node.handle_pfs_command(&peer, frame(), &request(45), &options)).unwrap();
        let first = node.pfs_local_keys();
        let answered = mac.take_unicasts();
        // Inside the rate limit's window, and asking for another lifetime.
        let repeat = block_on_ready(node.handle_pfs_command(
            &peer,
            on_channel(channel),
            &request(90),
            &options,
        ));

        assert!(repeat.unwrap().is_none());
        let again = mac.take_unicasts();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].payload, answered[0].payload);
        assert_eq!(again[0].channel, Some(channel));
        assert_eq!(node.pfs_local_keys(), first);
        assert_eq!(node.state().borrow().pfs.sessions().len(), 1);
        assert!(mac.state.borrow().removed_ephemerals.is_empty());
        assert_eq!(node.pfs_refused_ephemeral_keys(), 0);
        assert_eq!(node.pfs_rate_limited_requests(), 0);
    }

    /// Only a contact may open a session: a stranger, or a peer the MAC
    /// learned without the application adding it, is refused and counted.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_request_from_a_peer_that_is_not_a_contact_is_refused() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let options = SendOptions::default();
        let stranger = PublicKey([0x55; 32]);
        let learned = PublicKey([0x56; 32]);
        block_on_ready(mac.ensure_transient_peer(&learned));
        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([0x44; 32]),
            duration_minutes: 60,
        };

        for requester in [&stranger, &learned] {
            let answered =
                block_on_ready(node.handle_pfs_command(requester, frame(), &request, &options));
            assert!(answered.unwrap().is_none());
        }

        assert!(mac.take_unicasts().is_empty());
        assert!(node.state().borrow().pfs.sessions().is_empty());
        assert_eq!(node.pfs_refused_requesters(), 2);
        let peers: Vec<PublicKey> = mac.state.borrow().peers.iter().map(|(k, _)| *k).collect();
        assert_eq!(peers, vec![learned]);
    }

    /// A contact opens at most one session a minute: a further request is
    /// refused and counted, and leaves the standing session in place.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_requests_from_one_peer_are_limited_to_one_a_minute() {
        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32], [9u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let other = PublicKey([0x66; 32]);
        let options = SendOptions::default();
        let request = |key: u8| OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([key; 32]),
            duration_minutes: 60,
        };
        block_on_ready(node.peer(peer)).unwrap();
        block_on_ready(node.peer(other)).unwrap();

        let opened =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x44), &options));
        assert!(opened.unwrap().is_some());
        let first = node.pfs_local_keys();
        mac.take_unicasts();

        mac.state.borrow_mut().now_ms += 59_999;
        let early =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x45), &options));
        assert!(early.unwrap().is_none());
        assert!(mac.take_unicasts().is_empty());
        assert_eq!(node.pfs_local_keys(), first);
        assert_eq!(node.pfs_rate_limited_requests(), 1);

        // Another peer has its own window.
        let theirs =
            block_on_ready(node.handle_pfs_command(&other, frame(), &request(0x46), &options));
        assert!(theirs.unwrap().is_some());

        mac.state.borrow_mut().now_ms += 1;
        let later =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x47), &options));
        assert!(later.unwrap().is_some());
        assert_eq!(node.pfs_rate_limited_requests(), 1);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_sessions_give_back_their_peer_slots() {
        let random_blocks = (1..=20u8).map(|n| [n; 32]).collect();
        let mac = FakeMac::new(random_blocks);
        let node = test_node(mac.clone());
        let options = SendOptions::default();
        block_on_ready(node.peer(PublicKey([0xC0; 32]))).unwrap();
        for n in 0..20u8 {
            block_on_ready(node.peer(PublicKey([0x80 + n; 32]))).unwrap();
        }
        let registered = mac.state.borrow().peers.len();

        for n in 0..20u8 {
            let peer = PublicKey([0x80 + n; 32]);
            let peer_ephemeral = PublicKey([0x20 + n; 32]);
            if n % 2 == 0 {
                // Answered: the peer asks, and later ends it.
                let request = OwnedMacCommand::PfsSessionRequest {
                    ephemeral_key: peer_ephemeral,
                    duration_minutes: 60,
                };
                let opened =
                    block_on_ready(node.handle_pfs_command(&peer, frame(), &request, &options));
                assert!(opened.unwrap().is_some());
                assert_eq!(mac.state.borrow().peers.len(), registered + 1);
                let end = OwnedMacCommand::EndPfsSession;
                block_on_ready(node.handle_pfs_command(&peer, frame(), &end, &options)).unwrap();
            } else {
                // Requested: this node asks, and later ends it.
                block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
                let response = OwnedMacCommand::PfsSessionResponse {
                    ephemeral_key: peer_ephemeral,
                    duration_minutes: 60,
                };
                let opened =
                    block_on_ready(node.handle_pfs_command(&peer, frame(), &response, &options));
                assert!(opened.unwrap().is_some());
                assert_eq!(mac.state.borrow().peers.len(), registered + 1);
                block_on_ready(node.end_pfs(&peer, &options)).unwrap();
            }
            assert_eq!(mac.state.borrow().peers.len(), registered, "session {n}");
        }
        assert!(node.state().borrow().pfs.sessions().is_empty());
        assert_eq!(mac.state.borrow().removed_ephemerals.len(), 20);
    }

    /// A contact the application adds under a session's peer ephemeral key
    /// while the session lasts is still a contact once the session ends.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_session_end_keeps_a_contact_added_under_its_key() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let options = SendOptions::default();
        let peer = PublicKey([0x55; 32]);
        let peer_ephemeral = PublicKey([0x44; 32]);
        block_on_ready(node.peer(peer)).unwrap();
        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: peer_ephemeral,
            duration_minutes: 60,
        };
        let opened = block_on_ready(node.handle_pfs_command(&peer, frame(), &request, &options));
        assert!(opened.unwrap().is_some());

        block_on_ready(node.peer(peer_ephemeral)).unwrap();
        let end = OwnedMacCommand::EndPfsSession;
        block_on_ready(node.handle_pfs_command(&peer, frame(), &end, &options)).unwrap();

        assert!(node.state().borrow().pfs.sessions().is_empty());
        assert!(
            mac.state
                .borrow()
                .peers
                .iter()
                .any(|(k, _)| *k == peer_ephemeral)
        );
        assert!(block_on_ready(node.remove_peer(&peer_ephemeral)));
        assert!(
            !mac.state
                .borrow()
                .peers
                .iter()
                .any(|(k, _)| *k == peer_ephemeral)
        );
    }

    /// Closing a contact exchange gives back only the slots it held: a
    /// contact it reached, whether added before or during the exchange,
    /// stays, and a stranger it reached goes.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn closing_a_meet_keeps_the_contacts_it_reached() {
        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let node = test_node(mac.clone());
        let before = PublicKey([0x41; 32]);
        let during = PublicKey([0x42; 32]);
        let stranger = PublicKey([0x43; 32]);
        block_on_ready(node.peer(before)).unwrap();

        block_on_ready(node.open_meet()).unwrap();
        for to in [&before, &during, &stranger] {
            block_on_ready(node.send_meet(Some(to), b"meet")).unwrap();
        }
        block_on_ready(node.peer(during)).unwrap();
        block_on_ready(node.close_meet());

        let peers: Vec<PublicKey> = mac.state.borrow().peers.iter().map(|(k, _)| *k).collect();
        assert_eq!(peers, vec![before, during]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_request_naming_a_registered_peer_is_refused() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let options = SendOptions::default();
        let contact = PublicKey([0x42; 32]);
        let mallory = PublicKey([0x66; 32]);
        block_on_ready(node.peer(contact)).unwrap();
        block_on_ready(node.peer(mallory)).unwrap();

        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: contact,
            duration_minutes: 60,
        };
        let answered =
            block_on_ready(node.handle_pfs_command(&mallory, frame(), &request, &options));

        assert!(answered.unwrap().is_none());
        assert!(mac.take_unicasts().is_empty());
        assert!(node.state().borrow().pfs.sessions().is_empty());
        assert!(mac.state.borrow().peers.iter().any(|(k, _)| *k == contact));
        assert_eq!(node.pfs_refused_ephemeral_keys(), 1);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_request_naming_this_node_is_refused() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let options = SendOptions::default();
        let own = PublicKey([0x11; 32]);
        let peer = PublicKey([0x55; 32]);
        mac.set_own_key(own);
        block_on_ready(node.peer(peer)).unwrap();

        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: own,
            duration_minutes: 60,
        };
        let answered = block_on_ready(node.handle_pfs_command(&peer, frame(), &request, &options));

        assert!(answered.unwrap().is_none());
        assert!(mac.take_unicasts().is_empty());
        assert_eq!(mac.state.borrow().peers.len(), 1);
        assert_eq!(node.pfs_refused_ephemeral_keys(), 1);
    }

    /// A response this node no longer wants, holding no session with its
    /// sender, is answered with an End so that the sender drops its half:
    /// one nobody asked for, as after a reboot, or one that arrived after
    /// the request timed out. A repeat of the response that opened the
    /// session held, or any response while one is held, is dropped.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_late_response_is_answered_with_an_end() {
        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        let response = |key: u8| OwnedMacCommand::PfsSessionResponse {
            ephemeral_key: PublicKey([key; 32]),
            duration_minutes: 60,
        };
        let ended_with = |mac: &FakeMac| {
            let sent = mac.take_unicasts();
            assert_eq!(sent.len(), 1);
            assert_eq!((sent[0].from, sent[0].to), (LocalIdentityId(1), peer));
            assert_eq!(
                parse_owned_mac_command(&sent[0].payload),
                OwnedMacCommand::EndPfsSession
            );
        };

        // Nothing was asked of this peer.
        let answered =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &response(0x44), &options));
        assert!(answered.unwrap().is_none());
        ended_with(&mac);
        // An End for no session is not answered.
        let end = OwnedMacCommand::EndPfsSession;
        let ended = block_on_ready(node.handle_pfs_command(&peer, frame(), &end, &options));
        assert!(ended.unwrap().is_none());
        assert!(mac.take_unicasts().is_empty());

        // The request gave up before its response came.
        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
        mac.take_unicasts();
        assert_eq!(node.expire_pfs_requests(u64::MAX), vec![peer]);
        let late =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &response(0x45), &options));
        assert!(late.unwrap().is_none());
        ended_with(&mac);
        assert_eq!(node.pfs_unwanted_responses(), 2);

        // A repeat of the response that opened a session, and one older.
        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
        mac.take_unicasts();
        let opened =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &response(0x46), &options));
        assert!(opened.unwrap().is_some());
        let local = node.pfs_local_keys();
        for key in [0x46, 0x45] {
            let repeat =
                block_on_ready(node.handle_pfs_command(&peer, frame(), &response(key), &options));
            assert!(repeat.unwrap().is_none());
        }
        assert!(mac.take_unicasts().is_empty());
        assert_eq!(node.pfs_local_keys(), local);
        assert_eq!(node.pfs_unwanted_responses(), 2);
        assert_eq!(node.pfs_refused_ephemeral_keys(), 0);
    }

    /// Two peers that ask each other for a session at once hold one: the
    /// request under the lower ephemeral key stands, its sender ignores the
    /// other, and the other's sender answers it.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_crossed_requests_open_one_session() {
        use crate::node::PfsLifecycle;
        use crate::pfs::PfsState;

        let alice_key = PublicKey([0xA1; 32]);
        let bob_key = PublicKey([0xB2; 32]);
        let alice_mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let bob_mac = FakeMac::new(vec![[9u8; 32], [10u8; 32]]);
        let alice = test_node(alice_mac.clone());
        let bob = test_node(bob_mac.clone());
        let options = SendOptions::default();
        block_on_ready(alice.peer(bob_key)).unwrap();
        block_on_ready(bob.peer(alice_key)).unwrap();

        block_on_ready(alice.request_pfs(&bob_key, 60, &options)).unwrap();
        block_on_ready(bob.request_pfs(&alice_key, 60, &options)).unwrap();
        let alices = parse_owned_mac_command(&alice_mac.take_unicasts()[0].payload);
        let bobs = parse_owned_mac_command(&bob_mac.take_unicasts()[0].payload);
        block_on_ready(bob.handle_pfs_command(&alice_key, frame(), &alices, &options)).unwrap();
        block_on_ready(alice.handle_pfs_command(&bob_key, frame(), &bobs, &options)).unwrap();

        // One of them answered.
        let (alice_sent, bob_sent) = (alice_mac.take_unicasts(), bob_mac.take_unicasts());
        assert_eq!(alice_sent.len() + bob_sent.len(), 1);
        let (winner, winner_key, winner_request, loser, loser_key, loser_request, response) =
            if bob_sent.is_empty() {
                (
                    &bob,
                    bob_key,
                    &bobs,
                    &alice,
                    alice_key,
                    &alices,
                    &alice_sent[0],
                )
            } else {
                (
                    &alice,
                    alice_key,
                    &alices,
                    &bob,
                    bob_key,
                    &bobs,
                    &bob_sent[0],
                )
            };
        let request_key = |request: &OwnedMacCommand| match request {
            OwnedMacCommand::PfsSessionRequest { ephemeral_key, .. } => *ephemeral_key,
            other => panic!("expected a request, got {other:?}"),
        };
        assert!(request_key(winner_request).0 < request_key(loser_request).0);
        assert_eq!(winner.pfs_crossed_requests(), 1);
        assert_eq!(loser.pfs_crossed_requests(), 0);

        let established = block_on_ready(winner.handle_pfs_command(
            &loser_key,
            frame(),
            &parse_owned_mac_command(&response.payload),
            &options,
        ));
        assert_eq!(
            established.unwrap(),
            Some(PfsLifecycle::Established(loser_key))
        );

        // Each holds one session, made of the other's halves.
        let held = |node: &crate::node::LocalNode<FakeMac>| {
            let state = node.state().borrow();
            let sessions = state.pfs.sessions();
            assert_eq!(sessions.len(), 1);
            let session = &sessions[0];
            (
                session.local_ephemeral,
                session.peer_ephemeral,
                session.state,
            )
        };
        let (winner_local, winner_peer, winner_state) = held(winner);
        let (loser_local, loser_peer, loser_state) = held(loser);
        assert_eq!(winner_local, request_key(winner_request));
        assert_eq!((winner_peer, loser_peer), (loser_local, winner_local));
        assert_eq!(
            (winner_state, loser_state),
            (PfsState::Active, PfsState::Answered)
        );
        // Neither is left with a request to time out.
        assert!(winner.expire_pfs_requests(u64::MAX).is_empty());
        assert!(loser.expire_pfs_requests(u64::MAX).is_empty());

        // The winner's first frame under the session confirms it.
        assert_eq!(
            loser.note_pfs_frame(LocalIdentityId(10), &winner_local),
            Some(winner_key)
        );
        assert_eq!(held(loser).2, PfsState::Active);
    }

    /// A responder sends nothing under the session it answered until the
    /// peer's first frame there shows the response arrived. While the
    /// response may be lost, what it sends goes under the long-term keys.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_answered_session_waits_for_the_peers_first_frame() {
        use crate::Transport;

        let mac = FakeMac::new(vec![[7u8; 32]]);
        let mut host = crate::Host::new(mac.clone());
        let node = host.add_node(LocalIdentityId(1));
        let peer = PublicKey([0x55; 32]);
        let peer_ephemeral = PublicKey([0x44; 32]);
        let options = SendOptions::default();
        let established = Rc::new(RefCell::new(Vec::new()));
        let log = established.clone();
        let _subscription = node.on_pfs_established(move |peer| log.borrow_mut().push(peer));
        block_on_ready(node.peer(peer)).unwrap();
        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: peer_ephemeral,
            duration_minutes: 60,
        };
        let answered = block_on_ready(node.handle_pfs_command(&peer, frame(), &request, &options));
        assert!(answered.unwrap().is_some());
        mac.take_unicasts();

        let payload = encode_text_payload("on my way");
        let sent_from = |mac: &FakeMac| {
            block_on_ready(node.send(&peer, &payload, &options)).unwrap();
            let sent = mac.take_unicasts().pop().unwrap();
            (sent.from, sent.to)
        };
        assert!(matches!(
            block_on_ready(node.pfs_status(&peer)).unwrap(),
            crate::PfsStatus::Requested
        ));
        assert!(matches!(
            block_on_ready(node.send_with_secrecy(&peer, &payload, &options, true)),
            Err(crate::NodeError::PfsSessionMissing)
        ));
        assert_eq!(sent_from(&mac), (LocalIdentityId(1), peer));

        // A frame from anyone else under the session's identity shows nothing.
        mac.script(LocalIdentityId(10), session_frame(PublicKey([0x66; 32])));
        block_on_ready(host.pump_once()).unwrap();
        assert!(established.borrow().is_empty());

        mac.script(LocalIdentityId(10), session_frame(peer_ephemeral));
        block_on_ready(host.pump_once()).unwrap();
        assert_eq!(established.borrow().as_slice(), &[peer]);
        assert!(matches!(
            block_on_ready(node.pfs_status(&peer)).unwrap(),
            crate::PfsStatus::Active { .. }
        ));
        assert_eq!(sent_from(&mac), (LocalIdentityId(10), peer_ephemeral));
    }

    /// Three acknowledged sends in a row under a session that go
    /// undelivered end it, and the peer is told under the long-term keys.
    /// One delivered in between starts the count again.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_session_ends_after_three_undelivered_sends() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let mut host = crate::Host::new(mac.clone());
        let node = host.add_node(LocalIdentityId(1));
        let peer = PublicKey([0x55; 32]);
        let peer_ephemeral = PublicKey([0x44; 32]);
        let options = SendOptions::default();
        let ended = Rc::new(RefCell::new(Vec::new()));
        let log = ended.clone();
        let _subscription = node.on_pfs_ended(move |peer| log.borrow_mut().push(peer));
        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
        let response = OwnedMacCommand::PfsSessionResponse {
            ephemeral_key: peer_ephemeral,
            duration_minutes: 60,
        };
        block_on_ready(node.handle_pfs_command(&peer, frame(), &response, &options)).unwrap();
        mac.take_unicasts();

        let session = LocalIdentityId(10);
        let undelivered = |sends: usize| {
            for _ in 0..sends {
                let timeout = MacEventRef::AckTimeout {
                    peer: peer_ephemeral,
                    receipt: SendReceipt(42),
                };
                mac.script(session, timeout);
            }
        };
        undelivered(2);
        let delivered = MacEventRef::AckReceived {
            peer: peer_ephemeral,
            receipt: SendReceipt(43),
            via_route_retry: false,
        };
        mac.script(session, delivered);
        undelivered(2);
        block_on_ready(host.pump_once()).unwrap();
        assert!(matches!(
            block_on_ready(node.pfs_status(&peer)).unwrap(),
            crate::PfsStatus::Active { .. }
        ));
        assert!(mac.take_unicasts().is_empty());

        undelivered(1);
        block_on_ready(host.pump_once()).unwrap();
        assert!(matches!(
            block_on_ready(node.pfs_status(&peer)).unwrap(),
            crate::PfsStatus::Inactive
        ));
        assert_eq!(ended.borrow().as_slice(), &[peer]);
        assert_eq!(node.pfs_undelivered_sessions(), 1);
        assert_eq!(mac.state.borrow().removed_ephemerals, vec![session]);
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!((sent[0].from, sent[0].to), (LocalIdentityId(1), peer));
        assert_eq!(
            parse_owned_mac_command(&sent[0].payload),
            OwnedMacCommand::EndPfsSession
        );
    }

    /// A peer that rebooted holds no session, and its End under the
    /// long-term keys clears the stale one held with it, whichever side
    /// asked for it.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_end_from_a_rebooted_peer_clears_a_stale_session() {
        use crate::node::PfsLifecycle;

        for asked in [true, false] {
            let mac = FakeMac::new(vec![[7u8; 32]]);
            let node = test_node(mac.clone());
            let peer = PublicKey([0x55; 32]);
            let peer_ephemeral = PublicKey([0x44; 32]);
            let options = SendOptions::default();
            block_on_ready(node.peer(peer)).unwrap();
            let handshake = if asked {
                block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
                OwnedMacCommand::PfsSessionResponse {
                    ephemeral_key: peer_ephemeral,
                    duration_minutes: 60,
                }
            } else {
                OwnedMacCommand::PfsSessionRequest {
                    ephemeral_key: peer_ephemeral,
                    duration_minutes: 60,
                }
            };
            block_on_ready(node.handle_pfs_command(&peer, frame(), &handshake, &options)).unwrap();
            assert_eq!(node.pfs_local_keys().len(), 1);

            // Sent after the reboot, under a counter past the handshake's.
            let end = OwnedMacCommand::EndPfsSession;
            let ended = block_on_ready(node.handle_pfs_command(&peer, frame(), &end, &options));
            assert_eq!(
                ended.unwrap(),
                Some(PfsLifecycle::Ended(peer)),
                "asked {asked}"
            );
            assert!(node.state().borrow().pfs.sessions().is_empty());
            assert_eq!(
                mac.state.borrow().removed_ephemerals,
                vec![LocalIdentityId(10)]
            );
            assert_eq!(node.pfs_stale_ends(), 0);
        }
    }

    /// An End under the session's own keys ends that session.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_end_under_the_session_keys_ends_it() {
        use crate::node::PfsLifecycle;

        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let peer_ephemeral = PublicKey([0x44; 32]);
        let options = SendOptions::default();
        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
        let response = OwnedMacCommand::PfsSessionResponse {
            ephemeral_key: peer_ephemeral,
            duration_minutes: 60,
        };
        block_on_ready(node.handle_pfs_command(&peer, frame(), &response, &options)).unwrap();

        let end = OwnedMacCommand::EndPfsSession;
        let carriage = crate::pfs::Carriage::default();
        let ended =
            block_on_ready(node.handle_pfs_command(&peer_ephemeral, carriage, &end, &options));
        assert_eq!(ended.unwrap(), Some(PfsLifecycle::Ended(peer)));
        assert!(node.state().borrow().pfs.sessions().is_empty());
    }

    /// An End is about the session held when it was sent. One delayed or
    /// replayed past a newer session's handshake ends nothing, and neither
    /// does one that reaches a request still waiting for its response.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_old_end_does_not_end_a_newer_session() {
        use crate::node::PfsLifecycle;

        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        let end = OwnedMacCommand::EndPfsSession;
        block_on_ready(node.peer(peer)).unwrap();

        // An End from before the request reaches it while it waits, and
        // again once the response has come.
        block_on_ready(node.request_pfs(&peer, 60, &options)).unwrap();
        let stray = frame();
        let ended = block_on_ready(node.handle_pfs_command(&peer, stray, &end, &options));
        assert!(ended.unwrap().is_none());
        let response = OwnedMacCommand::PfsSessionResponse {
            ephemeral_key: PublicKey([0x44; 32]),
            duration_minutes: 60,
        };
        block_on_ready(node.handle_pfs_command(&peer, frame(), &response, &options)).unwrap();
        let ended = block_on_ready(node.handle_pfs_command(&peer, stray, &end, &options));
        assert!(ended.unwrap().is_none());
        assert_eq!(node.pfs_local_keys().len(), 1);

        // The peer ends that session, then asks for another.
        let first_end = frame();
        let ended = block_on_ready(node.handle_pfs_command(&peer, first_end, &end, &options));
        assert_eq!(ended.unwrap(), Some(PfsLifecycle::Ended(peer)));
        let request = OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([0x45; 32]),
            duration_minutes: 60,
        };
        block_on_ready(node.handle_pfs_command(&peer, frame(), &request, &options)).unwrap();
        let second = node.pfs_local_keys();
        assert_eq!(second.len(), 1);

        // The first End again, as a replay or a late copy, and one whose
        // counter is unknown.
        for carriage in [first_end, crate::pfs::Carriage::default()] {
            let ended = block_on_ready(node.handle_pfs_command(&peer, carriage, &end, &options));
            assert!(ended.unwrap().is_none());
        }
        assert_eq!(node.pfs_local_keys(), second);
        assert_eq!(node.pfs_stale_ends(), 4);

        let ended = block_on_ready(node.handle_pfs_command(&peer, frame(), &end, &options));
        assert_eq!(ended.unwrap(), Some(PfsLifecycle::Ended(peer)));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_unsent_response_leaves_nothing_behind() {
        let mac = FakeMac::new(vec![[7u8; 32], [8u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);
        let options = SendOptions::default();
        block_on_ready(node.peer(peer)).unwrap();

        mac.state.borrow_mut().refuse_sends = true;
        let request = |key: u8| OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: PublicKey([key; 32]),
            duration_minutes: 60,
        };
        let failed =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x44), &options));
        assert!(failed.is_err());

        assert!(node.state().borrow().pfs.sessions().is_empty());
        assert_eq!(
            mac.state.borrow().removed_ephemerals,
            vec![LocalIdentityId(10)]
        );

        // Nothing was answered, so the peer's retry is not held to the
        // rate limit.
        mac.state.borrow_mut().refuse_sends = false;
        let retry =
            block_on_ready(node.handle_pfs_command(&peer, frame(), &request(0x45), &options));
        assert!(retry.unwrap().is_some());
        assert_eq!(node.pfs_rate_limited_requests(), 0);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pfs_unsent_request_leaves_nothing_behind() {
        let mac = FakeMac::new(vec![[7u8; 32]]);
        let node = test_node(mac.clone());
        let peer = PublicKey([0x55; 32]);

        mac.state.borrow_mut().refuse_sends = true;
        assert!(block_on_ready(node.request_pfs(&peer, 60, &SendOptions::default())).is_err());

        assert!(node.state().borrow().pfs.sessions().is_empty());
    }

    /// How the next PFS command from a peer arrives in these tests: under
    /// a frame counter past every earlier one's, as a sender's counter runs.
    #[cfg(feature = "software-crypto")]
    fn frame() -> crate::pfs::Carriage {
        std::thread_local! {
            static COUNTER: core::cell::Cell<u32> = const { core::cell::Cell::new(100) };
        }
        let counter = COUNTER.with(|counter| {
            counter.set(counter.get() + 1);
            counter.get()
        });
        crate::pfs::Carriage {
            channel: None,
            counter: Some(counter),
        }
    }

    /// A frame heard from `from` under some local identity.
    #[cfg(feature = "software-crypto")]
    fn session_frame(from: PublicKey) -> MacEventRef<'static> {
        let payload = encode_text_payload("under the session");
        MacEventRef::Received(test_unicast_packet(
            from,
            Box::leak(payload.into_boxed_slice()),
        ))
    }

    /// The next PFS command, as a blind unicast on `channel`.
    #[cfg(feature = "software-crypto")]
    fn on_channel(channel: ChannelKey) -> crate::pfs::Carriage {
        crate::pfs::Carriage {
            channel: Some(channel),
            ..frame()
        }
    }

    #[cfg(feature = "software-crypto")]
    fn encode_text_payload(text: &str) -> Vec<u8> {
        let message = OwnedTextMessage::basic(text);
        let mut body = [0u8; 512];
        let len = umsh_text::text_message::encode(&message.as_borrowed(), &mut body).unwrap();
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(umsh_core::PayloadType::TextMessage as u8);
        payload.extend_from_slice(&body[..len]);
        payload
    }

    #[cfg(feature = "software-crypto")]
    fn test_unicast_packet<'a>(from: PublicKey, payload: &'a [u8]) -> ReceivedPacketRef<'a> {
        test_unicast_packet_with_rx(from, payload, umsh_mac::RxMetadata::default())
    }

    #[cfg(feature = "software-crypto")]
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
            signature: None,
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
    #[cfg(feature = "software-crypto")]
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
            signature: None,
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
    #[cfg(feature = "software-crypto")]
    fn test_broadcast_packet(
        from: PublicKey,
        flood_hops: Option<u8>,
        route: Option<&'static [u8]>,
    ) -> ReceivedPacketRef<'static> {
        test_broadcast_packet_with_trace(from, flood_hops, route, None)
    }

    /// As above, plus an accumulated trace of router hints (carried as a
    /// hints-only trace)—what a steered solicitation looks like once
    /// repeaters have prepended themselves to it.
    #[cfg(feature = "software-crypto")]
    fn test_broadcast_packet_with_trace(
        from: PublicKey,
        flood_hops: Option<u8>,
        route: Option<&'static [u8]>,
        hints: Option<&'static [u8]>,
    ) -> ReceivedPacketRef<'static> {
        let trace = hints.map(|hints| {
            let mut value = vec![0xFE];
            value.extend_from_slice(hints);
            &*Box::leak(value.into_boxed_slice())
        });
        test_broadcast_packet_with_traces(from, flood_hops, route, trace)
    }

    /// As above, with `trace` the whole Trace option value, in any form.
    #[cfg(feature = "software-crypto")]
    fn test_broadcast_packet_with_traces(
        from: PublicKey,
        flood_hops: Option<u8>,
        route: Option<&'static [u8]>,
        trace: Option<&'static [u8]>,
    ) -> ReceivedPacketRef<'static> {
        let route_len = route.map_or(0, <[u8]>::len);
        let trace_len = trace.map_or(0, <[u8]>::len);
        let options_len = route_len + trace_len;
        let mut bytes = route.map_or_else(Vec::new, <[u8]>::to_vec);
        bytes.extend_from_slice(trace.unwrap_or(&[]));
        let wire: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        let mut options = umsh_core::ParsedOptions::default();
        if route.is_some() {
            options.source_route = Some(0..route_len);
        }
        if trace.is_some() {
            options.trace = Some(route_len..route_len + trace_len);
        }
        let header = umsh_core::PacketHeader {
            fcf: umsh_core::Fcf::new(umsh_core::PacketType::Broadcast, false, false),
            options_range: 0..options_len,
            flood_hops: flood_hops.map(umsh_core::FloodHops),
            dst: None,
            channel: None,
            source: umsh_core::SourceAddrRef::Hint(from.hint()),
            sec_info: None,
            signature: None,
            body_range: options_len..wire.len(),
            mic_range: wire.len()..wire.len(),
            total_len: wire.len(),
        };
        ReceivedPacketRef::new(
            wire,
            &wire[options_len..],
            header,
            options,
            Some(from),
            Some(from.hint()),
            false,
            None,
            umsh_mac::RxMetadata::default(),
        )
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
        broadcasts: Vec<(Vec<u8>, SendOptions)>,
        removed_ephemerals: Vec<LocalIdentityId>,
        peers: Vec<(PublicKey, PeerId)>,
        /// The peers the application holds, once each.
        contacts: Vec<PublicKey>,
        /// One entry per session hold.
        session_holds: Vec<PublicKey>,
        channels: Vec<umsh_core::ChannelKey>,
        observations: Vec<umsh_mac::TransmitterObservation>,
        own_key: Option<PublicKey>,
        /// Parks `add_peer`, as a busy MAC would.
        hold_add_peer: bool,
        /// Fails every unicast.
        refuse_sends: bool,
        /// What the next `next_event` reports, in order.
        events: VecDeque<(LocalIdentityId, MacEventRef<'static>)>,
    }

    #[cfg(feature = "software-crypto")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SentUnicast {
        from: LocalIdentityId,
        to: PublicKey,
        payload: Vec<u8>,
        options: SendOptions,
        /// The channel a blind unicast went out on; `None` for plain unicast.
        channel: Option<ChannelKey>,
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

        fn take_broadcasts(&self) -> Vec<(Vec<u8>, SendOptions)> {
            core::mem::take(&mut self.state.borrow_mut().broadcasts)
        }

        fn holds_channel(&self, key: &umsh_core::ChannelKey) -> bool {
            self.state.borrow().channels.iter().any(|k| k.0 == key.0)
        }

        fn observe(&self, hint: umsh_core::RouterHint, rssi_dbm: i16, snr: umsh_hal::Snr) {
            let mut state = self.state.borrow_mut();
            let last_seen_ms = state.now_ms;
            state.observations.push(umsh_mac::TransmitterObservation {
                hint,
                rssi_snr: Some((rssi_dbm, snr)),
                last_seen_ms,
            });
        }

        fn set_own_key(&self, key: PublicKey) {
            self.state.borrow_mut().own_key = Some(key);
        }

        /// Have the next pump cycle report `event` under `identity`.
        fn script(&self, identity: LocalIdentityId, event: MacEventRef<'static>) {
            self.state.borrow_mut().events.push_back((identity, event));
        }
    }

    #[cfg(feature = "software-crypto")]
    impl MacBackend for FakeMac {
        type SendError = SendError;
        type CapacityError = CapacityError;
        type RunError = core::convert::Infallible;

        async fn next_event(
            &self,
            mut on_event: impl FnMut(LocalIdentityId, umsh_mac::MacEventRef<'_>),
        ) -> Result<(), Self::RunError> {
            // The events a test scripted, taken before any is reported so
            // that a callback may script more for the next cycle.
            let events: Vec<_> = self.state.borrow_mut().events.drain(..).collect();
            for (identity, event) in events {
                on_event(identity, event);
            }
            Ok(())
        }

        async fn hold_peer(
            &self,
            key: PublicKey,
            holder: PeerHolder,
        ) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>> {
            core::future::poll_fn(|_| {
                if self.state.borrow().hold_add_peer {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            let mut state = self.state.borrow_mut();
            match holder {
                PeerHolder::Application if !state.contacts.contains(&key) => {
                    state.contacts.push(key)
                }
                PeerHolder::Application => {}
                PeerHolder::Session => state.session_holds.push(key),
            }
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

        async fn release_peer(&self, key: &PublicKey, holder: PeerHolder) -> bool {
            let mut state = self.state.borrow_mut();
            if !state.peers.iter().any(|(existing, _)| existing == key) {
                return false;
            }
            let holds = match holder {
                PeerHolder::Application => &mut state.contacts,
                PeerHolder::Session => &mut state.session_holds,
            };
            let held = match holds.iter().position(|held| held == key) {
                Some(index) => {
                    holds.remove(index);
                    true
                }
                None => false,
            };
            let still_held = state.contacts.contains(key) || state.session_holds.contains(key);
            if !held && (holder == PeerHolder::Session || still_held) {
                return false;
            }
            if !still_held {
                state.peers.retain(|(existing, _)| existing != key);
            }
            true
        }

        async fn ensure_transient_peer(&self, key: &PublicKey) -> bool {
            let mut state = self.state.borrow_mut();
            if !state.peers.iter().any(|(existing, _)| existing == key) {
                let peer_id = PeerId(state.next_peer_id);
                state.next_peer_id = state.next_peer_id.wrapping_add(1);
                state.peers.push((*key, peer_id));
            }
            true
        }

        async fn is_application_peer(&self, key: &PublicKey) -> bool {
            self.state.borrow().contacts.contains(key)
        }

        async fn for_each_peer(&self, f: &mut dyn FnMut(PublicKey)) {
            let peers: Vec<PublicKey> = self.state.borrow().peers.iter().map(|(k, _)| *k).collect();
            for peer in peers {
                f(peer);
            }
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
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>> {
            self.state
                .borrow_mut()
                .broadcasts
                .push((payload.to_vec(), options.clone()));
            Ok(SendReceipt(99))
        }

        async fn send_multicast(
            &self,
            _from: LocalIdentityId,
            _channel: &ChannelKey,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(SendReceipt(99))
        }

        async fn payload_capacity(
            &self,
            _from: LocalIdentityId,
            _destination: umsh_mac::SendDestination<'_>,
            _options: &SendOptions,
        ) -> Result<usize, MacBackendError<Self::SendError, Self::CapacityError>> {
            Ok(255)
        }

        async fn send_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>>
        {
            if self.state.borrow().refuse_sends {
                return Err(MacBackendError::Send(SendError::PeerMissing));
            }
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
            channel: &ChannelKey,
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

        async fn identity_public_key(&self, _id: LocalIdentityId) -> Option<PublicKey> {
            self.state.borrow().own_key
        }
    }

    #[cfg(feature = "software-crypto")]
    fn parse_owned_mac_command(payload: &[u8]) -> OwnedMacCommand {
        OwnedMacCommand::from(
            crate::parse_mac_command_payload(umsh_core::PacketType::Unicast, payload).unwrap(),
        )
    }

    #[cfg(feature = "software-crypto")]
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

    /// Polls `future` once and reports whether it parked.
    #[cfg(feature = "software-crypto")]
    fn parks<F: Future>(future: core::pin::Pin<&mut F>) -> bool {
        future
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    }

    // --- Identity Request responder ---

    #[cfg(feature = "software-crypto")]
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
            Rc::default(),
            state,
        )
    }

    #[cfg(feature = "software-crypto")]
    fn test_profile(public_key: PublicKey) -> crate::NodeIdentityProfile {
        crate::NodeIdentityProfile::new(
            public_key,
            crate::NodeRole::Repeater,
            crate::NodeCapabilities::REPEATER | crate::NodeCapabilities::TEXT_MESSAGES,
        )
        .with_name("repeater-1")
    }

    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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
            Some(channel_key),
            "a blind request must not be answered off its channel"
        );
    }

    /// A multicast solicitation carries a channel too, but every node it
    /// selects answers the same frame; targeted unicast replies are what keep
    /// one solicitation from filling the channel with them.
    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
    #[test]
    fn responder_answers_a_router_hint_prefix_and_replies_down_the_trace() {
        let mac = FakeMac::new(vec![[0x12; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));

        // Two bytes of our own hint—everything a route reveals about us.
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
        assert!(
            unicasts[0].options.trace,
            "the reply records its own path, or the requester ends the \
             exchange holding no route back to us"
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

    /// An ask after a hint goes where it is aimed and never floods: to
    /// direct range with no route, or along the one given, traced so the
    /// answer has a way home.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn an_identity_request_is_aimed_and_never_floods() {
        let mac = FakeMac::new(vec![[0x12; 32], [0x13; 32]]);
        let node = responder_node(&mac);
        let hint = umsh_core::RouterHint([0xA0, 0x9A]);
        let filter = crate::IdentityFilter {
            hint_prefix: Some(&hint.0),
            ..Default::default()
        };

        block_on_ready(node.request_identities(&filter, &[])).unwrap();
        let sent = mac.take_broadcasts();
        let [(payload, options)] = &sent[..] else {
            panic!("one request");
        };
        let Ok(crate::MacCommand::IdentityRequest { options: body }) =
            crate::mac_command::parse(&payload[1..])
        else {
            panic!("an identity request");
        };
        let filters = crate::mac_command::IdentityRequestFilters::new(body);
        assert!(filters.hint_filtered());
        assert!(filters.nonce().unwrap().is_some());
        assert!(options.full_source);
        assert_eq!(options.flood_hops, None);
        assert_eq!(options.source_route, None);
        assert!(!options.trace);

        let route = [umsh_core::RouterHint([1, 2])];
        block_on_ready(node.request_identities(&filter, &route)).unwrap();
        let sent = mac.take_broadcasts();
        let [(_, options)] = &sent[..] else {
            panic!("one request");
        };
        assert_eq!(options.source_route.as_deref(), Some(&route[..]));
        assert!(options.trace);
        assert_eq!(options.flood_hops, None, "a route lends no flood budget");
    }

    /// One solicitation gets one reply, however many copies of it arrive.
    ///
    /// A request is unauthenticated and carries no frame counter, so nothing
    /// below the node layer can recognize a repeat of one; a repeater that
    /// carried a copy it should have left alone used to buy the requester an
    /// extra reply from every node in earshot.
    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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

        // Same nonce, different askers—a nonce is only unique to its sender.
        for requester in [PublicKey([0x41; 32]), PublicKey([0x42; 32])] {
            let packet = test_broadcast_packet(requester, None, None);
            let plan = node
                .evaluate_identity_request(&packet, requester, &options, 1_000)
                .expect("each requester is owed an answer");
            block_on_ready(node.send_identity_response(plan));
        }
        assert_eq!(mac.take_unicasts().len(), 2);
    }

    #[cfg(feature = "software-crypto")]
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
    /// That trace is the requester's only path home—the reply carries no
    /// flood budget, and receiving a broadcast teaches the MAC no route—so
    /// the reply must go back down it, copied verbatim rather than reversed.
    #[cfg(feature = "software-crypto")]
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

    /// A trace on the way in is answered by a trace on the way back
    /// (beacons.md § Path Discovery, bidirectional establishment). The
    /// question taught this node a path home; without a trace on the answer
    /// the requester learns nothing, because a routed reply arrives with its
    /// Route option consumed and its `FHOPS_ACC` counting only the tail.
    ///
    #[cfg(feature = "software-crypto")]
    #[test]
    fn identity_response_mirrors_the_trace_options_its_request_carried() {
        let mac = FakeMac::new(vec![[0x00; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_role(crate::NodeRole::Repeater)
            .unwrap()
            .build();

        let steered = test_broadcast_packet_with_traces(
            requester,
            Some(0x00),
            Some(&[]),
            Some(&[0x12, 0x34, 0x5A, 0x00]),
        );
        let plan = node
            .evaluate_identity_request(&steered, requester, &options, 0)
            .expect("a steered solicitation is answered");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        let reply = &unicasts[0];
        assert!(reply.options.trace, "the trace is mirrored");
        // The mirror rides alongside the steering rather than replacing it:
        // the route is how the answer gets home, the trace is what the
        // requester keeps from it.
        assert_eq!(
            reply.options.source_route.as_deref(),
            Some([umsh_core::RouterHint([0x12, 0x34])].as_slice())
        );
    }

    /// A request that asked for no path to be recorded gets none back. The
    /// responder mirrors what it was sent and invents nothing; whether an
    /// unrouted reply still earns a trace is the MAC's discovery floor to
    /// decide, not the responder's.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn identity_response_to_an_untraced_request_mirrors_nothing() {
        let mac = FakeMac::new(vec![[0x00; 32]]);
        let node = responder_node(&mac);
        let our_key = PublicKey([0x11; 32]);
        let requester = PublicKey([0x41; 32]);
        node.enable_identity_responder_default(test_profile(our_key));
        let options = crate::mac_command::IdentityRequestBuilder::new()
            .filter_hint(&our_key.hint())
            .unwrap()
            .build();

        let packet = test_broadcast_packet(requester, None, None);
        let plan = node
            .evaluate_identity_request(&packet, requester, &options, 0)
            .expect("a hint-filtered solicitation is answered");
        block_on_ready(node.send_identity_response(plan));

        let unicasts = mac.take_unicasts();
        assert_eq!(unicasts.len(), 1);
        assert!(!unicasts[0].options.trace);
    }

    /// The ordinary in-range case is unchanged: no trace in, no route out,
    /// and above all no empty Route option on the wire.
    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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
            trace: None,
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

    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
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
    #[cfg(feature = "software-crypto")]
    /// The peer-repeater listing names the neighborhood around this node. A
    /// request that arrived concealed on a channel is answered there, not in
    /// the open.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn peer_repeaters_response_follows_a_blind_request_onto_its_channel() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();
        let channel = ChannelKey([0x5A; 32]);

        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            Some(channel),
            &peer_repeaters_request(Some(7), None),
        ));

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].channel, Some(channel));
    }

    /// Pull the one response the responder sent back off the fake MAC and
    /// reparse it exactly as a receiver would.
    #[cfg(feature = "software-crypto")]
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

    /// A node is not its own neighbor, whichever source names it: its own
    /// advertisement heard back, or a trace that begins with its own hint.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn the_listing_never_names_the_node_itself() {
        let mac = FakeMac::new(Vec::new());
        let own = PublicKey([0x5A; 32]);
        mac.set_own_key(own);
        let node = responder_node(&mac);
        node.observe_peer_identity(
            own,
            &peer_identity("Myself", &[]),
            crate::IdentityUpdate::Replace,
            None,
            0,
        );
        node.observe_peer_identity(
            PublicKey([0xAA; 32]),
            &peer_identity("Ridge", &[]),
            crate::IdentityUpdate::Replace,
            None,
            0,
        );
        mac.observe(
            umsh_core::RouterHint([own.0[0], own.0[1]]),
            -82,
            umsh_hal::Snr::from_decibels(27),
        );

        let peers = block_on_ready(node.peer_repeaters());
        let names: Vec<Option<&str>> = peers.iter().map(|peer| peer.name.as_deref()).collect();
        assert_eq!(names, [Some("Ridge")]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_disabled_responder_answers_nothing() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.observe_peer_identity(
            PublicKey([0xAA; 32]),
            &peer_identity("Ridge", &[]),
            crate::IdentityUpdate::Replace,
            None,
            0,
        );

        block_on_ready(node.answer_peer_repeaters_request(
            PublicKey([0x41; 32]),
            None,
            &peer_repeaters_request(None, None),
        ));
        assert!(mac.take_unicasts().is_empty());
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_response_echoes_the_nonce_and_reports_what_both_sources_know() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();

        let peer = PublicKey([0xAA; 32]);
        // Heard advertising at one signal, then heard forwarding at another;
        // the forwarding is newer, so its figures are the ones reported.
        node.observe_peer_identity(
            peer,
            &peer_identity("Ridge", &["SJC", "0x1234"]),
            crate::IdentityUpdate::Replace,
            Some((-60, umsh_hal::Snr::from_decibels(8))),
            0,
        );
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

    #[cfg(feature = "software-crypto")]
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
                crate::IdentityUpdate::Replace,
                None,
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
    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_cursor_from_a_changed_listing_restarts_the_walk() {
        let mac = FakeMac::new(Vec::new());
        let node = responder_node(&mac);
        node.enable_peer_repeaters_responder();
        for seed in 0..3u8 {
            node.observe_peer_identity(
                PublicKey([seed; 32]),
                &peer_identity("Peer", &[]),
                crate::IdentityUpdate::Replace,
                None,
                0,
            );
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
        node.observe_peer_identity(
            PublicKey([0x77; 32]),
            &peer_identity("Newcomer", &[]),
            crate::IdentityUpdate::Replace,
            None,
            0,
        );
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

    /// The listing is the answer even when it is empty—a repeater that
    /// knows of nobody says so rather than staying silent.
    #[cfg(feature = "software-crypto")]
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
