//! The node adapter over a real MAC with real signatures: what goes out
//! on `EMERGENCY` signed and what does not, how its frames are sized, and
//! what a receiver shows.
//!
//! Frames are taken from the sender's transmit queue and handed to the
//! receiver's MAC by hand, so a test sees exactly what went on the air.

#![cfg(feature = "software-crypto")]

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use umsh_core::{ChannelKey, PacketHeader, PacketType, PayloadType, PublicKey};
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_crypto::{CryptoEngine, NodeIdentity};
use umsh_hal::{RxInfo, RxOrigin, Snr};
use umsh_mac::test_support::{
    DummyClock, DummyCounterStore, DummyDelay, DummyKeyValueStore, DummyRng, SimulatedNetwork,
    SimulatedRadio,
};
use umsh_mac::{Mac, MacEventRef, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::{Channel, Host, LocalNode};
use umsh_sync::AsyncRefCell;
use umsh_text::chat::{ChatFacade, ChatOutput, Seeds, TextSource};
use umsh_text::engine::{ArchiveResult, ComposeIntent, ComposeRef, EngineConfig, MAX_FRAME};
use umsh_text::node_adapter::{
    BudgetQuery, Inbound, Refusal, TransmitPolicy, TransmitQueue, WellKnownChannels, inbound_text,
    payload_budget,
};
use umsh_text::{ConversationKey, MessageType, TextMessage, encode_text_message};

/// What the radio sends, as LoRa does.
const MAX_RADIO_FRAME: usize = 255;

struct Platform;

impl umsh_mac::Platform for Platform {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = SimulatedRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = DummyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}

type Handle = MacHandle<'static, Platform>;

/// One node: its MAC, the node over it, and its chat session.
struct Station {
    mac: &'static AsyncRefCell<Mac<Platform>>,
    node: LocalNode<Handle>,
    key: PublicKey,
    chat: ChatFacade,
    queue: TransmitQueue,
}

fn well_known() -> WellKnownChannels {
    WellKnownChannels::derive()
}

fn policy() -> TransmitPolicy {
    TransmitPolicy {
        default_flood_hops: 5,
        well_known: well_known(),
    }
}

fn engine() -> CryptoEngine<SoftwareAes, SoftwareSha256> {
    CryptoEngine::new(SoftwareAes, SoftwareSha256)
}

/// A private channel whose key shares `EMERGENCY`'s 2-byte identifier: the
/// first of `n ‖ 77…77`, counting `n` up from zero, that does. The search
/// takes seconds in a debug build, so its result is written down and
/// checked.
fn colliding_with_emergency() -> ChannelKey {
    let mut bytes = [0x77; 32];
    bytes[..4].copy_from_slice(&COLLIDING_N.to_be_bytes());
    let key = ChannelKey(bytes);
    let emergency = well_known().emergency;
    assert_ne!(key, emergency);
    assert_eq!(
        engine().derive_channel_id(&key),
        engine().derive_channel_id(&emergency)
    );
    key
}

const COLLIDING_N: u32 = 0xB283;

/// A node on its own radio as `secret` makes it, holding `public`,
/// `EMERGENCY` and `channels`.
fn station(secret: u8, channels: &[ChannelKey]) -> Station {
    let network = SimulatedNetwork::new();
    let mac: &'static AsyncRefCell<Mac<Platform>> =
        Box::leak(Box::new(AsyncRefCell::new(Mac::new(
            network.add_radio_with_config(MAX_RADIO_FRAME, 10),
            engine(),
            DummyClock::new(1_000),
            DummyRng::default(),
            DummyCounterStore,
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        ))));
    let handle = MacHandle::new(mac);
    let identity = SoftwareIdentity::from_secret_bytes(&[secret; 32]);
    let key = *identity.public_key();
    let id = block_on(handle.add_identity(identity)).unwrap();
    let mut host = Host::new(handle);
    let node = host.add_node(id);
    // The node's dispatch tables live in the host.
    Box::leak(Box::new(host));

    let mut chat = ChatFacade::new(
        umsh_text::validate::DirectChannelProfile,
        key,
        EngineConfig {
            reorder_grace_ms: 0,
            fragment_grace_ms: 0,
            group_jitter_ms: 0,
            ..EngineConfig::default()
        },
        Seeds {
            session_id: u64::from(secret),
            jitter_seed: 1,
        },
    );
    let well_known = well_known();
    for key in [well_known.public, well_known.emergency]
        .iter()
        .chain(channels)
    {
        block_on(node.join(&Channel::private(*key, ""))).unwrap();
        let tag = engine().derive_channel_tag(key);
        chat.channels_mut().register(tag, *key, None);
    }
    Station {
        mac,
        node,
        key,
        chat,
        queue: TransmitQueue::new(8),
    }
}

fn group(key: &ChannelKey) -> ConversationKey {
    ConversationKey::ChannelGroup {
        channel: engine().derive_channel_tag(key),
    }
}

/// A text payload carrying `body`, with its payload-type byte.
fn text_payload(body: &str) -> Vec<u8> {
    let mut buffer = [0u8; 512];
    let len = encode_text_message(&TextMessage::basic(body), &mut buffer).unwrap();
    let mut payload = vec![PayloadType::TextMessage as u8];
    payload.extend_from_slice(&buffer[..len]);
    payload
}

/// Options for a frame on `EMERGENCY` as its rules ask, but unsigned.
fn unsigned() -> SendOptions {
    SendOptions::default().with_full_source().unencrypted()
}

impl Station {
    /// What one frame to `conversation` carries, as the adapter measures it.
    fn budget(&self, conversation: ConversationKey) -> usize {
        let query = BudgetQuery::new(self.chat.channels(), &policy(), conversation).unwrap();
        block_on(payload_budget(&self.node, &query)).unwrap()
    }

    /// The frames the MAC has queued to send, oldest first.
    fn sent(&self) -> Vec<Vec<u8>> {
        let mut mac = block_on(self.mac.borrow_mut());
        core::iter::from_fn(|| mac.tx_queue_mut().pop_next())
            .map(|queued| queued.frame.to_vec())
            .collect()
    }

    /// A multicast of `payload` on the channel `key` names.
    fn multicast(&self, key: &ChannelKey, payload: &[u8], options: &SendOptions) -> Vec<u8> {
        let bound = self
            .node
            .bound_channel(&Channel::private(*key, ""))
            .unwrap();
        block_on(umsh_node::Transport::send_all(&bound, payload, options)).unwrap();
        only(self.sent())
    }

    /// A blind unicast of `payload` to `peer` over the channel `key` names.
    fn blind_unicast(
        &self,
        key: &ChannelKey,
        peer: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Vec<u8> {
        block_on(self.node.peer(*peer)).unwrap();
        let bound = self
            .node
            .bound_channel(&Channel::private(*key, ""))
            .unwrap();
        block_on(umsh_node::Transport::send(&bound, peer, payload, options)).unwrap();
        only(self.sent())
    }

    /// What the chat layer makes of `frame` once this node's MAC has
    /// accepted it; `None` when the MAC delivered nothing, or the chat
    /// layer has nothing to say about it.
    fn receive(&self, frame: &[u8]) -> Option<Inbound> {
        let mut mac = block_on(self.mac.borrow_mut());
        let mut buffer = [0u8; umsh_mac::DEFAULT_FRAME];
        buffer[..frame.len()].copy_from_slice(frame);
        let rx = RxInfo {
            len: frame.len(),
            rssi: -70,
            snr: Snr::from_decibels(5),
            lqi: None,
            origin: RxOrigin::Air,
            buffered: None,
        };
        let well_known = well_known();
        let mut inbound = None;
        block_on(
            mac.process_received_frame(&mut buffer, frame.len(), &rx, |_, event| {
                if let MacEventRef::Received(packet) = event {
                    inbound = inbound_text(&packet, &self.key, &well_known);
                }
            }),
        );
        inbound
    }

    /// Feeds a received text frame to the chat session.
    fn take(&mut self, frame: &[u8], now_ms: u64) {
        let Some(Inbound::Text(text)) = self.receive(frame) else {
            panic!("not a text frame");
        };
        let source = text.source(self.chat.channels()).unwrap();
        self.chat.receive(source, &text.payload, now_ms).unwrap();
    }

    /// Sends what the chat session has released.
    fn pump(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let drain = self.chat.drain();
        self.queue.enqueue(drain.outbound);
        block_on(
            self.queue
                .pump(&self.node, &mut self.chat, &policy(), now_ms),
        );
        self.sent()
    }
}

fn header(frame: &[u8]) -> PacketHeader {
    PacketHeader::parse(frame).unwrap()
}

fn signed(frame: &[u8]) -> bool {
    header(frame)
        .sec_info
        .is_some_and(|sec_info| sec_info.scf.signed())
}

fn refused(inbound: Option<Inbound>) -> Option<Refusal> {
    match inbound {
        Some(Inbound::Refused(refusal)) => Some(refusal),
        _ => None,
    }
}

fn accepted(inbound: &Option<Inbound>) -> bool {
    matches!(inbound, Some(Inbound::Text(_)))
}

// ─── Receiving ───────────────────────────────────────────────────────

#[test]
fn unsigned_emergency_chat_is_refused_and_signed_is_shown() {
    let sender = station(1, &[]);
    let receiver = station(2, &[]);
    let emergency = well_known().emergency;
    let payload = text_payload("Smoke at the trailhead");

    let frame = sender.multicast(&emergency, &payload, &unsigned());
    assert_eq!(
        refused(receiver.receive(&frame)),
        Some(Refusal::UnsignedEmergency)
    );

    let frame = sender.multicast(&emergency, &payload, &unsigned().with_signature());
    assert!(signed(&frame));
    assert!(accepted(&receiver.receive(&frame)));
}

/// The same bytes mean different things on different channels: it is the
/// channel's key, not the payload, that asks for a signature.
#[test]
fn whether_a_signature_is_needed_follows_the_channel() {
    let colliding = colliding_with_emergency();
    let sender = station(1, &[colliding]);
    let receiver = station(2, &[colliding]);
    let well_known = well_known();
    let payload = text_payload("Smoke at the trailhead");

    let on_public = sender.multicast(&well_known.public, &payload, &unsigned());
    assert!(accepted(&receiver.receive(&on_public)));

    let on_emergency = sender.multicast(&well_known.emergency, &payload, &unsigned());
    assert_eq!(
        refused(receiver.receive(&on_emergency)),
        Some(Refusal::UnsignedEmergency)
    );

    // A blind unicast names its sender by its pairwise MIC.
    let direct = sender.blind_unicast(&well_known.emergency, &receiver.key, &payload, &unsigned());
    assert!(matches!(
        header(&direct).packet_type(),
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq
    ));
    block_on(receiver.node.peer(sender.key)).unwrap();
    assert!(accepted(&receiver.receive(&direct)));

    // Another channel that only shares EMERGENCY's identifier is not it.
    let on_colliding = sender.multicast(&colliding, &payload, &unsigned());
    assert_eq!(header(&on_colliding).channel, header(&on_emergency).channel);
    let inbound = receiver.receive(&on_colliding);
    let Some(Inbound::Text(text)) = &inbound else {
        panic!(
            "refused on a channel that is not EMERGENCY: {:?}",
            refused(inbound)
        );
    };
    assert_eq!(text.channel_key(), Some(colliding));
}

/// Earlier traffic from the same sender, on other channels and families,
/// does not stand in the way of its signed `EMERGENCY` message, and a
/// replay of that message never reaches the text layer.
#[test]
fn emergency_after_other_traffic_is_shown_once() {
    let sender = station(1, &[]);
    let receiver = station(2, &[]);
    let well_known = well_known();
    block_on(receiver.node.peer(sender.key)).unwrap();

    let broadcast = {
        block_on(umsh_node::Transport::send_all(
            &sender.node,
            &[PayloadType::Unspecified as u8, 1, 2, 3],
            &SendOptions::default().with_signature(),
        ))
        .unwrap();
        only(sender.sent())
    };
    assert!(header(&broadcast).signature().is_some());
    receiver.receive(&broadcast);

    let public = sender.multicast(&well_known.public, &text_payload("hello"), &unsigned());
    assert!(accepted(&receiver.receive(&public)));

    let emergency = sender.multicast(
        &well_known.emergency,
        &text_payload("Smoke at the trailhead"),
        &unsigned().with_signature(),
    );
    assert!(accepted(&receiver.receive(&emergency)));
    assert!(receiver.receive(&emergency).is_none(), "a replay was shown");
}

// ─── Sending ─────────────────────────────────────────────────────────

/// A message too long for one frame goes out on `EMERGENCY` as signed
/// multicast fragments, each within the frame; a member that missed one
/// asks for it by unsigned blind unicast, and both the repair and a
/// Message Unavailable go back to the whole channel, signed.
#[test]
fn emergency_repairs_go_to_the_channel_signed() {
    let mut sender = station(1, &[]);
    let mut receiver = station(2, &[]);
    let emergency = well_known().emergency;
    let conversation = group(&emergency);

    let budget = sender.budget(conversation);
    assert!(budget < MAX_FRAME, "a signed frame leaves less room");
    let body: String = (0..600)
        .map(|index| char::from(b'a' + (index % 26) as u8))
        .collect();
    let batch = sender
        .chat
        .compose_within(conversation, 1, text(&body), None, budget, 0)
        .unwrap();
    let archives = batch.archives.clone();
    let outbound = sender.chat.commit(batch).unwrap();
    sender.queue.enqueue(outbound);
    let fragments = sender.pump(0);
    assert!(fragments.len() > 1);
    assert_eq!(fragments.len(), archives.len());
    for frame in &fragments {
        assert_eq!(header(frame).packet_type(), PacketType::Multicast);
        assert!(signed(frame));
        assert!(frame.len() <= MAX_RADIO_FRAME);
    }

    // The receiver spoke here lately, so it repairs the gap on its own.
    let spoken = receiver
        .chat
        .compose_within(
            conversation,
            2,
            text("copy"),
            None,
            receiver.budget(conversation),
            0,
        )
        .unwrap();
    let outbound = receiver.chat.commit(spoken).unwrap();
    receiver.queue.enqueue(outbound);
    receiver.pump(0);

    // Two fragments go missing on the way.
    for (index, frame) in fragments.iter().enumerate() {
        if index != 1 && index != 2 {
            receiver.take(frame, 10);
        }
    }
    block_on(sender.node.peer(receiver.key)).unwrap();
    // Soon after: a fragment's arrival defers repair by twice the gap
    // since the one before it.
    let mut now_ms = 100;

    // The first is served from the archive, as it was sent.
    let lookup = repair_lookup(&mut sender, &mut receiver, &mut now_ms);
    let archived = archives
        .iter()
        .find(|archive| archive.key == lookup.key)
        .unwrap();
    let budget = sender.budget(conversation);
    sender.chat.archive_result_within(
        lookup.request_id,
        ArchiveResult::Found {
            payload: &archived.payload,
        },
        budget,
        now_ms,
    );
    let repair = only(sender.pump(now_ms));
    assert_eq!(header(&repair).packet_type(), PacketType::Multicast);
    assert!(signed(&repair), "a group repair goes signed");
    let Some(Inbound::Text(shown)) = receiver.receive(&repair) else {
        panic!("a group repair was not shown");
    };
    assert_eq!(
        shown.payload, archived.payload,
        "the repair resends the archived bytes unchanged"
    );
    let source = shown.source(receiver.chat.channels()).unwrap();
    receiver
        .chat
        .receive(source, &shown.payload, now_ms)
        .unwrap();

    // The second is no longer held.
    let lookup = repair_lookup(&mut sender, &mut receiver, &mut now_ms);
    sender
        .chat
        .archive_result_within(lookup.request_id, ArchiveResult::Unknown, budget, now_ms);
    let unavailable = only(sender.pump(now_ms));
    assert_eq!(header(&unavailable).packet_type(), PacketType::Multicast);
    assert!(signed(&unavailable), "Message Unavailable goes signed");
    let Some(Inbound::Text(shown)) = receiver.receive(&unavailable) else {
        panic!("Message Unavailable was not shown");
    };
    assert_eq!(
        umsh_text::parse_text_message(&shown.payload)
            .unwrap()
            .message_type,
        MessageType::MessageUnavailable
    );
}

/// Ticks `receiver` until it asks `sender` for a missing fragment, which
/// must go as an unsigned blind unicast, and hands the request over.
/// Returns the lookup the sender made of it.
fn repair_lookup(
    sender: &mut Station,
    receiver: &mut Station,
    now_ms: &mut u64,
) -> umsh_text::chat::ArchiveLookup {
    let request = loop {
        assert!(*now_ms < 60_000, "no resend request was sent");
        receiver.chat.tick(*now_ms);
        let sent = receiver.pump(*now_ms);
        *now_ms += 3_000;
        if !sent.is_empty() {
            break only(sent);
        }
    };
    assert!(matches!(
        header(&request).packet_type(),
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq
    ));
    assert!(!signed(&request), "a resend request goes unsigned");
    sender.take(&request, *now_ms);
    sender
        .chat
        .drain()
        .outputs
        .into_iter()
        .find_map(|output| match output {
            ChatOutput::Lookup(lookup) => Some(lookup),
            _ => None,
        })
        .expect("the request was looked up")
}

fn only(mut frames: Vec<Vec<u8>>) -> Vec<u8> {
    assert_eq!(frames.len(), 1);
    frames.pop().unwrap()
}

/// Stored material that no longer fits the destination is answered as
/// unavailable rather than sent.
#[test]
fn material_past_the_current_budget_is_unavailable() {
    let mut sender = station(1, &[]);
    let receiver = station(2, &[]);
    let public = well_known().public;
    let conversation = group(&public);

    // Composed when frames had all the room the engine allows.
    let body: String = core::iter::repeat_n('x', 200).collect();
    let batch = sender
        .chat
        .compose(conversation, 1, text(&body), None, 0)
        .unwrap();
    let archives = batch.archives.clone();
    let outbound = sender.chat.commit(batch).unwrap();
    sender.queue.enqueue(outbound);
    sender.pump(0);
    let largest = archives
        .iter()
        .max_by_key(|archive| archive.payload.len())
        .unwrap();

    // A resend request for it, from a member, under a budget it misses.
    let request = TextMessage {
        message_type: MessageType::ResendRequest,
        sequence: Some(umsh_text::MessageSequence {
            message_id: largest.key.message_id,
            fragment: largest.key.fragment.map(|index| umsh_text::Fragment {
                index,
                count: archives.len() as u8,
            }),
        }),
        channel_group_resend: true,
        ..TextMessage::basic("")
    };
    let mut buffer = [0u8; 64];
    let len = encode_text_message(&request, &mut buffer).unwrap();
    sender
        .chat
        .receive(
            TextSource::ChannelDirect {
                channel: engine().derive_channel_tag(&public),
                peer: receiver.key,
            },
            &buffer[..len],
            10,
        )
        .unwrap();
    let lookup = sender
        .chat
        .drain()
        .outputs
        .into_iter()
        .find_map(|output| match output {
            ChatOutput::Lookup(lookup) => Some(lookup),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        sender.chat.lookup_conversation(lookup.request_id),
        Some(conversation)
    );
    sender.chat.archive_result_within(
        lookup.request_id,
        ArchiveResult::Found {
            payload: &largest.payload,
        },
        largest.payload.len() - 1,
        20,
    );
    let drain = sender.chat.drain();
    let transmissions = drain.outbound.transmissions();
    assert_eq!(transmissions.len(), 1);
    let answer = umsh_text::parse_text_message(&transmissions[0].payload).unwrap();
    assert_eq!(answer.message_type, MessageType::MessageUnavailable);
}

// ─── Sizing ──────────────────────────────────────────────────────────

/// What a signed `EMERGENCY` frame leaves for text, and the longest
/// message that makes at ten fragments, against the engine's default.
#[test]
fn a_signed_emergency_message_is_bounded_by_its_frames() {
    let mut sender = station(1, &[]);
    let well_known = well_known();
    let emergency = group(&well_known.emergency);
    let public = group(&well_known.public);

    // 255 bytes, less 122 for a 16-byte MIC, the full source, flood hops
    // and the signature, less the payload-type byte.
    let budget = sender.budget(emergency);
    assert_eq!(budget, 132);
    assert!(sender.budget(public) > budget);

    assert_eq!(sender.chat.max_body_len(&emergency, MAX_FRAME), 1_600);
    let longest = sender.chat.max_body_len(&emergency, budget);
    assert_eq!(longest, 1_260);

    // A reply that long still goes, within the frame.
    let original = sender
        .chat
        .compose_within(emergency, 1, text("first"), None, budget, 0)
        .unwrap();
    let handle = original.mutations[0].handle;
    sender.chat.commit(original).unwrap();
    let body: String = core::iter::repeat_n('x', longest).collect();
    let reply = sender
        .chat
        .compose_within(
            emergency,
            2,
            ComposeIntent::Reply {
                body: &body,
                regarding: umsh_text::engine::RegardingRef::Handle(handle),
                status: false,
            },
            None,
            budget,
            1,
        )
        .unwrap();
    assert_eq!(reply.archives.len(), 10);
    assert!(
        reply
            .archives
            .iter()
            .all(|archive| archive.payload.len() <= budget)
    );
}

fn text(body: &str) -> ComposeIntent<'_> {
    ComposeIntent::Text {
        body,
        status: false,
    }
}

/// A peer's frames are measured only once the node has registered it, and
/// measuring registers nobody.
#[test]
fn a_peer_is_measured_once_registered() {
    let sender = station(1, &[]);
    let peer = PublicKey([0x33; 32]);
    let conversation = ConversationKey::Direct { peer };
    let query = BudgetQuery::new(sender.chat.channels(), &policy(), conversation).unwrap();
    assert_eq!(query.peer(), Some(peer));
    assert_eq!(block_on(payload_budget(&sender.node, &query)), None);
    assert_eq!(block_on(payload_budget(&sender.node, &query)), None);

    block_on(sender.node.peer(peer)).unwrap();
    let budget = block_on(payload_budget(&sender.node, &query)).unwrap();
    assert!(budget > 0 && budget <= MAX_FRAME);
}

/// An edit's replacement is planned against the budget the edit is
/// composed under, not the original's fragment boundaries.
#[test]
fn an_edit_replacement_is_planned_for_the_current_budget() {
    let mut sender = station(1, &[]);
    let emergency = well_known().emergency;
    let conversation = group(&emergency);
    let body: String = core::iter::repeat_n('x', 300).collect();

    let batch = sender
        .chat
        .compose(conversation, 1, text(&body), None, 0)
        .unwrap();
    let original = batch.mutations[0].handle;
    let original_id = batch.archives[0].key.message_id;
    let original_fragments = batch.archives.len();
    sender.chat.commit(batch).unwrap();

    let budget = sender.budget(conversation);
    let edited: String = core::iter::repeat_n('y', 300).collect();
    let batch = sender
        .chat
        .compose_within(
            conversation,
            2,
            ComposeIntent::Edit {
                original: ComposeRef::Handle(original),
                body: &edited,
            },
            None,
            budget,
            1,
        )
        .unwrap();
    let replacement: Vec<_> = batch
        .archives
        .iter()
        .filter(|archive| archive.key.message_id == original_id)
        .collect();
    assert!(replacement.len() > original_fragments);
    for archive in &replacement {
        assert!(archive.payload.len() <= budget, "{}", archive.payload.len());
    }
}

// ─── Plumbing ────────────────────────────────────────────────────────

/// Runs `future` to completion. Everything here is ready at once, or as
/// soon as the MAC's own borrow is released.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}
