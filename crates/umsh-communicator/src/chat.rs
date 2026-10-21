//! The chat half of the communicator's node: the chat facade, fed the
//! frames the device node receives, over the store that keeps what they
//! say.
//!
//! A channel is held while the device holds it (`PROP_DEV_CHANNEL_KEYS`).
//! The device reports only its channels' tags: the keys of `public` and
//! `EMERGENCY` are known by name, a channel joined here brings its own,
//! and the device node hands over the rest.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Write as _;

use umsh_core::{ChannelKey, ChannelTag, NodeHint, PublicKey, base58};
use umsh_text::chat::{Change, ChatFacade, ChatOutput, Seeds};
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    self, ArchiveKey, ArchiveResult, ComposeIntent, ComposeRef, EngineConfig, MAX_FRAME,
    RegardingRef,
};
use umsh_text::node_adapter::{
    Departed, Departure, InboundText, Sent, TransmitPolicy, TransmitQueue,
    WELL_KNOWN_CHANNEL_MAX_FLOOD_HOPS, WellKnownChannels,
};
use umsh_text::validate::DirectChannelProfile;
use umsh_text::{ConversationKey, MessageType, SenderScope};
use umsh_ux_communicator::avatar::{self, AvatarStyle, PeerShape};
use umsh_ux_communicator::buoyant::view::{EditBuffer, EditText as _};
use umsh_ux_communicator::heapless::String;
use umsh_ux_communicator::model::{
    self, ChatKind, ChatSummary, Details, Member, Message, NodeEvent, Presence, Sender,
};
use umsh_ux_communicator::text::{DraftText, SharedText, TextHeap};

use crate::batch::{Batch, Committed, Subject};
use crate::ids::{ChatId, MessageId};
use crate::record::{
    self, BODY_MAX, BuiltinChannel, ChannelAccess, ChannelChange, ChatChange, ChatRecord, LinkInfo,
    MessageRecord,
};
use crate::store::ChatStore;
use crate::task::Command;

mod channels;
mod peers;

pub(crate) use channels::Joined;

use peers::{Link, shape, short_age};

/// The most of a message a reply's quote keeps, in octets: more than one
/// line of a bubble shows.
const QUOTED_MAX: usize = 96;

/// How many outbound checkpoints seed the engine when the chats start.
const RESTORED_CHECKPOINTS: usize = 32;

/// How many times one input's outputs are settled. Answering a resend
/// request or failing a frame can produce more, which settle in turn.
const SETTLE_ROUNDS: usize = 4;

/// How many of the chats' frames the device node holds at once: half its
/// transmit queue, so a long message leaves room for what else it sends.
const TRANSMIT_WINDOW: usize = 4;

/// How far a message travels when nothing narrower applies: as far as
/// the protocol lets `public` go.
const FLOOD_HOPS: u8 = WELL_KNOWN_CHANNEL_MAX_FLOOD_HOPS;

/// The fragments a message can have, each with its bit in [`Delivery`].
///
/// [`Delivery`]: crate::Delivery
const FRAGMENTS: u8 = 16;

/// What the node needs of the board's cryptography, which it does not
/// carry itself.
#[derive(Clone, Copy)]
pub struct ChannelCrypto {
    /// The keys of `public` and `EMERGENCY`.
    pub well_known: WellKnownChannels,
    /// A channel's tag, as `umsh_crypto::CryptoEngine::derive_channel_tag`
    /// derives it.
    pub tag: fn(&ChannelKey) -> ChannelTag,
    /// A named channel's key, as
    /// `umsh_crypto::CryptoEngine::derive_named_channel_key` derives it, or
    /// `None` for a name that names no channel.
    pub named: fn(&str) -> Option<ChannelKey>,
    /// Whether a signature by a key verifies, as
    /// `umsh_crypto::verify_ed25519_signature` checks it: the check a
    /// shared node's identity needs.
    pub verify: fn(&PublicKey, &[u8], &[u8; 64]) -> bool,
}

impl ChannelCrypto {
    /// The channel keys a communicator's device lists hold after a reset
    /// with none kept: `public` and `EMERGENCY` (`ulcp-device.md`, Lists
    /// Held by the Device's Store). The board hands them to the session as
    /// it holds the lists.
    pub fn starting_keys(&self) -> [[u8; 32]; 2] {
        [self.well_known.public.0, self.well_known.emergency.0]
    }

    /// The software crypto back end's derivations.
    #[cfg(feature = "software-crypto")]
    pub fn software() -> Self {
        fn engine() -> umsh_crypto::CryptoEngine<
            umsh_crypto::software::SoftwareAes,
            umsh_crypto::software::SoftwareSha256,
        > {
            umsh_crypto::CryptoEngine::new(
                umsh_crypto::software::SoftwareAes,
                umsh_crypto::software::SoftwareSha256,
            )
        }
        Self {
            well_known: WellKnownChannels::derive(),
            tag: |key| engine().derive_channel_tag(key),
            named: |name| engine().derive_named_channel_key(name).ok(),
            verify: umsh_crypto::verify_ed25519_signature,
        }
    }

    fn builtin(&self, key: &ChannelKey) -> Option<BuiltinChannel> {
        if self.well_known.is_public(key) {
            Some(BuiltinChannel::Public)
        } else if self.well_known.is_emergency(key) {
            Some(BuiltinChannel::Emergency)
        } else {
            None
        }
    }
}

/// The chats: the facade, once the device identity is known, and the
/// store.
pub(crate) struct Chats<S> {
    store: S,
    crypto: ChannelCrypto,
    heap: TextHeap,
    facade: Option<ChatFacade<DirectChannelProfile>>,
    /// What the facade's engine runs as.
    seeds: Seeds,
    /// The store's IDs for the engine's handles, for the engine's
    /// lifetime.
    handles: BTreeMap<MessageHandle, MessageId>,
    /// The device's channels, by tag.
    held: Vec<ChannelTag>,
    /// The frames the facade released, on their way to the device node.
    outbox: TransmitQueue,
    policy: TransmitPolicy,
    /// What each composed message is told apart by.
    token: u32,
    /// Messages sent again that have had no word since.
    retrying: BTreeSet<MessageId>,
    /// How each node was last heard, which the store does not keep.
    links: BTreeMap<[u8; 32], Link>,
    /// The round trip of each peer's last answered ping, in milliseconds.
    pings: BTreeMap<[u8; 32], u64>,
    /// Sessions with forward secrecy, asked for or held, by peer.
    secrecy: BTreeMap<[u8; 32], peers::Session>,
    /// What the chats ask of the device node besides sending frames.
    commands: VecDeque<Command>,
    /// The saved peers, as last taken from the device.
    saved: Vec<[u8; 32]>,
    /// Room for one body, read before it goes onto the text heap.
    body: RefCell<Vec<u8>>,
}

impl<S: ChatStore> Chats<S> {
    pub fn new(store: S, crypto: ChannelCrypto, heap: TextHeap) -> Self {
        Self {
            store,
            crypto,
            heap,
            facade: None,
            seeds: Seeds {
                session_id: 0,
                jitter_seed: 0,
            },
            handles: BTreeMap::new(),
            held: Vec::new(),
            outbox: TransmitQueue::new(TRANSMIT_WINDOW),
            policy: TransmitPolicy {
                default_flood_hops: FLOOD_HOPS,
                well_known: crypto.well_known,
            },
            token: 0,
            retrying: BTreeSet::new(),
            links: BTreeMap::new(),
            pings: BTreeMap::new(),
            secrecy: BTreeMap::new(),
            commands: VecDeque::new(),
            saved: Vec::new(),
            body: RefCell::new(vec![0; BODY_MAX]),
        }
    }

    pub fn started(&self) -> bool {
        self.facade.is_some()
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Starts the chats as `local_key`, the device identity, carrying on
    /// each outbound stream from where the store left it. What the store
    /// shows on its way went with the last session, and has failed.
    pub fn start(
        &mut self,
        local_key: PublicKey,
        seeds: Seeds,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        if self.facade.is_some() {
            return;
        }
        // Left unwritten, those messages read as sending until retried.
        _ = self.store.interrupt();
        let mut facade = ChatFacade::new(
            DirectChannelProfile,
            local_key,
            EngineConfig::default(),
            seeds,
        );
        let checkpoints: Vec<_> = self
            .store
            .recent_checkpoints(RESTORED_CHECKPOINTS)
            .collect();
        facade.restore(&checkpoints, now_ms);
        self.facade = Some(facade);
        self.seeds = seeds;
        let held = core::mem::take(&mut self.held);
        self.hold(held.into_iter(), events);
    }

    /// The device holds exactly `tags`.
    pub fn hold(
        &mut self,
        tags: impl Iterator<Item = ChannelTag>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        self.held.clear();
        self.held.extend(tags);
        let Some(facade) = &mut self.facade else {
            return;
        };
        let gone: Vec<ChannelTag> = facade
            .channels()
            .tags()
            .filter(|tag| !self.held.contains(tag))
            .collect();
        for tag in &gone {
            facade.channels_mut().remove(tag);
        }
        let well_known = self.crypto.well_known;
        for key in [well_known.public, well_known.emergency] {
            let tag = (self.crypto.tag)(&key);
            if self.held.contains(&tag) {
                self.register(tag, key, events);
            }
        }
    }

    /// Whether the device holds a channel the chats have no key for: one
    /// joined elsewhere, whose key the device node has.
    pub fn misses_keys(&self) -> bool {
        self.facade
            .as_ref()
            .is_some_and(|facade| self.held.iter().any(|tag| !facade.channels().contains(tag)))
    }

    /// Takes `key`, the key of a channel the device node holds, for the
    /// channel the device lists under its tag.
    pub fn learn_key(&mut self, key: ChannelKey, events: &mut dyn FnMut(NodeEvent)) {
        let tag = (self.crypto.tag)(&key);
        if self.held.contains(&tag) {
            self.register(tag, key, events);
        }
    }

    /// Holds the channel `key` names in the facade, and keeps a chat for
    /// it.
    fn register(&mut self, tag: ChannelTag, key: ChannelKey, events: &mut dyn FnMut(NodeEvent)) {
        let Some(facade) = &mut self.facade else {
            return;
        };
        if facade.channels().contains(&tag) {
            return;
        }
        facade.channels_mut().register(tag, key, None);
        if !self
            .store
            .channels()
            .flatten()
            .any(|channel| channel.tag == tag)
        {
            let builtin = self.crypto.builtin(&key);
            let (name, access) = match builtin {
                Some(builtin @ BuiltinChannel::Public) => {
                    (record::name(builtin.name()), ChannelAccess::Named)
                }
                Some(builtin @ BuiltinChannel::Emergency) => {
                    (record::name(builtin.name()), ChannelAccess::Clear)
                }
                None => (channels::default_name(&key), ChannelAccess::Private),
            };
            let change = ChannelChange::Add {
                name: name.as_str(),
                access,
                builtin,
            };
            if self.store.update_channel(&tag, change).is_err() {
                return;
            }
        }
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        if self.store.chat_for(&conversation).is_none() {
            let open = ChatChange::Open {
                conversation,
                name: None,
            };
            if let Ok(chat) = self.store.update_chat(ChatId(0), open) {
                events(NodeEvent::ChatChanged(chat.0));
            }
        }
    }

    // ─── Input ───────────────────────────────────────────────────────

    /// Takes one received text frame, kept at `time`, the wall-clock
    /// seconds when known.
    pub fn receive(
        &mut self,
        inbound: InboundText,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        // The key that authenticated the frame is one the node holds.
        if let Some(key) = inbound.channel_key() {
            let tag = (self.crypto.tag)(&key);
            self.register(tag, key, events);
        }
        let Some(facade) = &mut self.facade else {
            return;
        };
        let Some(source) = inbound.source(facade.channels()) else {
            return;
        };
        if let Some(key) = source.full_key() {
            self.hear(&key, &inbound.rx, now_ms, events);
        }
        let Some(facade) = &mut self.facade else {
            return;
        };
        let at = inbound.received_at_ms.unwrap_or(now_ms);
        // A frame the engine cannot take is dropped; its diagnostic drains
        // with everything else.
        let _ = facade.receive(source, &inbound.payload, at);
        let link = LinkInfo {
            rssi_dbm: inbound.rx.rssi_dbm,
            snr_centibels: inbound.rx.snr_centibels,
            hop_count: inbound.rx.hop_count,
            authenticated: inbound.rx.source_authenticated,
            forward_secret: inbound.rx.forward_secret,
        };
        self.settle(Some(link), now_ms, time, events);
    }

    /// Advances the engine's timers: reassembly, notification, repair.
    pub fn tick(&mut self, now_ms: u64, time: Option<u32>, events: &mut dyn FnMut(NodeEvent)) {
        let Some(facade) = &mut self.facade else {
            return;
        };
        facade.tick(now_ms);
        self.settle(None, now_ms, time, events);
        self.lapse_links(now_ms, events);
    }

    /// Commits what the facade produced and answers what it asked. `link`
    /// describes the frame behind the first round's outputs.
    fn settle(
        &mut self,
        mut link: Option<LinkInfo>,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        for _ in 0..SETTLE_ROUNDS {
            let Some(facade) = &mut self.facade else {
                return;
            };
            let drain = facade.drain();
            if drain.is_empty() {
                return;
            }
            self.outbox.enqueue(drain.outbound);
            self.commit(&drain.outputs, link.take(), time, events);
            for output in &drain.outputs {
                match output {
                    ChatOutput::Lookup(lookup) => {
                        let mut payload = [0u8; MAX_FRAME];
                        let result = match self.store.archive(&lookup.key, &mut payload) {
                            Ok(Some(payload)) => ArchiveResult::Found { payload },
                            _ => ArchiveResult::Unknown,
                        };
                        if let Some(facade) = &mut self.facade {
                            facade.archive_result(lookup.request_id, result, now_ms);
                        }
                    }
                    ChatOutput::SenderResolved(_) => events(NodeEvent::IdentitiesLearned),
                    _ => {}
                }
            }
        }
    }

    fn commit(
        &mut self,
        outputs: &[ChatOutput],
        link: Option<LinkInfo>,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let committed = {
            let handles = &self.handles;
            let resolve = |handle| handles.get(&handle).copied();
            let mut batch = Batch::new(time, &resolve);
            let mut kept = false;
            for output in outputs {
                kept |= batch.push_chat(output, link);
            }
            if !kept {
                return;
            }
            // A received message the store cannot keep is lost to the
            // transcript; there is nothing to take back.
            let Ok(committed) = self.store.commit(&batch) else {
                return;
            };
            committed
        };
        self.handles.extend(committed.inserted.iter().copied());
        for output in outputs {
            if let ChatOutput::Delivery(delivery) = output
                && let Some(id) = self.handles.get(&delivery.handle)
            {
                self.retrying.remove(id);
            }
        }

        // What arrives in full, inbound and meant to be noticed, is
        // announced as an arrival; anything else that changed, as a change.
        let arrived: Vec<MessageId> = outputs
            .iter()
            .filter_map(|output| match output {
                ChatOutput::Mutation(mutation) => Some(mutation),
                _ => None,
            })
            .filter(|mutation| match &mutation.change {
                Change::Insert(insert) => {
                    insert.direction == engine::Direction::Inbound
                        && insert.presence == engine::Presence::Present
                        && insert.notify
                }
                Change::UpdateBody { notify, .. } => *notify,
                Change::Edit { .. } | Change::Delete { .. } => false,
            })
            .filter_map(|mutation| self.handles.get(&mutation.handle).copied())
            .collect();
        self.announce(&committed, &arrived, events);
    }

    /// Tells the interface what a commit changed. The messages in
    /// `arrived` are announced as arrivals.
    fn announce(
        &self,
        committed: &Committed,
        arrived: &[MessageId],
        events: &mut dyn FnMut(NodeEvent),
    ) {
        for &id in &committed.messages {
            let Ok(Some(record)) = self.store.message(id) else {
                continue;
            };
            let (chat, message) = (record.chat.0, id.0);
            events(if arrived.contains(&id) {
                NodeEvent::Arrived { chat, message }
            } else {
                NodeEvent::MessageChanged { chat, message }
            });
        }
        for chat in &committed.chats {
            events(NodeEvent::ChatChanged(chat.0));
        }
    }

    // ─── Sending ─────────────────────────────────────────────────────

    /// Carries `name` as the Sender Handle of our channel messages.
    pub fn set_handle(&mut self, name: &str) {
        if let Some(facade) = &mut self.facade
            && facade.local_handle() != name
        {
            facade.set_local_handle(name);
        }
    }

    /// Keeps `text`, in reply to `reply_to` if it is one, as the newest
    /// message of `chat`, and queues it to go. A reply whose original
    /// can no longer be named goes as a plain message. With
    /// `forward_secret`, as the composer showed it, it goes to the chat's
    /// peer under a session with forward secrecy or not at all; without,
    /// never under one.
    pub fn send(
        &mut self,
        chat: model::ChatId,
        text: &str,
        reply_to: Option<model::MessageId>,
        forward_secret: bool,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Message> {
        let conversation = self.conversation(chat)?;
        let intent = match reply_to.and_then(|id| self.regarding(id, &conversation)) {
            Some(regarding) => ComposeIntent::Reply {
                body: text,
                regarding,
                status: false,
            },
            None => ComposeIntent::Text {
                body: text,
                status: false,
            },
        };
        // A peer who prefers forward secrecy has a session asked for
        // before anything is said, when none is.
        if let ConversationKey::Direct { peer } = conversation {
            self.keep_secrecy(peer);
        }
        let committed = self.compose(conversation, intent, forward_secret, now_ms, time, events)?;
        let &(_, id) = committed.inserted.first()?;
        _ = self
            .store
            .update_chat(ChatId(chat), ChatChange::Draft(None));
        let record = self.store.message(id).ok()??;
        self.message_of(&record, &conversation)
    }

    /// Keeps `reaction` as mine to `message` in `chat`, and sends it;
    /// `None` withdraws mine.
    pub fn react(
        &mut self,
        chat: model::ChatId,
        message: model::MessageId,
        reaction: Option<model::Reaction>,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let Some(conversation) = self.conversation(chat) else {
            return;
        };
        let Some(regarding) = self.regarding(message, &conversation) else {
            return;
        };
        let body = reaction.map_or("", |reaction| emote(reaction).token());
        let intent = ComposeIntent::Reply {
            body,
            regarding,
            status: true,
        };
        let forward_secret = self.holds_secrecy(&conversation);
        _ = self.compose(conversation, intent, forward_secret, now_ms, time, events);
    }

    /// Deletes my `message` in `chat` for everyone: its body goes, and the
    /// deletion is sent. Returns whether it was composed.
    pub fn delete_message(
        &mut self,
        chat: model::ChatId,
        message: model::MessageId,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> bool {
        let Some(conversation) = self.conversation(chat) else {
            return false;
        };
        let Ok(Some(record)) = self.store.message(MessageId(message)) else {
            return false;
        };
        if record.chat.0 != chat || record.direction != engine::Direction::Outbound {
            return false;
        }
        let original = match (self.handle_of(record.id), record.wire_id) {
            (Some(handle), _) => ComposeRef::Handle(handle),
            (None, Some(message_id)) => ComposeRef::Wire {
                message_id,
                epoch: record.epoch,
            },
            (None, None) => return false,
        };
        self.retrying.remove(&record.id);
        let forward_secret = self.holds_secrecy(&conversation);
        self.compose(
            conversation,
            ComposeIntent::Delete { original },
            forward_secret,
            now_ms,
            time,
            events,
        )
        .is_some()
    }

    /// Sends `message` in `chat`, which was to go under a session with
    /// forward secrecy and went unacknowledged, again without one, as the
    /// user chose to. Returns whether it is on its way.
    pub fn retry_without_secrecy(
        &mut self,
        chat: model::ChatId,
        message: model::MessageId,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> bool {
        let Ok(Some(record)) = self.store.message(MessageId(message)) else {
            return false;
        };
        if record.chat.0 != chat || !record.flags.forward_secret {
            return false;
        }
        let resolve = |_| None;
        let mut batch = Batch::new(time, &resolve);
        batch.secrecy(Subject::Kept(record.id), false);
        let Ok(committed) = self.store.commit(&batch) else {
            return false;
        };
        self.announce(&committed, &[], events);
        self.retry(chat, message, now_ms, time, events)
    }

    /// Sends again each fragment of `message` in `chat` that went
    /// unacknowledged, while its wire ID is still the message's in its
    /// stream, before a restart or since. Returns whether any is on its
    /// way.
    pub fn retry(
        &mut self,
        chat: model::ChatId,
        message: model::MessageId,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> bool {
        let Some(conversation) = self.conversation(chat) else {
            return false;
        };
        let Ok(Some(record)) = self.store.message(MessageId(message)) else {
            return false;
        };
        let Some(message_id) = record.wire_id else {
            return false;
        };
        if record.chat.0 != chat || record.direction != engine::Direction::Outbound {
            return false;
        }
        // One to go under forward secrecy asks for a session, if none is.
        if let ConversationKey::Direct { peer } = conversation
            && record.flags.forward_secret
        {
            self.keep_secrecy(peer);
        }
        let known = self.handle_of(record.id);
        let Some(facade) = &mut self.facade else {
            return false;
        };
        // A message sent before a restart is taken back under its wire ID.
        let handle = match known {
            Some(handle) => handle,
            None => {
                let stored = self.store.checkpoint(&conversation);
                let Some(handle) = facade.adopt(
                    conversation,
                    message_id,
                    record.epoch,
                    stored.as_ref(),
                    now_ms,
                ) else {
                    return false;
                };
                self.handles.insert(handle, record.id);
                handle
            }
        };
        let mut payload = [0u8; MAX_FRAME];
        let mut queued = false;
        // An unfragmented message is archived whole; a fragmented one by
        // fragment, from the first.
        let whole = ArchiveKey {
            conversation,
            message_id,
            fragment: None,
        };
        let keys = core::iter::once(whole).chain((0..FRAGMENTS).map(|index| ArchiveKey {
            fragment: Some(index),
            ..whole
        }));
        for key in keys {
            let bit = 1u16 << key.fragment.unwrap_or(0);
            match self.store.archive(&key, &mut payload) {
                Ok(Some(frame)) if record.delivery.acked & bit == 0 => {
                    queued |= facade.retransmit(&key, handle, frame);
                }
                Ok(Some(_)) => {}
                _ if key.fragment.is_some() => break,
                _ => {}
            }
            if key.fragment.is_none() && queued {
                break;
            }
        }
        if queued {
            self.retrying.insert(record.id);
            events(NodeEvent::MessageChanged { chat, message });
        }
        self.settle(None, now_ms, time, events);
        queued
    }

    /// Composes `intent` into `conversation`, keeps what it makes, and
    /// queues its frames. `None` when it cannot be composed or kept.
    fn compose(
        &mut self,
        conversation: ConversationKey,
        intent: ComposeIntent<'_>,
        forward_secret: bool,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Committed> {
        let facade = self.facade.as_mut()?;
        self.token = self.token.wrapping_add(1);
        // The stored checkpoint carries the conversation's sequence on when
        // the engine no longer remembers it.
        let stored = self.store.checkpoint(&conversation);
        let composed = facade
            .compose(conversation, self.token, intent, stored.as_ref(), now_ms)
            .ok()?;
        let kept = {
            let handles = &self.handles;
            let resolve = |handle| handles.get(&handle).copied();
            let mut batch = Batch::new(time, &resolve);
            batch.push_composed(&composed);
            // Kept with the message, so that it is never found without.
            if forward_secret && matches!(conversation, ConversationKey::Direct { .. }) {
                for mutation in &composed.mutations {
                    if matches!(mutation.change, Change::Insert(_)) {
                        batch.secrecy(Subject::Handle(mutation.handle), true);
                    }
                }
            }
            self.store.commit(&batch)
        };
        let Ok(committed) = kept else {
            self.reject(composed, now_ms, time, events);
            return None;
        };
        self.handles.extend(committed.inserted.iter().copied());
        if let Some(facade) = &mut self.facade
            && let Ok(outbound) = facade.commit(composed)
        {
            self.outbox.enqueue(outbound);
        }
        self.announce(&committed, &[], events);
        Some(committed)
    }

    /// Gives up on a composed message the store could not keep. The engine
    /// is rebuilt from what the store holds, as a new session: everything
    /// on its way fails first, since no word of it will be taken.
    fn reject(
        &mut self,
        composed: umsh_text::chat::PendingBatch,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let Some(facade) = &mut self.facade else {
            return;
        };
        // Their receipts are not canceled: whatever still goes out, its
        // word is the old session's, and ignored.
        _ = self.outbox.fail_all(facade, now_ms);
        let checkpoints: Vec<_> = self
            .store
            .recent_checkpoints(RESTORED_CHECKPOINTS)
            .collect();
        self.seeds.session_id = self.seeds.session_id.wrapping_add(1).max(1);
        let Ok(drain) = facade.reject(composed, &checkpoints, self.seeds, now_ms) else {
            return;
        };
        self.commit(&drain.outputs, None, time, events);
        self.handles.clear();
        self.retrying.clear();
    }

    /// The next frame for the device node, or `None` while nothing may go.
    pub fn depart(
        &mut self,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Departure> {
        loop {
            let facade = self.facade.as_mut()?;
            match self.outbox.depart(facade.channels(), &self.policy)? {
                Ok(mut departure) => {
                    self.bind_secrecy(&mut departure);
                    return Some(departure);
                }
                Err(undeliverable) => {
                    undeliverable.fail(facade, now_ms);
                    self.settle(None, now_ms, time, events);
                }
            }
        }
    }

    /// Holds a frame to a peer to what was decided when its message was
    /// sent: under a session with forward secrecy, or never under one.
    fn bind_secrecy(&self, departure: &mut Departure) {
        if departure.peer().is_none() {
            return;
        }
        let Some(record) = departure
            .message()
            .and_then(|handle| self.handles.get(&handle))
            .and_then(|&id| self.store.message(id).ok().flatten())
        else {
            return;
        };
        departure.require_forward_secrecy(record.flags.forward_secret);
    }

    /// Takes how the device node took `departure`. Returns whether it has
    /// room for more.
    pub fn departed(
        &mut self,
        departure: Departure,
        sent: Sent,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> bool {
        match self.outbox.departed(departure, sent, now_ms) {
            Departed::Sent => true,
            Departed::Failed(undeliverable) => {
                if let Some(facade) = &mut self.facade {
                    undeliverable.fail(facade, now_ms);
                }
                self.settle(None, now_ms, time, events);
                true
            }
            Departed::Busy => false,
        }
    }

    /// Takes the word on the frames in flight: transmitted, acknowledged,
    /// or failed.
    pub fn service(&mut self, now_ms: u64, time: Option<u32>, events: &mut dyn FnMut(NodeEvent)) {
        let Some(facade) = &mut self.facade else {
            return;
        };
        // A frame that never resolves keeps its slot in the window; there
        // is nothing to do about one here.
        _ = self.outbox.service(facade, now_ms);
        self.settle(None, now_ms, time, events);
    }

    /// The engine's handle for the message the store keeps as `id`.
    fn handle_of(&self, id: MessageId) -> Option<MessageHandle> {
        self.handles
            .iter()
            .find(|&(_, &kept)| kept == id)
            .map(|(&handle, _)| handle)
    }

    /// What a reply or reaction to `message` names it by: its handle while
    /// the engine knows it, else its coordinates on the wire.
    fn regarding(
        &self,
        message: model::MessageId,
        conversation: &ConversationKey,
    ) -> Option<RegardingRef> {
        let id = MessageId(message);
        if let Some(handle) = self.handle_of(id) {
            return Some(RegardingRef::Handle(handle));
        }
        let record = self.store.message(id).ok()??;
        if self.store.chat_for(conversation) != Some(record.chat) {
            return None;
        }
        let sender_hint = match record.sender {
            SenderScope::ClaimedMember(hint) => Some(hint),
            SenderScope::Peer(key) => Some(key.hint()),
            SenderScope::Local => None,
        };
        Some(RegardingRef::Wire {
            message_id: record.wire_id?,
            direction: record.direction,
            sender_hint,
            epoch: Some(record.epoch),
        })
    }

    // ─── Reads ───────────────────────────────────────────────────────

    pub fn chats(&self, chats: &mut model::Chats) {
        for record in self.store.chats().flatten() {
            if chats.is_full() {
                break;
            }
            if let Some(summary) = self.summary(&record) {
                _ = chats.push(summary);
            }
        }
    }

    pub fn chat(&self, chat: model::ChatId) -> Option<ChatSummary> {
        let record = self
            .store
            .chats()
            .flatten()
            .find(|record| record.id.0 == chat)?;
        self.summary(&record)
    }

    pub fn load(&self, chat: model::ChatId, messages: &mut model::Messages) {
        let Some(conversation) = self.conversation(chat) else {
            return;
        };
        let newest: Vec<MessageRecord> = self
            .store
            .messages(ChatId(chat), None)
            .flatten()
            .take(model::MAX_MESSAGES)
            .collect();
        for record in newest.iter().rev() {
            if let Some(message) = self.message_of(record, &conversation) {
                model::push_newest(messages, message);
            }
        }
    }

    pub fn message(&self, chat: model::ChatId, message: model::MessageId) -> Option<Message> {
        let record = self.store.message(MessageId(message)).ok()??;
        if record.chat.0 != chat {
            return None;
        }
        self.message_of(&record, &self.conversation(chat)?)
    }

    pub fn opened(&mut self, chat: model::ChatId) {
        _ = self.store.update_chat(ChatId(chat), ChatChange::Read);
    }

    /// Keeps `text` as the chat's draft; text that is only whitespace
    /// clears it.
    pub fn save_draft(&mut self, chat: model::ChatId, text: &str) {
        let draft = Some(text).filter(|text| !text.trim().is_empty());
        let unchanged = {
            let mut body = self.body.borrow_mut();
            let kept = self.store.draft(ChatId(chat), &mut body[..]).ok().flatten();
            kept == draft
        };
        if !unchanged {
            _ = self
                .store
                .update_chat(ChatId(chat), ChatChange::Draft(draft));
        }
    }

    /// How `message` reached this device, and who reacted to it: this
    /// node drawn as `mine`.
    pub fn details(
        &self,
        chat: model::ChatId,
        message: model::MessageId,
        mine: &AvatarStyle,
    ) -> Option<Details> {
        let record = self.store.message(MessageId(message)).ok()??;
        if record.chat.0 != chat {
            return None;
        }
        let mut details = Details {
            time: record.time,
            ..Details::default()
        };
        if let Some(link) = record.link {
            details.hops = link.hop_count;
            details.rssi = link.rssi_dbm;
            details.snr = link.snr_centibels;
            details.forward_secret = link.forward_secret;
        }
        // Mine went under forward secrecy if it went at all.
        if record.direction == engine::Direction::Outbound {
            details.forward_secret = record.flags.forward_secret;
        }
        let conversation = self.conversation(chat)?;
        let reactors: Vec<_> = self.store.reactors(MessageId(message)).collect();
        // The latest, as many as are shown.
        let skip = reactors.len().saturating_sub(model::MAX_REACTORS);
        for reactor in &reactors[skip..] {
            let shown = if reactor.mine {
                Some((None, mine.clone()))
            } else {
                self.reactor(reactor.sender, &conversation)
                    .and_then(|(name, avatar)| {
                        Some((Some(SharedText::new(self.heap, &name)?), avatar))
                    })
            };
            if let Some((name, avatar)) = shown {
                _ = details.reactors.push(model::Reactor {
                    name,
                    avatar,
                    reaction: reaction(reactor.reaction),
                });
            }
        }
        Some(details)
    }

    /// Who reacted to a message in `conversation`, as its details show
    /// them: the peer of a direct chat as the chat shows them; a channel's
    /// member by the name they are known by, or else by their address.
    fn reactor(
        &self,
        sender: SenderScope,
        conversation: &ConversationKey,
    ) -> Option<(String<32>, AvatarStyle)> {
        let ConversationKey::ChannelGroup { channel } = conversation else {
            let chat = self.store.chat_for(conversation)?;
            let record = self
                .store
                .chats()
                .flatten()
                .find(|record| record.id == chat)?;
            let (name, avatar, _) = self.face(&record)?;
            return Some((name, avatar));
        };
        let (hint, key) = match sender {
            SenderScope::Peer(key) => (key.hint(), Some(key)),
            SenderScope::ClaimedMember(hint) => (
                hint,
                self.facade
                    .as_ref()
                    .and_then(|facade| facade.member_key(channel, &hint))
                    .or_else(|| self.only_peer_with(hint)),
            ),
            SenderScope::Local => return None,
        };
        let mut lettering = String::<8>::new();
        let shape = match key {
            Some(key) => {
                _ = lettering.push_str(address(&key.0).get(..4).unwrap_or_default());
                PeerShape::Circle
            }
            None => {
                _ = write!(lettering, "{hint}");
                PeerShape::Hexagon
            }
        };
        let named = key
            .and_then(|key| self.store.peer(&key).ok().flatten())
            .and_then(|kept| kept.name.as_deref().map(cut));
        let name = named.unwrap_or_else(|| cut(&unnamed_member(&lettering)));
        Some((name, AvatarStyle::peer(hint.0, &lettering, shape)))
    }

    pub fn member(
        &self,
        chat: model::ChatId,
        message: model::MessageId,
        now_ms: u64,
        wall: Option<u32>,
    ) -> Option<Member> {
        let record = self.store.message(MessageId(message)).ok()??;
        if record.chat.0 != chat {
            return None;
        }
        let conversation = self.conversation(chat)?;
        let (hint, key) = self.sender_key(&record, &conversation)?;
        let sender = self.sender(&record, &conversation)?;
        let mut hint_text = String::new();
        _ = write!(hint_text, "{hint}");
        let kept = key.and_then(|key| self.store.peer(&key).ok().flatten());
        Some(Member {
            sender,
            hint: hint_text,
            address: key.map(|key| address(&key.0)),
            heard: key
                .and_then(|key| self.heard_ago(&key, kept.as_ref(), now_ms, wall))
                .map(short_age)
                .unwrap_or_default(),
            saved: kept.is_some_and(|kept| kept.saved),
        })
    }

    /// The peer at the other end of the direct chat `chat`.
    pub fn chat_member(
        &self,
        chat: model::ChatId,
        now_ms: u64,
        wall: Option<u32>,
    ) -> Option<Member> {
        let record = self
            .store
            .chats()
            .flatten()
            .find(|record| record.id.0 == chat)?;
        let ConversationKey::Direct { peer } = record.conversation else {
            return None;
        };
        let (name, avatar, _) = self.face(&record)?;
        let mut member = self.member_of(&peer, now_ms, wall);
        // Called as their chat is.
        member.sender = Sender {
            name: cut(&name),
            avatar,
        };
        Some(member)
    }

    /// Deletes the direct chat `chat` and its messages. The store keeps
    /// where the conversation stood, so its peer's next message is told
    /// from what came before and starts a new chat.
    pub fn delete_chat(&mut self, chat: model::ChatId, events: &mut dyn FnMut(NodeEvent)) {
        if !matches!(
            self.conversation(chat),
            Some(ConversationKey::Direct { .. })
        ) {
            return;
        }
        if self
            .store
            .update_chat(ChatId(chat), ChatChange::Delete)
            .is_ok()
        {
            events(NodeEvent::ChatRemoved(chat));
        }
    }

    pub(super) fn conversation(&self, chat: model::ChatId) -> Option<ConversationKey> {
        self.store
            .chats()
            .flatten()
            .find(|record| record.id.0 == chat)
            .map(|record| record.conversation)
    }

    fn summary(&self, record: &ChatRecord) -> Option<ChatSummary> {
        let (name, avatar, kind) = self.face(record)?;
        let mut summary = ChatSummary::new(record.id.0, avatar, &name, self.heap);
        summary.kind = kind;
        summary.unread = record.unread > 0;
        summary.muted = record.muted;
        summary.last_activity = record.last_activity;
        summary.forward_secret = self.holds_secrecy(&record.conversation);
        let last = self.store.messages(record.id, None).flatten().next();
        if let Some(last) = last.and_then(|last| self.message_of(&last, &record.conversation)) {
            summary.preview(&last);
        }
        if record.has_draft {
            let mut body = self.body.borrow_mut();
            if let Ok(Some(text)) = self.store.draft(record.id, &mut body[..]) {
                let mut draft = DraftText::new(self.heap);
                _ = draft.splice(0..0, text);
                summary.draft = EditBuffer::with_text(draft);
            }
        }
        Some(summary)
    }

    /// How a chat is shown: its name, its avatar, and whom it is with.
    fn face(&self, record: &ChatRecord) -> Option<(String<32>, AvatarStyle, ChatKind)> {
        match record.conversation {
            ConversationKey::ChannelGroup { channel } => {
                let kept = self
                    .store
                    .channels()
                    .flatten()
                    .find(|kept| kept.tag == channel)?;
                // A built-in channel is shown by its own name, whatever was
                // kept for it.
                let name = record
                    .name
                    .as_deref()
                    .or(kept.builtin.map(BuiltinChannel::name))
                    .unwrap_or(kept.name.as_str());
                let builtin = kept.builtin.map(|builtin| match builtin {
                    BuiltinChannel::Public => avatar::BuiltinChannel::Public,
                    BuiltinChannel::Emergency => avatar::BuiltinChannel::Emergency,
                });
                let tint = [channel.0[0], channel.0[1], channel.0[2]];
                let access = match kept.access {
                    ChannelAccess::Named => model::ChannelAccess::Named,
                    ChannelAccess::Private => model::ChannelAccess::Private,
                    ChannelAccess::Clear => model::ChannelAccess::Clear,
                };
                Some((
                    cut(name),
                    AvatarStyle::channel(builtin, name, tint),
                    ChatKind::Channel { access },
                ))
            }
            ConversationKey::Direct { peer } | ConversationKey::ChannelDirect { peer, .. } => {
                let kept = self.store.peer(&peer).ok().flatten();
                let lettering = address(&peer.0);
                let lettering = lettering.get(..4).unwrap_or_default();
                let name = match record.name.as_deref() {
                    Some(name) => cut(name),
                    None => match kept.as_ref().and_then(|kept| kept.name.as_deref()) {
                        Some(name) => cut(name),
                        None => cut(lettering),
                    },
                };
                let hint = peer.hint().0;
                let hops = self.links.get(&peer.0).and_then(Link::hops);
                Some((
                    name,
                    AvatarStyle::peer(hint, lettering, shape(kept.as_ref())),
                    ChatKind::Peer { hops },
                ))
            }
            ConversationKey::Room { .. } => None,
        }
    }

    fn message_of(
        &self,
        record: &MessageRecord,
        conversation: &ConversationKey,
    ) -> Option<Message> {
        let (text, card) = {
            let mut body = self.body.borrow_mut();
            let body = self.store.body(record.id, &mut body[..]).ok()??;
            let card = (record.message_type == MessageType::Basic && !record.flags.deleted)
                .then(|| self.card_in(body))
                .flatten();
            (SharedText::new(self.heap, body)?, card)
        };
        let direction = match record.direction {
            engine::Direction::Inbound => model::Direction::Inbound,
            engine::Direction::Outbound => model::Direction::Outbound,
        };
        let channel = matches!(conversation, ConversationKey::ChannelGroup { .. });
        let delivery = match direction {
            model::Direction::Inbound => model::Delivery::Delivered,
            model::Direction::Outbound => {
                let delivery = record.delivery;
                if self.retrying.contains(&record.id) {
                    model::Delivery::Sending
                } else if delivery.failed != 0 {
                    model::Delivery::Unconfirmed
                } else if delivery.acked != 0 && delivery.sent & !delivery.acked == 0 {
                    model::Delivery::Delivered
                } else if delivery.sent != 0 && channel {
                    model::Delivery::Sent
                } else {
                    model::Delivery::Sending
                }
            }
        };
        let reactions = record
            .reactions
            .iter()
            .map(|reacted| model::Reacted {
                reaction: reaction(reacted.reaction),
                count: u8::try_from(reacted.count).unwrap_or(u8::MAX),
                mine: reacted.mine,
            })
            .collect();
        let presence = match record.presence {
            engine::Presence::Present => Presence::Present,
            engine::Presence::GapPending => Presence::PendingRepair,
            engine::Presence::Unavailable => Presence::Unavailable,
        };
        Some(Message {
            id: record.id.0,
            direction,
            sender: self.sender(record, conversation),
            text,
            delivery,
            reactions,
            card,
            reply: record
                .regarding
                .filter(|_| record.message_type == MessageType::Basic)
                .and_then(|regarding| self.quote(regarding, conversation)),
            time: record.time,
            presence,
            edited: record.flags.edited,
            deleted: record.flags.deleted,
            late: record.flags.late,
            forward_secret: record.flags.forward_secret,
            parts: match record.status {
                engine::CompletionStatus::Complete => None,
                engine::CompletionStatus::Partial {
                    present,
                    count,
                    finalized,
                } => {
                    let all = 1u16
                        .checked_shl(u32::from(count))
                        .map_or(u16::MAX, |bit| bit - 1);
                    Some(model::Parts {
                        count,
                        received: present,
                        lost: if finalized { all & !present } else { 0 },
                    })
                }
            },
        })
    }

    /// What a reply quotes of `id`, in `conversation`: who sent it, and
    /// as much of what it says as one line shows.
    fn quote(&self, id: MessageId, conversation: &ConversationKey) -> Option<model::Quote> {
        let record = self.store.message(id).ok()??;
        let text = {
            let mut body = self.body.borrow_mut();
            let body = self.store.body(id, &mut body[..]).ok()??;
            SharedText::new(self.heap, record::clip(body, QUOTED_MAX))?
        };
        let name = match record.direction {
            engine::Direction::Outbound => None,
            engine::Direction::Inbound => {
                let name = match self.sender(&record, conversation) {
                    Some(sender) => cut::<32>(&sender.name),
                    None => {
                        let chat = self.store.chat_for(conversation)?;
                        let kept = self.store.chats().flatten().find(|kept| kept.id == chat)?;
                        self.face(&kept)?.0
                    }
                };
                Some(SharedText::new(self.heap, &name)?)
            }
        };
        Some(model::Quote { name, text })
    }

    /// The hint an incoming channel message names its sender by, and the
    /// key behind it when one is known.
    fn sender_key(
        &self,
        record: &MessageRecord,
        conversation: &ConversationKey,
    ) -> Option<(NodeHint, Option<PublicKey>)> {
        let ConversationKey::ChannelGroup { channel } = conversation else {
            return None;
        };
        match record.sender {
            SenderScope::ClaimedMember(hint) => Some((
                hint,
                self.facade
                    .as_ref()
                    .and_then(|facade| facade.member_key(channel, &hint))
                    .or_else(|| self.only_peer_with(hint)),
            )),
            SenderScope::Peer(key) => Some((key.hint(), Some(key))),
            SenderScope::Local => None,
        }
    }

    /// Who sent an incoming channel message, as the channel shows them:
    /// by the name they gave, or else by their address.
    fn sender(&self, record: &MessageRecord, conversation: &ConversationKey) -> Option<Sender> {
        if record.direction != engine::Direction::Inbound {
            return None;
        }
        let (hint, key) = self.sender_key(record, conversation)?;
        let mut lettering = String::<8>::new();
        let shape = match key {
            Some(key) => {
                _ = lettering.push_str(address(&key.0).get(..4).unwrap_or_default());
                PeerShape::Circle
            }
            // Known by nothing but a hint.
            None => {
                _ = write!(lettering, "{hint}");
                PeerShape::Hexagon
            }
        };
        let mut name = String::new();
        match record.sender_handle.as_deref() {
            Some(handle) if !handle.trim().is_empty() => push_cut(&mut name, handle),
            _ => name = unnamed_member(&lettering),
        }
        Some(Sender {
            name,
            avatar: AvatarStyle::peer(hint.0, &lettering, shape),
        })
    }
}

/// The emote `reaction` goes on the air as.
fn emote(reaction: model::Reaction) -> crate::Reaction {
    match reaction {
        model::Reaction::Heart => crate::Reaction::Heart,
        model::Reaction::ThumbsUp => crate::Reaction::ThumbsUp,
        model::Reaction::ThumbsDown => crate::Reaction::ThumbsDown,
        model::Reaction::Laugh => crate::Reaction::Laugh,
        model::Reaction::Exclaim => crate::Reaction::Exclaim,
        model::Reaction::Question => crate::Reaction::Question,
    }
}

fn reaction(reaction: crate::Reaction) -> model::Reaction {
    match reaction {
        crate::Reaction::Heart => model::Reaction::Heart,
        crate::Reaction::ThumbsUp => model::Reaction::ThumbsUp,
        crate::Reaction::ThumbsDown => model::Reaction::ThumbsDown,
        crate::Reaction::Laugh => model::Reaction::Laugh,
        crate::Reaction::Exclaim => model::Reaction::Exclaim,
        crate::Reaction::Question => model::Reaction::Question,
    }
}

/// What a member who gave no name is called.
fn unnamed_member(lettering: &str) -> String<24> {
    let mut name = String::new();
    _ = write!(name, "Member {lettering}");
    name
}

/// A key's address: its base58 encoding.
pub(crate) fn address(key: &[u8; 32]) -> String<44> {
    let mut address = String::new();
    for &digit in &base58::encode(key) {
        _ = address.push(char::from(digit));
    }
    address
}

fn cut<const N: usize>(text: &str) -> String<N> {
    let mut out = String::new();
    push_cut(&mut out, text);
    out
}

fn push_cut<const N: usize>(out: &mut String<N>, text: &str) {
    for c in text.chars() {
        if out.push(c).is_err() {
            break;
        }
    }
}
