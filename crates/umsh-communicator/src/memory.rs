//! The store in memory, alone or over a durable layer.
//!
//! It keeps two parts. Its records—chats, messages, archives, checkpoints,
//! peers, channels, and the counters behind its identifiers—are what a
//! power cut leaves. Its index—chats by activity, each chat's messages,
//! wire aliases, peers by hint—is kept up to date as it goes and rebuilt
//! from the records when it is mounted again, so a power cut can be armed
//! and the store remounted to see what survived.
//!
//! Alone ([`Volatile`]), the records in memory are what survives, which
//! serves tests and anything before durable storage. Over a layer that
//! keeps them ([`Durable`]), the records in memory are a working copy:
//! each one changed is handed to the layer at the end of every step of a
//! commit, and mounting reads them all back from it.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{ChannelTag, NodeHint, PublicKey, RouterHint};
use umsh_text::chat::{self, Insert, Mutation};
use umsh_text::engine::{ArchiveKey, Direction, Presence, ResolvedRef, StreamCheckpoint};
use umsh_text::{ConversationKey, MessageType, SenderScope, WireRef};

use crate::batch::{Batch, Change, CommitStep, Committed, Subject};
use crate::durable::{Durable, Volatile};
use crate::ids::{ChatId, MessageId, PeerId};
use crate::reaction::{REACTIONS, Reacted, Reaction, Reactions};
use crate::record::{
    self, BODY_MAX, ChannelChange, ChannelRecord, ChatChange, ChatRecord, Delivery, IDENTITY_MAX,
    LinkInfo, MessageFlags, MessageMeta, MessageRecord, PeerChange, PeerFilter, PeerRecord,
    ROUTE_MAX, ReactorRecord, StoreError, Usage, WireAlias,
};
use crate::store::ChatStore;
use crate::wire::{AliasCode, ArchiveCode, ConversationCode, SenderCode, archive_code};

mod codec;

/// How much a store keeps before it evicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Octets of messages and archived payloads kept before the oldest
    /// messages go.
    pub bytes: usize,
    /// The newest messages of each chat that eviction never takes, however
    /// busy another chat is.
    pub keep_per_chat: usize,
    /// Heard peers kept besides the saved ones, most recently heard first.
    pub heard_peers: usize,
}

impl Quota {
    pub const DEFAULT: Self = Self {
        bytes: 300 * 1024,
        keep_per_chat: 50,
        heard_peers: 32,
    };
}

impl Default for Quota {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a message costs against the quota besides its body: about what a
/// durable back end spends on its record and its index entries.
pub const RECORD_COST: usize = 96;

// ─── What survives power loss ────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ChatEntry {
    record: ChatRecord,
    /// Orders chats by activity: the store's clock when it last had a
    /// message.
    activity: u64,
    draft: Option<String>,
}

#[derive(Clone, Debug)]
struct Reactor {
    who: SenderCode,
    mine: bool,
    reaction: Reaction,
}

#[derive(Clone, Debug)]
struct MessageEntry {
    /// The record, its reactions left to be counted on reading.
    record: MessageRecord,
    conversation: ConversationKey,
    body: String,
    /// The engine revision it was last changed at, so a mutation seen
    /// again is not applied twice.
    revision: u32,
    /// The latest reaction from each sender, in the order they came.
    reactors: Vec<Reactor>,
}

#[derive(Clone, Debug)]
struct PeerEntry {
    record: PeerRecord,
    /// The store's clock when it was last heard.
    heard: u64,
}

/// The kinds of identifier, as [`Disk::ids`] counts them.
const CHAT: usize = 0;
const MESSAGE: usize = 1;
const PEER: usize = 2;

/// How far ahead of what it has given out a durable store's kept
/// counters reach.
const ID_BLOCK: u32 = 64;

#[derive(Clone, Debug, Default)]
struct Disk {
    /// The next chat, message, and peer identifiers.
    ids: [u32; 3],
    /// How far the kept counters reach: no identifier at or past these
    /// has been given out.
    reserved: [u32; 3],
    /// Orders everything the store does.
    clock: u64,
    /// Each conversation's outbound checkpoint, and when it was last used.
    checkpoints: BTreeMap<ConversationCode, (StreamCheckpoint, u64)>,
    archives: BTreeMap<ArchiveCode, Vec<u8>>,
    chats: BTreeMap<u32, ChatEntry>,
    messages: BTreeMap<u32, MessageEntry>,
    peers: BTreeMap<[u8; 32], PeerEntry>,
    channels: BTreeMap<[u8; 16], ChannelRecord>,
    /// The record the device keeps here of its own lists.
    device_lists: Option<Vec<u8>>,
    /// The characters last picked, as the interface keeps them.
    recent_picks: Option<Vec<u8>>,
}

impl Disk {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// The next identifier of `kind`. The kept counters reach a block ahead
    /// of what has been given out, and move on before an identifier past
    /// them is: a store mounted after a power cut skips the rest of the
    /// block rather than give any of it out again.
    fn take_id(&mut self, kind: usize, dirty: &mut Dirty) -> u32 {
        let id = self.ids[kind];
        self.ids[kind] += 1;
        if self.ids[kind] > self.reserved[kind] {
            self.reserved[kind] = id + ID_BLOCK;
            dirty.mark(RecordKey::Counters);
        }
        id
    }
}

/// A record, by what names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RecordKey {
    Counters,
    Checkpoint(ConversationCode),
    Archive(ArchiveCode),
    Chat(u32),
    Message(u32),
    Peer([u8; 32]),
    Channel([u8; 16]),
    DeviceLists,
    RecentPicks,
}

/// Records changed since they were last handed to the durable layer, in
/// the order they first changed.
#[derive(Debug, Default)]
struct Dirty {
    order: Vec<RecordKey>,
    seen: BTreeSet<RecordKey>,
}

impl Dirty {
    fn mark(&mut self, key: RecordKey) {
        if self.seen.insert(key) {
            self.order.push(key);
        }
    }

    fn take(&mut self) -> Vec<RecordKey> {
        self.seen.clear();
        core::mem::take(&mut self.order)
    }
}

// ─── What is rebuilt on mounting ─────────────────────────────────────────

#[derive(Debug, Default, PartialEq, Eq)]
struct Index {
    chat_for: BTreeMap<ConversationCode, u32>,
    by_activity: BTreeMap<u64, u32>,
    /// Each chat's messages, by ID, oldest first.
    chat_messages: BTreeMap<u32, Vec<u32>>,
    aliases: BTreeMap<AliasCode, BTreeSet<u32>>,
    hints: BTreeMap<[u8; 3], BTreeSet<[u8; 32]>>,
    /// Heard peers that are not saved, by when they were heard.
    heard: BTreeMap<u64, [u8; 32]>,
    /// Octets counted against the quota.
    bytes: usize,
}

impl Index {
    fn build(disk: &Disk) -> Self {
        let mut index = Self::default();
        for (&id, chat) in &disk.chats {
            index.add_chat(id, chat);
        }
        for (&id, message) in &disk.messages {
            index.add_message(id, message);
        }
        index.bytes += disk.archives.values().map(Vec::len).sum::<usize>();
        for (key, peer) in &disk.peers {
            index.add_peer(key, peer);
        }
        index
    }

    fn add_chat(&mut self, id: u32, chat: &ChatEntry) {
        self.chat_for.insert((&chat.record.conversation).into(), id);
        self.by_activity.insert(chat.activity, id);
        self.chat_messages.entry(id).or_default();
    }

    fn remove_chat(&mut self, id: u32, chat: &ChatEntry) {
        self.chat_for.remove(&(&chat.record.conversation).into());
        self.by_activity.remove(&chat.activity);
        self.chat_messages.remove(&id);
    }

    fn add_message(&mut self, id: u32, message: &MessageEntry) {
        let ids = self.chat_messages.entry(message.record.chat.0).or_default();
        if let Err(slot) = ids.binary_search(&id) {
            ids.insert(slot, id);
        }
        if let Some(alias) = alias_code(message) {
            self.aliases.entry(alias).or_default().insert(id);
        }
        self.bytes += cost(message);
    }

    fn remove_message(&mut self, id: u32, message: &MessageEntry) {
        if let Some(ids) = self.chat_messages.get_mut(&message.record.chat.0)
            && let Ok(slot) = ids.binary_search(&id)
        {
            ids.remove(slot);
        }
        if let Some(alias) = alias_code(message)
            && let Some(ids) = self.aliases.get_mut(&alias)
        {
            ids.remove(&id);
            if ids.is_empty() {
                self.aliases.remove(&alias);
            }
        }
        self.bytes -= cost(message);
    }

    fn add_peer(&mut self, key: &[u8; 32], peer: &PeerEntry) {
        self.hints.entry(hint_of(key)).or_default().insert(*key);
        if !peer.record.saved {
            self.heard.insert(peer.heard, *key);
        }
    }

    fn remove_peer(&mut self, key: &[u8; 32], peer: &PeerEntry) {
        let hint = hint_of(key);
        if let Some(keys) = self.hints.get_mut(&hint) {
            keys.remove(key);
            if keys.is_empty() {
                self.hints.remove(&hint);
            }
        }
        if !peer.record.saved {
            self.heard.remove(&peer.heard);
        }
    }
}

fn cost(message: &MessageEntry) -> usize {
    RECORD_COST + message.body.len()
}

fn alias_code(message: &MessageEntry) -> Option<AliasCode> {
    Some((
        (&message.conversation).into(),
        (&message.record.sender).into(),
        message.record.wire_id?,
    ))
}

fn hint_of(key: &[u8; 32]) -> [u8; 3] {
    [key[0], key[1], key[2]]
}

fn reactions(reactors: &[Reactor]) -> Reactions {
    let mut counted = Reactions::new();
    for reactor in reactors {
        if let Some(reacted) = counted
            .iter_mut()
            .find(|reacted| reacted.reaction == reactor.reaction)
        {
            reacted.count += 1;
            reacted.mine |= reactor.mine;
        } else if counted.len() < REACTIONS {
            counted.push(Reacted {
                reaction: reactor.reaction,
                count: 1,
                mine: reactor.mine,
            });
        }
    }
    counted
}

// ─── The store ───────────────────────────────────────────────────────────

/// A [`ChatStore`] in memory, alone or over a durable layer.
pub struct MemoryStore<D: Durable = Volatile> {
    disk: Disk,
    index: Index,
    quota: Quota,
    durable: D,
    dirty: Dirty,
    /// Where records are encoded on their way to the durable layer.
    scratch: Vec<u8>,
    /// Power goes once a commit finishes this step.
    cut: Option<CommitStep>,
    /// Power is gone: nothing more is written until it is back.
    off: bool,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::with_quota(Quota::DEFAULT)
    }

    pub fn with_quota(quota: Quota) -> Self {
        Self::over(Volatile, quota)
    }
}

impl<D: Durable> MemoryStore<D> {
    fn over(durable: D, quota: Quota) -> Self {
        Self {
            disk: Disk::default(),
            index: Index::default(),
            quota,
            durable,
            dirty: Dirty::default(),
            scratch: Vec::new(),
            cut: None,
            off: false,
        }
    }

    /// The store `durable` keeps, read back. A record that does not decode
    /// is left out, and the rest are kept.
    pub fn mount(durable: D, quota: Quota) -> Result<Self, StoreError> {
        let mut store = Self::over(durable, quota);
        store.remount()?;
        Ok(store)
    }

    /// [`MemoryStore::mount`], or, when what `durable` keeps cannot be
    /// read at all, an empty store over it cleared: storage that held
    /// something else before the store was put there.
    pub fn mount_or_clear(durable: D, quota: Quota) -> Result<Self, StoreError> {
        let mut store = Self::over(durable, quota);
        if store.remount().is_err() {
            store.durable.clear()?;
            store.remount()?;
        }
        Ok(store)
    }

    /// The durable layer.
    pub fn durable(&self) -> &D {
        &self.durable
    }

    /// The durable layer, for a test to cut its power or restore it.
    pub fn durable_mut(&mut self) -> &mut D {
        &mut self.durable
    }

    /// Lose power once the next commit has finished `step`: nothing after
    /// it is written, and nothing more is until [`MemoryStore::power_on`].
    pub fn cut_power_after(&mut self, step: CommitStep) {
        self.cut = Some(step);
    }

    /// Mount again from what was written, as after a power cut or a
    /// reboot.
    pub fn power_on(&mut self) -> Result<(), StoreError> {
        self.off = false;
        self.cut = None;
        self.remount()
    }

    /// Read the records back from what keeps them, and rebuild the index.
    fn remount(&mut self) -> Result<(), StoreError> {
        self.dirty.take();
        if D::KEEPS {
            let mut disk = Disk::default();
            self.durable
                .read(&mut |key, record| codec::restore(&mut disk, key, record))?;
            let orphans = codec::settle(&mut disk);
            self.disk = disk;
            // What no longer belongs anywhere goes at the next change.
            for orphan in orphans {
                self.dirty.mark(orphan);
            }
        }
        self.index = Index::build(&self.disk);
        Ok(())
    }

    /// Hand the durable layer every record changed since it was last
    /// handed any, in the order they changed.
    fn flush(&mut self) -> Result<(), StoreError> {
        let keys = self.dirty.take();
        if !D::KEEPS || self.off {
            return Ok(());
        }
        let mut key_bytes = heapless::Vec::<u8, { codec::KEY_MAX }>::new();
        for key in keys {
            codec::key(&key, &mut key_bytes);
            self.scratch.clear();
            let kept = codec::record(&self.disk, &key, &mut self.scratch);
            self.durable
                .write(&key_bytes, kept.then_some(&self.scratch[..]))?;
        }
        Ok(())
    }

    /// Hand over what changed. When the layer refuses, what it kept is
    /// read back, so the store is as the layer has it and the change it
    /// was making is undone.
    fn settle(&mut self) -> Result<(), StoreError> {
        let flushed = self.flush();
        if flushed.is_err() {
            let _ = self.remount();
        }
        flushed
    }

    fn writable(&self) -> Result<(), StoreError> {
        if self.off {
            Err(StoreError::PoweredOff)
        } else {
            Ok(())
        }
    }

    /// `step` is done, and handed to the durable layer. Returns whether
    /// power went with it.
    fn reached(&mut self, step: CommitStep) -> Result<bool, StoreError> {
        self.settle()?;
        Ok(self.reached_cut(step))
    }

    fn reached_cut(&mut self, step: CommitStep) -> bool {
        if self.cut == Some(step) {
            self.cut = None;
            self.off = true;
        }
        self.off
    }

    /// The index agrees with one rebuilt from storage.
    fn check_index(&self) {
        #[cfg(test)]
        assert_eq!(
            self.index,
            Index::build(&self.disk),
            "the index drifted from what a remount builds"
        );
    }

    // ─── Archives ────────────────────────────────────────────────────

    fn delete_archives(&mut self, conversation: ConversationCode, message_id: u8) {
        let range = (conversation, message_id, 0)..=(conversation, message_id, u8::MAX);
        let keys: Vec<ArchiveCode> = self
            .disk
            .archives
            .range(range)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            if let Some(payload) = self.disk.archives.remove(&key) {
                self.index.bytes -= payload.len();
                self.dirty.mark(RecordKey::Archive(key));
            }
        }
    }

    fn put_archive(&mut self, key: ArchiveCode, payload: &[u8]) {
        self.dirty.mark(RecordKey::Archive(key));
        if let Some(old) = self.disk.archives.insert(key, payload.to_vec()) {
            self.index.bytes -= old.len();
        }
        self.index.bytes += payload.len();
    }

    // ─── Chats ───────────────────────────────────────────────────────

    fn open_chat(&mut self, conversation: &ConversationKey, name: Option<&str>) -> u32 {
        if let Some(&id) = self.index.chat_for.get(&conversation.into()) {
            return id;
        }
        let id = self.disk.take_id(CHAT, &mut self.dirty);
        self.dirty.mark(RecordKey::Chat(id));
        let activity = self.disk.tick();
        let chat = ChatEntry {
            record: ChatRecord {
                id: ChatId(id),
                conversation: *conversation,
                name: name.map(record::name),
                muted: false,
                unread: 0,
                last_activity: None,
                has_draft: false,
            },
            activity,
            draft: None,
        };
        self.index.add_chat(id, &chat);
        self.disk.chats.insert(id, chat);
        id
    }

    /// A message was kept in `chat` at `time`.
    fn touch_chat(&mut self, chat: u32, time: Option<u32>, unread: bool) {
        let activity = self.disk.tick();
        let Some(entry) = self.disk.chats.get_mut(&chat) else {
            return;
        };
        self.dirty.mark(RecordKey::Chat(chat));
        self.index.by_activity.remove(&entry.activity);
        entry.activity = activity;
        self.index.by_activity.insert(activity, chat);
        if time.is_some() {
            entry.record.last_activity = time;
        }
        if unread {
            entry.record.unread += 1;
        }
    }

    // ─── Messages ────────────────────────────────────────────────────

    /// Change a kept message, keeping the index with it.
    fn update_message(&mut self, id: u32, change: impl FnOnce(&mut MessageEntry)) -> bool {
        let Some(mut message) = self.disk.messages.remove(&id) else {
            return false;
        };
        self.dirty.mark(RecordKey::Message(id));
        self.index.remove_message(id, &message);
        change(&mut message);
        self.index.add_message(id, &message);
        self.disk.messages.insert(id, message);
        true
    }

    /// Remove a message, and its resend material with it unless a newer
    /// message now holds its wire ID.
    fn remove_message(&mut self, id: u32) {
        let Some(message) = self.disk.messages.get(&id) else {
            return;
        };
        if message.record.direction == Direction::Outbound
            && let Some(alias) = alias_code(message)
            && self.index.aliases.get(&alias).and_then(BTreeSet::last) == Some(&id)
        {
            self.delete_archives(alias.0, alias.2);
        }
        if let Some(message) = self.disk.messages.remove(&id) {
            self.dirty.mark(RecordKey::Message(id));
            self.index.remove_message(id, &message);
        }
    }

    fn record(&self, id: u32) -> Option<MessageRecord> {
        let message = self.disk.messages.get(&id)?;
        let mut record = message.record.clone();
        record.reactions = reactions(&message.reactors);
        Some(record)
    }

    fn resolve(
        &self,
        batch: &Batch<'_>,
        committed: &Committed,
        handle: umsh_text::engine::sequence::MessageHandle,
    ) -> Option<u32> {
        committed
            .id_of(handle)
            .or_else(|| batch.resolve(handle))
            .map(|id| id.0)
            .filter(|id| self.disk.messages.contains_key(id))
    }

    /// The message `reference` names in `conversation`.
    ///
    /// A one-to-one Regarding is one octet, a wire ID with no stream, so
    /// the engine leaves it unresolved, scoped to the peer, when the ID
    /// could be either party's. With `either_party`, such a reference
    /// matches the newest message with that ID in either stream. An edit
    /// or delete never does: its original is always its own sender's.
    fn resolve_ref(
        &self,
        batch: &Batch<'_>,
        committed: &Committed,
        reference: &ResolvedRef,
        conversation: &ConversationKey,
        either_party: bool,
    ) -> Option<u32> {
        match reference {
            ResolvedRef::Handle(handle) => self.resolve(batch, committed, *handle),
            ResolvedRef::Unresolved(WireRef::SenderScoped { sender, message_id }) => {
                let alias = WireAlias {
                    conversation: *conversation,
                    sender: *sender,
                    epoch: None,
                    wire_id: *message_id,
                };
                let one_to_one = matches!(
                    conversation,
                    ConversationKey::Direct { .. } | ConversationKey::ChannelDirect { .. }
                );
                let ours = (either_party && one_to_one && *sender != SenderScope::Local)
                    .then(|| {
                        self.resolve_wire(&WireAlias {
                            sender: SenderScope::Local,
                            ..alias
                        })
                    })
                    .flatten();
                self.resolve_wire(&alias).max(ours).map(|id| id.0)
            }
            // A room numbers its messages itself, whoever sent them.
            ResolvedRef::Unresolved(WireRef::RoomCanonical { message_id }) => {
                let conversation = ConversationCode::from(conversation);
                self.index
                    .aliases
                    .range(
                        (conversation, SenderCode::MIN, 0)
                            ..=(conversation, SenderCode::MAX, u8::MAX),
                    )
                    .filter(|((_, _, wire_id), _)| wire_id == message_id)
                    .filter_map(|(_, ids)| ids.last().copied())
                    .max()
            }
        }
    }

    fn apply(&mut self, batch: &Batch<'_>) -> Committed {
        let mut committed = Committed::default();
        for change in batch.changes() {
            match change {
                Change::Message { mutation, link } => {
                    self.mutate(batch, &mut committed, mutation, link);
                }
                Change::Delivery {
                    handle,
                    fragment,
                    state,
                } => {
                    if let Some(id) = self.resolve(batch, &committed, handle)
                        && let Some(message) = self.disk.messages.get_mut(&id)
                    {
                        self.dirty.mark(RecordKey::Message(id));
                        message.record.delivery.set(fragment, state);
                        committed.touch_message(MessageId(id));
                    }
                }
                Change::Secrecy {
                    message,
                    forward_secret,
                } => {
                    let id = match message {
                        Subject::Handle(handle) => self.resolve(batch, &committed, handle),
                        Subject::Kept(id) => Some(id.0),
                    };
                    if let Some(id) = id
                        && let Some(message) = self.disk.messages.get_mut(&id)
                        && message.record.flags.forward_secret != forward_secret
                    {
                        self.dirty.mark(RecordKey::Message(id));
                        message.record.flags.forward_secret = forward_secret;
                        committed.touch_message(MessageId(id));
                    }
                }
            }
        }
        committed
    }

    fn mutate(
        &mut self,
        batch: &Batch<'_>,
        committed: &mut Committed,
        mutation: &Mutation,
        link: Option<LinkInfo>,
    ) {
        let revision = mutation.revision;
        match mutation.change {
            chat::Change::Insert(Insert {
                conversation,
                sender,
                direction,
                message_type,
                wire_id,
                epoch,
                ref sender_handle,
                regarding,
                bg_color,
                text_color,
                ref body,
                status,
                presence,
                late,
                notify,
                ..
            }) => {
                let sender_handle = sender_handle.as_deref();
                let regarding_id = regarding.and_then(|reference| {
                    self.resolve_ref(batch, committed, &reference, &conversation, true)
                });
                // A slot already kept under this handle is filled in place.
                if let Some(id) = self.resolve(batch, committed, mutation.handle) {
                    let mut noticed = false;
                    let mut shown = false;
                    self.update_message(id, |message| {
                        if revision <= message.revision {
                            return;
                        }
                        let record = &mut message.record;
                        noticed = notify && !record.flags.notify && direction == Direction::Inbound;
                        shown =
                            presence == Presence::Present && record.presence != Presence::Present;
                        message.revision = revision;
                        message.body = record::clip(body, BODY_MAX).into();
                        record.sender = sender;
                        record.sender_handle = sender_handle.map(record::name);
                        record.wire_id = wire_id;
                        record.epoch = epoch;
                        record.message_type = message_type;
                        record.regarding = regarding_id.map(MessageId);
                        record.body_len = message.body.len() as u16;
                        record.bg_color = bg_color;
                        record.text_color = text_color;
                        record.status = status;
                        record.presence = presence;
                        record.flags.late |= late;
                        record.flags.notify |= notify;
                        record.link = link.or(record.link);
                        record.time = record.time.or(batch.time());
                    });
                    if let Some(chat) = self.disk.messages.get(&id).map(|m| m.record.chat.0)
                        && (noticed || shown)
                    {
                        self.touch_chat(chat, batch.time(), noticed);
                        committed.touch_chat(ChatId(chat));
                    }
                    committed.touch_message(MessageId(id));
                    return;
                }

                // A reaction folds into what it is about.
                if message_type == MessageType::Status && regarding.is_some() {
                    if let Some(target) = regarding_id {
                        let who = SenderCode::from(&sender);
                        let reaction = Reaction::from_body(body);
                        self.update_message(target, |message| {
                            message.reactors.retain(|reactor| reactor.who != who);
                            if let Some(reaction) = reaction {
                                message.reactors.push(Reactor {
                                    who,
                                    mine: direction == Direction::Outbound,
                                    reaction,
                                });
                            }
                        });
                        committed.touch_message(MessageId(target));
                    }
                    return;
                }

                let chat = self.open_chat(&conversation, None);
                let id = self.disk.take_id(MESSAGE, &mut self.dirty);
                self.dirty.mark(RecordKey::Message(id));
                let body = record::clip(body, BODY_MAX);
                let message = MessageEntry {
                    record: MessageRecord {
                        id: MessageId(id),
                        chat: ChatId(chat),
                        direction,
                        sender,
                        sender_handle: sender_handle.map(record::name),
                        wire_id,
                        epoch,
                        message_type,
                        regarding: regarding_id.map(MessageId),
                        body_len: body.len() as u16,
                        bg_color,
                        text_color,
                        status,
                        presence,
                        flags: MessageFlags {
                            late,
                            notify,
                            ..MessageFlags::default()
                        },
                        delivery: Delivery::default(),
                        link,
                        time: batch.time(),
                        reactions: Reactions::new(),
                    },
                    conversation,
                    body: body.into(),
                    revision,
                    reactors: Vec::new(),
                };
                self.index.add_message(id, &message);
                self.disk.messages.insert(id, message);
                if presence == Presence::Present {
                    let noticed = notify && direction == Direction::Inbound;
                    self.touch_chat(chat, batch.time(), noticed);
                }
                committed.inserted.push((mutation.handle, MessageId(id)));
                committed.touch_message(MessageId(id));
                committed.touch_chat(ChatId(chat));
            }
            chat::Change::UpdateBody {
                ref body,
                status,
                late,
                notify,
            } => {
                let Some(id) = self.resolve(batch, committed, mutation.handle) else {
                    return;
                };
                let mut noticed = false;
                self.update_message(id, |message| {
                    if revision <= message.revision {
                        return;
                    }
                    let record = &mut message.record;
                    noticed =
                        notify && !record.flags.notify && record.direction == Direction::Inbound;
                    message.revision = revision;
                    message.body = record::clip(body, BODY_MAX).into();
                    record.body_len = message.body.len() as u16;
                    record.status = status;
                    record.flags.late |= late;
                    record.flags.notify |= notify;
                });
                if noticed && let Some(chat) = self.disk.messages.get(&id).map(|m| m.record.chat.0)
                {
                    self.touch_chat(chat, batch.time(), true);
                    committed.touch_chat(ChatId(chat));
                }
                committed.touch_message(MessageId(id));
            }
            chat::Change::Edit {
                conversation,
                original,
                ref body,
            } => {
                let Some(id) = self.resolve_ref(batch, committed, &original, &conversation, false)
                else {
                    return;
                };
                self.update_message(id, |message| {
                    message.body = record::clip(body, BODY_MAX).into();
                    message.record.body_len = message.body.len() as u16;
                    message.record.flags.edited = true;
                });
                committed.touch_message(MessageId(id));
            }
            chat::Change::Delete {
                conversation,
                original,
            } => {
                let Some(id) = self.resolve_ref(batch, committed, &original, &conversation, false)
                else {
                    return;
                };
                let held = self
                    .disk
                    .messages
                    .get(&id)
                    .is_some_and(|message| message.record.presence == Presence::GapPending);
                if held {
                    // A slot held for a message that never came, and never
                    // will: nothing was shown, so nothing stays.
                    self.remove_message(id);
                } else {
                    // The tombstone stays as long as its wire alias does.
                    self.update_message(id, |message| {
                        message.body.clear();
                        message.record.body_len = 0;
                        message.record.flags.deleted = true;
                        message.reactors.clear();
                    });
                }
                committed.touch_message(MessageId(id));
            }
        }
    }

    /// Make room: the oldest messages go first, across every chat, except
    /// each chat's newest.
    fn evict(&mut self) {
        while self.index.bytes > self.quota.bytes {
            let keep = self.quota.keep_per_chat;
            let victim = self.disk.messages.iter().find_map(|(&id, message)| {
                let held = self
                    .index
                    .chat_messages
                    .get(&message.record.chat.0)
                    .map_or(0, Vec::len);
                (held > keep).then_some(id)
            });
            let Some(victim) = victim else {
                break;
            };
            self.remove_message(victim);
        }
    }

    // ─── Peers ───────────────────────────────────────────────────────

    /// Forget the heard peers beyond the quota, least recently heard first.
    fn forget_unheard(&mut self) {
        while self.index.heard.len() > self.quota.heard_peers {
            let Some((_, key)) = self.index.heard.pop_first() else {
                break;
            };
            if let Some(peer) = self.disk.peers.remove(&key) {
                self.dirty.mark(RecordKey::Peer(key));
                self.index.remove_peer(&key, &peer);
            }
        }
    }
}

impl<D: Durable> ChatStore for MemoryStore<D> {
    fn commit(&mut self, batch: &Batch<'_>) -> Result<Committed, StoreError> {
        self.writable()?;
        for checkpoint in batch.checkpoints() {
            let used = self.disk.tick();
            let code = (&checkpoint.conversation).into();
            self.dirty.mark(RecordKey::Checkpoint(code));
            self.disk.checkpoints.insert(code, (*checkpoint, used));
        }
        if self.reached(CommitStep::Checkpoint)? {
            return Err(StoreError::Io);
        }
        for (conversation, message_id) in batch.archive_deletes() {
            self.delete_archives(conversation.into(), *message_id);
        }
        if self.reached(CommitStep::ArchiveDeletes)? {
            return Err(StoreError::Io);
        }
        for (key, payload) in batch.archives() {
            self.put_archive(archive_code(key), payload);
        }
        if self.reached(CommitStep::Archives)? {
            return Err(StoreError::Io);
        }
        let committed = self.apply(batch);
        self.evict();
        self.check_index();
        // Power lost after the transcript loses nothing: the commit is
        // whole.
        self.reached(CommitStep::Transcript)?;
        Ok(committed)
    }

    fn messages(
        &self,
        chat: ChatId,
        before: Option<MessageId>,
    ) -> impl Iterator<Item = Result<MessageRecord, StoreError>> + '_ {
        self.index
            .chat_messages
            .get(&chat.0)
            .into_iter()
            .flat_map(move |ids| {
                let end =
                    before.map_or(ids.len(), |before| ids.partition_point(|&id| id < before.0));
                ids[..end].iter().rev()
            })
            .map(|&id| self.record(id).ok_or(StoreError::Corrupt))
    }

    fn message(&self, id: MessageId) -> Result<Option<MessageRecord>, StoreError> {
        Ok(self.record(id.0))
    }

    fn message_count(&self, chat: ChatId) -> usize {
        self.index.chat_messages.get(&chat.0).map_or(0, Vec::len)
    }

    fn message_id_at(&self, chat: ChatId, index: usize) -> Option<MessageId> {
        let ids = self.index.chat_messages.get(&chat.0)?;
        ids.get(index).copied().map(MessageId)
    }

    fn message_meta(&self, id: MessageId) -> Result<Option<MessageMeta>, StoreError> {
        let meta = self.disk.messages.get(&id.0).map(|message| {
            let record = &message.record;
            MessageMeta {
                chat: record.chat,
                direction: record.direction,
                sender: record.sender,
                sender_handle: record.sender_handle.clone(),
                presence: record.presence,
                flags: record.flags,
                delivery: record.delivery,
                time: record.time,
            }
        });
        Ok(meta)
    }

    fn body<'b>(&self, id: MessageId, out: &'b mut [u8]) -> Result<Option<&'b str>, StoreError> {
        let Some(message) = self.disk.messages.get(&id.0) else {
            return Ok(None);
        };
        copy_text(&message.body, out).map(Some)
    }

    fn reactors(&self, id: MessageId) -> impl Iterator<Item = ReactorRecord> + '_ {
        self.disk
            .messages
            .get(&id.0)
            .into_iter()
            .flat_map(|message| &message.reactors)
            .map(|reactor| ReactorRecord {
                sender: reactor.who.scope(),
                mine: reactor.mine,
                reaction: reactor.reaction,
            })
    }

    fn resolve_wire(&self, alias: &WireAlias) -> Option<MessageId> {
        let code: AliasCode = (
            (&alias.conversation).into(),
            (&alias.sender).into(),
            alias.wire_id,
        );
        self.index
            .aliases
            .get(&code)?
            .iter()
            .rev()
            .find(|id| {
                alias.epoch.is_none_or(|epoch| {
                    self.disk
                        .messages
                        .get(id)
                        .is_some_and(|message| message.record.epoch == epoch)
                })
            })
            .map(|&id| MessageId(id))
    }

    fn archive<'b>(
        &self,
        key: &ArchiveKey,
        out: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, StoreError> {
        let Some(payload) = self.disk.archives.get(&archive_code(key)) else {
            return Ok(None);
        };
        let out = out
            .get_mut(..payload.len())
            .ok_or(StoreError::BufferTooSmall)?;
        out.copy_from_slice(payload);
        Ok(Some(out))
    }

    fn checkpoint(&self, conversation: &ConversationKey) -> Option<StreamCheckpoint> {
        self.disk
            .checkpoints
            .get(&conversation.into())
            .map(|(checkpoint, _)| *checkpoint)
    }

    fn recent_checkpoints(&self, limit: usize) -> impl Iterator<Item = StreamCheckpoint> + '_ {
        let mut used: Vec<(u64, StreamCheckpoint)> = self
            .disk
            .checkpoints
            .values()
            .map(|(checkpoint, used)| (*used, *checkpoint))
            .collect();
        used.sort_unstable_by_key(|(used, _)| *used);
        let skip = used.len().saturating_sub(limit);
        used.into_iter()
            .skip(skip)
            .map(|(_, checkpoint)| checkpoint)
    }

    fn chats(&self) -> impl Iterator<Item = Result<ChatRecord, StoreError>> + '_ {
        self.index.by_activity.values().rev().map(|id| {
            self.disk
                .chats
                .get(id)
                .map(|chat| chat.record.clone())
                .ok_or(StoreError::Corrupt)
        })
    }

    fn chat_for(&self, conversation: &ConversationKey) -> Option<ChatId> {
        self.index
            .chat_for
            .get(&conversation.into())
            .map(|&id| ChatId(id))
    }

    fn draft<'b>(&self, chat: ChatId, out: &'b mut [u8]) -> Result<Option<&'b str>, StoreError> {
        let Some(draft) = self
            .disk
            .chats
            .get(&chat.0)
            .and_then(|chat| chat.draft.as_ref())
        else {
            return Ok(None);
        };
        copy_text(draft, out).map(Some)
    }

    fn update_chat(&mut self, chat: ChatId, change: ChatChange<'_>) -> Result<ChatId, StoreError> {
        self.writable()?;
        if let ChatChange::Open { conversation, name } = change {
            let id = self.open_chat(&conversation, name);
            self.check_index();
            self.settle()?;
            return Ok(ChatId(id));
        }
        if !self.disk.chats.contains_key(&chat.0) {
            return Err(StoreError::NotFound);
        }
        if let ChatChange::Delete = change {
            let messages: Vec<u32> = self
                .index
                .chat_messages
                .get(&chat.0)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            for id in messages {
                self.remove_message(id);
            }
            if let Some(entry) = self.disk.chats.remove(&chat.0) {
                self.dirty.mark(RecordKey::Chat(chat.0));
                self.index.remove_chat(chat.0, &entry);
            }
            self.check_index();
            self.settle()?;
            return Ok(chat);
        }
        let Some(entry) = self.disk.chats.get_mut(&chat.0) else {
            return Err(StoreError::NotFound);
        };
        self.dirty.mark(RecordKey::Chat(chat.0));
        match change {
            ChatChange::Rename(name) => entry.record.name = name.map(record::name),
            ChatChange::Mute(muted) => entry.record.muted = muted,
            ChatChange::Read => entry.record.unread = 0,
            ChatChange::Draft(draft) => {
                entry.draft = draft
                    .filter(|draft| !draft.is_empty())
                    .map(|draft| record::clip(draft, BODY_MAX).into());
                entry.record.has_draft = entry.draft.is_some();
            }
            ChatChange::Open { .. } | ChatChange::Delete => unreachable!(),
        }
        self.check_index();
        self.settle()?;
        Ok(chat)
    }

    fn peer(&self, key: &PublicKey) -> Result<Option<PeerRecord>, StoreError> {
        Ok(self.disk.peers.get(&key.0).map(|peer| peer.record.clone()))
    }

    fn peers_with_hint(&self, hint: NodeHint) -> impl Iterator<Item = PublicKey> + '_ {
        self.index
            .hints
            .get(&hint.0)
            .into_iter()
            .flatten()
            .map(|key| PublicKey(*key))
    }

    fn peers_with_router_hint(&self, hint: RouterHint) -> impl Iterator<Item = PublicKey> + '_ {
        let [a, b] = hint.0;
        self.index
            .hints
            .range([a, b, 0x00]..=[a, b, 0xFF])
            .flat_map(|(_, keys)| keys)
            .map(|key| PublicKey(*key))
    }

    fn peers(
        &self,
        filter: PeerFilter,
    ) -> impl Iterator<Item = Result<PeerRecord, StoreError>> + '_ {
        let keys: Vec<[u8; 32]> = match filter {
            PeerFilter::All => self.disk.peers.keys().copied().collect(),
            PeerFilter::Saved => self
                .disk
                .peers
                .iter()
                .filter(|(_, peer)| peer.record.saved)
                .map(|(key, _)| *key)
                .collect(),
            PeerFilter::Heard => self.index.heard.values().rev().copied().collect(),
        };
        keys.into_iter().map(|key| {
            self.disk
                .peers
                .get(&key)
                .map(|peer| peer.record.clone())
                .ok_or(StoreError::Corrupt)
        })
    }

    fn update_peer(
        &mut self,
        key: &PublicKey,
        change: PeerChange<'_>,
    ) -> Result<PeerId, StoreError> {
        self.writable()?;
        let existing = self.disk.peers.remove(&key.0);
        if let Some(peer) = &existing {
            self.dirty.mark(RecordKey::Peer(key.0));
            self.index.remove_peer(&key.0, peer);
        }
        let mut peer = match (existing, change) {
            (Some(peer), PeerChange::Forget) => {
                self.check_index();
                self.settle()?;
                return Ok(peer.record.id);
            }
            (Some(peer), _) => peer,
            (None, PeerChange::Heard { .. } | PeerChange::Save { .. }) => {
                let id = PeerId(self.disk.take_id(PEER, &mut self.dirty));
                self.dirty.mark(RecordKey::Peer(key.0));
                PeerEntry {
                    record: PeerRecord {
                        id,
                        key: *key,
                        name: None,
                        identity: heapless::Vec::new(),
                        linked: false,
                        last_heard: None,
                        route: None,
                        forward_secrecy: false,
                        saved: false,
                    },
                    heard: 0,
                }
            }
            (None, _) => return Err(StoreError::NotFound),
        };
        match change {
            PeerChange::Heard {
                at,
                name,
                identity,
                linked,
            } => {
                peer.heard = self.disk.tick();
                peer.record.last_heard = at.or(peer.record.last_heard);
                // Someone else's word never overrides the node's own.
                if linked || !peer.record.linked {
                    // What it calls itself, unless someone here named it.
                    if let Some(name) = name
                        && !(peer.record.saved && peer.record.name.is_some())
                    {
                        peer.record.name = Some(record::name(name));
                    }
                    if let Some(identity) = identity
                        && identity.len() <= IDENTITY_MAX
                    {
                        peer.record.identity =
                            heapless::Vec::from_slice(identity).unwrap_or_default();
                    }
                    if name.is_some() || identity.is_some() {
                        peer.record.linked = linked;
                    }
                }
            }
            PeerChange::Route(route) => {
                peer.record.route = route.map(|hints| {
                    heapless::Vec::from_slice(&hints[..hints.len().min(ROUTE_MAX)])
                        .unwrap_or_default()
                });
            }
            PeerChange::Save { name } => {
                peer.record.saved = true;
                if let Some(name) = name {
                    peer.record.name = Some(record::name(name));
                }
            }
            PeerChange::Unsave => {
                peer.record.saved = false;
                peer.heard = self.disk.tick();
            }
            PeerChange::Rename(name) => peer.record.name = name.map(record::name),
            PeerChange::ForwardSecrecy(preferred) => peer.record.forward_secrecy = preferred,
            PeerChange::Forget => unreachable!(),
        }
        let id = peer.record.id;
        self.index.add_peer(&key.0, &peer);
        self.disk.peers.insert(key.0, peer);
        self.forget_unheard();
        self.check_index();
        self.settle()?;
        Ok(id)
    }

    fn channels(&self) -> impl Iterator<Item = Result<ChannelRecord, StoreError>> + '_ {
        self.disk.channels.values().cloned().map(Ok)
    }

    fn update_channel(
        &mut self,
        tag: &ChannelTag,
        change: ChannelChange<'_>,
    ) -> Result<(), StoreError> {
        self.writable()?;
        self.dirty.mark(RecordKey::Channel(tag.0));
        match change {
            ChannelChange::Add {
                name,
                access,
                builtin,
            } => {
                self.disk.channels.insert(
                    tag.0,
                    ChannelRecord {
                        tag: *tag,
                        name: record::name(name),
                        access,
                        builtin,
                    },
                );
            }
            ChannelChange::Rename(name) => {
                self.disk
                    .channels
                    .get_mut(&tag.0)
                    .ok_or(StoreError::NotFound)?
                    .name = record::name(name);
            }
            ChannelChange::Remove => {
                self.disk
                    .channels
                    .remove(&tag.0)
                    .ok_or(StoreError::NotFound)?;
            }
        }
        self.settle()
    }

    fn device_lists<'b>(&self, out: &'b mut [u8]) -> Result<Option<&'b [u8]>, StoreError> {
        let Some(lists) = &self.disk.device_lists else {
            return Ok(None);
        };
        let out = out
            .get_mut(..lists.len())
            .ok_or(StoreError::BufferTooSmall)?;
        out.copy_from_slice(lists);
        Ok(Some(out))
    }

    fn keep_device_lists(&mut self, record: Option<&[u8]>) -> Result<(), StoreError> {
        self.writable()?;
        self.disk.device_lists = record.map(<[u8]>::to_vec);
        self.dirty.mark(RecordKey::DeviceLists);
        self.settle()
    }

    fn recent_picks<'b>(&self, out: &'b mut [u8]) -> Result<Option<&'b [u8]>, StoreError> {
        let Some(picks) = &self.disk.recent_picks else {
            return Ok(None);
        };
        let out = out
            .get_mut(..picks.len())
            .ok_or(StoreError::BufferTooSmall)?;
        out.copy_from_slice(picks);
        Ok(Some(out))
    }

    fn keep_recent_picks(&mut self, record: Option<&[u8]>) -> Result<(), StoreError> {
        self.writable()?;
        self.disk.recent_picks = record.map(<[u8]>::to_vec);
        self.dirty.mark(RecordKey::RecentPicks);
        self.settle()
    }

    fn interrupt(&mut self) -> Result<(), StoreError> {
        self.writable()?;
        let Disk {
            chats, messages, ..
        } = &mut self.disk;
        for (&id, message) in messages.iter_mut() {
            if message.record.direction != Direction::Outbound {
                continue;
            }
            let multicast = chats.get(&message.record.chat.0).is_some_and(|chat| {
                matches!(
                    chat.record.conversation,
                    ConversationKey::ChannelGroup { .. }
                )
            });
            if message.record.delivery.interrupt(multicast) {
                self.dirty.mark(RecordKey::Message(id));
            }
        }
        self.settle()
    }

    fn usage(&self) -> Usage {
        Usage {
            chats: self.disk.chats.len(),
            messages: self.disk.messages.len(),
            peers: self.disk.peers.len(),
            channels: self.disk.channels.len(),
            archives: self.disk.archives.len(),
            checkpoints: self.disk.checkpoints.len(),
            bytes: self.index.bytes,
            quota: self.quota.bytes,
        }
    }

    fn erase(&mut self) -> Result<(), StoreError> {
        self.writable()?;
        self.dirty.take();
        if let Err(error) = self.durable.clear() {
            let _ = self.remount();
            return Err(error);
        }
        self.disk = Disk {
            ids: self.disk.ids,
            clock: self.disk.clock,
            ..Disk::default()
        };
        self.index = Index::build(&self.disk);
        // The counters are kept again at once, so that no identifier given
        // out before is given out again.
        for kind in [CHAT, MESSAGE, PEER] {
            self.disk.reserved[kind] = self.disk.ids[kind] + ID_BLOCK;
        }
        self.dirty.mark(RecordKey::Counters);
        self.settle()
    }
}

fn copy_text<'b>(text: &str, out: &'b mut [u8]) -> Result<&'b str, StoreError> {
    let out = out
        .get_mut(..text.len())
        .ok_or(StoreError::BufferTooSmall)?;
    out.copy_from_slice(text.as_bytes());
    core::str::from_utf8(out).map_err(|_| StoreError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::{self, Harness};

    struct Memory;

    impl Harness for Memory {
        type Store = MemoryStore;

        fn fresh(&mut self) -> MemoryStore {
            MemoryStore::new()
        }

        fn cut_power_after(&mut self, store: &mut MemoryStore, step: CommitStep) {
            store.cut_power_after(step);
        }

        fn power_on(&mut self, store: &mut MemoryStore) {
            store.power_on().unwrap();
        }
    }

    use crate::conformance::{Rig, archived, direct, group, record};

    /// A durable layer that keeps records in a map, so that every remount
    /// reads them back through their encoding.
    #[derive(Default)]
    struct Kept(BTreeMap<Vec<u8>, Vec<u8>>);

    impl Durable for Kept {
        const KEEPS: bool = true;

        fn write(&mut self, key: &[u8], record: Option<&[u8]>) -> Result<(), StoreError> {
            match record {
                Some(record) => self.0.insert(key.to_vec(), record.to_vec()),
                None => self.0.remove(key),
            };
            Ok(())
        }

        fn read(&mut self, each: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), StoreError> {
            for (key, record) in &self.0 {
                each(key, record);
            }
            Ok(())
        }

        fn clear(&mut self) -> Result<(), StoreError> {
            self.0.clear();
            Ok(())
        }
    }

    struct Encoded;

    impl Harness for Encoded {
        type Store = MemoryStore<Kept>;

        fn fresh(&mut self) -> MemoryStore<Kept> {
            MemoryStore::mount(Kept::default(), Quota::DEFAULT).unwrap()
        }

        fn cut_power_after(&mut self, store: &mut MemoryStore<Kept>, step: CommitStep) {
            store.cut_power_after(step);
        }

        fn power_on(&mut self, store: &mut MemoryStore<Kept>) {
            store.power_on().unwrap();
        }
    }

    /// Every record reads back as it was written: a store mounted from
    /// what its layer keeps is the store that wrote it.
    #[test]
    fn records_read_back_whole() {
        let mut store = Encoded.fresh();
        let mut rig = Rig::new();
        for n in 0..5 {
            rig.say(&mut store, direct(), &alloc::format!("calm {n:03}"));
            rig.say(&mut store, group(), &alloc::format!("busy {n:03}"));
        }
        let peer = PublicKey([0x42; 32]);
        store
            .update_peer(
                &peer,
                PeerChange::Heard {
                    at: Some(1_800_000_000),
                    name: Some("Juniper"),
                    identity: Some(&[2, 4]),
                    linked: true,
                },
            )
            .unwrap();
        store
            .update_peer(
                &peer,
                PeerChange::Route(Some(&[umsh_core::RouterHint([1, 2])])),
            )
            .unwrap();
        let chat = store.chat_for(&direct()).unwrap();
        store
            .update_chat(chat, ChatChange::Draft(Some("half a thought")))
            .unwrap();
        store
            .update_channel(
                &ChannelTag([7; 16]),
                ChannelChange::Add {
                    name: "Ridge",
                    access: crate::ChannelAccess::Private,
                    builtin: None,
                },
            )
            .unwrap();

        let before = (
            store.disk.messages.clone(),
            store.disk.chats.len(),
            store.disk.archives.clone(),
            store.disk.checkpoints.clone(),
        );
        let mounted = MemoryStore::mount(Kept(store.durable.0.clone()), Quota::DEFAULT).unwrap();
        assert_eq!(mounted.disk.messages.len(), before.0.len());
        for (id, message) in &before.0 {
            let read = &mounted.disk.messages[id];
            assert_eq!(read.record, message.record);
            assert_eq!(read.body, message.body);
            assert_eq!(read.conversation, message.conversation);
            assert_eq!(read.revision, message.revision);
        }
        assert_eq!(mounted.disk.chats.len(), before.1);
        for (id, chat) in &store.disk.chats {
            assert_eq!(mounted.disk.chats[id].record, chat.record);
            assert_eq!(mounted.disk.chats[id].draft, chat.draft);
            assert_eq!(mounted.disk.chats[id].activity, chat.activity);
        }
        assert_eq!(mounted.disk.archives, before.2);
        assert_eq!(
            mounted
                .disk
                .checkpoints
                .values()
                .map(|(c, u)| (c.next_id, c.epoch, *u))
                .collect::<Vec<_>>(),
            before
                .3
                .values()
                .map(|(c, u)| (c.next_id, c.epoch, *u))
                .collect::<Vec<_>>()
        );
        assert_eq!(mounted.peer(&peer).unwrap(), store.peer(&peer).unwrap());
        assert_eq!(
            mounted.channels().collect::<Vec<_>>(),
            store.channels().collect::<Vec<_>>()
        );
        assert_eq!(mounted.index, store.index);
    }

    /// Identifiers given out before a power cut are not given out again,
    /// even when the records that held them were not kept.
    #[test]
    fn identifiers_outlive_power_cuts() {
        let mut store = Encoded.fresh();
        let (_, first) = Rig::new().say(&mut store, direct(), "one");
        // The message's record is lost, as if power went before it was
        // written; the counters were kept before it was given out.
        let mut kept = store.durable.0.clone();
        kept.retain(|key, _| key[0] != codec::MESSAGE_RECORD);
        let mut store = MemoryStore::mount(Kept(kept), Quota::DEFAULT).unwrap();
        let (_, next) = Rig::new().say(&mut store, group(), "two");
        assert!(next > first);
    }

    #[test]
    fn encoded_transcript() {
        conformance::transcript(&mut Encoded);
    }

    #[test]
    fn encoded_paging() {
        conformance::paging(&mut Encoded);
    }

    #[test]
    fn encoded_delivery() {
        conformance::delivery(&mut Encoded);
    }

    #[test]
    fn encoded_interruption() {
        conformance::interruption(&mut Encoded);
    }

    #[test]
    fn encoded_device_lists() {
        conformance::device_lists(&mut Encoded);
    }

    #[test]
    fn encoded_recent_picks() {
        conformance::recent_picks(&mut Encoded);
    }

    #[test]
    fn encoded_wire_aliases() {
        conformance::wire_aliases(&mut Encoded);
    }

    #[test]
    fn encoded_reactions() {
        conformance::reactions(&mut Encoded);
    }

    #[test]
    fn encoded_edits_and_deletes() {
        conformance::edits_and_deletes(&mut Encoded);
    }

    #[test]
    fn encoded_chats() {
        conformance::chats(&mut Encoded);
    }

    #[test]
    fn encoded_peers() {
        conformance::peers(&mut Encoded);
    }

    #[test]
    fn encoded_channels() {
        conformance::channels(&mut Encoded);
    }

    #[test]
    fn encoded_remount() {
        conformance::remount(&mut Encoded);
    }

    #[test]
    fn encoded_power_cuts() {
        conformance::power_cuts(&mut Encoded);
    }

    #[test]
    fn encoded_erase() {
        conformance::erase(&mut Encoded);
    }

    /// What one short message costs against the quota, its archive
    /// included.
    fn cost_of_one() -> usize {
        let mut store = MemoryStore::new();
        Rig::new().say(&mut store, group(), "busy 000");
        store.usage().bytes
    }

    #[test]
    fn eviction_takes_the_oldest_across_chats_but_each_keeps_its_newest() {
        let cost = cost_of_one();
        let mut store = MemoryStore::with_quota(Quota {
            bytes: 80 * cost,
            ..Quota::DEFAULT
        });
        let mut rig = Rig::new();
        let quiet: Vec<MessageId> = (0..10)
            .map(|n| {
                rig.say(&mut store, direct(), &alloc::format!("calm {n:03}"))
                    .1
            })
            .collect();
        let mut first_wire = None;
        let busy: Vec<MessageId> = (0..200)
            .map(|n| {
                let id = rig
                    .say(&mut store, group(), &alloc::format!("busy {n:03}"))
                    .1;
                first_wire = first_wire.or(record(&store, id).wire_id);
                id
            })
            .collect();

        // The quiet chat is older than all of it, and loses nothing.
        for &id in &quiet {
            assert!(store.message(id).unwrap().is_some());
        }
        // The busy chat lost its oldest, and only as much as it had to.
        let usage = store.usage();
        assert!(usage.bytes <= usage.quota);
        let kept = store
            .messages(store.chat_for(&group()).unwrap(), None)
            .count();
        assert!((60..=70).contains(&kept), "{kept}");
        let oldest = busy[200 - kept];
        assert!(store.message(oldest).unwrap().is_some());
        assert!(store.message(busy[199 - kept]).unwrap().is_none());

        // What is left stands at positions from the oldest kept.
        let chat = store.chat_for(&group()).unwrap();
        assert_eq!(store.message_count(chat), kept);
        assert_eq!(store.message_id_at(chat, 0), Some(oldest));
        assert_eq!(store.message_id_at(chat, kept - 1), Some(busy[199]));

        // An evicted message's resend material went with it.
        assert_eq!(archived(&store, group(), first_wire.unwrap()), None);
        let newest_wire = record(&store, busy[199]).wire_id.unwrap();
        assert!(archived(&store, group(), newest_wire).is_some());
        assert!(store.checkpoint(&group()).is_some());
    }

    #[test]
    fn no_chat_is_cut_below_its_newest() {
        let cost = cost_of_one();
        let mut store = MemoryStore::with_quota(Quota {
            bytes: 10 * cost,
            ..Quota::DEFAULT
        });
        let mut rig = Rig::new();
        for n in 0..20 {
            rig.say(&mut store, direct(), &alloc::format!("calm {n:03}"));
        }
        for n in 0..120 {
            rig.say(&mut store, group(), &alloc::format!("busy {n:03}"));
        }
        let count = |conversation| {
            store
                .messages(store.chat_for(&conversation).unwrap(), None)
                .count()
        };
        // Over quota, and still each chat keeps its newest 50.
        assert_eq!(count(direct()), 20);
        assert_eq!(count(group()), 50);
        assert!(store.usage().bytes > store.usage().quota);
    }

    #[test]
    fn transcript() {
        conformance::transcript(&mut Memory);
    }

    #[test]
    fn paging() {
        conformance::paging(&mut Memory);
    }

    #[test]
    fn delivery() {
        conformance::delivery(&mut Memory);
    }

    #[test]
    fn interruption() {
        conformance::interruption(&mut Memory);
    }

    #[test]
    fn device_lists() {
        conformance::device_lists(&mut Memory);
    }

    #[test]
    fn recent_picks() {
        conformance::recent_picks(&mut Memory);
    }

    #[test]
    fn wire_aliases() {
        conformance::wire_aliases(&mut Memory);
    }

    #[test]
    fn reactions() {
        conformance::reactions(&mut Memory);
    }

    #[test]
    fn edits_and_deletes() {
        conformance::edits_and_deletes(&mut Memory);
    }

    #[test]
    fn chats() {
        conformance::chats(&mut Memory);
    }

    #[test]
    fn peers() {
        conformance::peers(&mut Memory);
    }

    #[test]
    fn channels() {
        conformance::channels(&mut Memory);
    }

    #[test]
    fn buffers() {
        conformance::buffers(&mut Memory);
    }

    #[test]
    fn remount() {
        conformance::remount(&mut Memory);
    }

    #[test]
    fn power_cuts() {
        conformance::power_cuts(&mut Memory);
    }

    #[test]
    fn erase() {
        conformance::erase(&mut Memory);
    }
}
