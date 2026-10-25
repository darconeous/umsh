//! Allocated chat facade around the text engine (feature `alloc`).
//!
//! [`ChatFacade`] owns an [`Engine`] and the state every platform keeps
//! beside it: the channels a session can hold conversations in, the full
//! keys learned for channel members known only by hint, and the bookkeeping
//! that lets a rejected compose put the engine back the way storage last saw
//! it. Conversations are typed [`ConversationKey`]s; platform address formats
//! are codecs over them, outside this module.
//!
//! Engine outputs leave the facade owned—bodies copied out of the engine's
//! render arena—and in the order the engine produced them. Frames for the
//! radio leave only inside an [`Outbound`], which only the facade makes:
//!
//! - [`ChatFacade::compose`] returns a [`PendingBatch`] that holds its frames
//!   until [`ChatFacade::commit`] releases them, after the platform has stored
//!   the batch's checkpoint, archive changes, and transcript mutations. A
//!   failed store calls [`ChatFacade::reject`] instead, which fails the frames
//!   and rebuilds the engine from the checkpoints storage still holds.
//! - [`ChatFacade::drain`] returns everything else the engine produced, with
//!   the frames that answer resend requests and ask for repairs. None of them
//!   allocates a wire ID, so none waits on storage.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{ChannelKey, ChannelTag, NodeHint, PublicKey, RouterHint};

use crate::engine::sequence::MessageHandle;
use crate::engine::{
    ArchiveKey, ArchiveResult, BodyRef, CompletionStatus, ComposeError, ComposeIntent,
    DeliveryState, Diagnostic, Direction, Engine, EngineConfig, Event, MessageMutation,
    MutationKind, Output, Presence, ReceiveError, ResolvedRef, StreamCheckpoint, Transmission,
};
use crate::model::{ConversationKey, MessageType, SenderScope};
use crate::validate::{DeliveryPath, DirectChannelProfile, Envelope, TextProfile};

/// The channels a session can hold a conversation in, and the keys to reach
/// them.
///
/// Channel membership already lives in the MAC, which resolves an inbound
/// frame to a key by authenticating it. This is the chat layer's own view: it
/// maps between the tag a conversation is keyed by and the key a send needs,
/// in both directions.
#[derive(Clone, Default)]
pub struct ChannelRegistry {
    entries: BTreeMap<ChannelTag, ChannelEntry>,
}

/// One registered channel: its key, and how far the user lets its traffic
/// travel.
#[derive(Clone, Copy)]
struct ChannelEntry {
    key: ChannelKey,
    /// The user's own flood-hop ceiling for this channel, or `None` to use
    /// the session-wide default.
    max_flood_hops: Option<u8>,
}

impl ChannelRegistry {
    /// Hold `tag`'s channel, reached with `key`. Registering a held channel
    /// again replaces its key and ceiling.
    pub fn register(&mut self, tag: ChannelTag, key: ChannelKey, max_flood_hops: Option<u8>) {
        self.entries.insert(
            tag,
            ChannelEntry {
                key,
                max_flood_hops,
            },
        );
    }

    pub fn remove(&mut self, tag: &ChannelTag) {
        self.entries.remove(tag);
    }

    pub fn key(&self, tag: &ChannelTag) -> Option<ChannelKey> {
        self.entries.get(tag).map(|entry| entry.key)
    }

    /// The tag of the held channel `key` reaches.
    ///
    /// A received frame names its channel by the key that authenticated it,
    /// which is the truth about which channel it belongs to: distinct keys
    /// may share the two-byte identifier the frame carried.
    pub fn tag_for(&self, key: &ChannelKey) -> Option<ChannelTag> {
        self.entries
            .iter()
            .find(|(_, entry)| entry.key.0 == key.0)
            .map(|(tag, _)| *tag)
    }

    /// The flood-hop ceiling registered for a channel, if the user set one.
    /// `None` both for a channel left at the default and for one not
    /// registered at all.
    pub fn max_flood_hops(&self, tag: &ChannelTag) -> Option<u8> {
        self.entries.get(tag).and_then(|entry| entry.max_flood_hops)
    }

    pub fn contains(&self, tag: &ChannelTag) -> bool {
        self.entries.contains_key(tag)
    }

    pub fn tags(&self) -> impl Iterator<Item = ChannelTag> + '_ {
        self.entries.keys().copied()
    }
}

/// Values a facade session is started from.
///
/// Both come from the platform, so the facade needs no randomness of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seeds {
    /// Names the engine instance whose [`MessageHandle`]s and transmission
    /// IDs a platform holds, so they cannot be mistaken for another
    /// instance's after a restart or a rejected batch. Never zero: zero is
    /// taken as one.
    pub session_id: u64,
    /// Drives group-repair desynchronization only; scheduling randomness,
    /// not security material.
    pub jitter_seed: u64,
}

/// Who a received text payload came from, and over what.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextSource {
    /// Authenticated unicast from a peer.
    Direct { peer: PublicKey },
    /// Multicast to a channel. The sender claims a hint; the full key is
    /// present only when they addressed the frame with it.
    ChannelGroup {
        channel: ChannelTag,
        hint: NodeHint,
        full_key: Option<PublicKey>,
    },
    /// Blind unicast to us over a channel key, from an addressable peer.
    ChannelDirect {
        channel: ChannelTag,
        peer: PublicKey,
    },
}

impl TextSource {
    pub fn channel(&self) -> Option<ChannelTag> {
        match self {
            Self::Direct { .. } => None,
            Self::ChannelGroup { channel, .. } | Self::ChannelDirect { channel, .. } => {
                Some(*channel)
            }
        }
    }

    /// The engine envelope for a payload from this source.
    ///
    /// A multicast member is always the claimed hint, with any full key
    /// passed beside it: naming the key here instead would split one member
    /// into two streams the moment a frame omitted it.
    pub fn envelope(&self) -> Envelope {
        match *self {
            Self::Direct { peer } => Envelope {
                path: DeliveryPath::Unicast,
                conversation: ConversationKey::Direct { peer },
                sender: SenderScope::Peer(peer),
            },
            Self::ChannelGroup { channel, hint, .. } => Envelope {
                path: DeliveryPath::Multicast,
                conversation: ConversationKey::ChannelGroup { channel },
                sender: SenderScope::ClaimedMember(hint),
            },
            Self::ChannelDirect { channel, peer } => Envelope {
                path: DeliveryPath::BlindUnicast,
                conversation: ConversationKey::ChannelDirect { channel, peer },
                sender: SenderScope::Peer(peer),
            },
        }
    }

    /// The sender's full key, when the frame carried or authenticated one.
    pub fn full_key(&self) -> Option<PublicKey> {
        match *self {
            Self::Direct { peer } | Self::ChannelDirect { peer, .. } => Some(peer),
            Self::ChannelGroup { full_key, .. } => full_key,
        }
    }
}

/// An owned transcript mutation (see [`MessageMutation`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutation {
    pub handle: MessageHandle,
    /// Apply only if newer than the last revision applied for `handle`.
    pub revision: u32,
    pub change: Change,
}

impl Mutation {
    /// The owned form of one of the engine's mutations, read while it is
    /// fresh: `body` is [`Engine::body`] until the engine's queue empties.
    /// `sender_key` gives the full key behind a sender scope, where one is
    /// known.
    pub fn from_engine<'e>(
        mutation: MessageMutation,
        body: impl Fn(&BodyRef) -> &'e str,
        sender_key: impl FnOnce(ConversationKey, SenderScope) -> Option<PublicKey>,
    ) -> Self {
        let change = match mutation.kind {
            MutationKind::Insert {
                conversation,
                sender,
                direction,
                message_type,
                wire_id,
                epoch,
                client_token,
                sender_handle,
                regarding,
                bg_color,
                text_color,
                body: text,
                status,
                presence,
                late,
                notify,
            } => Change::Insert(Insert {
                conversation,
                sender,
                sender_key: sender_key(conversation, sender),
                direction,
                message_type,
                wire_id,
                epoch,
                client_token,
                sender_handle: sender_handle.map(|value| String::from(body(&value))),
                regarding,
                bg_color,
                text_color,
                body: String::from(body(&text)),
                status,
                presence,
                late,
                notify,
            }),
            MutationKind::UpdateBody {
                body: text,
                status,
                late,
                notify,
            } => Change::UpdateBody {
                body: String::from(body(&text)),
                status,
                late,
                notify,
            },
            MutationKind::Edit {
                conversation,
                original,
                body: text,
            } => Change::Edit {
                conversation,
                original,
                body: String::from(body(&text)),
            },
            MutationKind::Delete {
                conversation,
                original,
            } => Change::Delete {
                conversation,
                original,
            },
        };
        Self {
            handle: mutation.handle,
            revision: mutation.revision,
            change,
        }
    }

    /// Whether this record describes content that arrived in the frame that
    /// produced it, as opposed to an outbound echo, a gap placeholder, or a
    /// change to an earlier message. Radio metadata belongs only on these.
    pub fn describes_receipt(&self) -> bool {
        match &self.change {
            Change::Insert(insert) => {
                insert.direction == Direction::Inbound && insert.presence == Presence::Present
            }
            Change::UpdateBody { .. } => true,
            Change::Edit { .. } | Change::Delete { .. } => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Insert(Insert),
    /// Replace the rendered body (reassembly progress or finalization).
    UpdateBody {
        body: String,
        status: CompletionStatus,
        late: bool,
        notify: bool,
    },
    /// Apply an edit to the referenced original message.
    Edit {
        conversation: ConversationKey,
        original: ResolvedRef,
        body: String,
    },
    /// Mark the referenced original message deleted.
    Delete {
        conversation: ConversationKey,
        original: ResolvedRef,
    },
}

/// A new transcript record (see [`MutationKind::Insert`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insert {
    pub conversation: ConversationKey,
    pub sender: SenderScope,
    /// The sender's full key: an authenticated peer's, or the key a claimed
    /// member's hint has resolved to. `None` for our own messages and for
    /// members not yet resolved.
    pub sender_key: Option<PublicKey>,
    pub direction: Direction,
    pub message_type: MessageType,
    pub wire_id: Option<u8>,
    pub epoch: u16,
    pub client_token: Option<u32>,
    pub sender_handle: Option<String>,
    pub regarding: Option<ResolvedRef>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub body: String,
    pub status: CompletionStatus,
    pub presence: Presence,
    pub late: bool,
    pub notify: bool,
}

/// A change in a frame's delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub handle: MessageHandle,
    pub fragment: Option<u8>,
    pub state: DeliveryState,
    /// The acknowledgment answered the flood that followed a miss on the
    /// peer's route, not the routed send itself.
    pub via_flood: bool,
}

/// The repeaters overheard carrying one of our frames, as tallied so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repeats {
    pub handle: MessageHandle,
    pub fragment: Option<u8>,
    /// Repeaters the forwards named, each once, in the order first heard.
    pub repeaters: Vec<RouterHint>,
    /// Forwards that named no repeater, each taken for a repeater of its own.
    pub anonymous: u16,
}

/// Look up resendable material; answer with [`ChatFacade::archive_result`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveLookup {
    pub request_id: u32,
    pub key: ArchiveKey,
}

/// Store this exact payload as resendable material under `key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveWrite {
    pub key: ArchiveKey,
    pub payload: Vec<u8>,
}

/// Retire every archived fragment stored under one message ID.
///
/// Emitted when an edit or delete supersedes that ID's content, ahead of any
/// replacement [`ArchiveWrite`], so superseded content can never be served
/// to a resend request again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveDelete {
    pub conversation: ConversationKey,
    pub message_id: u8,
}

/// A channel member previously known only by their claimed hint has been
/// resolved to a full public key.
///
/// Announced once per channel and hint: the first full key seen for a hint
/// is the one kept, since a hint is only three bytes and two members could
/// claim the same one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenderResolution {
    pub channel: ChannelTag,
    pub hint: NodeHint,
    pub key: PublicKey,
}

/// One owned facade output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatOutput {
    Mutation(Mutation),
    Delivery(Delivery),
    /// The whole tally so far, each time it grows.
    Repeats(Repeats),
    Lookup(ArchiveLookup),
    SenderResolved(SenderResolution),
    StoreArchive(ArchiveWrite),
    DeleteArchive(ArchiveDelete),
    /// Engine events other than delivery changes (repair progress, remote
    /// unavailability).
    Event(Event),
    Diagnostic(Diagnostic),
}

/// Frames released to the radio, from one engine session.
///
/// Only the facade makes one: by committing a [`PendingBatch`], or in a
/// [`Drain`].
#[derive(Debug)]
pub struct Outbound {
    session_id: u64,
    transmissions: Vec<Transmission>,
}

impl Outbound {
    /// The session whose transmission IDs these are. Delivery reports name
    /// it, so a report for a frame of an engine since rebuilt is ignored
    /// rather than applied to an unrelated frame that reuses the ID.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn is_empty(&self) -> bool {
        self.transmissions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.transmissions.len()
    }

    pub fn transmissions(&self) -> &[Transmission] {
        &self.transmissions
    }

    pub fn into_transmissions(self) -> Vec<Transmission> {
        self.transmissions
    }
}

/// What the facade produced since the last drain.
#[derive(Debug)]
pub struct Drain {
    /// The session whose handles the outputs name.
    pub session_id: u64,
    pub outputs: Vec<ChatOutput>,
    pub outbound: Outbound,
}

impl Drain {
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty() && self.outbound.is_empty()
    }
}

/// A composed message waiting to be stored.
///
/// Store, in order, the checkpoint, the archive deletes, the archives, and
/// the mutations; then [`ChatFacade::commit`] releases the frames. If storing
/// fails, [`ChatFacade::reject`] fails them instead. The frames cannot reach
/// the radio any other way.
#[must_use = "a composed batch holds its frames until it is committed or rejected"]
#[derive(Debug)]
pub struct PendingBatch {
    id: u64,
    session_id: u64,
    pub checkpoint: StreamCheckpoint,
    pub archive_deletes: Vec<ArchiveDelete>,
    pub archives: Vec<ArchiveWrite>,
    pub mutations: Vec<Mutation>,
    /// Anything else the compose produced: deliveries, events, diagnostics.
    pub outputs: Vec<ChatOutput>,
    transmissions: Vec<Transmission>,
}

impl PendingBatch {
    /// Unique within a facade; never zero.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The session whose handles the mutations name.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// How many frames the message goes out in. For an original message
    /// this matches the archive count, but an edit's frames carry the
    /// editing option while its replacement archive is re-encoded without
    /// it, so the two can fragment differently.
    pub fn transmission_count(&self) -> usize {
        self.transmissions.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatComposeError {
    /// An earlier batch is still waiting to be committed or rejected.
    /// Rejecting rebuilds the engine, which would invalidate a second batch
    /// composed in the meantime, so only one may be outstanding.
    BatchPending,
    Engine(ComposeError),
    /// The engine's output queue overflowed and the batch is incomplete;
    /// nothing was released.
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatReceiveError {
    /// The source names a channel this session does not hold.
    ChannelNotHeld,
    Engine(ReceiveError),
}

/// The batch is not the one this facade is waiting on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchMismatch;

/// Transport progress for a released frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransmitUpdate {
    Sent,
    Acked {
        /// The acknowledgment answered a route-retry flood.
        via_flood: bool,
    },
    Failed,
}

/// The chat facade.
pub struct ChatFacade<
    P: TextProfile + Clone = DirectChannelProfile,
    const SLOTS: usize = 4,
    const PAGES: usize = 24,
> {
    /// Kept off the caller's stack: the engine is a large bounded value.
    engine: Box<Engine<P, SLOTS, PAGES>>,
    profile: P,
    config: EngineConfig,
    local_key: PublicKey,
    /// Reapplied whenever the engine is rebuilt.
    local_handle: String,
    session_id: u64,
    channels: ChannelRegistry,
    /// Full keys learned for claimed member hints, per channel; the first
    /// key seen for a hint stays.
    members: BTreeMap<(ChannelTag, [u8; 3]), PublicKey>,
    /// Frames, as `(handle, fragment)`, whose acknowledgment came back
    /// through a route-retry flood, held until the delivery is drained.
    flooded: BTreeSet<(u32, Option<u8>)>,
    staged: Vec<ChatOutput>,
    staged_transmissions: Vec<Transmission>,
    next_batch_id: u64,
    pending_batch: Option<u64>,
}

/// Engine outputs collected and converted, before they are sorted into a
/// batch or a drain.
struct Collected {
    checkpoint: Option<StreamCheckpoint>,
    outputs: Vec<ChatOutput>,
    transmissions: Vec<Transmission>,
}

impl<P: TextProfile + Clone, const SLOTS: usize, const PAGES: usize> ChatFacade<P, SLOTS, PAGES> {
    pub fn new(profile: P, local_key: PublicKey, config: EngineConfig, seeds: Seeds) -> Self {
        Self {
            engine: Box::new(Engine::new(
                profile.clone(),
                local_key,
                config.clone(),
                seeds.jitter_seed,
            )),
            profile,
            config,
            local_key,
            local_handle: String::new(),
            session_id: seeds.session_id.max(1),
            channels: ChannelRegistry::default(),
            members: BTreeMap::new(),
            flooded: BTreeSet::new(),
            staged: Vec::new(),
            staged_transmissions: Vec::new(),
            next_batch_id: 1,
            pending_batch: None,
        }
    }

    pub fn local_key(&self) -> PublicKey {
        self.local_key
    }

    /// The current engine session; see [`Seeds::session_id`].
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn channels(&self) -> &ChannelRegistry {
        &self.channels
    }

    pub fn channels_mut(&mut self) -> &mut ChannelRegistry {
        &mut self.channels
    }

    /// Whether a composed batch is waiting to be committed or rejected.
    pub fn has_pending_batch(&self) -> bool {
        self.pending_batch.is_some()
    }

    /// Set the Sender Handle carried on our own group messages. It survives
    /// a rebuild of the engine.
    pub fn set_local_handle(&mut self, handle: &str) {
        self.local_handle.clear();
        self.local_handle.push_str(handle);
        self.engine.set_local_handle(handle);
    }

    pub fn local_handle(&self) -> &str {
        &self.local_handle
    }

    /// The full key a channel member's hint resolved to, if one has.
    pub fn member_key(&self, channel: &ChannelTag, hint: &NodeHint) -> Option<PublicKey> {
        self.members.get(&(*channel, hint.0)).copied()
    }

    /// Seed outbound stream continuity from stored checkpoints, oldest
    /// first (see [`Engine::restore`]).
    pub fn restore(&mut self, checkpoints: &[StreamCheckpoint], now_ms: u64) {
        self.engine.restore(checkpoints, now_ms);
        self.stage();
    }

    /// Compose a message into `conversation`. `stored` is the checkpoint
    /// storage holds for it, if any, which the engine continues from when it
    /// no longer remembers the conversation itself (see [`Engine::recall`]).
    pub fn compose(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        intent: ComposeIntent<'_>,
        stored: Option<&StreamCheckpoint>,
        now_ms: u64,
    ) -> Result<PendingBatch, ChatComposeError> {
        if self.pending_batch.is_some() {
            return Err(ChatComposeError::BatchPending);
        }
        if let Some(stored) = stored.filter(|stored| stored.conversation == conversation) {
            self.engine.recall(stored);
        }
        if let Err(error) = self
            .engine
            .compose(conversation, client_token, intent, now_ms)
        {
            // Encoding can fail after some fragments were queued.
            self.discard_outputs(now_ms);
            return Err(ChatComposeError::Engine(error));
        }
        let collected = self.collect();
        let Some(checkpoint) = collected.checkpoint else {
            self.abandon(collected.transmissions, now_ms);
            return Err(ChatComposeError::Incomplete);
        };
        let mut batch = PendingBatch {
            id: self.next_batch_id,
            session_id: self.session_id,
            checkpoint,
            archive_deletes: Vec::new(),
            archives: Vec::new(),
            mutations: Vec::new(),
            outputs: Vec::new(),
            transmissions: collected.transmissions,
        };
        for output in collected.outputs {
            match output {
                ChatOutput::Mutation(mutation) => batch.mutations.push(mutation),
                ChatOutput::StoreArchive(archive) => batch.archives.push(archive),
                ChatOutput::DeleteArchive(delete) => batch.archive_deletes.push(delete),
                other => batch.outputs.push(other),
            }
        }
        self.next_batch_id = self.next_batch_id.wrapping_add(1).max(1);
        self.pending_batch = Some(batch.id);
        Ok(batch)
    }

    /// Release a stored batch's frames.
    pub fn commit(&mut self, batch: PendingBatch) -> Result<Outbound, BatchMismatch> {
        if self.pending_batch != Some(batch.id) {
            return Err(BatchMismatch);
        }
        self.pending_batch = None;
        Ok(Outbound {
            session_id: batch.session_id,
            transmissions: batch.transmissions,
        })
    }

    /// Give up on a batch that could not be stored.
    ///
    /// Its frames are failed, and the engine is rebuilt from `checkpoints`—
    /// what storage holds—so nothing it composed since is remembered as
    /// sent. The channels, the resolved members, and the Sender Handle are
    /// the session's, not the engine's, and are kept.
    ///
    /// The returned drain holds everything produced up to the rebuild,
    /// named by the old session. The rebuilt engine runs as
    /// `seeds.session_id`, which must differ from the old one: the new
    /// engine reissues handles and transmission IDs from the start.
    pub fn reject(
        &mut self,
        batch: PendingBatch,
        checkpoints: &[StreamCheckpoint],
        seeds: Seeds,
        now_ms: u64,
    ) -> Result<Drain, BatchMismatch> {
        if self.pending_batch != Some(batch.id) {
            return Err(BatchMismatch);
        }
        self.pending_batch = None;
        for transmission in &batch.transmissions {
            self.engine.transmit_update(
                transmission.transmission_id,
                DeliveryState::Failed,
                now_ms,
            );
        }
        self.stage();
        let drain = self.drain();

        *self.engine = Engine::new(
            self.profile.clone(),
            self.local_key,
            self.config.clone(),
            seeds.jitter_seed,
        );
        self.engine.set_local_handle(&self.local_handle);
        self.session_id = seeds.session_id.max(1);
        self.flooded.clear();
        self.engine.restore(checkpoints, now_ms);
        self.discard_outputs(now_ms);
        Ok(drain)
    }

    /// Feed one received text payload (without the payload-type byte).
    pub fn receive(
        &mut self,
        source: TextSource,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), ChatReceiveError> {
        if let Some(channel) = source.channel()
            && !self.channels.contains(&channel)
        {
            return Err(ChatReceiveError::ChannelNotHeld);
        }
        if let TextSource::ChannelGroup {
            channel,
            hint,
            full_key: Some(key),
        } = source
        {
            self.resolve_member(channel, hint, key);
        }
        let result = self
            .engine
            .receive(&source.envelope(), source.full_key(), payload, now_ms)
            .map_err(ChatReceiveError::Engine);
        self.stage();
        result
    }

    /// Answer an [`ArchiveLookup`].
    pub fn archive_result(&mut self, request_id: u32, result: ArchiveResult<'_>, now_ms: u64) {
        self.engine.archive_result(request_id, result, now_ms);
        self.stage();
    }

    /// Send one of the message `handle`'s frames again, as the archive
    /// keeps it under `key` (see [`Engine::retransmit`]). Returns whether it
    /// was queued.
    pub fn retransmit(&mut self, key: &ArchiveKey, handle: MessageHandle, payload: &[u8]) -> bool {
        let queued = self.engine.retransmit(key, handle, payload);
        self.stage();
        queued
    }

    /// Take back one of our messages sent before this session, as the
    /// store keeps it (see [`Engine::adopt`]), with `stored` the
    /// conversation's checkpoint as for [`ChatFacade::compose`]. Returns
    /// the handle it goes by now.
    pub fn adopt(
        &mut self,
        conversation: ConversationKey,
        message_id: u8,
        epoch: u16,
        stored: Option<&StreamCheckpoint>,
        now_ms: u64,
    ) -> Option<MessageHandle> {
        if let Some(stored) = stored.filter(|stored| stored.conversation == conversation) {
            self.engine.recall(stored);
        }
        let handle = self.engine.adopt(conversation, message_id, epoch, now_ms);
        self.stage();
        handle
    }

    /// Advance timers: reassembly expiry, notify deadlines, repair.
    pub fn tick(&mut self, now_ms: u64) {
        self.engine.tick(now_ms);
        self.stage();
    }

    /// Report transport progress for a frame released in `session_id`.
    /// Reports for an earlier session are ignored.
    pub fn transmit_update(
        &mut self,
        session_id: u64,
        transmission_id: u32,
        update: TransmitUpdate,
        now_ms: u64,
    ) {
        if session_id != self.session_id {
            return;
        }
        let state = match update {
            TransmitUpdate::Sent => DeliveryState::Sent,
            TransmitUpdate::Acked { via_flood } => {
                if via_flood
                    && let Some((handle, fragment)) = self.engine.in_flight_frame(transmission_id)
                {
                    self.flooded.insert((handle.0, fragment));
                }
                DeliveryState::Acked
            }
            TransmitUpdate::Failed => DeliveryState::Failed,
        };
        self.engine.transmit_update(transmission_id, state, now_ms);
        self.stage();
    }

    /// The message and fragment a frame released in `session_id` carries,
    /// while the engine still tracks it: a frame that will never be
    /// acknowledged is let go once it is sent.
    pub fn in_flight_frame(
        &self,
        session_id: u64,
        transmission_id: u32,
    ) -> Option<(MessageHandle, Option<u8>)> {
        if session_id != self.session_id {
            return None;
        }
        self.engine.in_flight_frame(transmission_id)
    }

    /// Report the repeaters overheard carrying a frame released in
    /// `session_id`. Reports for an earlier session are ignored.
    pub fn transmit_repeats(&mut self, session_id: u64, repeats: Repeats) {
        if session_id != self.session_id {
            return;
        }
        self.staged.push(ChatOutput::Repeats(repeats));
    }

    /// Everything produced since the last drain, in order.
    pub fn drain(&mut self) -> Drain {
        Drain {
            session_id: self.session_id,
            outputs: core::mem::take(&mut self.staged),
            outbound: Outbound {
                session_id: self.session_id,
                transmissions: core::mem::take(&mut self.staged_transmissions),
            },
        }
    }

    fn resolve_member(&mut self, channel: ChannelTag, hint: NodeHint, key: PublicKey) {
        if self.members.contains_key(&(channel, hint.0)) {
            return;
        }
        self.members.insert((channel, hint.0), key);
        self.staged
            .push(ChatOutput::SenderResolved(SenderResolution {
                channel,
                hint,
                key,
            }));
    }

    /// Collect the engine's outputs into the staged drain.
    fn stage(&mut self) {
        let collected = self.collect();
        // Only compose stores a checkpoint, and compose collects its own.
        debug_assert!(collected.checkpoint.is_none());
        self.staged.extend(collected.outputs);
        self.staged_transmissions.extend(collected.transmissions);
    }

    /// Drop whatever the engine has queued, failing its frames so the engine
    /// stops tracking them.
    fn discard_outputs(&mut self, now_ms: u64) {
        let collected = self.collect();
        self.abandon(collected.transmissions, now_ms);
    }

    fn abandon(&mut self, transmissions: Vec<Transmission>, now_ms: u64) {
        for transmission in transmissions {
            self.engine.transmit_update(
                transmission.transmission_id,
                DeliveryState::Failed,
                now_ms,
            );
        }
        while self.engine.poll_output().is_some() {}
    }

    fn collect(&mut self) -> Collected {
        let mut collected = Collected {
            checkpoint: None,
            outputs: Vec::new(),
            transmissions: Vec::new(),
        };
        // Bodies are read from the render arena as each output is taken: it
        // resets once the queue is empty.
        while let Some(output) = self.engine.poll_output() {
            match output {
                Output::Transmit(transmission) => {
                    if let Some(key) = transmission.archive {
                        collected
                            .outputs
                            .push(ChatOutput::StoreArchive(ArchiveWrite {
                                key,
                                payload: transmission.payload.to_vec(),
                            }));
                    }
                    collected.transmissions.push(transmission);
                }
                Output::StoreCheckpoint {
                    conversation,
                    next_id,
                    epoch,
                } => {
                    collected.checkpoint = Some(StreamCheckpoint {
                        conversation,
                        next_id,
                        epoch,
                    });
                }
                Output::LookupOutbound {
                    request_id,
                    conversation,
                    sequence,
                } => collected.outputs.push(ChatOutput::Lookup(ArchiveLookup {
                    request_id,
                    key: ArchiveKey {
                        conversation,
                        message_id: sequence.message_id,
                        fragment: sequence.fragment.map(|fragment| fragment.index),
                    },
                })),
                Output::StoreArchive { key, payload } => {
                    collected
                        .outputs
                        .push(ChatOutput::StoreArchive(ArchiveWrite {
                            key,
                            payload: payload.to_vec(),
                        }));
                }
                Output::DeleteArchive {
                    conversation,
                    message_id,
                } => collected
                    .outputs
                    .push(ChatOutput::DeleteArchive(ArchiveDelete {
                        conversation,
                        message_id,
                    })),
                Output::StoreMessage(mutation) => {
                    let mutation = self.owned_mutation(mutation);
                    collected.outputs.push(ChatOutput::Mutation(mutation));
                }
                Output::Event(Event::DeliveryStateChanged {
                    handle,
                    fragment,
                    state,
                }) => collected.outputs.push(ChatOutput::Delivery(Delivery {
                    handle,
                    fragment,
                    state,
                    via_flood: state == DeliveryState::Acked
                        && self.flooded.remove(&(handle.0, fragment)),
                })),
                Output::Event(event) => collected.outputs.push(ChatOutput::Event(event)),
                Output::Diagnostic(diagnostic) => {
                    collected.outputs.push(ChatOutput::Diagnostic(diagnostic));
                }
            }
        }
        collected
    }

    fn owned_mutation(&self, mutation: MessageMutation) -> Mutation {
        Mutation::from_engine(
            mutation,
            |body| self.engine.body(body),
            |conversation, sender| self.sender_key(conversation, sender),
        )
    }

    /// The sender's full key when one is known. A multicast member claims
    /// only a hint, so this is whatever key that hint has resolved to.
    fn sender_key(&self, conversation: ConversationKey, sender: SenderScope) -> Option<PublicKey> {
        match sender {
            SenderScope::Peer(peer) => Some(peer),
            SenderScope::Local => None,
            SenderScope::ClaimedMember(hint) => match conversation {
                ConversationKey::ChannelGroup { channel } => self.member_key(&channel, &hint),
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod tests;
