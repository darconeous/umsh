//! Owned mobile facade records for the sans-I/O text engine.
//!
//! Conversations are addressed by an opaque string that discriminates the two
//! kinds the platform can hold: a peer's base58 address for a direct
//! conversation, and `ch:<hex tag>` for a channel's group conversation. Room
//! profiles are still outside this facade, and are dropped rather than
//! exported in a form Swift would have to interpret.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use rand::Rng;
use umsh_core::{ChannelKey, ChannelTag, NodeHint, PublicKey};
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveKey, CompletionStatus, ComposeIntent, ComposeRef, DeliveryState, Direction, Engine,
    EngineConfig, Event, MessageMutation, MutationKind, Output, Presence, RegardingRef,
    ResolvedRef, StreamCheckpoint, Transmission,
};
use umsh_text::model::{ConversationKey, SenderScope, WireRef};
use umsh_text::validate::DirectChannelProfile;

pub(crate) type ChatEngine = Engine<DirectChannelProfile>;

/// Prefix marking a channel group conversation address.
const CHANNEL_ADDRESS_PREFIX: &str = "ch:";
/// Prefix marking a blind-unicast conversation over a channel key.
const CHANNEL_DIRECT_ADDRESS_PREFIX: &str = "chd:";

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatCheckpointRecord {
    pub conversation_address: String,
    pub next_id: u8,
    pub epoch: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatArchiveRecord {
    pub conversation_address: String,
    pub message_id: u8,
    pub fragment_index: Option<u8>,
    pub payload: Vec<u8>,
}

/// Retire every archived fragment stored under one message ID. Emitted when
/// an edit or delete supersedes that ID's content; the platform must apply
/// these *before* the batch's archive upserts so an edit's replacement
/// payloads land on a clean slate and the superseded content can never be
/// served to a resend request again.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatArchiveDeleteRecord {
    pub conversation_address: String,
    pub message_id: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatMutationKind {
    Insert,
    UpdateBody,
    Edit,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatDirection {
    Inbound,
    Outbound,
}

/// Ordered-slot presence of a transcript row (mirrors the engine's
/// [`Presence`]). A `GapPending` row is a reserved spinner placeholder; an
/// `Unavailable` row is a permanent loss marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatPresence {
    Present,
    GapPending,
    Unavailable,
}

/// Physical-layer metadata for a record produced by a live received frame.
///
/// The engine is transport-agnostic and carries none of this, so the facade
/// attaches it alongside the mutation the frame produced. Absent on records
/// that came from a timer, a compose, or a repair drain.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatRxMetadataRecord {
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
    /// Radio links the frame crossed to get here, counting the final one into
    /// this device: a frame heard directly from its sender is one hop. The
    /// same count a ping reply reports, and absent for the same reason — a
    /// frame source-routed without a trace route crossed hops nobody
    /// recorded.
    pub hop_count: Option<u8>,
    /// Intermediate-router hints in trace-route order: each forwarding
    /// repeater prepends its own hint, so the list starts nearest us and ends
    /// nearest the sender. That is return-path order — usable directly as a
    /// source route back — and the reverse of the path the frame travelled.
    pub route_hints: Vec<Vec<u8>>,
    pub source_authenticated: bool,
}

/// A channel member previously known only by their claimed hint has been
/// resolved to a full public key.
///
/// Multicast senders are identified on the wire by a 3-byte hint. The platform
/// renders those as anonymous members until a frame carries the full key;
/// this record lets it upgrade the rows it already stored, keyed by
/// conversation and hint.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatSenderResolutionRecord {
    pub conversation_address: String,
    pub sender_hint: Vec<u8>,
    pub sender_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatMutationRecord {
    /// A facade-session namespace prevents the engine's process-local u32
    /// handles from colliding after restart.
    pub session_id: u64,
    pub handle: u32,
    pub revision: u32,
    pub kind: MobileChatMutationKind,
    pub conversation_address: Option<String>,
    pub sender_address: Option<String>,
    /// The sender's 3-byte claimed hint, for a channel group message. The
    /// only sender identity a multicast frame is required to carry; present
    /// whether or not `sender_address` could be resolved.
    pub sender_hint: Option<Vec<u8>>,
    pub direction: Option<MobileChatDirection>,
    pub message_type: Option<u8>,
    pub wire_id: Option<u8>,
    pub epoch: Option<u16>,
    pub client_token: Option<u32>,
    pub sender_handle: Option<String>,
    pub regarding_handle: Option<u32>,
    /// When a reply or emote references a message the engine holds no live
    /// handle for, these export the wire reference the same way the
    /// `original_*` fields do for edits: the target's wire ID within
    /// `regarding_direction`'s stream, plus the hint identifying which
    /// member's stream in a channel group.
    pub regarding_wire_id: Option<u8>,
    pub regarding_direction: Option<MobileChatDirection>,
    pub regarding_sender_hint: Option<Vec<u8>>,
    pub background_color: Option<Vec<u8>>,
    pub text_color: Option<Vec<u8>>,
    pub original_handle: Option<u32>,
    /// When an edit/delete references a message the engine no longer holds a
    /// live handle for (composed before a restart), these export the wire
    /// reference so the platform can resolve it against persisted rows:
    /// the original's wire ID within `original_direction`'s stream of the
    /// record's `conversation_address` conversation.
    pub original_wire_id: Option<u8>,
    pub original_direction: Option<MobileChatDirection>,
    /// The claimed hint of the original's sender, for a channel group
    /// conversation. Inbound group streams are per-member, so matching a wire
    /// reference there needs the hint as well as the ID and direction.
    pub original_sender_hint: Option<Vec<u8>>,
    pub body: Option<String>,
    pub complete: Option<bool>,
    pub present_fragments: Option<u16>,
    pub fragment_count: Option<u8>,
    pub finalized: Option<bool>,
    /// Ordered-slot presence for `Insert` records (spinner placeholder, real
    /// message, or loss marker). `UpdateBody`/`Edit`/`Delete` leave it at
    /// `Present`; the host does not reinterpret presence on those.
    pub presence: MobileChatPresence,
    /// The record fills a slot reserved earlier by a gap, so it arrived out of
    /// order and should render a "received late" caption.
    pub received_late: bool,
    /// The host should raise a user notification for this record (single-frame
    /// arrival, fragment completion, or notify deadline; never placeholders).
    ///
    /// Whether a notification is actually shown remains the host's decision —
    /// a muted conversation still produces records with this set, and still
    /// counts as unread.
    pub notify: bool,
    /// Radio metadata for the frame that produced this record, when one did.
    pub rx: Option<MobileChatRxMetadataRecord>,
}

/// Platform-persisted identity of a previously composed outbound message,
/// used to target an edit or delete. `session_id`/`handle` identify it when
/// composed by the current facade session; `wire_id`/`epoch` are the durable
/// fallback for messages composed before a restart.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatOriginalRef {
    pub session_id: u64,
    pub handle: u32,
    pub wire_id: Option<u8>,
    pub epoch: Option<u16>,
}

/// Platform-persisted identity of the message a reply or emote is about.
///
/// Unlike [`MobileChatOriginalRef`], which only ever names a message we
/// composed, this can name either party's: `direction` says whose stream the
/// wire ID belongs to, and `sender_hint` says which member's within a channel
/// group. Reacting to a message read before the app last launched is the
/// ordinary case, so the wire fields carry the weight here.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatRegardingRef {
    pub session_id: u64,
    pub handle: u32,
    pub wire_id: Option<u8>,
    pub direction: Option<MobileChatDirection>,
    pub sender_hint: Option<Vec<u8>>,
    pub epoch: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatDeliveryState {
    Sent,
    Acknowledged,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatDeliveryRecord {
    pub session_id: u64,
    pub handle: u32,
    pub fragment_index: Option<u8>,
    pub state: MobileChatDeliveryState,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatArchiveLookupRecord {
    pub request_id: u32,
    pub conversation_address: String,
    pub message_id: u8,
    pub fragment_index: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatArchiveResultKind {
    Found,
    Deleted,
    Evicted,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatComposeBatchRecord {
    pub batch_id: u64,
    pub checkpoint: MobileChatCheckpointRecord,
    /// Applied before `archives`: archive retirements for superseded
    /// (edited or deleted) message IDs.
    pub archive_deletes: Vec<MobileChatArchiveDeleteRecord>,
    /// These exact payloads must be committed with the checkpoint before the
    /// batch is released to the radio.
    pub archives: Vec<MobileChatArchiveRecord>,
    pub mutations: Vec<MobileChatMutationRecord>,
}

pub(crate) struct PendingChatBatch {
    pub transmissions: Vec<Transmission>,
}

pub(crate) struct ComposedChatBatch {
    pub record: MobileChatComposeBatchRecord,
    pub deliveries: Vec<MobileChatDeliveryRecord>,
    pub diagnostics: Vec<String>,
}

pub(crate) struct ChatDrain {
    pub checkpoint: Option<MobileChatCheckpointRecord>,
    pub transmissions: Vec<Transmission>,
    pub archive_deletes: Vec<MobileChatArchiveDeleteRecord>,
    pub archives: Vec<MobileChatArchiveRecord>,
    pub mutations: Vec<MobileChatMutationRecord>,
    pub deliveries: Vec<MobileChatDeliveryRecord>,
    pub lookups: Vec<MobileChatArchiveLookupRecord>,
    pub resolutions: Vec<MobileChatSenderResolutionRecord>,
    pub diagnostics: Vec<String>,
}

impl ChatDrain {
    fn new() -> Self {
        Self {
            checkpoint: None,
            transmissions: Vec::new(),
            archive_deletes: Vec::new(),
            archives: Vec::new(),
            mutations: Vec::new(),
            deliveries: Vec::new(),
            lookups: Vec::new(),
            resolutions: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

/// The channels this session can hold a conversation in, and the keys to
/// reach them.
///
/// Channel membership already lives in the MAC, which resolves an inbound
/// frame to a key by authenticating it. This is the chat layer's own view:
/// it maps between the tag a conversation is keyed by and the key a send
/// needs, in both directions.
#[derive(Default)]
pub(crate) struct ChannelRegistry {
    entries: BTreeMap<ChannelTag, ChannelKey>,
}

impl ChannelRegistry {
    pub fn register(&mut self, tag: ChannelTag, key: ChannelKey) {
        self.entries.insert(tag, key);
    }

    pub fn remove(&mut self, tag: &ChannelTag) {
        self.entries.remove(tag);
    }

    pub fn key(&self, tag: &ChannelTag) -> Option<ChannelKey> {
        self.entries.get(tag).copied()
    }

    pub fn contains(&self, tag: &ChannelTag) -> bool {
        self.entries.contains_key(tag)
    }
}

pub(crate) struct MobileChatState {
    /// Keep the reducer off the worker future's stack. The mobile MAC/host is
    /// already a large bounded value, and combining both inline can exhaust a
    /// debug-build thread stack.
    pub engine: Box<ChatEngine>,
    pub session_id: u64,
    next_batch_id: u64,
    pub pending_batches: BTreeMap<u64, PendingChatBatch>,
    /// Shared with the worker so a batch rejection — which rebuilds the
    /// reducer — cannot lose the channels the platform registered.
    pub channels: Rc<RefCell<ChannelRegistry>>,
    /// Full keys learned for claimed member hints, per channel. A hint is only
    /// 3 bytes and two members could in principle claim the same one, so this
    /// records the first key seen for a hint and leaves it there.
    resolved_members: BTreeMap<(ChannelTag, [u8; 3]), PublicKey>,
    /// Hints already reported to the platform, so one resolution is announced
    /// once rather than on every frame.
    announced_members: BTreeSet<(ChannelTag, [u8; 3])>,
}

impl MobileChatState {
    pub fn new(local_key: PublicKey, channels: Rc<RefCell<ChannelRegistry>>) -> Self {
        Self {
            engine: Box::new(ChatEngine::new(
                DirectChannelProfile,
                local_key,
                EngineConfig::default(),
                rand::rng().next_u64(),
            )),
            session_id: rand::rng().next_u64().max(1),
            next_batch_id: 1,
            pending_batches: BTreeMap::new(),
            channels,
            resolved_members: BTreeMap::new(),
            announced_members: BTreeSet::new(),
        }
    }

    pub fn restore(
        &mut self,
        checkpoints: &[MobileChatCheckpointRecord],
        now_ms: u64,
    ) -> Vec<String> {
        let mut diagnostics = Vec::new();
        let mut restored = Vec::new();
        for record in checkpoints {
            match self.checkpoint_from_record(record) {
                Some(checkpoint) => restored.push(checkpoint),
                None => diagnostics.push(format!(
                    "chat checkpoint for unknown conversation {}",
                    record.conversation_address
                )),
            }
        }
        self.engine.restore(&restored, now_ms);
        let _ = self.drain();
        diagnostics
    }

    /// Note a channel member's full key, learned from a frame that carried
    /// both it and the claimed hint. Returns a record the first time a hint
    /// resolves, so the platform can upgrade rows it stored anonymously.
    pub fn resolve_member(
        &mut self,
        channel: ChannelTag,
        hint: NodeHint,
        key: PublicKey,
    ) -> Option<MobileChatSenderResolutionRecord> {
        self.resolved_members
            .entry((channel, hint.0))
            .or_insert(key);
        if !self.announced_members.insert((channel, hint.0)) {
            return None;
        }
        Some(MobileChatSenderResolutionRecord {
            conversation_address: channel_address(channel),
            sender_hint: hint.0.to_vec(),
            sender_address: address(key),
        })
    }

    pub fn compose_text(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        body: &str,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Text {
                body,
                status: false,
            },
            now_ms,
        )
    }

    pub fn compose_edit(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        original: &MobileChatOriginalRef,
        body: &str,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        let original = self.compose_ref(original).ok_or(())?;
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Edit { original, body },
            now_ms,
        )
    }

    pub fn compose_delete(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        original: &MobileChatOriginalRef,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        let original = self.compose_ref(original).ok_or(())?;
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Delete { original },
            now_ms,
        )
    }

    /// Emote about a message: a reaction, or — with an empty body — the
    /// withdrawal of one. Replacing a reaction is another emote, not an edit
    /// of the previous one; the newest emote from a sender is the one that
    /// counts.
    pub fn compose_reaction(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        target: &MobileChatRegardingRef,
        body: &str,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        let regarding = self.regarding_ref(target).ok_or(())?;
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Reply {
                body,
                regarding,
                status: true,
            },
            now_ms,
        )
    }

    /// Resolve the platform's persisted identity of a regarding target to an
    /// engine reference, on the same terms as [`Self::compose_ref`].
    fn regarding_ref(&self, target: &MobileChatRegardingRef) -> Option<RegardingRef> {
        if target.session_id == self.session_id {
            return Some(RegardingRef::Handle(MessageHandle(target.handle)));
        }
        let sender_hint = match &target.sender_hint {
            None => None,
            Some(bytes) => Some(NodeHint(<[u8; 3]>::try_from(bytes.as_slice()).ok()?)),
        };
        Some(RegardingRef::Wire {
            message_id: target.wire_id?,
            direction: match target.direction? {
                MobileChatDirection::Inbound => Direction::Inbound,
                MobileChatDirection::Outbound => Direction::Outbound,
            },
            sender_hint,
            epoch: target.epoch,
        })
    }

    /// Resolve the platform's persisted identity of an original message to
    /// an engine compose reference. Same facade session: the engine handle
    /// is still live. Earlier session: fall back to the persisted wire
    /// identity, which the engine validates against stream continuity.
    fn compose_ref(&self, original: &MobileChatOriginalRef) -> Option<ComposeRef> {
        if original.session_id == self.session_id {
            return Some(ComposeRef::Handle(MessageHandle(original.handle)));
        }
        match (original.wire_id, original.epoch) {
            (Some(message_id), Some(epoch)) => Some(ComposeRef::Wire { message_id, epoch }),
            _ => None,
        }
    }

    fn compose_batch(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        intent: ComposeIntent<'_>,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        self.engine
            .compose(conversation, client_token, intent, now_ms)
            .map_err(|_| ())?;
        let mut drain = self.drain();
        let checkpoint = drain.checkpoint.ok_or(())?;
        let fragment_count = u8::try_from(drain.archives.len()).map_err(|_| ())?;
        for mutation in &mut drain.mutations {
            if mutation.kind == MobileChatMutationKind::Insert
                && mutation.direction == Some(MobileChatDirection::Outbound)
            {
                mutation.fragment_count = Some(fragment_count.max(1));
            }
        }
        let batch_id = self.next_batch_id;
        self.next_batch_id = self.next_batch_id.wrapping_add(1).max(1);
        self.pending_batches.insert(
            batch_id,
            PendingChatBatch {
                transmissions: drain.transmissions,
            },
        );
        Ok(ComposedChatBatch {
            record: MobileChatComposeBatchRecord {
                batch_id,
                checkpoint,
                archive_deletes: drain.archive_deletes,
                archives: drain.archives,
                mutations: drain.mutations,
            },
            deliveries: drain.deliveries,
            diagnostics: drain.diagnostics,
        })
    }

    pub fn drain(&mut self) -> ChatDrain {
        let mut drained = ChatDrain::new();
        while let Some(output) = self.engine.poll_output() {
            match output {
                Output::Transmit(transmission) => {
                    if let Some(archive) = transmission.archive {
                        if let Some(record) =
                            self.archive_record(archive, transmission.payload.as_slice())
                        {
                            drained.archives.push(record);
                        }
                    }
                    drained.transmissions.push(transmission);
                }
                Output::StoreCheckpoint {
                    conversation,
                    next_id,
                    epoch,
                } => {
                    drained.checkpoint =
                        self.conversation_address(conversation)
                            .map(|conversation_address| MobileChatCheckpointRecord {
                                conversation_address,
                                next_id,
                                epoch,
                            });
                }
                Output::LookupOutbound {
                    request_id,
                    conversation,
                    sequence,
                } => {
                    if let Some(conversation_address) = self.conversation_address(conversation) {
                        drained.lookups.push(MobileChatArchiveLookupRecord {
                            request_id,
                            conversation_address,
                            message_id: sequence.message_id,
                            fragment_index: sequence.fragment.map(|fragment| fragment.index),
                        });
                    }
                }
                Output::StoreArchive { key, payload } => {
                    if let Some(record) = self.archive_record(key, payload.as_slice()) {
                        drained.archives.push(record);
                    }
                }
                Output::DeleteArchive {
                    conversation,
                    message_id,
                } => {
                    if let Some(conversation_address) = self.conversation_address(conversation) {
                        drained.archive_deletes.push(MobileChatArchiveDeleteRecord {
                            conversation_address,
                            message_id,
                        });
                    }
                }
                Output::StoreMessage(mutation) => {
                    if let Some(record) = self.mutation_record(mutation) {
                        drained.mutations.push(record);
                    }
                }
                Output::Event(Event::DeliveryStateChanged {
                    handle,
                    fragment,
                    state,
                }) => drained.deliveries.push(MobileChatDeliveryRecord {
                    session_id: self.session_id,
                    handle: handle.0,
                    fragment_index: fragment,
                    state: match state {
                        DeliveryState::Sent => MobileChatDeliveryState::Sent,
                        DeliveryState::Acked => MobileChatDeliveryState::Acknowledged,
                        DeliveryState::Failed => MobileChatDeliveryState::Failed,
                    },
                }),
                Output::Event(event) => drained.diagnostics.push(format!("{event:?}")),
                Output::Diagnostic(diagnostic) => {
                    drained.diagnostics.push(format!("{diagnostic:?}"));
                }
            }
        }
        drained
    }

    fn mutation_record(&self, mutation: MessageMutation) -> Option<MobileChatMutationRecord> {
        let mut record = MobileChatMutationRecord {
            session_id: self.session_id,
            handle: mutation.handle.0,
            revision: mutation.revision,
            kind: MobileChatMutationKind::Insert,
            conversation_address: None,
            sender_address: None,
            sender_hint: None,
            direction: None,
            message_type: None,
            wire_id: None,
            epoch: None,
            client_token: None,
            sender_handle: None,
            regarding_handle: None,
            regarding_wire_id: None,
            regarding_direction: None,
            regarding_sender_hint: None,
            background_color: None,
            text_color: None,
            original_handle: None,
            original_wire_id: None,
            original_direction: None,
            original_sender_hint: None,
            body: None,
            complete: None,
            present_fragments: None,
            fragment_count: None,
            finalized: None,
            presence: MobileChatPresence::Present,
            received_late: false,
            notify: false,
            rx: None,
        };
        match mutation.kind {
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
                body,
                status,
                presence,
                late,
                notify,
            } => {
                record.conversation_address = self.conversation_address(conversation);
                record.sender_address = self.sender_address(conversation, sender);
                record.sender_hint = claimed_hint(sender);
                record.direction = Some(match direction {
                    Direction::Inbound => MobileChatDirection::Inbound,
                    Direction::Outbound => MobileChatDirection::Outbound,
                });
                record.message_type = Some(message_type.to_byte());
                record.wire_id = wire_id;
                record.epoch = Some(epoch);
                record.client_token = client_token;
                record.sender_handle =
                    sender_handle.map(|value| self.engine.body(&value).to_owned());
                if let Some(regarding) = regarding {
                    apply_regarding(&mut record, regarding);
                }
                record.background_color = bg_color.map(|color| color.to_vec());
                record.text_color = text_color.map(|color| color.to_vec());
                record.body = Some(self.engine.body(&body).to_owned());
                record.presence = mobile_presence(presence);
                record.received_late = late;
                record.notify = notify;
                apply_completion(&mut record, status);
            }
            MutationKind::UpdateBody {
                body,
                status,
                late,
                notify,
            } => {
                record.kind = MobileChatMutationKind::UpdateBody;
                record.body = Some(self.engine.body(&body).to_owned());
                record.received_late = late;
                record.notify = notify;
                apply_completion(&mut record, status);
            }
            MutationKind::Edit {
                conversation,
                original,
                body,
            } => {
                record.kind = MobileChatMutationKind::Edit;
                record.conversation_address = self.conversation_address(conversation);
                apply_original(&mut record, original);
                record.body = Some(self.engine.body(&body).to_owned());
            }
            MutationKind::Delete {
                conversation,
                original,
            } => {
                record.kind = MobileChatMutationKind::Delete;
                record.conversation_address = self.conversation_address(conversation);
                apply_original(&mut record, original);
            }
        }
        Some(record)
    }

    /// The platform-facing address of a conversation: a peer's base58 address
    /// for a direct one, a prefixed tag for a channel. Rooms have no address
    /// in this facade.
    fn conversation_address(&self, conversation: ConversationKey) -> Option<String> {
        match conversation {
            ConversationKey::Direct { peer } => Some(address(peer)),
            ConversationKey::ChannelGroup { channel } => Some(channel_address(channel)),
            ConversationKey::ChannelDirect { channel, peer } => Some(format!(
                "{CHANNEL_DIRECT_ADDRESS_PREFIX}{}:{}",
                hex(&channel.0),
                address(peer)
            )),
            ConversationKey::Room { .. } => None,
        }
    }

    /// The sender's full address when one is known. A multicast member claims
    /// only a hint, so this is whatever key that hint has resolved to.
    fn sender_address(&self, conversation: ConversationKey, sender: SenderScope) -> Option<String> {
        match sender {
            SenderScope::Peer(peer) => Some(address(peer)),
            SenderScope::Local => None,
            SenderScope::ClaimedMember(hint) => {
                let ConversationKey::ChannelGroup { channel } = conversation else {
                    return None;
                };
                self.resolved_members
                    .get(&(channel, hint.0))
                    .map(|peer| address(*peer))
            }
        }
    }

    fn archive_record(&self, key: ArchiveKey, payload: &[u8]) -> Option<MobileChatArchiveRecord> {
        Some(MobileChatArchiveRecord {
            conversation_address: self.conversation_address(key.conversation)?,
            message_id: key.message_id,
            fragment_index: key.fragment,
            payload: payload.to_vec(),
        })
    }

    fn checkpoint_from_record(
        &self,
        record: &MobileChatCheckpointRecord,
    ) -> Option<StreamCheckpoint> {
        let conversation = self.parse_conversation_address(&record.conversation_address)?;
        Some(StreamCheckpoint {
            conversation,
            next_id: record.next_id,
            epoch: record.epoch,
        })
    }

    /// Resolve a stored address back to a conversation. A channel address only
    /// resolves while its key is registered — the platform registers channels
    /// before restoring chat, so an unresolvable one means the channel was
    /// left.
    pub fn parse_conversation_address(&self, value: &str) -> Option<ConversationKey> {
        if let Some(rest) = value.strip_prefix(CHANNEL_DIRECT_ADDRESS_PREFIX) {
            let (tag, peer) = rest.split_once(':')?;
            let channel = parse_channel_tag(tag)?;
            if !self.channels.borrow().contains(&channel) {
                return None;
            }
            return Some(ConversationKey::ChannelDirect {
                channel,
                peer: decode_address(peer)?,
            });
        }
        if let Some(tag) = value.strip_prefix(CHANNEL_ADDRESS_PREFIX) {
            let channel = parse_channel_tag(tag)?;
            if !self.channels.borrow().contains(&channel) {
                return None;
            }
            return Some(ConversationKey::ChannelGroup { channel });
        }
        Some(ConversationKey::Direct {
            peer: decode_address(value)?,
        })
    }
}

fn mobile_presence(presence: Presence) -> MobileChatPresence {
    match presence {
        Presence::Present => MobileChatPresence::Present,
        Presence::GapPending => MobileChatPresence::GapPending,
        Presence::Unavailable => MobileChatPresence::Unavailable,
    }
}

fn apply_completion(record: &mut MobileChatMutationRecord, status: CompletionStatus) {
    match status {
        CompletionStatus::Complete => record.complete = Some(true),
        CompletionStatus::Partial {
            present,
            count,
            finalized,
        } => {
            record.complete = Some(false);
            record.present_fragments = Some(present);
            record.fragment_count = Some(count);
            record.finalized = Some(finalized);
        }
    }
}

/// Export an edit/delete target: a live handle when resolved, otherwise the
/// wire reference for the platform to match against its persisted rows.
/// Room-scoped reference forms are outside this facade.
fn apply_original(record: &mut MobileChatMutationRecord, reference: ResolvedRef) {
    match reference {
        ResolvedRef::Handle(MessageHandle(handle)) => {
            record.original_handle = Some(handle);
        }
        ResolvedRef::Unresolved(WireRef::SenderScoped { sender, message_id }) => {
            record.original_wire_id = Some(message_id);
            record.original_direction = Some(wire_ref_direction(sender));
            record.original_sender_hint = claimed_hint(sender);
        }
        ResolvedRef::Unresolved(WireRef::RoomCanonical { .. }) => {}
    }
}

/// Export a reply/emote target, on the same terms as [`apply_original`].
/// Reactions overwhelmingly target messages received long before this
/// process started, so the unresolved form is the common case here rather
/// than the exception.
fn apply_regarding(record: &mut MobileChatMutationRecord, reference: ResolvedRef) {
    match reference {
        ResolvedRef::Handle(MessageHandle(handle)) => {
            record.regarding_handle = Some(handle);
        }
        ResolvedRef::Unresolved(WireRef::SenderScoped { sender, message_id }) => {
            record.regarding_wire_id = Some(message_id);
            record.regarding_direction = Some(wire_ref_direction(sender));
            record.regarding_sender_hint = claimed_hint(sender);
        }
        ResolvedRef::Unresolved(WireRef::RoomCanonical { .. }) => {}
    }
}

fn wire_ref_direction(sender: SenderScope) -> MobileChatDirection {
    match sender {
        SenderScope::Local => MobileChatDirection::Outbound,
        // A channel member's message is inbound like any other peer's; the
        // hint is what tells the platform whose stream it was.
        SenderScope::Peer(_) | SenderScope::ClaimedMember(_) => MobileChatDirection::Inbound,
    }
}

fn claimed_hint(sender: SenderScope) -> Option<Vec<u8>> {
    match sender {
        SenderScope::ClaimedMember(hint) => Some(hint.0.to_vec()),
        SenderScope::Local | SenderScope::Peer(_) => None,
    }
}

/// The conversation address of a channel's group conversation.
pub(crate) fn channel_address(channel: ChannelTag) -> String {
    format!("{CHANNEL_ADDRESS_PREFIX}{}", hex(&channel.0))
}

fn parse_channel_tag(value: &str) -> Option<ChannelTag> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(value.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(ChannelTag(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn address(key: PublicKey) -> String {
    umsh_core::base58::encode(&key.0)
        .into_iter()
        .map(char::from)
        .collect()
}

fn decode_address(value: &str) -> Option<PublicKey> {
    umsh_core::base58::decode(value.as_bytes())
        .ok()
        .map(PublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: PublicKey = PublicKey([0xAA; 32]);
    const PEER: PublicKey = PublicKey([0x11; 32]);
    const CHANNEL_KEY: ChannelKey = ChannelKey([0x42; 32]);

    fn direct() -> ConversationKey {
        ConversationKey::Direct { peer: PEER }
    }

    /// A state whose registry already holds the test channel.
    fn state_with_channel() -> (MobileChatState, ChannelTag) {
        let tag = crate::channel_tag(&CHANNEL_KEY);
        let registry = Rc::new(RefCell::new(ChannelRegistry::default()));
        registry.borrow_mut().register(tag, CHANNEL_KEY);
        (MobileChatState::new(LOCAL, registry), tag)
    }

    fn empty_state() -> MobileChatState {
        MobileChatState::new(LOCAL, Rc::new(RefCell::new(ChannelRegistry::default())))
    }

    /// A channel conversation survives a facade restart: its checkpoint is
    /// addressed by tag, and restoring it resumes the same outbound stream
    /// rather than starting a fresh one that would replay wire IDs.
    #[test]
    fn a_channel_checkpoint_round_trips_through_restore() {
        let (mut first, tag) = state_with_channel();
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        let composed = first
            .compose_text(conversation, 5, "on my way", 0)
            .expect("composing into a held channel succeeds");
        let checkpoint = composed.record.checkpoint;
        assert_eq!(checkpoint.conversation_address, channel_address(tag));

        let (mut restarted, _) = state_with_channel();
        assert!(
            restarted
                .restore(std::slice::from_ref(&checkpoint), 0)
                .is_empty(),
            "a checkpoint for a held channel restores without complaint"
        );
        // Continuity proves the restore landed on the same stream: a cold
        // engine would hand out the ID the first message already used.
        let next = restarted
            .compose_text(conversation, 6, "still moving", 1)
            .expect("composing after restore succeeds");
        assert_ne!(
            next.record.mutations[0].wire_id, composed.record.mutations[0].wire_id,
            "the restored stream must not reissue a spent wire ID"
        );
    }

    /// A checkpoint whose channel this session no longer holds is reported
    /// rather than dropped in silence — the channel was left, and the stream
    /// it belonged to cannot be resumed without the key.
    #[test]
    fn a_checkpoint_for_an_unheld_channel_is_diagnosed() {
        let (mut held, tag) = state_with_channel();
        let checkpoint = held
            .compose_text(ConversationKey::ChannelGroup { channel: tag }, 1, "hi", 0)
            .expect("composing into a held channel succeeds")
            .record
            .checkpoint;

        let diagnostics = empty_state().restore(std::slice::from_ref(&checkpoint), 0);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert!(
            diagnostics[0].contains(&checkpoint.conversation_address),
            "the diagnostic must name the conversation: {}",
            diagnostics[0]
        );
    }

    /// The full restart round trip at the facade level: the persisted
    /// (wire_id, epoch) of a message composed by one facade session lets a
    /// fresh session — restored from the persisted checkpoint — compose an
    /// edit whose mutation record exports a platform-resolvable reference.
    #[test]
    fn edit_by_persisted_reference_after_facade_restart() {
        let mut first = empty_state();
        let composed = first
            .compose_text(direct(), 7, "v1", 0)
            .expect("compose succeeds");
        let insert = composed
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("insert mutation");
        let original = MobileChatOriginalRef {
            session_id: insert.session_id,
            handle: insert.handle,
            wire_id: insert.wire_id,
            epoch: insert.epoch,
        };
        let checkpoint = composed.record.checkpoint;

        let mut restarted = empty_state();
        assert_ne!(
            restarted.session_id, first.session_id,
            "sessions must not collide"
        );
        let _ = restarted.restore(std::slice::from_ref(&checkpoint), 0);
        let edited = restarted
            .compose_edit(direct(), 8, &original, "v2", 1)
            .expect("wire-referenced edit composes after restart");
        let edit = edited
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Edit)
            .expect("edit mutation");
        assert_eq!(edit.original_handle, None);
        assert_eq!(edit.original_wire_id, insert.wire_id);
        assert_eq!(edit.original_direction, Some(MobileChatDirection::Outbound));
        assert_eq!(edit.conversation_address, insert.conversation_address);
        assert_eq!(edit.body.as_deref(), Some("v2"));

        // Superseded content is retired and re-issued under the original wire
        // ID: a resend request served from the archive can only carry "v2".
        assert!(
            edited
                .record
                .archive_deletes
                .iter()
                .any(|delete| Some(delete.message_id) == insert.wire_id)
        );
        assert!(
            edited
                .record
                .archives
                .iter()
                .any(|archive| Some(archive.message_id) == insert.wire_id)
        );

        // Deleting retires the archive without replacing it.
        let deleted = restarted
            .compose_delete(direct(), 9, &original, 2)
            .expect("delete composes");
        assert!(
            deleted
                .record
                .archive_deletes
                .iter()
                .any(|delete| Some(delete.message_id) == insert.wire_id)
        );
        assert!(
            !deleted
                .record
                .archives
                .iter()
                .any(|archive| Some(archive.message_id) == insert.wire_id)
        );

        // Without continuity (no restored checkpoint) the same reference is
        // rejected instead of silently starting a dangling edit.
        let mut cold = empty_state();
        assert!(cold.compose_delete(direct(), 9, &original, 0).is_err());
    }

    /// The ordinary reaction: the target is a message the peer sent, and no
    /// live handle backs it, so the record must carry the wire coordinates
    /// for the platform to match against its own rows.
    #[test]
    fn compose_reaction_exports_wire_regarding() {
        let (mut state, tag) = state_with_channel();
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        let hint = vec![0x33, 0x44, 0x55];
        let target = MobileChatRegardingRef {
            // A session that is not ours: the handle cannot be trusted.
            session_id: state.session_id.wrapping_add(1),
            handle: 0,
            wire_id: Some(9),
            direction: Some(MobileChatDirection::Inbound),
            sender_hint: Some(hint.clone()),
            epoch: Some(0),
        };
        let composed = state
            .compose_reaction(conversation, 1, &target, "+1", 0)
            .expect("reaction composes against a persisted target");
        let insert = composed
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("insert mutation");
        assert_eq!(insert.message_type, Some(1), "an emote is status text");
        assert_eq!(insert.body.as_deref(), Some("+1"));
        assert_eq!(insert.regarding_handle, None);
        assert_eq!(insert.regarding_wire_id, Some(9));
        assert_eq!(
            insert.regarding_direction,
            Some(MobileChatDirection::Inbound)
        );
        assert_eq!(insert.regarding_sender_hint, Some(hint));

        // Withdrawal is the same message with nothing in it — never an edit
        // or a delete, which would target the emote row instead.
        let withdrawn = state
            .compose_reaction(conversation, 2, &target, "", 1)
            .expect("withdrawal composes");
        let insert = withdrawn
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("withdrawal is an insert");
        assert_eq!(insert.body.as_deref(), Some(""));
        assert_eq!(insert.regarding_wire_id, Some(9));
    }

    /// Reacting to one of our own messages from an earlier launch: the handle
    /// belongs to a dead session, so the persisted wire identity carries it.
    #[test]
    fn reaction_target_from_prior_session_uses_wire_ref() {
        let mut first = empty_state();
        let composed = first
            .compose_text(direct(), 7, "mine", 0)
            .expect("compose succeeds");
        let insert = composed
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("insert mutation");
        let target = MobileChatRegardingRef {
            session_id: insert.session_id,
            handle: insert.handle,
            wire_id: insert.wire_id,
            direction: Some(MobileChatDirection::Outbound),
            sender_hint: None,
            epoch: insert.epoch,
        };
        let checkpoint = composed.record.checkpoint;

        let mut restarted = empty_state();
        let _ = restarted.restore(std::slice::from_ref(&checkpoint), 0);
        let reacted = restarted
            .compose_reaction(direct(), 8, &target, "<3", 1)
            .expect("wire-referenced reaction composes after restart");
        let emote = reacted
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("insert mutation");
        assert_eq!(emote.regarding_handle, None);
        assert_eq!(emote.regarding_wire_id, insert.wire_id);
        assert_eq!(
            emote.regarding_direction,
            Some(MobileChatDirection::Outbound)
        );

        // A cold session has no continuity, so the reference is refused
        // rather than aimed at whatever now holds that wire ID.
        let mut cold = empty_state();
        assert!(
            cold.compose_reaction(direct(), 9, &target, "<3", 0)
                .is_err()
        );
    }
}
