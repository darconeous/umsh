//! Owned mobile records over the chat facade (`umsh_text::chat`).
//!
//! Conversations are addressed by an opaque string that discriminates the
//! kinds the platform can hold: a peer's base58 address for a direct
//! conversation, `ch:<hex tag>` for a channel's group conversation, and
//! `chd:<hex tag>:<address>` for a blind-unicast conversation over a channel.
//! These are a codec over the facade's typed conversation keys. Room profiles
//! are still outside this facade, and are dropped rather than exported in a
//! form Swift would have to interpret.

use std::collections::{BTreeMap, BTreeSet};

use umsh_core::{ChannelTag, NodeHint, PublicKey};
use umsh_node::{LocalNode, MacBackend, PfsStatus};
use umsh_text::chat::{
    ArchiveLookup, Change, ChannelRegistry, ChatComposeError, ChatFacade, ChatOutput, Delivery,
    Drain, Mutation, Outbound, PendingBatch, Repeats, Seeds, SenderResolution,
};
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveKey, CompletionStatus, ComposeIntent, ComposeRef, DeliveryState, Direction,
    EngineConfig, Presence, RegardingRef, ResolvedRef, StreamCheckpoint,
};
use umsh_text::model::{ConversationKey, SenderScope, WireRef};
use umsh_text::node_adapter::{TransmitPolicy, TransmitQueue};
use umsh_text::validate::DirectChannelProfile;

pub(crate) type MobileChatFacade = ChatFacade<DirectChannelProfile>;

/// Prefix marking a channel group conversation address.
const CHANNEL_ADDRESS_PREFIX: &str = "ch:";
/// Prefix marking a blind-unicast conversation over a channel key.
const CHANNEL_DIRECT_ADDRESS_PREFIX: &str = "chd:";

/// How long frames held to forward secrecy wait on a session their peer is
/// still setting up before they fail: as long as a node waits for its own
/// request for one to be answered.
const SECRECY_WAIT_MS: u64 = 30_000;

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
/// [`Presence`]). A `GapPending` row is a reserved spinner placeholder; a
/// `GapIdle` row is a missing message waiting for the user to ask for it
/// (`MobileMeshSession::request_chat_repair`); an `Unavailable` row is a
/// permanent loss marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatPresence {
    Present,
    GapPending,
    GapIdle,
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
    /// same count a ping reply reports, and absent for the same reason—a
    /// frame source-routed without a trace route crossed hops nobody
    /// recorded.
    pub hop_count: Option<u8>,
    /// Intermediate-router hints in trace-route order: each forwarding
    /// repeater prepends its own hint, so the list starts nearest us and ends
    /// nearest the sender. That is return-path order—usable directly as a
    /// source route back—and the reverse of the path the frame travelled.
    pub route_hints: Vec<Vec<u8>>,
    pub source_authenticated: bool,
    /// Seconds the frame spent queued on the radio before delivery; zero
    /// for a live reception. Platforms stamping the record into a
    /// transcript subtract this so a drained backlog reads as when it was
    /// received off the air, not as a burst of "just now".
    pub buffered_age_seconds: u32,
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
    /// The message says it replies to another, in a form this receiver could
    /// not read: a reply to an unknown message.
    pub regarding_unknown: bool,
    /// The message came as an edit of something this receiver could not
    /// identify, and stands as a message of its own.
    pub unknown_original: bool,
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
    /// Whether a notification is actually shown remains the host's decision—
    /// a muted conversation still produces records with this set, and still
    /// counts as unread.
    pub notify: bool,
    /// Radio metadata for the frame that produced this record, when one did.
    pub rx: Option<MobileChatRxMetadataRecord>,
    /// Whether a message of ours goes under a session with forward secrecy,
    /// as decided when it was composed: then it never goes without one, and
    /// otherwise never under one. Set on the records a compose makes; absent
    /// on every other.
    pub forward_secret: Option<bool>,
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
    /// It went on the air, or the session setup it waits on did.
    Sent,
    Acknowledged,
    /// It went on the air and was not acknowledged: it may have arrived.
    Failed,
    /// It never went out where the peer could read it: it did not arrive.
    Undelivered,
}

/// A message of ours sent again in place: the frames it had unacknowledged
/// go again under its wire ID, and word of them is reported under
/// `delivery_session_id`/`delivery_handle`, which differ from the message's
/// own once the app has restarted since it was composed. Comes ahead of
/// any word of those frames: the platform forgets what it last heard of
/// every fragment not yet acknowledged, and points the message's delivery
/// at the new handle.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatResendRecord {
    /// The message, as the platform named it to send again.
    pub message: MobileChatOriginalRef,
    pub delivery_session_id: u64,
    pub delivery_handle: u32,
    /// Whether it now goes under a session with forward secrecy.
    pub forward_secret: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatDeliveryRecord {
    pub session_id: u64,
    pub handle: u32,
    pub fragment_index: Option<u8>,
    pub state: MobileChatDeliveryState,
    /// The acknowledgment answered the flood that followed a miss on the
    /// peer's route, not the routed send itself.
    pub via_flood: bool,
}

/// The repeaters overheard carrying one fragment of a message of ours, as
/// tallied so far. Each record holds the whole tally, so a later one
/// supersedes an earlier one for the same fragment.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatRepeatRecord {
    pub session_id: u64,
    pub handle: u32,
    pub fragment_index: Option<u8>,
    /// Repeaters the forwards named, each once, in the order first heard.
    pub repeaters: Vec<crate::RouterHintRecord>,
    /// Forwards that named no repeater, each taken for a repeater of its own.
    pub anonymous_repeats: u16,
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

pub(crate) struct ComposedChatBatch {
    pub record: MobileChatComposeBatchRecord,
    pub deliveries: Vec<MobileChatDeliveryRecord>,
    pub diagnostics: Vec<String>,
}

/// Why a compose produced no batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComposeFailure {
    /// An earlier batch is still waiting on the platform.
    Pending,
    /// The engine refused it, or a reference did not resolve.
    Refused,
}

/// A message of ours could not be sent again under its wire ID: its stream
/// has moved past it, or the frames given are not its.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NotInPlace;

pub(crate) struct ChatDrain {
    pub outbound: Outbound,
    pub mutations: Vec<MobileChatMutationRecord>,
    pub deliveries: Vec<MobileChatDeliveryRecord>,
    pub repeats: Vec<MobileChatRepeatRecord>,
    pub lookups: Vec<MobileChatArchiveLookupRecord>,
    pub resolutions: Vec<MobileChatSenderResolutionRecord>,
    pub diagnostics: Vec<String>,
}

/// The worker's chat state: the facade, the batch Swift is storing, and what
/// goes under a session with forward secrecy.
pub(crate) struct MobileChatState {
    pub facade: MobileChatFacade,
    pending: Option<PendingBatch>,
    /// The peers a session with forward secrecy is held with: what a direct
    /// conversation's next message goes under.
    held: BTreeSet<[u8; 32]>,
    /// Whether each message of ours to a peer goes under such a session, as
    /// decided when it was composed, by the facade session and handle that
    /// name it. Its frames are held to that each time they go.
    forward_secret: BTreeMap<(u64, u32), bool>,
    /// The peers frames wait on a session with, and since when.
    secrecy_waits: BTreeMap<[u8; 32], u64>,
}

impl MobileChatState {
    pub fn new(local_key: PublicKey, seeds: Seeds) -> Self {
        Self {
            facade: ChatFacade::new(
                DirectChannelProfile,
                local_key,
                EngineConfig::default(),
                seeds,
            ),
            pending: None,
            held: BTreeSet::new(),
            forward_secret: BTreeMap::new(),
            secrecy_waits: BTreeMap::new(),
        }
    }

    /// Takes `peers` as those a session with forward secrecy is held with.
    /// Returns whether that changed.
    pub fn hold_secrecy(&mut self, peers: BTreeSet<[u8; 32]>) -> bool {
        if self.held == peers {
            return false;
        }
        self.held = peers;
        true
    }

    /// The addresses of the direct conversations whose next message goes
    /// under a session with forward secrecy.
    pub fn forward_secret_conversations(&self) -> Vec<String> {
        self.held
            .iter()
            .filter_map(|&peer| {
                conversation_address(ConversationKey::Direct {
                    peer: PublicKey(peer),
                })
            })
            .collect()
    }

    /// Hands what `queue` holds to `node` while its window has room, each
    /// frame of a message of ours held to what was decided for it when it
    /// was composed. Returns how many were sent.
    pub async fn pump<M: MacBackend>(
        &mut self,
        queue: &mut TransmitQueue,
        node: &LocalNode<M>,
        policy: &TransmitPolicy,
        now_ms: u64,
    ) -> usize {
        let forward_secret = &self.forward_secret;
        queue
            .pump(node, &mut self.facade, policy, now_ms, |departure| {
                let decided = departure
                    .message()
                    .and_then(|message| forward_secret.get(&(departure.session_id(), message.0)));
                if let Some(&decided) = decided {
                    departure.require_forward_secrecy(decided);
                }
            })
            .await
    }

    /// Settles the frames in `queue` waiting on a session with forward
    /// secrecy: those to a peer one is held with go next, those to a peer
    /// still setting one up wait for at most [`SECRECY_WAIT_MS`], and the
    /// rest fail, undelivered. This phone asks for a session itself only
    /// when the user sends a message again under one.
    pub async fn settle_secrecy_waits<M: MacBackend>(
        &mut self,
        queue: &mut TransmitQueue,
        node: &LocalNode<M>,
        now_ms: u64,
    ) {
        let awaiting = queue.awaiting_secrecy();
        self.secrecy_waits.retain(|peer, _| awaiting.contains(peer));
        for peer in awaiting {
            let since = *self.secrecy_waits.entry(peer).or_insert(now_ms);
            let key = PublicKey(peer);
            match node.pfs_status(&key).await {
                Ok(PfsStatus::Active { .. }) => queue.release_secrecy_waits(&key),
                Ok(PfsStatus::Requested) if now_ms.saturating_sub(since) < SECRECY_WAIT_MS => {
                    continue;
                }
                _ => queue.fail_secrecy_waits(&key, &mut self.facade, now_ms),
            }
            self.secrecy_waits.remove(&peer);
        }
    }

    /// The facade-session namespace stamped on records, so the engine's
    /// process-local handles cannot collide after a restart.
    pub fn session_id(&self) -> u64 {
        self.facade.session_id()
    }

    pub fn has_pending_batch(&self) -> bool {
        self.pending.is_some()
    }

    pub fn channels(&self) -> &ChannelRegistry {
        self.facade.channels()
    }

    pub fn restore(
        &mut self,
        checkpoints: &[MobileChatCheckpointRecord],
        now_ms: u64,
    ) -> Vec<String> {
        let (restored, diagnostics) = self.checkpoints(checkpoints);
        self.facade.restore(&restored, now_ms);
        diagnostics
    }

    /// Compose a new message as the user typed it, which may make it status
    /// text; see [`ComposeIntent::typed`].
    pub fn compose_typed(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        text: &str,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::typed(text),
            budget,
            now_ms,
        )
    }

    /// Compose `body` as status text, as it stands.
    pub fn compose_status(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        body: &str,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Text { body, status: true },
            budget,
            now_ms,
        )
    }

    /// Compose `body` again as a new message, as text or status text, under
    /// a session with forward secrecy or never under one, as the user chose
    /// in sending it again. The caller asks for a session when one is to be
    /// had and none is.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_again(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        body: &str,
        status: bool,
        forward_secret: bool,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        self.compose_batch_under(
            conversation,
            client_token,
            ComposeIntent::Text { body, status },
            Some(forward_secret),
            budget,
            now_ms,
        )
    }

    /// Send again, under its wire ID, the message of ours `original` names in
    /// `conversation`: `frames` are those of its fragments not yet
    /// acknowledged, as the platform archived them. A message composed before
    /// this facade session is taken back first. Its frames go under a
    /// session with forward secrecy or never under one, as `forward_secret`
    /// says; the caller asks for a session when one is to be had and none
    /// is. Returns what the platform is told ahead of any word of them.
    pub fn resend(
        &mut self,
        conversation: ConversationKey,
        original: &MobileChatOriginalRef,
        frames: &[MobileChatArchiveRecord],
        forward_secret: bool,
        now_ms: u64,
    ) -> Result<MobileChatResendRecord, NotInPlace> {
        let message_id = original.wire_id.ok_or(NotInPlace)?;
        let address = conversation_address(conversation).ok_or(NotInPlace)?;
        if frames.is_empty()
            || frames.iter().any(|frame| {
                frame.conversation_address != address || frame.message_id != message_id
            })
        {
            return Err(NotInPlace);
        }
        let handle = if original.session_id == self.session_id() {
            MessageHandle(original.handle)
        } else {
            // The facade holds every stream's checkpoint since it was
            // restored.
            let epoch = original.epoch.ok_or(NotInPlace)?;
            self.facade
                .adopt(conversation, message_id, epoch, None, now_ms)
                .ok_or(NotInPlace)?
        };
        let mut queued = false;
        for frame in frames {
            let key = ArchiveKey {
                conversation,
                message_id,
                fragment: frame.fragment_index,
            };
            queued |= self.facade.retransmit(&key, handle, &frame.payload);
        }
        if !queued {
            return Err(NotInPlace);
        }
        let session_id = self.session_id();
        if matches!(conversation, ConversationKey::Direct { .. }) {
            self.forward_secret
                .insert((session_id, handle.0), forward_secret);
        }
        Ok(MobileChatResendRecord {
            message: original.clone(),
            delivery_session_id: session_id,
            delivery_handle: handle.0,
            forward_secret,
        })
    }

    /// Compose `body` as basic text, as it stands.
    pub fn compose_text(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        body: &str,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Text {
                body,
                status: false,
            },
            budget,
            now_ms,
        )
    }

    pub fn compose_edit(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        original: &MobileChatOriginalRef,
        body: &str,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        let original = self.compose_ref(original).ok_or(ComposeFailure::Refused)?;
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Edit { original, body },
            budget,
            now_ms,
        )
    }

    pub fn compose_delete(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        original: &MobileChatOriginalRef,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        let original = self.compose_ref(original).ok_or(ComposeFailure::Refused)?;
        self.compose_batch(
            conversation,
            client_token,
            ComposeIntent::Delete { original },
            budget,
            now_ms,
        )
    }

    /// Emote about a message: a reaction, or—with an empty body—the
    /// withdrawal of one. Replacing a reaction is another emote, not an edit
    /// of the previous one; the newest emote from a sender is the one that
    /// counts.
    pub fn compose_reaction(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        target: &MobileChatRegardingRef,
        body: &str,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        self.compose_regarding(
            conversation,
            client_token,
            target,
            body,
            true,
            budget,
            now_ms,
        )
    }

    /// A text message in reply to another. A reply whose original can no
    /// longer be named goes as a plain message: what was written still
    /// goes, without the quote.
    pub fn compose_reply(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        target: &MobileChatRegardingRef,
        body: &str,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        let reply = self.compose_regarding(
            conversation,
            client_token,
            target,
            body,
            false,
            budget,
            now_ms,
        );
        // Anything else the engine refuses a reply for, it refuses the
        // plain message for too.
        match reply {
            Err(ComposeFailure::Refused) => {
                self.compose_text(conversation, client_token, body, budget, now_ms)
            }
            composed => composed,
        }
    }

    /// Compose about `target`. A row this session stored can still be one
    /// the engine holds no handle for, as with an edit of a message never
    /// received, so a refused handle falls back on the target's wire
    /// coordinates.
    #[allow(clippy::too_many_arguments)]
    fn compose_regarding(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        target: &MobileChatRegardingRef,
        body: &str,
        status: bool,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        let intent = |regarding| ComposeIntent::Reply {
            body,
            regarding,
            status,
        };
        let regarding = self.regarding_ref(target).ok_or(ComposeFailure::Refused)?;
        let composed = self.compose_batch(
            conversation,
            client_token,
            intent(regarding),
            budget,
            now_ms,
        );
        match (composed, Self::wire_regarding_ref(target)) {
            (Err(ComposeFailure::Refused), Some(wire)) if wire != regarding => {
                self.compose_batch(conversation, client_token, intent(wire), budget, now_ms)
            }
            (composed, _) => composed,
        }
    }

    /// Release the frames of the batch Swift has stored.
    pub fn commit(&mut self, batch_id: u64) -> Option<Outbound> {
        let batch = self.pending.take_if(|batch| batch.id() == batch_id)?;
        self.facade.commit(batch).ok()
    }

    /// Give up on the batch Swift could not store, rebuilding the engine from
    /// the checkpoints it still holds. Returns the drain that fails the
    /// batch's frames, and diagnostics for checkpoints that no longer
    /// resolve.
    pub fn reject(
        &mut self,
        batch_id: u64,
        checkpoints: &[MobileChatCheckpointRecord],
        seeds: Seeds,
        now_ms: u64,
    ) -> Option<(ChatDrain, Vec<String>)> {
        let batch = self.pending.take_if(|batch| batch.id() == batch_id)?;
        let (restored, diagnostics) = self.checkpoints(checkpoints);
        let drain = self.facade.reject(batch, &restored, seeds, now_ms).ok()?;
        Some((drain_records(drain), diagnostics))
    }

    pub fn drain(&mut self) -> ChatDrain {
        drain_records(self.facade.drain())
    }

    /// Resolve a stored address back to a conversation. A channel address
    /// only resolves while its key is registered—the platform registers
    /// channels before restoring chat, so an unresolvable one means the
    /// channel was left.
    pub fn parse_conversation_address(&self, value: &str) -> Option<ConversationKey> {
        parse_conversation_address(value, self.facade.channels())
    }

    fn checkpoints(
        &self,
        records: &[MobileChatCheckpointRecord],
    ) -> (Vec<StreamCheckpoint>, Vec<String>) {
        let mut restored = Vec::new();
        let mut diagnostics = Vec::new();
        for record in records {
            match self.parse_conversation_address(&record.conversation_address) {
                Some(conversation) => restored.push(StreamCheckpoint {
                    conversation,
                    next_id: record.next_id,
                    epoch: record.epoch,
                }),
                None => diagnostics.push(format!(
                    "chat checkpoint for unknown conversation {}",
                    record.conversation_address
                )),
            }
        }
        (restored, diagnostics)
    }

    /// Resolve the platform's persisted identity of a regarding target to an
    /// engine reference, on the same terms as [`Self::compose_ref`].
    fn regarding_ref(&self, target: &MobileChatRegardingRef) -> Option<RegardingRef> {
        if target.session_id == self.session_id() {
            return Some(RegardingRef::Handle(MessageHandle(target.handle)));
        }
        Self::wire_regarding_ref(target)
    }

    /// `target` by its coordinates on the wire, where it has them.
    fn wire_regarding_ref(target: &MobileChatRegardingRef) -> Option<RegardingRef> {
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
        if original.session_id == self.session_id() {
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
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        self.compose_batch_under(conversation, client_token, intent, None, budget, now_ms)
    }

    /// [`Self::compose_batch`], under a session with forward secrecy or
    /// never under one as `secrecy` says, or, without, as one is held.
    fn compose_batch_under(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        intent: ComposeIntent<'_>,
        secrecy: Option<bool>,
        budget: usize,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ComposeFailure> {
        // Rooms have no address in this facade, so nothing composed to one
        // could be stored.
        let Some(checkpoint_address) = conversation_address(conversation) else {
            return Err(ComposeFailure::Refused);
        };
        let batch = self
            .facade
            .compose_within(conversation, client_token, intent, None, budget, now_ms)
            .map_err(|error| match error {
                ChatComposeError::BatchPending => ComposeFailure::Pending,
                ChatComposeError::Engine(_) | ChatComposeError::Incomplete => {
                    ComposeFailure::Refused
                }
            })?;
        let session_id = batch.session_id();
        let fragment_count = u8::try_from(batch.archives.len()).unwrap_or(u8::MAX);
        let transmission_count = u8::try_from(batch.transmission_count()).unwrap_or(u8::MAX);
        // A message to a peer goes under a session with forward secrecy when
        // one is held as it is composed, or as it was asked to, and its
        // frames are held to that.
        let forward_secret = match conversation {
            ConversationKey::Direct { peer } => {
                let secret = secrecy.unwrap_or_else(|| self.held.contains(&peer.0));
                for mutation in &batch.mutations {
                    self.forward_secret
                        .insert((session_id, mutation.handle.0), secret);
                }
                secret
            }
            _ => false,
        };
        let mut mutations: Vec<_> = batch
            .mutations
            .iter()
            .map(|mutation| mutation_record(session_id, mutation))
            .collect();
        for mutation in &mut mutations {
            mutation.forward_secret = Some(forward_secret);
            match mutation.kind {
                MobileChatMutationKind::Insert
                    if mutation.direction == Some(MobileChatDirection::Outbound) =>
                {
                    mutation.fragment_count = Some(fragment_count.max(1));
                }
                // Stamped so the platform can re-key the edited message's
                // delivery tracking to the edit's transmissions and still
                // know how many acknowledgments make it delivered.
                MobileChatMutationKind::Edit => {
                    mutation.fragment_count = Some(transmission_count.max(1));
                }
                _ => {}
            }
        }
        let mut deliveries = Vec::new();
        let mut diagnostics = Vec::new();
        for output in &batch.outputs {
            match output {
                ChatOutput::Delivery(delivery) => {
                    deliveries.push(delivery_record(session_id, delivery));
                }
                ChatOutput::Event(event) => diagnostics.push(format!("{event:?}")),
                ChatOutput::Diagnostic(diagnostic) => diagnostics.push(format!("{diagnostic:?}")),
                _ => {}
            }
        }
        let record = MobileChatComposeBatchRecord {
            batch_id: batch.id(),
            checkpoint: MobileChatCheckpointRecord {
                conversation_address: checkpoint_address,
                next_id: batch.checkpoint.next_id,
                epoch: batch.checkpoint.epoch,
            },
            archive_deletes: batch
                .archive_deletes
                .iter()
                .filter_map(|delete| {
                    Some(MobileChatArchiveDeleteRecord {
                        conversation_address: conversation_address(delete.conversation)?,
                        message_id: delete.message_id,
                    })
                })
                .collect(),
            archives: batch
                .archives
                .iter()
                .filter_map(|archive| {
                    Some(MobileChatArchiveRecord {
                        conversation_address: conversation_address(archive.key.conversation)?,
                        message_id: archive.key.message_id,
                        fragment_index: archive.key.fragment,
                        payload: archive.payload.clone(),
                    })
                })
                .collect(),
            mutations,
        };
        self.pending = Some(batch);
        Ok(ComposedChatBatch {
            record,
            deliveries,
            diagnostics,
        })
    }
}

/// Records for what the facade drained, stamped with the session that
/// produced it.
fn drain_records(drain: Drain) -> ChatDrain {
    let session_id = drain.session_id;
    let mut records = ChatDrain {
        outbound: drain.outbound,
        mutations: Vec::new(),
        deliveries: Vec::new(),
        repeats: Vec::new(),
        lookups: Vec::new(),
        resolutions: Vec::new(),
        diagnostics: Vec::new(),
    };
    for output in drain.outputs {
        match output {
            ChatOutput::Mutation(mutation) => {
                records
                    .mutations
                    .push(mutation_record(session_id, &mutation));
            }
            ChatOutput::Delivery(delivery) => {
                records
                    .deliveries
                    .push(delivery_record(session_id, &delivery));
            }
            ChatOutput::Repeats(repeats) => {
                records.repeats.push(repeat_record(session_id, &repeats));
            }
            ChatOutput::Lookup(lookup) => {
                if let Some(record) = lookup_record(&lookup) {
                    records.lookups.push(record);
                }
            }
            ChatOutput::SenderResolved(resolution) => {
                records.resolutions.push(resolution_record(&resolution));
            }
            // Only a compose stores archives, and its batch carries them.
            ChatOutput::StoreArchive(_) | ChatOutput::DeleteArchive(_) => {}
            ChatOutput::Event(event) => records.diagnostics.push(format!("{event:?}")),
            ChatOutput::Diagnostic(diagnostic) => {
                records.diagnostics.push(format!("{diagnostic:?}"));
            }
        }
    }
    records
}

fn delivery_record(session_id: u64, delivery: &Delivery) -> MobileChatDeliveryRecord {
    MobileChatDeliveryRecord {
        session_id,
        handle: delivery.handle.0,
        fragment_index: delivery.fragment,
        state: match delivery.state {
            DeliveryState::Sent => MobileChatDeliveryState::Sent,
            DeliveryState::Acked => MobileChatDeliveryState::Acknowledged,
            DeliveryState::Failed => MobileChatDeliveryState::Failed,
            DeliveryState::Undelivered => MobileChatDeliveryState::Undelivered,
        },
        via_flood: delivery.via_flood,
    }
}

fn repeat_record(session_id: u64, repeats: &Repeats) -> MobileChatRepeatRecord {
    MobileChatRepeatRecord {
        session_id,
        handle: repeats.handle.0,
        fragment_index: repeats.fragment,
        repeaters: repeats
            .repeaters
            .iter()
            .map(|hint| crate::RouterHintRecord {
                bytes: hint.0.to_vec(),
                text: hint.to_string(),
            })
            .collect(),
        anonymous_repeats: repeats.anonymous,
    }
}

fn lookup_record(lookup: &ArchiveLookup) -> Option<MobileChatArchiveLookupRecord> {
    Some(MobileChatArchiveLookupRecord {
        request_id: lookup.request_id,
        conversation_address: conversation_address(lookup.key.conversation)?,
        message_id: lookup.key.message_id,
        fragment_index: lookup.key.fragment,
    })
}

fn resolution_record(resolution: &SenderResolution) -> MobileChatSenderResolutionRecord {
    MobileChatSenderResolutionRecord {
        conversation_address: channel_address(resolution.channel),
        sender_hint: resolution.hint.0.to_vec(),
        sender_address: address(resolution.key),
    }
}

fn mutation_record(session_id: u64, mutation: &Mutation) -> MobileChatMutationRecord {
    let mut record = MobileChatMutationRecord {
        session_id,
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
        regarding_unknown: false,
        unknown_original: false,
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
        forward_secret: None,
    };
    match &mutation.change {
        Change::Insert(insert) => {
            record.conversation_address = conversation_address(insert.conversation);
            record.sender_address = insert.sender_key.map(address);
            record.sender_hint = claimed_hint(insert.sender);
            record.direction = Some(mobile_direction(insert.direction));
            record.message_type = Some(insert.message_type.to_byte());
            record.wire_id = insert.wire_id;
            record.epoch = Some(insert.epoch);
            record.client_token = insert.client_token;
            record.sender_handle = insert.sender_handle.clone();
            if let Some(regarding) = insert.regarding {
                apply_regarding(&mut record, regarding);
            }
            record.background_color = insert.bg_color.map(|color| color.to_vec());
            record.text_color = insert.text_color.map(|color| color.to_vec());
            record.body = Some(insert.body.clone());
            record.presence = mobile_presence(insert.presence);
            record.received_late = insert.late;
            record.notify = insert.notify;
            record.unknown_original = insert.unknown_original;
            apply_completion(&mut record, insert.status);
        }
        Change::UpdateBody {
            body,
            status,
            late,
            notify,
        } => {
            record.kind = MobileChatMutationKind::UpdateBody;
            record.body = Some(body.clone());
            record.received_late = *late;
            record.notify = *notify;
            apply_completion(&mut record, *status);
        }
        Change::Edit {
            conversation,
            original,
            body,
            ..
        } => {
            record.kind = MobileChatMutationKind::Edit;
            record.conversation_address = conversation_address(*conversation);
            apply_original(&mut record, *original);
            record.body = Some(body.clone());
        }
        Change::Delete {
            conversation,
            original,
        } => {
            record.kind = MobileChatMutationKind::Delete;
            record.conversation_address = conversation_address(*conversation);
            apply_original(&mut record, *original);
        }
    }
    record
}

fn mobile_direction(direction: Direction) -> MobileChatDirection {
    match direction {
        Direction::Inbound => MobileChatDirection::Inbound,
        Direction::Outbound => MobileChatDirection::Outbound,
    }
}

fn mobile_presence(presence: Presence) -> MobileChatPresence {
    match presence {
        Presence::Present => MobileChatPresence::Present,
        Presence::GapPending => MobileChatPresence::GapPending,
        Presence::GapIdle => MobileChatPresence::GapIdle,
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
        ResolvedRef::Unresolved(WireRef::RoomCanonical { .. }) | ResolvedRef::Unknown => {}
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
        ResolvedRef::Unknown => record.regarding_unknown = true,
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

/// The platform-facing address of a conversation: a peer's base58 address
/// for a direct one, a prefixed tag for a channel. Rooms have no address in
/// this facade.
pub(crate) fn conversation_address(conversation: ConversationKey) -> Option<String> {
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

/// Resolve an address back to a conversation. A channel address only
/// resolves while `channels` holds its key.
pub(crate) fn parse_conversation_address(
    value: &str,
    channels: &ChannelRegistry,
) -> Option<ConversationKey> {
    if let Some(rest) = value.strip_prefix(CHANNEL_DIRECT_ADDRESS_PREFIX) {
        let (tag, peer) = rest.split_once(':')?;
        let channel = parse_channel_tag(tag)?;
        if !channels.contains(&channel) {
            return None;
        }
        return Some(ConversationKey::ChannelDirect {
            channel,
            peer: decode_address(peer)?,
        });
    }
    if let Some(tag) = value.strip_prefix(CHANNEL_ADDRESS_PREFIX) {
        let channel = parse_channel_tag(tag)?;
        if !channels.contains(&channel) {
            return None;
        }
        return Some(ConversationKey::ChannelGroup { channel });
    }
    Some(ConversationKey::Direct {
        peer: decode_address(value)?,
    })
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
    use umsh_core::ChannelKey;
    use umsh_text::chat::Insert;
    use umsh_text::engine::MAX_FRAME;
    use umsh_text::model::MessageType;

    const LOCAL: PublicKey = PublicKey([0xAA; 32]);
    const PEER: PublicKey = PublicKey([0x11; 32]);
    const CHANNEL_KEY: ChannelKey = ChannelKey([0x42; 32]);

    fn direct() -> ConversationKey {
        ConversationKey::Direct { peer: PEER }
    }

    /// Seeds for a fresh session, distinct from every earlier one in the
    /// process.
    fn fresh_seeds() -> Seeds {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let session_id = NEXT.fetch_add(1, Ordering::Relaxed);
        Seeds {
            session_id,
            jitter_seed: session_id,
        }
    }

    /// A state whose registry already holds the test channel.
    fn state_with_channel() -> (MobileChatState, ChannelTag) {
        let tag = crate::channel_tag(&CHANNEL_KEY);
        let mut state = empty_state();
        state.facade.channels_mut().register(tag, CHANNEL_KEY, None);
        (state, tag)
    }

    fn empty_state() -> MobileChatState {
        MobileChatState::new(LOCAL, fresh_seeds())
    }

    /// A channel conversation survives a facade restart: its checkpoint is
    /// addressed by tag, and restoring it resumes the same outbound stream
    /// rather than starting a fresh one that would replay wire IDs.
    #[test]
    fn a_channel_checkpoint_round_trips_through_restore() {
        let (mut first, tag) = state_with_channel();
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        let composed = first
            .compose_text(conversation, 5, "on my way", MAX_FRAME, 0)
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
            .compose_text(conversation, 6, "still moving", MAX_FRAME, 1)
            .expect("composing after restore succeeds");
        assert_ne!(
            next.record.mutations[0].wire_id, composed.record.mutations[0].wire_id,
            "the restored stream must not reissue a spent wire ID"
        );
    }

    /// A checkpoint whose channel this session no longer holds is reported
    /// rather than dropped in silence—the channel was left, and the stream
    /// it belonged to cannot be resumed without the key.
    #[test]
    fn a_checkpoint_for_an_unheld_channel_is_diagnosed() {
        let (mut held, tag) = state_with_channel();
        let checkpoint = held
            .compose_text(
                ConversationKey::ChannelGroup { channel: tag },
                1,
                "hi",
                MAX_FRAME,
                0,
            )
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
    /// fresh session—restored from the persisted checkpoint—compose an
    /// edit whose mutation record exports a platform-resolvable reference.
    #[test]
    fn edit_by_persisted_reference_after_facade_restart() {
        let mut first = empty_state();
        let composed = first
            .compose_text(direct(), 7, "v1", MAX_FRAME, 0)
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
            restarted.session_id(),
            first.session_id(),
            "sessions must not collide"
        );
        let _ = restarted.restore(std::slice::from_ref(&checkpoint), 0);
        let edited = restarted
            .compose_edit(direct(), 8, &original, "v2", MAX_FRAME, 1)
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
        assert!(restarted.commit(edited.record.batch_id).is_some());
        let deleted = restarted
            .compose_delete(direct(), 9, &original, MAX_FRAME, 2)
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
        assert!(
            cold.compose_delete(direct(), 9, &original, MAX_FRAME, 0)
                .is_err()
        );
    }

    /// A row this session stored for an edit of a message never received
    /// is keyed by a handle the engine does not know it by.
    #[test]
    fn compose_reaction_falls_back_on_wire_coordinates() {
        let (mut state, tag) = state_with_channel();
        let target = MobileChatRegardingRef {
            session_id: state.session_id(),
            handle: 0xBEEF,
            wire_id: Some(9),
            direction: Some(MobileChatDirection::Inbound),
            sender_hint: Some(vec![0x33, 0x44, 0x55]),
            epoch: None,
        };
        let composed = state
            .compose_reaction(
                ConversationKey::ChannelGroup { channel: tag },
                1,
                &target,
                "+1",
                MAX_FRAME,
                0,
            )
            .expect("the wire coordinates still name it");
        assert!(composed.record.mutations.iter().any(|mutation| {
            mutation.kind == MobileChatMutationKind::Insert && mutation.regarding_wire_id == Some(9)
        }));
    }

    /// What could not be interpreted reaches the platform to be said.
    #[test]
    fn unknown_targets_are_exported() {
        let mutation = Mutation {
            handle: MessageHandle(1),
            revision: 1,
            change: Change::Insert(Insert {
                conversation: direct(),
                sender: SenderScope::Peer(PublicKey([0x11; 32])),
                sender_key: None,
                direction: Direction::Inbound,
                message_type: MessageType::Basic,
                wire_id: Some(3),
                epoch: 0,
                client_token: None,
                sender_handle: None,
                regarding: Some(ResolvedRef::Unknown),
                bg_color: None,
                text_color: None,
                body: "hi".into(),
                status: CompletionStatus::Complete,
                presence: Presence::Present,
                late: false,
                notify: true,
                unknown_original: true,
            }),
        };
        let record = mutation_record(7, &mutation);
        assert!(record.regarding_unknown);
        assert!(record.unknown_original);
        assert_eq!(record.regarding_handle, None);
        assert_eq!(record.regarding_wire_id, None);
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
            session_id: state.session_id().wrapping_add(1),
            handle: 0,
            wire_id: Some(9),
            direction: Some(MobileChatDirection::Inbound),
            sender_hint: Some(hint.clone()),
            epoch: Some(0),
        };
        let composed = state
            .compose_reaction(conversation, 1, &target, "+1", MAX_FRAME, 0)
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

        // Withdrawal is the same message with nothing in it—never an edit
        // or a delete, which would target the emote row instead.
        assert!(state.commit(composed.record.batch_id).is_some());
        let withdrawn = state
            .compose_reaction(conversation, 2, &target, "", MAX_FRAME, 1)
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
            .compose_text(direct(), 7, "mine", MAX_FRAME, 0)
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
            .compose_reaction(direct(), 8, &target, "<3", MAX_FRAME, 1)
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
            cold.compose_reaction(direct(), 9, &target, "<3", MAX_FRAME, 0)
                .is_err()
        );
    }

    /// A reply is ordinary text carrying the reference, so the platform can
    /// quote what it answers.
    #[test]
    fn only_what_is_typed_as_new_reads_a_me_prefix() {
        let mut state = empty_state();
        let typed = state
            .compose_typed(direct(), 1, "/me waves", MAX_FRAME, 0)
            .expect("typed status");
        let insert = &typed.record.mutations[0];
        assert_eq!(insert.message_type, Some(1));
        assert_eq!(insert.body.as_deref(), Some("waves"));

        let resent = empty_state()
            .compose_text(direct(), 2, "/me waves", MAX_FRAME, 1)
            .expect("literal text");
        let insert = &resent.record.mutations[0];
        assert_eq!(insert.message_type, Some(0));
        assert_eq!(insert.body.as_deref(), Some("/me waves"));

        let status = empty_state()
            .compose_status(direct(), 3, "waves", MAX_FRAME, 2)
            .expect("status again");
        assert_eq!(status.record.mutations[0].message_type, Some(1));
    }

    #[test]
    fn compose_reply_exports_basic_regarding() {
        let (mut state, tag) = state_with_channel();
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        let hint = vec![0x33, 0x44, 0x55];
        let target = MobileChatRegardingRef {
            session_id: state.session_id().wrapping_add(1),
            handle: 0,
            wire_id: Some(9),
            direction: Some(MobileChatDirection::Inbound),
            sender_hint: Some(hint.clone()),
            epoch: Some(0),
        };
        let composed = state
            .compose_reply(
                conversation,
                1,
                &target,
                "Spikes were plenty.",
                MAX_FRAME,
                0,
            )
            .expect("reply composes against a persisted target");
        let insert = composed
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("insert mutation");
        assert_eq!(insert.message_type, Some(0), "a reply is basic text");
        assert_eq!(insert.body.as_deref(), Some("Spikes were plenty."));
        assert_eq!(insert.regarding_wire_id, Some(9));
        assert_eq!(
            insert.regarding_direction,
            Some(MobileChatDirection::Inbound)
        );
        assert_eq!(insert.regarding_sender_hint, Some(hint));
    }

    /// Where the original can no longer be named, what was written still
    /// goes, as a plain message.
    #[test]
    fn reply_to_unnamed_original_goes_as_plain_text() {
        let mut first = empty_state();
        let composed = first
            .compose_text(direct(), 7, "mine", MAX_FRAME, 0)
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

        // No continuity: the engine refuses the reference.
        let mut cold = empty_state();
        let plain = cold
            .compose_reply(direct(), 8, &target, "still going", MAX_FRAME, 0)
            .expect("the text still composes");
        let insert = plain
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Insert)
            .expect("insert mutation");
        assert_eq!(insert.message_type, Some(0));
        assert_eq!(insert.body.as_deref(), Some("still going"));
        assert_eq!(insert.regarding_handle, None);
        assert_eq!(insert.regarding_wire_id, None);

        // No wire identity and a foreign session: nothing to name it by.
        assert!(cold.commit(plain.record.batch_id).is_some());
        let unnamed = MobileChatRegardingRef {
            session_id: cold.session_id().wrapping_add(1),
            wire_id: None,
            ..target
        };
        let plain = cold
            .compose_reply(direct(), 9, &unnamed, "again", MAX_FRAME, 1)
            .expect("the text still composes");
        assert!(
            plain
                .record
                .mutations
                .iter()
                .all(|mutation| mutation.regarding_wire_id.is_none()
                    && mutation.regarding_handle.is_none())
        );
    }

    /// A batch Swift could not store fails its frames under the session that
    /// composed it, and the rebuilt engine resumes from the checkpoints Swift
    /// still holds, as a new session that still names us on group messages.
    #[test]
    fn rejecting_a_batch_restores_and_keeps_the_display_name() {
        let (mut state, tag) = state_with_channel();
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        state.facade.set_local_handle("Ada");
        let stored = state
            .compose_text(conversation, 1, "kept", MAX_FRAME, 0)
            .expect("compose succeeds");
        let checkpoint = stored.record.checkpoint.clone();
        assert!(state.commit(stored.record.batch_id).is_some());

        let lost = state
            .compose_text(conversation, 2, "lost", MAX_FRAME, 1)
            .expect("compose succeeds");
        assert_eq!(
            state
                .compose_text(conversation, 3, "early", MAX_FRAME, 1)
                .err(),
            Some(ComposeFailure::Pending)
        );
        let old_session = state.session_id();
        let (drain, diagnostics) = state
            .reject(
                lost.record.batch_id,
                std::slice::from_ref(&checkpoint),
                fresh_seeds(),
                2,
            )
            .expect("the pending batch is rejected");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(drain.deliveries.len(), 1);
        assert_eq!(drain.deliveries[0].session_id, old_session);
        // Nothing of it went.
        assert_eq!(
            drain.deliveries[0].state,
            MobileChatDeliveryState::Undelivered
        );
        assert_ne!(state.session_id(), old_session);

        let next = state
            .compose_text(conversation, 4, "again", MAX_FRAME, 3)
            .expect("compose succeeds after a rejection");
        assert_eq!(
            next.record.mutations[0].wire_id, lost.record.mutations[0].wire_id,
            "the rejected message's wire ID never left, so it is reused"
        );
        let outbound = state.commit(next.record.batch_id).expect("released");
        let message = umsh_text::codec::parse(&outbound.transmissions()[0].payload)
            .expect("the frame parses");
        assert_eq!(message.sender_handle, Some("Ada"));
    }
}
