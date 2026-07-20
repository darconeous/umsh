//! Deterministic sans-I/O text-message engine.
//!
//! The engine is a reducer: platform code feeds it commands (compose,
//! receive, transmit updates, archive results, ticks) and drains a bounded
//! queue of effects and events. It never calls a database, sleeps, or
//! transmits directly, so it can be tested without a radio, clock, executor,
//! or platform runtime, and runs identically on mobile and pager targets.
//!
//! ## Output contract
//!
//! Outputs carry stable IDs and may be re-emitted; platform storage must
//! apply message mutations idempotently (a mutation with a `revision` not
//! newer than the last applied for its handle is a no-op). Rendered bodies
//! live in an internal arena addressed by [`BodyRef`]; drain all outputs
//! after each command — the arena resets once the queue is empty.

pub mod fragment;
pub mod repair;
pub mod sequence;

use heapless::{Deque, FnvIndexMap};
use umsh_core::PublicKey;

use crate::ParseError;
use crate::codec;
use crate::model::{
    ConversationKey, FRAGMENT_BODY_MAX, FRAGMENT_COUNT_MAX, Fragment, MessageSequence, MessageType,
    REASSEMBLED_BODY_MAX, Regarding, SenderScope, TextMessage,
};
use crate::validate::{self, Envelope, TextProfile, ValidateError, Validated};

use fragment::{FragmentPlan, InsertOutcome, ReassemblyPool, RenderSentinels, empty_slot};
use repair::{CoalesceRing, JitterSource, PendingLookup};
use sequence::{
    InboundStream, MessageHandle, OutboundStream, PendingRepair, SerialClass, StreamKey, classify,
};

/// Maximum encoded text payload the engine will hand to a transport.
pub const MAX_FRAME: usize = 240;

const ARENA_SIZE: usize = 4096;

/// Tuning knobs. Defaults suit a LoRa mesh; a pager may shrink the windows.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Grace period before acting on an inferred gap, absorbing reordering.
    pub reorder_grace_ms: u64,
    /// Minimum quiet time after the newest stored fragment before repair of
    /// that reassembly may begin. Every fragment arrival defers repair by at
    /// least this much (and by twice the observed inter-fragment gap when
    /// that is larger), so an actively delivering message is never repaired
    /// mid-flight. Platforms should set this to several frame airtimes.
    pub fragment_grace_ms: u64,
    /// Maximum extra randomized delay for channel-group repair requests.
    pub group_jitter_ms: u64,
    /// Largest forward gap repaired automatically (spec bound: 8).
    pub max_auto_repair_gap: u8,
    /// Minimum interval between resend requests on one stream.
    pub min_request_interval_ms: u64,
    /// Maximum resend requests transmitted per tick across all streams.
    pub max_requests_per_tick: u8,
    /// Maximum automatic request attempts per missing frame.
    pub max_repair_attempts: u8,
    /// Reassembly lifetime before a partial message is finalized.
    pub reassembly_ttl_ms: u64,
    /// Interval between repair attempts for the same frame.
    pub request_retry_ms: u64,
    /// Window in which duplicate resend requests are coalesced.
    pub coalesce_window_ms: u64,
    pub sentinels: RenderSentinels,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            reorder_grace_ms: 2_000,
            fragment_grace_ms: 8_000,
            group_jitter_ms: 4_000,
            max_auto_repair_gap: 8,
            min_request_interval_ms: 2_000,
            max_requests_per_tick: 4,
            max_repair_attempts: 4,
            reassembly_ttl_ms: 90_000,
            request_retry_ms: 8_000,
            coalesce_window_ms: 10_000,
            sentinels: RenderSentinels::default(),
        }
    }
}

/// Where a transmit effect should be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// Unicast to an authenticated peer.
    Peer(PublicKey),
    /// Multicast to a channel.
    Channel(umsh_core::ChannelId),
    /// Blind-unicast to a peer over a channel key.
    ChannelPeer {
        channel: umsh_core::ChannelId,
        peer: PublicKey,
    },
}

/// Archive key identifying resendable outbound material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveKey {
    pub conversation: ConversationKey,
    pub message_id: u8,
    pub fragment: Option<u8>,
}

/// A frame for the platform to transmit.
#[derive(Clone, Debug)]
pub struct Transmission {
    pub transmission_id: u32,
    pub destination: Destination,
    /// When present, the platform should archive this payload as resendable
    /// material under this key (control frames carry `None`).
    pub archive: Option<ArchiveKey>,
    /// Encoded text-message payload (without the payload-type byte).
    pub payload: heapless::Vec<u8, MAX_FRAME>,
}

/// Reference into the engine's render arena; resolve with [`Engine::body`].
/// Valid until the output queue has been fully drained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyRef {
    offset: u16,
    len: u16,
}

/// A protocol-level reference, resolved to a stable handle when unambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedRef {
    Handle(MessageHandle),
    Unresolved(crate::model::WireRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Completeness of a message's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionStatus {
    Complete,
    Partial {
        /// Bitmap of fragments present.
        present: u16,
        count: u8,
        /// No further repair will occur; the render is final.
        finalized: bool,
    },
}

/// An idempotent transcript mutation.
#[derive(Clone, Copy, Debug)]
pub struct MessageMutation {
    pub handle: MessageHandle,
    /// Monotonic across all mutations; apply only if newer than the last
    /// applied revision for this handle.
    pub revision: u32,
    pub kind: MutationKind,
}

#[derive(Clone, Copy, Debug)]
pub enum MutationKind {
    /// Create a transcript record.
    Insert {
        conversation: ConversationKey,
        sender: SenderScope,
        direction: Direction,
        message_type: MessageType,
        wire_id: Option<u8>,
        epoch: u16,
        /// Correlates an outbound record with the caller's compose call.
        client_token: Option<u32>,
        sender_handle: Option<BodyRef>,
        regarding: Option<ResolvedRef>,
        bg_color: Option<[u8; 3]>,
        text_color: Option<[u8; 3]>,
        body: BodyRef,
        status: CompletionStatus,
    },
    /// Replace the rendered body (reassembly progress or finalization).
    UpdateBody {
        body: BodyRef,
        status: CompletionStatus,
    },
    /// Apply an edit to the referenced original message.
    Edit {
        original: ResolvedRef,
        body: BodyRef,
    },
    /// Mark the referenced original message deleted (empty edit).
    Delete { original: ResolvedRef },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryState {
    Sent,
    Acked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairOutcome {
    Repaired,
    Unavailable,
    Exhausted,
    Expired,
    Unaddressable,
}

/// Application-visible events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    DeliveryStateChanged {
        handle: MessageHandle,
        fragment: Option<u8>,
        state: DeliveryState,
    },
    RepairStarted {
        conversation: ConversationKey,
        sender: SenderScope,
        message_id: u8,
        fragment: Option<u8>,
    },
    RepairFinished {
        conversation: ConversationKey,
        sender: SenderScope,
        message_id: u8,
        outcome: RepairOutcome,
    },
    /// The remote sender reported the named frame unavailable.
    MessageUnavailable {
        conversation: ConversationKey,
        sender: SenderScope,
        message_id: u8,
        fragment: Option<u8>,
    },
}

/// Non-fatal observations, surfaced for logging and counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Diagnostic {
    ParseFailed(ParseError),
    ValidateFailed(ValidateError),
    DuplicateMessage {
        message_id: u8,
    },
    DuplicateFragment {
        message_id: u8,
        fragment: u8,
    },
    /// Conflicting bytes for an already-filled fragment slot were discarded.
    FragmentConflict {
        message_id: u8,
        fragment: u8,
    },
    /// A fragment body above the wire maximum was dropped unstored.
    OversizedFragment {
        message_id: u8,
        fragment: u8,
    },
    /// A fragment count above the wire maximum was dropped unassembled.
    FragmentCountExceeded {
        message_id: u8,
        count: u8,
    },
    /// Fragments of one message disagreed about the fragment count.
    FragmentCountMismatch {
        message_id: u8,
    },
    /// Two known peer keys collide on one source hint; automatic repair is
    /// suppressed for the merged stream.
    HintCollision {
        conversation: ConversationKey,
    },
    /// A reassembly was evicted under memory pressure before completion.
    ReassemblyEvicted {
        message_id: u8,
    },
    /// A stream table was full and its least-recently-active entry evicted.
    StreamEvicted,
    /// Presentation options were duplicated; first occurrences were kept.
    RepeatedPresentationOptions {
        mask: u16,
    },
    /// A continuation fragment carried ignored message-level metadata.
    IgnoredContinuationMetadata {
        message_id: u8,
    },
    /// The render arena or output queue overflowed; see `lost_outputs`.
    OutputOverflow,
    /// An archive result arrived for an unknown request.
    UnknownLookup {
        request_id: u32,
    },
    /// A completely reassembled body failed UTF-8 validation (the spec
    /// validates only after every fragment is present); invalid sequences
    /// were replaced with U+FFFD in the rendered text.
    ReassembledInvalidUtf8 {
        message_id: u8,
    },
    /// A resend request was ignored because an equivalent one was answered
    /// within the coalescing window.
    CoalescedResend {
        message_id: u8,
    },
    /// A resend request arrived in a form the engine could not attribute.
    UnattributableResend,
}

/// One drained output: an effect for the platform or an application event.
#[derive(Clone, Debug)]
pub enum Output {
    Transmit(Transmission),
    /// Persist the outbound stream checkpoint *before* transmitting the
    /// frames queued after it.
    ///
    /// Failure contract: outputs are ordered, so the platform sees this
    /// before the [`Output::Transmit`]s it covers. If the write fails, the
    /// platform must drop (not send) those transmissions and resynchronize
    /// via [`Engine::restore`]; sending them anyway risks reusing a wire ID
    /// after the next power cycle without announcing a Sequence Reset.
    StoreCheckpoint {
        conversation: ConversationKey,
        next_id: u8,
        epoch: u16,
    },
    /// Look up resendable outbound material; answer with
    /// [`Engine::archive_result`].
    LookupOutbound {
        request_id: u32,
        conversation: ConversationKey,
        sequence: MessageSequence,
    },
    StoreMessage(MessageMutation),
    Event(Event),
    Diagnostic(Diagnostic),
}

/// Result of an outbound archive lookup.
#[derive(Clone, Copy, Debug)]
pub enum ArchiveResult<'a> {
    /// The exact stored payload originally handed to `Transmit`.
    Found {
        payload: &'a [u8],
    },
    Deleted,
    Evicted,
    Unknown,
}

/// Persisted outbound stream checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamCheckpoint {
    pub conversation: ConversationKey,
    pub next_id: u8,
    pub epoch: u16,
}

/// What the caller wants to send.
#[derive(Clone, Copy, Debug)]
pub enum ComposeIntent<'a> {
    /// Plain text (`status` renders like IRC `/me`).
    Text { body: &'a str, status: bool },
    /// Reply to (`status: false`) or emote about (`status: true`) a message.
    Reply {
        body: &'a str,
        regarding: MessageHandle,
        status: bool,
    },
    /// Replace a previously composed message's content.
    Edit {
        original: MessageHandle,
        body: &'a str,
    },
    /// Delete a previously composed message (empty edit on the wire).
    Delete { original: MessageHandle },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    /// The referenced message's wire ID is no longer in the outbound window.
    UnknownOriginal,
    /// The referenced message could not be resolved to a wire reference.
    UnknownRegarding,
    /// The body exceeds the wire maximum (10 fragments × 160 bytes).
    TooLarge,
    Encode(crate::EncodeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    Parse(ParseError),
    Validate(ValidateError),
}

/// The deterministic text engine.
///
/// `SLOTS`/`PAGES` size the shared reassembly pool (a page is 80 bytes; a
/// full 160-byte fragment consumes two pages).
pub struct Engine<P: TextProfile, const SLOTS: usize = 4, const PAGES: usize = 24> {
    profile: P,
    config: EngineConfig,
    local_key: PublicKey,
    jitter: JitterSource,
    outbound: FnvIndexMap<ConversationKey, OutboundStream, 8>,
    /// Sequence continuity for conversations outside the active `outbound`
    /// map: restored checkpoints not yet composed to, and streams demoted by
    /// eviction. Reactivation resumes from here instead of resetting.
    cold_checkpoints: heapless::Vec<(ConversationKey, u8, u16), 24>,
    inbound: FnvIndexMap<StreamKey, InboundStream, 16>,
    pool: ReassemblyPool<SLOTS, PAGES>,
    outputs: Deque<Output, 32>,
    arena: [u8; ARENA_SIZE],
    arena_used: usize,
    next_handle: u32,
    next_transmission: u32,
    next_request: u32,
    revision: u32,
    lookups: heapless::Vec<PendingLookup, 8>,
    coalesce: CoalesceRing,
    in_flight: heapless::Vec<InFlightFrame, 16>,
    /// The platform has reported transport progress at least once, so
    /// `in_flight` reflects real frame lifecycles rather than merely
    /// emissions that were never confirmed either way.
    saw_transmit_report: bool,
    lost_outputs: u32,
}

/// A tracked outbound frame between `Transmit` emission and its terminal
/// delivery report.
#[derive(Clone, Copy, Debug)]
struct InFlightFrame {
    transmission_id: u32,
    handle: MessageHandle,
    fragment: Option<u8>,
    /// Archive coordinates, used to coalesce resend requests that arrive
    /// around this frame's own transmission.
    archive: Option<ArchiveKey>,
}

impl<P: TextProfile, const SLOTS: usize, const PAGES: usize> Engine<P, SLOTS, PAGES> {
    /// `jitter_seed` drives group-repair desynchronization only; it is
    /// scheduling randomness, not security material.
    pub fn new(profile: P, local_key: PublicKey, config: EngineConfig, jitter_seed: u64) -> Self {
        Self {
            profile,
            config,
            local_key,
            jitter: JitterSource::new(jitter_seed),
            outbound: FnvIndexMap::new(),
            cold_checkpoints: heapless::Vec::new(),
            inbound: FnvIndexMap::new(),
            pool: ReassemblyPool::new(),
            outputs: Deque::new(),
            arena: [0; ARENA_SIZE],
            arena_used: 0,
            next_handle: 1,
            next_transmission: 1,
            next_request: 1,
            revision: 1,
            lookups: heapless::Vec::new(),
            coalesce: CoalesceRing::default(),
            in_flight: heapless::Vec::new(),
            saw_transmit_report: false,
            lost_outputs: 0,
        }
    }

    /// Drain the next output. The render arena resets when this returns
    /// `None`, invalidating previously returned [`BodyRef`]s.
    pub fn poll_output(&mut self) -> Option<Output> {
        let output = self.outputs.pop_front();
        if output.is_none() {
            self.arena_used = 0;
        }
        output
    }

    /// Resolve a [`BodyRef`] to its UTF-8 text.
    pub fn body(&self, body: &BodyRef) -> &str {
        let start = body.offset as usize;
        let end = start + body.len as usize;
        core::str::from_utf8(&self.arena[start..end]).unwrap_or("")
    }

    /// Outputs dropped because the queue overflowed (platform drained too
    /// slowly). Nonzero values warrant a resync from persistent storage.
    pub fn lost_outputs(&self) -> u32 {
        self.lost_outputs
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Seed outbound stream continuity from persisted checkpoints.
    /// Restored conversations resume their sequence at first use.
    ///
    /// Continuity is tracked in memory for 8 active plus 24 cold
    /// conversations. Pass checkpoints **oldest-first**: when more are
    /// supplied than the cold stash holds, the earliest entries are the
    /// ones displaced. A conversation without retained continuity (never
    /// restored, or displaced past the bound) starts a fresh epoch and
    /// announces a lazy Sequence Reset — safe by design, at the cost of
    /// receivers re-baselining that stream.
    pub fn restore(&mut self, checkpoints: &[StreamCheckpoint], _now_ms: u64) {
        for checkpoint in checkpoints {
            self.stash_checkpoint(
                checkpoint.conversation,
                checkpoint.next_id,
                checkpoint.epoch,
            );
        }
    }

    /// Compose and queue an outbound message. Returns the stable handle of
    /// the affected transcript record.
    pub fn compose(
        &mut self,
        conversation: ConversationKey,
        client_token: u32,
        intent: ComposeIntent<'_>,
        now_ms: u64,
    ) -> Result<MessageHandle, ComposeError> {
        let (body, status_type, regarding_handle, edit_original) = match intent {
            ComposeIntent::Text { body, status } => (body, status, None, None),
            ComposeIntent::Reply {
                body,
                status,
                regarding,
            } => (body, status, Some(regarding), None),
            ComposeIntent::Edit { original, body } => (body, false, None, Some(original)),
            ComposeIntent::Delete { original } => ("", false, None, Some(original)),
        };
        if body.len() > REASSEMBLED_BODY_MAX {
            return Err(ComposeError::TooLarge);
        }

        // Resolve references before allocating a wire ID.
        let regarding = match regarding_handle {
            None => None,
            Some(handle) => Some(
                self.wire_reference_for(conversation, handle)
                    .ok_or(ComposeError::UnknownRegarding)?,
            ),
        };
        let editing = match edit_original {
            None => None,
            Some(handle) => {
                let stream = self
                    .outbound
                    .get(&conversation)
                    .ok_or(ComposeError::UnknownOriginal)?;
                Some(
                    stream
                        .refs
                        .lookup_handle(handle)
                        .ok_or(ComposeError::UnknownOriginal)?,
                )
            }
        };

        self.ensure_outbound(conversation, now_ms);
        let stream = self.outbound.get_mut(&conversation).expect("just ensured");
        stream.last_active_ms = now_ms;
        let message_id = stream.allocate();
        let announce_reset = core::mem::take(&mut stream.announce_reset);
        let next_id = stream.next_id;
        let epoch = stream.epoch;

        // Commit the checkpoint advancement before any frame is released.
        self.push_output(Output::StoreCheckpoint {
            conversation,
            next_id,
            epoch,
        });

        let message_type = if status_type {
            MessageType::Status
        } else {
            MessageType::Basic
        };
        let template = TextMessage {
            message_type,
            sender_handle: None,
            sequence: Some(MessageSequence::unfragmented(message_id)),
            sequence_reset: announce_reset,
            regarding,
            editing,
            bg_color: None,
            text_color: None,
            channel_group_resend: false,
            extensions: Default::default(),
            body: body.as_bytes(),
        };

        let handle = self.alloc_handle();
        self.encode_and_queue(conversation, handle, &template, body.as_bytes(), message_id)?;

        // Record the mapping only for original messages; edit IDs must not
        // become reference targets.
        if editing.is_none() {
            let stream = self.outbound.get_mut(&conversation).expect("present");
            stream.refs.record(message_id, handle);
        }

        // Emit the transcript mutation.
        let body_ref = self
            .arena_store(body)
            .unwrap_or(BodyRef { offset: 0, len: 0 });
        let kind = match (edit_original, body.is_empty()) {
            (Some(original), true) => MutationKind::Delete {
                original: ResolvedRef::Handle(original),
            },
            (Some(original), false) => MutationKind::Edit {
                original: ResolvedRef::Handle(original),
                body: body_ref,
            },
            (None, _) => MutationKind::Insert {
                conversation,
                sender: SenderScope::Local,
                direction: Direction::Outbound,
                message_type,
                wire_id: Some(message_id),
                epoch,
                client_token: Some(client_token),
                sender_handle: None,
                regarding: regarding_handle.map(ResolvedRef::Handle),
                bg_color: None,
                text_color: None,
                body: body_ref,
                status: CompletionStatus::Complete,
            },
        };
        self.emit_mutation(handle, kind);
        Ok(handle)
    }

    /// Feed one MAC-validated received text payload (without the
    /// payload-type byte) through the engine.
    ///
    /// `sender_full_key` resolves a claimed multicast member to a full public
    /// key when the platform knows it; it is required for that sender's
    /// streams to be repairable.
    pub fn receive(
        &mut self,
        envelope: &Envelope,
        sender_full_key: Option<PublicKey>,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), ReceiveError> {
        let (message, info) = codec::parse_with_info(payload).map_err(|error| {
            self.push_output(Output::Diagnostic(Diagnostic::ParseFailed(error)));
            ReceiveError::Parse(error)
        })?;
        let (validated, notes) = validate::validate(&self.profile, envelope, &message, &info)
            .map_err(|error| {
                self.push_output(Output::Diagnostic(Diagnostic::ValidateFailed(error)));
                ReceiveError::Validate(error)
            })?;
        if notes.repeated_presentation_mask != 0 {
            self.push_output(Output::Diagnostic(
                Diagnostic::RepeatedPresentationOptions {
                    mask: notes.repeated_presentation_mask,
                },
            ));
        }

        match validated {
            Validated::Content(content) => {
                if notes.ignored_continuation_metadata
                    && let Some(sequence) = content.sequence
                {
                    self.push_output(Output::Diagnostic(
                        Diagnostic::IgnoredContinuationMetadata {
                            message_id: sequence.message_id,
                        },
                    ));
                }
                self.receive_content(envelope, sender_full_key, &content, now_ms);
            }
            Validated::ResendRequest {
                sequence,
                channel_group,
            } => self.receive_resend_request(envelope, sequence, channel_group, now_ms),
            Validated::Unavailable { sequence } => {
                self.receive_unavailable(envelope, sequence, now_ms)
            }
        }
        Ok(())
    }

    /// Report transport progress for a previously emitted transmission.
    pub fn transmit_update(&mut self, transmission_id: u32, state: DeliveryState, now_ms: u64) {
        self.saw_transmit_report = true;
        let Some(position) = self
            .in_flight
            .iter()
            .position(|frame| frame.transmission_id == transmission_id)
        else {
            return;
        };
        let frame = self.in_flight[position];
        self.push_output(Output::Event(Event::DeliveryStateChanged {
            handle: frame.handle,
            fragment: frame.fragment,
            state,
        }));
        if matches!(state, DeliveryState::Acked | DeliveryState::Failed) {
            self.in_flight.remove(position);
        }
        let _ = now_ms;
    }

    /// Answer a previously emitted `LookupOutbound` effect.
    pub fn archive_result(&mut self, request_id: u32, result: ArchiveResult<'_>, now_ms: u64) {
        let Some(position) = self
            .lookups
            .iter()
            .position(|lookup| lookup.request_id == request_id)
        else {
            self.push_output(Output::Diagnostic(Diagnostic::UnknownLookup { request_id }));
            return;
        };
        let lookup = self.lookups.remove(position);
        let destination = destination_for(&lookup.conversation);

        match result {
            ArchiveResult::Found { payload } if payload.len() <= MAX_FRAME => {
                let mut frame = heapless::Vec::new();
                let _ = frame.extend_from_slice(payload);
                self.queue_transmit(destination, None, frame, None);
            }
            _ => {
                // Deleted, evicted, unknown, or oversized stored material:
                // answer Message Unavailable for the requested frame.
                let response = TextMessage {
                    message_type: MessageType::MessageUnavailable,
                    sequence: Some(lookup.sequence),
                    ..TextMessage::basic("")
                };
                let mut buffer = [0u8; MAX_FRAME];
                if let Ok(len) = codec::encode(&response, &mut buffer) {
                    let mut frame = heapless::Vec::new();
                    let _ = frame.extend_from_slice(&buffer[..len]);
                    self.queue_transmit(destination, None, frame, None);
                }
            }
        }
        self.coalesce
            .record(lookup.conversation, &lookup.sequence, now_ms);
    }

    /// Advance timers: reassembly expiry and repair scheduling.
    pub fn tick(&mut self, now_ms: u64) {
        self.expire_slots(now_ms);
        self.schedule_fragment_repairs(now_ms);
        self.transmit_due_repairs(now_ms);
    }

    // ------------------------------------------------------------------
    // Content path
    // ------------------------------------------------------------------

    fn receive_content(
        &mut self,
        envelope: &Envelope,
        sender_full_key: Option<PublicKey>,
        content: &validate::ContentMessage<'_>,
        now_ms: u64,
    ) {
        let key = StreamKey {
            conversation: envelope.conversation,
            sender: envelope.sender,
        };
        self.ensure_inbound(key, now_ms);
        let stream = self.inbound.get_mut(&key).expect("just ensured");
        stream.last_active_ms = now_ms;

        // Hint-collision containment.
        if let Some(full_key) = sender_full_key {
            match stream.sender_key {
                None => stream.sender_key = Some(full_key),
                Some(existing) if existing != full_key => {
                    if !stream.collided {
                        stream.collided = true;
                        let conversation = envelope.conversation;
                        self.push_output(Output::Diagnostic(Diagnostic::HintCollision {
                            conversation,
                        }));
                    }
                }
                Some(_) => {}
            }
        }

        let sequence = content.sequence;
        if content.sequence_reset {
            let repeated_id = sequence.is_some_and(|sequence| {
                self.inbound
                    .get(&key)
                    .is_some_and(|stream| stream.seen.contains(sequence.message_id))
            });
            if !repeated_id {
                let stream = self.inbound.get_mut(&key).expect("present");
                // The arriving message itself establishes the new baseline
                // below. A retransmitted reset-bearing ID is still a
                // duplicate; applying its reset again would erase the very
                // state needed to suppress it.
                stream.reset_epoch(None);
                self.pool.drop_stream(&key);
            }
        }

        let Some(sequence) = sequence else {
            // Unsequenced: display-only, unreferencable, no dedup possible.
            self.insert_content(envelope, content, None, CompletionStatus::Complete, now_ms);
            return;
        };
        let id = sequence.message_id;

        // Sequence-window accounting (shared by fragments and whole
        // messages; fragment dedup happens against the slot bitmap).
        let stream = self.inbound.get_mut(&key).expect("present");
        let mut first_sighting = true;
        match stream.baseline {
            None => {
                stream.baseline = Some(id);
                stream.seen.insert(id);
            }
            Some(baseline) => match classify(baseline, id) {
                SerialClass::Baseline => first_sighting = false,
                SerialClass::Older(_) => {
                    if stream.seen.contains(id) {
                        first_sighting = false;
                    } else {
                        stream.seen.insert(id);
                    }
                }
                SerialClass::Newer(delta) => {
                    let gap = delta - 1;
                    let collided = stream.collided;
                    let can_repair = gap > 0
                        && gap <= self.config.max_auto_repair_gap
                        && !collided
                        && content.sequence.is_some();
                    if can_repair {
                        let group =
                            matches!(envelope.conversation, ConversationKey::ChannelGroup { .. });
                        let base_deadline = now_ms + self.config.reorder_grace_ms;
                        for step in 1..=gap {
                            let missing = baseline.wrapping_add(step);
                            let jitter = if group {
                                self.jitter.jitter_ms(self.config.group_jitter_ms)
                            } else {
                                0
                            };
                            let stream = self.inbound.get_mut(&key).expect("present");
                            let _ = stream.pending.push(PendingRepair {
                                message_id: missing,
                                fragment: None,
                                deadline_ms: base_deadline + jitter,
                                attempts: 0,
                            });
                        }
                    }
                    let stream = self.inbound.get_mut(&key).expect("present");
                    stream.seen.advance(baseline, delta);
                    stream.baseline = Some(id);
                    stream.seen.insert(id);
                }
                SerialClass::Ambiguous => {
                    // Re-baseline without backfill or epoch change.
                    stream.seen.clear();
                    stream.pending.clear();
                    stream.baseline = Some(id);
                    stream.seen.insert(id);
                }
            },
        }

        // A fragmented ID may legitimately appear many times while its slot
        // is open, once per distinct fragment and again for repairs. After
        // completion, expiry, or eviction closes that slot, however, any
        // already-seen fragment is late duplicate traffic. Never let it open
        // a second slot and render the same logical message again.
        if let Some(fragment) = sequence.fragment {
            let epoch = self.inbound.get(&key).expect("present").epoch;
            if !first_sighting && self.pool.find_slot(&key, epoch, id).is_none() {
                self.push_output(Output::Diagnostic(Diagnostic::DuplicateFragment {
                    message_id: id,
                    fragment: fragment.index,
                }));
                return;
            }
        }

        // An arrival satisfies pending repair for its frame.
        let stream = self.inbound.get_mut(&key).expect("present");
        let fragment_index = sequence.fragment.map(|fragment| fragment.index);
        let was_repairing = stream
            .pending
            .iter()
            .any(|pending| pending.message_id == id && pending.attempts > 0);
        stream.cancel_pending(id, fragment_index);
        if was_repairing && sequence.fragment.is_none() {
            self.push_output(Output::Event(Event::RepairFinished {
                conversation: key.conversation,
                sender: key.sender,
                message_id: id,
                outcome: RepairOutcome::Repaired,
            }));
        }

        match sequence.fragment {
            Some(fragment) => {
                self.receive_fragment(envelope, content, key, id, fragment, now_ms);
            }
            None => {
                if !first_sighting {
                    self.push_output(Output::Diagnostic(Diagnostic::DuplicateMessage {
                        message_id: id,
                    }));
                    return;
                }
                self.receive_single_frame(envelope, content, key, id, now_ms);
            }
        }
    }

    fn receive_single_frame(
        &mut self,
        envelope: &Envelope,
        content: &validate::ContentMessage<'_>,
        key: StreamKey,
        id: u8,
        now_ms: u64,
    ) {
        if let Some(original_id) = content.editing {
            // Edits and deletes target the sender's own stream.
            let original = self
                .inbound
                .get(&key)
                .and_then(|stream| stream.refs.lookup(original_id))
                .map(ResolvedRef::Handle)
                .unwrap_or(ResolvedRef::Unresolved(
                    crate::model::WireRef::SenderScoped {
                        sender: envelope.sender,
                        message_id: original_id,
                    },
                ));
            let handle = self.alloc_handle();
            let kind = if content.body.is_empty() {
                MutationKind::Delete { original }
            } else {
                let body = core::str::from_utf8(content.body).unwrap_or("");
                let body_ref = self
                    .arena_store(body)
                    .unwrap_or(BodyRef { offset: 0, len: 0 });
                MutationKind::Edit {
                    original,
                    body: body_ref,
                }
            };
            self.emit_mutation(handle, kind);
            return;
        }

        let handle = self.insert_content(
            envelope,
            content,
            Some(id),
            CompletionStatus::Complete,
            now_ms,
        );
        if let Some(stream) = self.inbound.get_mut(&key) {
            stream.refs.record(id, handle);
        }
    }

    fn receive_fragment(
        &mut self,
        envelope: &Envelope,
        content: &validate::ContentMessage<'_>,
        key: StreamKey,
        id: u8,
        fragment: Fragment,
        now_ms: u64,
    ) {
        if fragment.count > FRAGMENT_COUNT_MAX {
            // Above the wire maximum: account for the ID, drop the assembly.
            self.push_output(Output::Diagnostic(Diagnostic::FragmentCountExceeded {
                message_id: id,
                count: fragment.count,
            }));
            return;
        }
        let epoch = self
            .inbound
            .get(&key)
            .map(|stream| stream.epoch)
            .unwrap_or(0);

        let slot_index = match self.pool.find_slot(&key, epoch, id) {
            Some(index) => {
                let slot = self.pool.slots[index].as_ref().expect("occupied");
                if slot.count != fragment.count {
                    self.push_output(Output::Diagnostic(Diagnostic::FragmentCountMismatch {
                        message_id: id,
                    }));
                    return;
                }
                index
            }
            None => {
                let handle = self.alloc_handle();
                let mut slot = empty_slot(key, epoch, id, fragment.count, handle, now_ms);
                slot.deadline_ms = now_ms + self.config.reassembly_ttl_ms;
                let group = matches!(key.conversation, ConversationKey::ChannelGroup { .. });
                let jitter = if group {
                    self.jitter.jitter_ms(self.config.group_jitter_ms)
                } else {
                    0
                };
                slot.repair_at_ms = now_ms + self.config.fragment_grace_ms + jitter;
                match self.pool.open_slot(slot.clone()) {
                    Some(index) => index,
                    None => {
                        // Evict the oldest assembly to make room.
                        if let Some(oldest) = self.pool.oldest_slot() {
                            self.finalize_slot(oldest, now_ms, RepairOutcome::Expired, true);
                        }
                        match self.pool.open_slot(slot) {
                            Some(index) => index,
                            None => {
                                self.push_output(Output::Diagnostic(
                                    Diagnostic::ReassemblyEvicted { message_id: id },
                                ));
                                return;
                            }
                        }
                    }
                }
            }
        };

        // Fragment zero carries the message-level metadata, which applies to
        // the entire reassembled message. Captured first-arrival-wins and
        // before storage, so even an oversized fragment zero contributes its
        // valid, authenticated options.
        if fragment.index == 0 {
            let slot = self.pool.slots[slot_index].as_mut().expect("occupied");
            if !slot.have_meta {
                slot.meta = fragment::FirstMeta {
                    message_type_byte: content.message_type.to_byte(),
                    regarding: content.regarding,
                    editing: content.editing,
                };
                slot.have_meta = true;
            }
        }

        if content.body.len() > FRAGMENT_BODY_MAX {
            // Syntactically valid but beyond this receiver's storage (the
            // sender violated the wire maximum). Salvage the rest of the
            // message: mark just this fragment unavailable — a resend would
            // return the same oversized bytes — and let the assembly proceed
            // for every fragment we can hold.
            self.push_output(Output::Diagnostic(Diagnostic::OversizedFragment {
                message_id: id,
                fragment: fragment.index,
            }));
            let slot = self.pool.slots[slot_index].as_mut().expect("occupied");
            let bit = 1u16 << fragment.index;
            if slot.present & bit == 0 {
                slot.unavailable |= bit;
            }
            self.publish_slot(envelope, content, slot_index, now_ms);
            if self.pool.slots[slot_index]
                .as_ref()
                .is_some_and(|slot| slot.is_settled() && !slot.is_complete())
            {
                self.finalize_slot(slot_index, now_ms, RepairOutcome::Unavailable, false);
            }
            return;
        }

        // Store the fragment bytes.
        let mut outcome = self
            .pool
            .insert_fragment(slot_index, fragment.index, content.body);
        if outcome == InsertOutcome::NoSpace {
            // Free pages by evicting the oldest *other* slot, then retry.
            let oldest = self.pool.oldest_slot().filter(|index| *index != slot_index);
            if let Some(oldest) = oldest {
                self.finalize_slot(oldest, now_ms, RepairOutcome::Expired, true);
                outcome = self
                    .pool
                    .insert_fragment(slot_index, fragment.index, content.body);
            }
        }
        match outcome {
            InsertOutcome::Stored => {}
            InsertOutcome::Duplicate => {
                self.push_output(Output::Diagnostic(Diagnostic::DuplicateFragment {
                    message_id: id,
                    fragment: fragment.index,
                }));
                return;
            }
            InsertOutcome::Conflict => {
                self.push_output(Output::Diagnostic(Diagnostic::FragmentConflict {
                    message_id: id,
                    fragment: fragment.index,
                }));
                return;
            }
            InsertOutcome::NoSpace => {
                self.push_output(Output::Diagnostic(Diagnostic::ReassemblyEvicted {
                    message_id: id,
                }));
                return;
            }
            InsertOutcome::TooLarge => {
                // Validation already rejects oversized bodies; this arm keeps
                // the pool guard observable if that ever regresses.
                self.push_output(Output::Diagnostic(Diagnostic::OversizedFragment {
                    message_id: id,
                    fragment: fragment.index,
                }));
                return;
            }
        }

        // A stored fragment is proof the sender is still delivering: defer
        // repair by at least the configured grace, and by twice the observed
        // inter-fragment gap when the link is slower than that. Requesting a
        // resend of a frame the sender has merely not reached yet duplicates
        // it on air and delays the frames behind it — the repair timer must
        // only fire once arrivals actually stall.
        {
            let group = matches!(key.conversation, ConversationKey::ChannelGroup { .. });
            let jitter = if group {
                self.jitter.jitter_ms(self.config.group_jitter_ms)
            } else {
                0
            };
            let grace = self.config.fragment_grace_ms;
            let slot = self.pool.slots[slot_index].as_mut().expect("occupied");
            let gap = now_ms.saturating_sub(slot.last_fragment_ms);
            slot.last_fragment_ms = now_ms;
            let holdoff = grace.max(gap.saturating_mul(2));
            slot.repair_at_ms = slot.repair_at_ms.max(now_ms + holdoff + jitter);
        }

        self.publish_slot(envelope, content, slot_index, now_ms);
        // A stored fragment can settle a slot that carries unavailable
        // marks; nothing further can improve it, so finalize now rather
        // than waiting for the reassembly TTL.
        if self.pool.slots[slot_index]
            .as_ref()
            .is_some_and(|slot| slot.is_settled() && !slot.is_complete())
        {
            self.finalize_slot(slot_index, now_ms, RepairOutcome::Unavailable, false);
        }
    }

    /// Emit the appropriate mutation for a slot's current state, completing
    /// it if every fragment is present.
    ///
    /// `content` is the fragment that triggered this call. The announcing
    /// Insert always runs during the call that delivered fragment zero
    /// (`have_meta` is set in that same call), so presentation metadata —
    /// sender handle and colors — is borrowed from `content` at full
    /// fidelity instead of being retained in the slot.
    fn publish_slot(
        &mut self,
        envelope: &Envelope,
        content: &validate::ContentMessage<'_>,
        slot_index: usize,
        now_ms: u64,
    ) {
        let slot = self.pool.slots[slot_index].as_ref().expect("occupied");
        let key = slot.stream;
        let handle = slot.handle;
        let complete = slot.is_complete();
        let have_meta = slot.have_meta;
        let is_edit = slot.meta.editing.is_some();
        let announced = slot.announced;
        let id = slot.message_id;
        let present = slot.present;
        let count = slot.count;

        if !have_meta {
            // Until fragment zero arrives we cannot know how to present the
            // message (it may be an edit); keep accumulating silently.
            return;
        }

        if complete && is_edit {
            let original_id = self.pool.slots[slot_index]
                .as_ref()
                .expect("occupied")
                .meta
                .editing
                .expect("checked");
            let original = self
                .inbound
                .get(&key)
                .and_then(|stream| stream.refs.lookup(original_id))
                .map(ResolvedRef::Handle)
                .unwrap_or(ResolvedRef::Unresolved(
                    crate::model::WireRef::SenderScoped {
                        sender: key.sender,
                        message_id: original_id,
                    },
                ));
            let body_ref = self.render_to_arena(slot_index, true);
            let kind = if body_ref.len == 0 {
                MutationKind::Delete { original }
            } else {
                MutationKind::Edit {
                    original,
                    body: body_ref,
                }
            };
            self.emit_mutation(handle, kind);
            self.pool.close_slot(slot_index);
            return;
        }
        if is_edit {
            // Fragmented edit still incomplete: not displayed until whole.
            return;
        }

        let status = if complete {
            CompletionStatus::Complete
        } else {
            CompletionStatus::Partial {
                present,
                count,
                finalized: false,
            }
        };
        let body_ref = self.render_to_arena(slot_index, complete);

        if !announced {
            let slot = self.pool.slots[slot_index].as_mut().expect("occupied");
            slot.announced = true;
            let meta = slot.meta;
            let message_type = meta.message_type();
            let sender_handle = content
                .sender_handle
                .and_then(|text| self.arena_store(text));
            let regarding = meta
                .regarding
                .map(|r| self.resolved_from_wire(key.conversation, Some(key.sender), r));
            self.emit_mutation(
                handle,
                MutationKind::Insert {
                    conversation: envelope.conversation,
                    sender: envelope.sender,
                    direction: Direction::Inbound,
                    message_type,
                    wire_id: Some(id),
                    epoch: self.inbound.get(&key).map(|s| s.epoch).unwrap_or(0),
                    client_token: None,
                    sender_handle,
                    regarding,
                    bg_color: content.bg_color,
                    text_color: content.text_color,
                    body: body_ref,
                    status,
                },
            );
            if let Some(stream) = self.inbound.get_mut(&key) {
                stream.refs.record(id, handle);
            }
        } else {
            self.emit_mutation(
                handle,
                MutationKind::UpdateBody {
                    body: body_ref,
                    status,
                },
            );
        }

        if complete {
            self.pool.close_slot(slot_index);
            let was_repairing = self.inbound.get_mut(&key).is_some_and(|stream| {
                let repairing = stream
                    .pending
                    .iter()
                    .any(|pending| pending.message_id == id && pending.attempts > 0);
                stream.cancel_pending(id, None);
                repairing
            });
            if was_repairing {
                self.push_output(Output::Event(Event::RepairFinished {
                    conversation: key.conversation,
                    sender: key.sender,
                    message_id: id,
                    outcome: RepairOutcome::Repaired,
                }));
            }
        }
        let _ = now_ms;
    }

    fn insert_content(
        &mut self,
        envelope: &Envelope,
        content: &validate::ContentMessage<'_>,
        wire_id: Option<u8>,
        status: CompletionStatus,
        now_ms: u64,
    ) -> MessageHandle {
        let handle = self.alloc_handle();
        let body = core::str::from_utf8(content.body).unwrap_or("");
        let body_ref = self
            .arena_store(body)
            .unwrap_or(BodyRef { offset: 0, len: 0 });
        let sender_handle = content
            .sender_handle
            .and_then(|handle_text| self.arena_store(handle_text));
        let regarding = content
            .regarding
            .map(|r| self.resolved_from_wire(envelope.conversation, Some(envelope.sender), r));
        let epoch = self
            .inbound
            .get(&StreamKey {
                conversation: envelope.conversation,
                sender: envelope.sender,
            })
            .map(|stream| stream.epoch)
            .unwrap_or(0);
        self.emit_mutation(
            handle,
            MutationKind::Insert {
                conversation: envelope.conversation,
                sender: envelope.sender,
                direction: Direction::Inbound,
                message_type: content.message_type,
                wire_id,
                epoch,
                client_token: None,
                sender_handle,
                regarding,
                bg_color: content.bg_color,
                text_color: content.text_color,
                body: body_ref,
                status,
            },
        );
        let _ = now_ms;
        handle
    }

    // ------------------------------------------------------------------
    // Resend service
    // ------------------------------------------------------------------

    fn receive_resend_request(
        &mut self,
        envelope: &Envelope,
        sequence: MessageSequence,
        channel_group: bool,
        now_ms: u64,
    ) {
        // The requester must be an individually attributable peer.
        let SenderScope::Peer(requester) = envelope.sender else {
            self.push_output(Output::Diagnostic(Diagnostic::UnattributableResend));
            return;
        };
        // Select the archive stream from the arrival path and flag.
        let conversation = if channel_group {
            match envelope.conversation {
                ConversationKey::ChannelDirect { channel, .. } => {
                    ConversationKey::ChannelGroup { channel }
                }
                _ => {
                    self.push_output(Output::Diagnostic(Diagnostic::UnattributableResend));
                    return;
                }
            }
        } else {
            envelope.conversation
        };

        if self.coalesce.recently_answered(
            &conversation,
            &sequence,
            now_ms,
            self.config.coalesce_window_ms,
        ) {
            self.push_output(Output::Diagnostic(Diagnostic::CoalescedResend {
                message_id: sequence.message_id,
            }));
            return;
        }

        // The requested frame is still in flight on this node's own radio —
        // queued behind earlier frames or awaiting its delivery report. On a
        // slow serialized link the requester's patience can lapse before the
        // original arrives; answering now would duplicate the frame on air
        // and delay everything queued behind it. A genuinely lost frame
        // leaves `in_flight` with its failure report, after which requests
        // are served normally. Only meaningful on platforms that report
        // transport progress; without reports, emission tells us nothing
        // about whether the frame is still queued.
        let requested_fragment = sequence.fragment.map(|fragment| fragment.index);
        if self.saw_transmit_report
            && self.in_flight.iter().any(|frame| {
                frame.archive.is_some_and(|archive| {
                    archive.conversation == conversation
                        && archive.message_id == sequence.message_id
                        && archive.fragment == requested_fragment
                })
            })
        {
            self.push_output(Output::Diagnostic(Diagnostic::CoalescedResend {
                message_id: sequence.message_id,
            }));
            return;
        }

        // A lookup for the same frame is already outstanding: one response
        // will serve both requesters.
        if self
            .lookups
            .iter()
            .any(|lookup| lookup.conversation == conversation && lookup.sequence == sequence)
        {
            self.push_output(Output::Diagnostic(Diagnostic::CoalescedResend {
                message_id: sequence.message_id,
            }));
            return;
        }

        let request_id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1);
        if self.lookups.is_full() {
            self.lookups.remove(0);
        }
        let _ = self.lookups.push(PendingLookup {
            request_id,
            conversation,
            requester,
            sequence,
        });
        self.push_output(Output::LookupOutbound {
            request_id,
            conversation,
            sequence,
        });
    }

    fn receive_unavailable(&mut self, envelope: &Envelope, sequence: MessageSequence, now_ms: u64) {
        let key = StreamKey {
            conversation: envelope.conversation,
            sender: envelope.sender,
        };
        let id = sequence.message_id;
        let fragment = sequence.fragment.map(|fragment| fragment.index);

        if let Some(stream) = self.inbound.get_mut(&key) {
            stream.cancel_pending(id, fragment);
            // The position is accounted for; it no longer counts as a gap.
            stream.seen.insert(id);
            stream.last_active_ms = now_ms;
        }

        let epoch = self
            .inbound
            .get(&key)
            .map(|stream| stream.epoch)
            .unwrap_or(0);
        if let Some(slot_index) = self.pool.find_slot(&key, epoch, id) {
            match fragment {
                Some(index) => {
                    let slot = self.pool.slots[slot_index].as_mut().expect("occupied");
                    let bit = 1u16 << index;
                    if slot.present & bit == 0 {
                        slot.unavailable |= bit;
                    }
                    let settled = {
                        let slot = self.pool.slots[slot_index].as_ref().expect("occupied");
                        slot.is_settled()
                    };
                    if settled {
                        self.finalize_slot(slot_index, now_ms, RepairOutcome::Unavailable, false);
                    } else if self.pool.slots[slot_index]
                        .as_ref()
                        .is_some_and(|slot| slot.announced)
                    {
                        let body = self.render_to_arena(slot_index, false);
                        let slot = self.pool.slots[slot_index].as_ref().expect("occupied");
                        let status = CompletionStatus::Partial {
                            present: slot.present,
                            count: slot.count,
                            finalized: false,
                        };
                        let handle = slot.handle;
                        self.emit_mutation(handle, MutationKind::UpdateBody { body, status });
                    }
                }
                None => {
                    self.finalize_slot(slot_index, now_ms, RepairOutcome::Unavailable, false);
                }
            }
        }

        self.push_output(Output::Event(Event::MessageUnavailable {
            conversation: envelope.conversation,
            sender: envelope.sender,
            message_id: id,
            fragment,
        }));
    }

    // ------------------------------------------------------------------
    // Timers
    // ------------------------------------------------------------------

    fn expire_slots(&mut self, now_ms: u64) {
        for index in 0..SLOTS {
            let expired = self.pool.slots[index]
                .as_ref()
                .is_some_and(|slot| now_ms >= slot.deadline_ms);
            if expired {
                self.finalize_slot(index, now_ms, RepairOutcome::Expired, true);
            }
        }
    }

    /// Queue repair entries for missing fragments of stalled assemblies.
    fn schedule_fragment_repairs(&mut self, now_ms: u64) {
        for index in 0..SLOTS {
            let Some(slot) = self.pool.slots[index].as_ref() else {
                continue;
            };
            if now_ms < slot.repair_at_ms || slot.is_settled() {
                continue;
            }
            let key = slot.stream;
            let id = slot.message_id;
            if let Some(stream) = self.inbound.get_mut(&key) {
                if stream.collided {
                    continue;
                }
                // A fragmented message advances through missing fragments
                // serially. Do not queue an entire missing bitmap at once:
                // one request receives its full retry budget before repair
                // moves to the next fragment.
                if stream
                    .pending
                    .iter()
                    .any(|pending| pending.message_id == id)
                {
                    continue;
                }
                let next = self.pool.slots[index]
                    .as_ref()
                    .and_then(|slot| slot.repairable_missing().next());
                if let Some(fragment) = next {
                    let _ = stream.pending.push(PendingRepair {
                        message_id: id,
                        fragment: Some(fragment),
                        deadline_ms: now_ms,
                        attempts: 0,
                    });
                    if let Some(slot) = self.pool.slots[index].as_mut() {
                        slot.repair_at_ms = now_ms + self.config.request_retry_ms;
                    }
                }
            }
        }
    }

    fn transmit_due_repairs(&mut self, now_ms: u64) {
        let mut budget = self.config.max_requests_per_tick;
        let keys: heapless::Vec<StreamKey, 16> = self.inbound.keys().copied().collect();
        for key in keys {
            if budget == 0 {
                break;
            }
            let Some(stream) = self.inbound.get(&key) else {
                continue;
            };
            if stream.collided
                || now_ms.saturating_sub(stream.last_request_ms)
                    < self.config.min_request_interval_ms
            {
                continue;
            }
            let Some(position) = stream
                .pending
                .iter()
                .position(|pending| now_ms >= pending.deadline_ms)
            else {
                continue;
            };
            let pending = stream.pending[position];

            // Resolve the request destination.
            let destination = match key.conversation {
                ConversationKey::Direct { peer } => Destination::Peer(peer),
                ConversationKey::Room { room } => Destination::Peer(room),
                ConversationKey::ChannelDirect { channel, peer } => {
                    Destination::ChannelPeer { channel, peer }
                }
                ConversationKey::ChannelGroup { channel } => match stream.sender_key {
                    Some(peer) => Destination::ChannelPeer { channel, peer },
                    None => {
                        // Unaddressable: give up on this frame; expiry will
                        // finalize any partial render.
                        let stream = self.inbound.get_mut(&key).expect("present");
                        stream.pending.remove(position);
                        self.push_output(Output::Event(Event::RepairFinished {
                            conversation: key.conversation,
                            sender: key.sender,
                            message_id: pending.message_id,
                            outcome: RepairOutcome::Unaddressable,
                        }));
                        continue;
                    }
                },
            };
            let channel_group = matches!(key.conversation, ConversationKey::ChannelGroup { .. });

            // A fragment request needs the slot's fragment count.
            let sequence = match pending.fragment {
                None => MessageSequence::unfragmented(pending.message_id),
                Some(index) => {
                    let epoch = stream.epoch;
                    let count = self
                        .pool
                        .find_slot(&key, epoch, pending.message_id)
                        .and_then(|slot| self.pool.slots[slot].as_ref())
                        .map(|slot| slot.count);
                    let Some(count) = count else {
                        let stream = self.inbound.get_mut(&key).expect("present");
                        stream.pending.remove(position);
                        continue;
                    };
                    MessageSequence {
                        message_id: pending.message_id,
                        fragment: Some(Fragment { index, count }),
                    }
                }
            };

            let request = TextMessage {
                message_type: MessageType::ResendRequest,
                sequence: Some(sequence),
                channel_group_resend: channel_group,
                ..TextMessage::basic("")
            };
            let mut buffer = [0u8; MAX_FRAME];
            let Ok(len) = codec::encode(&request, &mut buffer) else {
                continue;
            };
            let mut frame = heapless::Vec::new();
            let _ = frame.extend_from_slice(&buffer[..len]);
            self.queue_transmit(destination, None, frame, None);
            budget -= 1;

            if pending.attempts == 0 {
                self.push_output(Output::Event(Event::RepairStarted {
                    conversation: key.conversation,
                    sender: key.sender,
                    message_id: pending.message_id,
                    fragment: pending.fragment,
                }));
            }

            let max_attempts = self.config.max_repair_attempts;
            let retry_ms = self.config.request_retry_ms;
            let stream = self.inbound.get_mut(&key).expect("present");
            stream.last_request_ms = now_ms;
            let entry = &mut stream.pending[position];
            entry.attempts += 1;
            if entry.attempts >= max_attempts {
                let message_id = entry.message_id;
                let fragment = entry.fragment;
                stream.pending.remove(position);
                if let Some(fragment) = fragment
                    && let Some(slot_index) = self.pool.find_slot(&key, stream.epoch, message_id)
                    && let Some(slot) = self.pool.slots[slot_index].as_mut()
                {
                    slot.repair_exhausted |= 1u16 << fragment;
                }
                self.push_output(Output::Event(Event::RepairFinished {
                    conversation: key.conversation,
                    sender: key.sender,
                    message_id,
                    outcome: RepairOutcome::Exhausted,
                }));
            } else {
                entry.deadline_ms = now_ms + retry_ms;
            }
        }
    }

    /// Finalize a slot: emit its final partial render (when displayable) and
    /// release its pages.
    fn finalize_slot(
        &mut self,
        slot_index: usize,
        now_ms: u64,
        outcome: RepairOutcome,
        evicted: bool,
    ) {
        let Some(slot) = self.pool.slots[slot_index].as_ref() else {
            return;
        };
        let key = slot.stream;
        let id = slot.message_id;
        let announced = slot.announced;
        let handle = slot.handle;
        let complete = slot.is_complete();

        if announced && !complete {
            let body = self.render_to_arena(slot_index, true);
            let slot = self.pool.slots[slot_index].as_ref().expect("occupied");
            let status = CompletionStatus::Partial {
                present: slot.present,
                count: slot.count,
                finalized: true,
            };
            self.emit_mutation(handle, MutationKind::UpdateBody { body, status });
        }
        self.pool.close_slot(slot_index);
        if evicted {
            self.push_output(Output::Diagnostic(Diagnostic::ReassemblyEvicted {
                message_id: id,
            }));
        }
        if let Some(stream) = self.inbound.get_mut(&key) {
            stream.cancel_pending(id, None);
            stream.last_active_ms = now_ms;
        }
        self.push_output(Output::Event(Event::RepairFinished {
            conversation: key.conversation,
            sender: key.sender,
            message_id: id,
            outcome,
        }));
    }

    // ------------------------------------------------------------------
    // Outbound encoding
    // ------------------------------------------------------------------

    fn encode_and_queue(
        &mut self,
        conversation: ConversationKey,
        handle: MessageHandle,
        template: &TextMessage<'_>,
        body: &[u8],
        message_id: u8,
    ) -> Result<(), ComposeError> {
        let destination = destination_for(&conversation);

        // Trial-encode with an empty body to learn the option overhead.
        let mut trial = *template;
        trial.body = &[];
        let mut buffer = [0u8; MAX_FRAME];
        let overhead = codec::encode(&trial, &mut buffer).map_err(ComposeError::Encode)?;
        let single_budget = MAX_FRAME.saturating_sub(overhead + 1);

        let Some(plan) =
            FragmentPlan::plan(body.len(), single_budget).map_err(|_| ComposeError::TooLarge)?
        else {
            let mut message = *template;
            message.body = body;
            let len = codec::encode(&message, &mut buffer).map_err(ComposeError::Encode)?;
            let mut frame = heapless::Vec::new();
            let _ = frame.extend_from_slice(&buffer[..len]);
            self.queue_transmit(
                destination,
                Some(ArchiveKey {
                    conversation,
                    message_id,
                    fragment: None,
                }),
                frame,
                Some((handle, None)),
            );
            return Ok(());
        };

        for index in 0..plan.count {
            let range = plan.range(index);
            let mut message = if index == 0 {
                *template
            } else {
                // Continuation fragments carry only sequence metadata.
                let mut continuation = TextMessage::basic("");
                continuation.sequence = template.sequence;
                continuation
            };
            message.sequence = Some(MessageSequence {
                message_id,
                fragment: Some(Fragment {
                    index,
                    count: plan.count,
                }),
            });
            message.body = &body[range];
            let len = codec::encode(&message, &mut buffer).map_err(ComposeError::Encode)?;
            if len > MAX_FRAME {
                return Err(ComposeError::TooLarge);
            }
            let mut frame = heapless::Vec::new();
            let _ = frame.extend_from_slice(&buffer[..len]);
            self.queue_transmit(
                destination,
                Some(ArchiveKey {
                    conversation,
                    message_id,
                    fragment: Some(index),
                }),
                frame,
                Some((handle, Some(index))),
            );
        }
        Ok(())
    }

    fn queue_transmit(
        &mut self,
        destination: Destination,
        archive: Option<ArchiveKey>,
        payload: heapless::Vec<u8, MAX_FRAME>,
        track: Option<(MessageHandle, Option<u8>)>,
    ) -> u32 {
        let transmission_id = self.next_transmission;
        self.next_transmission = self.next_transmission.wrapping_add(1);
        if let Some((handle, fragment)) = track {
            if self.in_flight.is_full() {
                self.in_flight.remove(0);
            }
            let _ = self.in_flight.push(InFlightFrame {
                transmission_id,
                handle,
                fragment,
                archive,
            });
        }
        self.push_output(Output::Transmit(Transmission {
            transmission_id,
            destination,
            archive,
            payload,
        }));
        transmission_id
    }

    // ------------------------------------------------------------------
    // Reference resolution
    // ------------------------------------------------------------------

    /// Build the wire Regarding form for a locally known message handle.
    fn wire_reference_for(
        &self,
        conversation: ConversationKey,
        handle: MessageHandle,
    ) -> Option<Regarding> {
        let multicast = conversation.uses_multicast_references();
        if let Some(stream) = self.outbound.get(&conversation)
            && let Some(id) = stream.refs.lookup_handle(handle)
        {
            return Some(if multicast {
                Regarding::Multicast {
                    message_id: id,
                    source_prefix: umsh_core::NodeHint([
                        self.local_key.0[0],
                        self.local_key.0[1],
                        self.local_key.0[2],
                    ]),
                }
            } else {
                Regarding::Unicast { message_id: id }
            });
        }
        for (key, stream) in self.inbound.iter() {
            if key.conversation != conversation {
                continue;
            }
            if let Some(id) = stream.refs.lookup_handle(handle) {
                return Some(if multicast {
                    let prefix = key.sender.hint()?;
                    Regarding::Multicast {
                        message_id: id,
                        source_prefix: prefix,
                    }
                } else {
                    Regarding::Unicast { message_id: id }
                });
            }
        }
        None
    }

    /// Resolve a received wire reference to a stable handle when unambiguous.
    fn resolved_from_wire(
        &self,
        conversation: ConversationKey,
        sender: Option<SenderScope>,
        regarding: Regarding,
    ) -> ResolvedRef {
        match regarding {
            Regarding::Multicast {
                message_id,
                source_prefix,
            } => {
                let local_prefix = umsh_core::NodeHint([
                    self.local_key.0[0],
                    self.local_key.0[1],
                    self.local_key.0[2],
                ]);
                if source_prefix == local_prefix
                    && let Some(handle) = self
                        .outbound
                        .get(&conversation)
                        .and_then(|stream| stream.refs.lookup(message_id))
                {
                    return ResolvedRef::Handle(handle);
                }
                let key = StreamKey {
                    conversation,
                    sender: SenderScope::ClaimedMember(source_prefix),
                };
                match self.inbound.get(&key) {
                    Some(stream) if !stream.collided => stream
                        .refs
                        .lookup(message_id)
                        .map(ResolvedRef::Handle)
                        .unwrap_or(ResolvedRef::Unresolved(
                            crate::model::WireRef::SenderScoped {
                                sender: SenderScope::ClaimedMember(source_prefix),
                                message_id,
                            },
                        )),
                    _ => ResolvedRef::Unresolved(crate::model::WireRef::SenderScoped {
                        sender: SenderScope::ClaimedMember(source_prefix),
                        message_id,
                    }),
                }
            }
            Regarding::Unicast { message_id } => {
                // In a one-to-one conversation the reference may target
                // either party's stream; resolve only when unambiguous.
                let inbound = sender.and_then(|sender| {
                    self.inbound
                        .get(&StreamKey {
                            conversation,
                            sender,
                        })
                        .and_then(|stream| stream.refs.lookup(message_id))
                });
                let outbound = self
                    .outbound
                    .get(&conversation)
                    .and_then(|stream| stream.refs.lookup(message_id));
                match (inbound, outbound) {
                    (Some(handle), None) | (None, Some(handle)) => ResolvedRef::Handle(handle),
                    _ => ResolvedRef::Unresolved(match sender {
                        Some(sender) => crate::model::WireRef::SenderScoped { sender, message_id },
                        None => crate::model::WireRef::RoomCanonical { message_id },
                    }),
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Infrastructure
    // ------------------------------------------------------------------

    fn ensure_outbound(&mut self, conversation: ConversationKey, now_ms: u64) {
        if self.outbound.contains_key(&conversation) {
            return;
        }
        if self.outbound.len() == self.outbound.capacity()
            && let Some(oldest) = self
                .outbound
                .iter()
                .min_by_key(|(_, stream)| stream.last_active_ms)
                .map(|(key, _)| *key)
        {
            // Demote the evicted stream's continuity to the cold stash so
            // reactivation resumes its sequence instead of resetting.
            if let Some(stream) = self.outbound.remove(&oldest)
                && !stream.announce_reset
            {
                self.stash_checkpoint(oldest, stream.next_id, stream.epoch);
            }
            self.push_output(Output::Diagnostic(Diagnostic::StreamEvicted));
        }
        let cold = self
            .cold_checkpoints
            .iter()
            .position(|(key, _, _)| *key == conversation);
        let stream = match cold {
            Some(position) => {
                let (_, next_id, epoch) = self.cold_checkpoints.remove(position);
                OutboundStream {
                    next_id,
                    epoch,
                    announce_reset: false,
                    refs: Default::default(),
                    last_active_ms: now_ms,
                }
            }
            None => OutboundStream::fresh(now_ms),
        };
        let _ = self.outbound.insert(conversation, stream);
    }

    /// Record `(next_id, epoch)` continuity for an inactive conversation,
    /// displacing the oldest entry when the stash is full.
    fn stash_checkpoint(&mut self, conversation: ConversationKey, next_id: u8, epoch: u16) {
        self.cold_checkpoints
            .retain(|(key, _, _)| *key != conversation);
        if self.cold_checkpoints.is_full() {
            self.cold_checkpoints.remove(0);
        }
        let _ = self.cold_checkpoints.push((conversation, next_id, epoch));
    }

    fn ensure_inbound(&mut self, key: StreamKey, now_ms: u64) {
        if self.inbound.contains_key(&key) {
            return;
        }
        if self.inbound.len() == self.inbound.capacity()
            && let Some(oldest) = self
                .inbound
                .iter()
                .min_by_key(|(_, stream)| stream.last_active_ms)
                .map(|(key, _)| *key)
        {
            self.pool.drop_stream(&oldest);
            self.inbound.remove(&oldest);
            self.push_output(Output::Diagnostic(Diagnostic::StreamEvicted));
        }
        let _ = self.inbound.insert(key, InboundStream::new(now_ms));
    }

    fn alloc_handle(&mut self) -> MessageHandle {
        let handle = MessageHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        handle
    }

    fn emit_mutation(&mut self, handle: MessageHandle, kind: MutationKind) {
        let revision = self.revision;
        self.revision = self.revision.wrapping_add(1);
        self.push_output(Output::StoreMessage(MessageMutation {
            handle,
            revision,
            kind,
        }));
    }

    fn push_output(&mut self, output: Output) {
        if self.outputs.push_back(output).is_err() {
            self.lost_outputs = self.lost_outputs.wrapping_add(1);
        }
    }

    fn arena_store(&mut self, text: &str) -> Option<BodyRef> {
        let bytes = text.as_bytes();
        if self.arena_used + bytes.len() > ARENA_SIZE || bytes.len() > u16::MAX as usize {
            self.push_output(Output::Diagnostic(Diagnostic::OutputOverflow));
            return None;
        }
        let offset = self.arena_used;
        self.arena[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.arena_used += bytes.len();
        Some(BodyRef {
            offset: offset as u16,
            len: bytes.len() as u16,
        })
    }

    /// Render a slot into the arena, returning the body reference.
    fn render_to_arena(&mut self, slot_index: usize, final_render: bool) -> BodyRef {
        let mut scratch = [0u8; REASSEMBLED_BODY_MAX + 64];
        let result = fragment::render_slot(
            &self.pool,
            slot_index,
            &self.config.sentinels,
            final_render,
            &mut scratch,
        );
        if result.complete && result.had_invalid {
            // The spec validates UTF-8 only once every fragment is present;
            // a complete body that fails is rendered lossily and reported.
            let message_id = self.pool.slots[slot_index]
                .as_ref()
                .expect("occupied")
                .message_id;
            self.push_output(Output::Diagnostic(Diagnostic::ReassembledInvalidUtf8 {
                message_id,
            }));
        }
        let text = core::str::from_utf8(&scratch[..result.len]).unwrap_or("");
        self.arena_store(text)
            .unwrap_or(BodyRef { offset: 0, len: 0 })
    }
}

/// Delivery mode of a conversation, used for original sends and for resend
/// responses (which return on the conversation's mode, not the request's
/// arrival path).
pub fn destination_for(conversation: &ConversationKey) -> Destination {
    match conversation {
        ConversationKey::Direct { peer } => Destination::Peer(*peer),
        ConversationKey::Room { room } => Destination::Peer(*room),
        ConversationKey::ChannelGroup { channel } => Destination::Channel(*channel),
        ConversationKey::ChannelDirect { channel, peer } => Destination::ChannelPeer {
            channel: *channel,
            peer: *peer,
        },
    }
}
