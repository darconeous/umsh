//! Owned mobile facade records for the sans-I/O text engine.
//!
//! This first mobile surface intentionally supports direct conversations only.
//! Channel and room profiles must be exported as typed destinations rather
//! than falling through or requiring Swift to interpret wire options.

use std::collections::BTreeMap;

use rand::Rng;
use umsh_core::PublicKey;
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveKey, CompletionStatus, ComposeIntent, ComposeRef, DeliveryState, Destination,
    Direction, Engine, EngineConfig, Event, MessageMutation, MutationKind, Output, ResolvedRef,
    StreamCheckpoint, Transmission,
};
use umsh_text::model::{ConversationKey, SenderScope, WireRef};
use umsh_text::validate::DirectChannelProfile;

pub(crate) type ChatEngine = Engine<DirectChannelProfile>;

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatCheckpointRecord {
    pub peer_address: String,
    pub next_id: u8,
    pub epoch: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatArchiveRecord {
    pub peer_address: String,
    pub message_id: u8,
    pub fragment_index: Option<u8>,
    pub payload: Vec<u8>,
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

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatMutationRecord {
    /// A facade-session namespace prevents the engine's process-local u32
    /// handles from colliding after restart.
    pub session_id: u64,
    pub handle: u32,
    pub revision: u32,
    pub kind: MobileChatMutationKind,
    pub peer_address: Option<String>,
    pub sender_address: Option<String>,
    pub direction: Option<MobileChatDirection>,
    pub message_type: Option<u8>,
    pub wire_id: Option<u8>,
    pub epoch: Option<u16>,
    pub client_token: Option<u32>,
    pub sender_handle: Option<String>,
    pub regarding_handle: Option<u32>,
    pub background_color: Option<Vec<u8>>,
    pub text_color: Option<Vec<u8>>,
    pub original_handle: Option<u32>,
    /// When an edit/delete references a message the engine no longer holds a
    /// live handle for (composed before a restart), these export the wire
    /// reference so the platform can resolve it against persisted rows:
    /// the original's wire ID within `original_direction`'s stream of the
    /// record's `peer_address` conversation.
    pub original_wire_id: Option<u8>,
    pub original_direction: Option<MobileChatDirection>,
    pub body: Option<String>,
    pub complete: Option<bool>,
    pub present_fragments: Option<u16>,
    pub fragment_count: Option<u8>,
    pub finalized: Option<bool>,
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
    pub peer_address: String,
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
    pub archives: Vec<MobileChatArchiveRecord>,
    pub mutations: Vec<MobileChatMutationRecord>,
    pub deliveries: Vec<MobileChatDeliveryRecord>,
    pub lookups: Vec<MobileChatArchiveLookupRecord>,
    pub diagnostics: Vec<String>,
}

impl ChatDrain {
    fn new() -> Self {
        Self {
            checkpoint: None,
            transmissions: Vec::new(),
            archives: Vec::new(),
            mutations: Vec::new(),
            deliveries: Vec::new(),
            lookups: Vec::new(),
            diagnostics: Vec::new(),
        }
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
}

impl MobileChatState {
    pub fn new(local_key: PublicKey) -> Self {
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
        }
    }

    pub fn restore(&mut self, checkpoints: &[MobileChatCheckpointRecord], now_ms: u64) {
        let checkpoints = checkpoints
            .iter()
            .filter_map(checkpoint_from_record)
            .collect::<Vec<_>>();
        self.engine.restore(&checkpoints, now_ms);
        let _ = self.drain();
    }

    pub fn compose_text(
        &mut self,
        peer: PublicKey,
        client_token: u32,
        body: &str,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        self.compose_batch(
            peer,
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
        peer: PublicKey,
        client_token: u32,
        original: &MobileChatOriginalRef,
        body: &str,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        let original = self.compose_ref(original).ok_or(())?;
        self.compose_batch(
            peer,
            client_token,
            ComposeIntent::Edit { original, body },
            now_ms,
        )
    }

    pub fn compose_delete(
        &mut self,
        peer: PublicKey,
        client_token: u32,
        original: &MobileChatOriginalRef,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        let original = self.compose_ref(original).ok_or(())?;
        self.compose_batch(
            peer,
            client_token,
            ComposeIntent::Delete { original },
            now_ms,
        )
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
        peer: PublicKey,
        client_token: u32,
        intent: ComposeIntent<'_>,
        now_ms: u64,
    ) -> Result<ComposedChatBatch, ()> {
        self.engine
            .compose(
                ConversationKey::Direct { peer },
                client_token,
                intent,
                now_ms,
            )
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
                            archive_record(archive, transmission.payload.as_slice())
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
                    drained.checkpoint = checkpoint_record(conversation, next_id, epoch);
                }
                Output::LookupOutbound {
                    request_id,
                    conversation,
                    sequence,
                } => {
                    if let Some(peer_address) = direct_peer_address(conversation) {
                        drained.lookups.push(MobileChatArchiveLookupRecord {
                            request_id,
                            peer_address,
                            message_id: sequence.message_id,
                            fragment_index: sequence.fragment.map(|fragment| fragment.index),
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
            peer_address: None,
            sender_address: None,
            direction: None,
            message_type: None,
            wire_id: None,
            epoch: None,
            client_token: None,
            sender_handle: None,
            regarding_handle: None,
            background_color: None,
            text_color: None,
            original_handle: None,
            original_wire_id: None,
            original_direction: None,
            body: None,
            complete: None,
            present_fragments: None,
            fragment_count: None,
            finalized: None,
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
            } => {
                record.peer_address = direct_peer_address(conversation);
                record.sender_address = sender_address(sender);
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
                record.regarding_handle = regarding.and_then(resolved_handle);
                record.background_color = bg_color.map(|color| color.to_vec());
                record.text_color = text_color.map(|color| color.to_vec());
                record.body = Some(self.engine.body(&body).to_owned());
                apply_completion(&mut record, status);
            }
            MutationKind::UpdateBody { body, status } => {
                record.kind = MobileChatMutationKind::UpdateBody;
                record.body = Some(self.engine.body(&body).to_owned());
                apply_completion(&mut record, status);
            }
            MutationKind::Edit {
                conversation,
                original,
                body,
            } => {
                record.kind = MobileChatMutationKind::Edit;
                record.peer_address = direct_peer_address(conversation);
                apply_original(&mut record, original);
                record.body = Some(self.engine.body(&body).to_owned());
            }
            MutationKind::Delete {
                conversation,
                original,
            } => {
                record.kind = MobileChatMutationKind::Delete;
                record.peer_address = direct_peer_address(conversation);
                apply_original(&mut record, original);
            }
        }
        Some(record)
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

fn resolved_handle(reference: ResolvedRef) -> Option<u32> {
    match reference {
        ResolvedRef::Handle(MessageHandle(handle)) => Some(handle),
        ResolvedRef::Unresolved(_) => None,
    }
}

/// Export an edit/delete target: a live handle when resolved, otherwise the
/// wire reference for the platform to match against its persisted rows.
/// Room-scoped reference forms are outside the direct-conversation facade.
fn apply_original(record: &mut MobileChatMutationRecord, reference: ResolvedRef) {
    match reference {
        ResolvedRef::Handle(MessageHandle(handle)) => {
            record.original_handle = Some(handle);
        }
        ResolvedRef::Unresolved(WireRef::SenderScoped { sender, message_id }) => {
            let direction = match sender {
                SenderScope::Local => Some(MobileChatDirection::Outbound),
                SenderScope::Peer(_) => Some(MobileChatDirection::Inbound),
                SenderScope::ClaimedMember(_) => None,
            };
            if let Some(direction) = direction {
                record.original_wire_id = Some(message_id);
                record.original_direction = Some(direction);
            }
        }
        ResolvedRef::Unresolved(WireRef::RoomCanonical { .. }) => {}
    }
}

fn sender_address(sender: SenderScope) -> Option<String> {
    match sender {
        SenderScope::Peer(peer) => Some(address(peer)),
        SenderScope::Local | SenderScope::ClaimedMember(_) => None,
    }
}

fn checkpoint_record(
    conversation: ConversationKey,
    next_id: u8,
    epoch: u16,
) -> Option<MobileChatCheckpointRecord> {
    Some(MobileChatCheckpointRecord {
        peer_address: direct_peer_address(conversation)?,
        next_id,
        epoch,
    })
}

fn checkpoint_from_record(record: &MobileChatCheckpointRecord) -> Option<StreamCheckpoint> {
    let peer = decode_address(&record.peer_address)?;
    Some(StreamCheckpoint {
        conversation: ConversationKey::Direct { peer },
        next_id: record.next_id,
        epoch: record.epoch,
    })
}

fn archive_record(key: ArchiveKey, payload: &[u8]) -> Option<MobileChatArchiveRecord> {
    Some(MobileChatArchiveRecord {
        peer_address: direct_peer_address(key.conversation)?,
        message_id: key.message_id,
        fragment_index: key.fragment,
        payload: payload.to_vec(),
    })
}

fn direct_peer_address(conversation: ConversationKey) -> Option<String> {
    match conversation {
        ConversationKey::Direct { peer } => Some(address(peer)),
        _ => None,
    }
}

pub(crate) fn transmission_peer(transmission: &Transmission) -> Option<PublicKey> {
    match transmission.destination {
        Destination::Peer(peer) => Some(peer),
        _ => None,
    }
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

    /// The full restart round trip at the facade level: the persisted
    /// (wire_id, epoch) of a message composed by one facade session lets a
    /// fresh session — restored from the persisted checkpoint — compose an
    /// edit whose mutation record exports a platform-resolvable reference.
    #[test]
    fn edit_by_persisted_reference_after_facade_restart() {
        let mut first = MobileChatState::new(LOCAL);
        let composed = first
            .compose_text(PEER, 7, "v1", 0)
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

        let mut restarted = MobileChatState::new(LOCAL);
        assert_ne!(
            restarted.session_id, first.session_id,
            "sessions must not collide"
        );
        restarted.restore(std::slice::from_ref(&checkpoint), 0);
        let edited = restarted
            .compose_edit(PEER, 8, &original, "v2", 1)
            .expect("wire-referenced edit composes after restart");
        let edit = edited
            .record
            .mutations
            .iter()
            .find(|mutation| mutation.kind == MobileChatMutationKind::Edit)
            .expect("edit mutation");
        assert_eq!(edit.original_handle, None);
        assert_eq!(edit.original_wire_id, insert.wire_id);
        assert_eq!(
            edit.original_direction,
            Some(MobileChatDirection::Outbound)
        );
        assert_eq!(edit.peer_address, insert.peer_address);
        assert_eq!(edit.body.as_deref(), Some("v2"));

        // Without continuity (no restored checkpoint) the same reference is
        // rejected instead of silently starting a dangling edit.
        let mut cold = MobileChatState::new(LOCAL);
        assert!(cold.compose_delete(PEER, 9, &original, 0).is_err());
    }
}
