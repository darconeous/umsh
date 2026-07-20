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
    ArchiveKey, CompletionStatus, ComposeIntent, DeliveryState, Destination, Direction, Engine,
    EngineConfig, Event, MessageMutation, MutationKind, Output, ResolvedRef, StreamCheckpoint,
    Transmission,
};
use umsh_text::model::{ConversationKey, SenderScope};
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
    pub body: Option<String>,
    pub complete: Option<bool>,
    pub present_fragments: Option<u16>,
    pub fragment_count: Option<u8>,
    pub finalized: Option<bool>,
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
        self.engine
            .compose(
                ConversationKey::Direct { peer },
                client_token,
                ComposeIntent::Text {
                    body,
                    status: false,
                },
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
            MutationKind::Edit { original, body } => {
                record.kind = MobileChatMutationKind::Edit;
                record.original_handle = resolved_handle(original);
                record.body = Some(self.engine.body(&body).to_owned());
            }
            MutationKind::Delete { original } => {
                record.kind = MobileChatMutationKind::Delete;
                record.original_handle = resolved_handle(original);
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
