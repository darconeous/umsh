//! One commit: the text engine's outputs, in the order the store writes
//! them.

use alloc::string::String;
use alloc::vec::Vec;

use umsh_text::ConversationKey;
use umsh_text::chat::{self, ChatOutput, Mutation, PendingBatch};
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveKey, BodyRef, DeliveryState, Event, MAX_FRAME, Output, StreamCheckpoint,
};
use umsh_text::model::SenderScope;

use crate::ids::{ChatId, MessageId};
use crate::record::{BODY_MAX, LinkInfo, NAME_MAX, clip};

/// The steps of a commit, in the order a store takes them. Power lost
/// after any of them leaves the store safe:
///
/// | Lost after | Effect |
/// |---|---|
/// | [`Checkpoint`](Self::Checkpoint) | one wire ID goes unused; a resend request for it is answered Message Unavailable |
/// | [`ArchiveDeletes`](Self::ArchiveDeletes) | an edited original no longer resends: it is answered Unavailable, never with superseded content |
/// | [`Archives`](Self::Archives) | resend material for a message neither sent nor shown |
/// | [`Transcript`](Self::Transcript) | complete: the transmissions are released |
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitStep {
    Checkpoint,
    ArchiveDeletes,
    Archives,
    Transcript,
}

impl CommitStep {
    pub const ALL: [Self; 4] = [
        Self::Checkpoint,
        Self::ArchiveDeletes,
        Self::Archives,
        Self::Transcript,
    ];
}

/// A transcript change, as a store reads it out of a [`Batch`].
#[derive(Clone, Copy, Debug)]
pub enum Change<'b> {
    /// One of the engine's transcript mutations, its body and Sender
    /// Handle already cut to what the store keeps.
    Message {
        mutation: &'b Mutation,
        /// What the radio said about the frame behind it, for a mutation
        /// a received frame produced.
        link: Option<LinkInfo>,
    },
    /// Word on one fragment of an outbound message.
    Delivery {
        handle: MessageHandle,
        fragment: Option<u8>,
        state: DeliveryState,
    },
    /// That an outbound message goes under a session with forward
    /// secrecy, or never does.
    Secrecy {
        message: Subject,
        forward_secret: bool,
    },
}

/// The message a change is to: one the engine knows by its handle, as one
/// composed in the same commit is, or one the store keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    Handle(MessageHandle),
    Kept(MessageId),
}

// Most entries are messages, so the mutation is kept inline rather than
// boxed for the sake of the rarer deliveries.
#[allow(clippy::large_enum_variant)]
enum Entry {
    Message {
        mutation: Mutation,
        link: Option<LinkInfo>,
    },
    Delivery {
        handle: MessageHandle,
        fragment: Option<u8>,
        state: DeliveryState,
    },
    Secrecy {
        message: Subject,
        forward_secret: bool,
    },
}

/// What one commit writes: the outbound checkpoints, then the archive
/// deletes, then the archives, then the transcript.
///
/// A batch is filled from what the chat facade drains, [`Batch::push_chat`]
/// taking each output in turn, or from the engine's own outputs through
/// [`Batch::push`]. It keeps its own copies—bodies out of the engine's
/// render arena, which is reused once the queue is empty, and payloads out
/// of the outputs—so it outlives both. What it borrows is the caller's map
/// from the engine's message handles to the store's message IDs, for
/// mutations of messages kept by an earlier commit.
pub struct Batch<'a> {
    time: Option<u32>,
    handles: &'a dyn Fn(MessageHandle) -> Option<MessageId>,
    checkpoints: Vec<StreamCheckpoint>,
    archive_deletes: Vec<(ConversationKey, u8)>,
    archives: Vec<(ArchiveKey, heapless::Vec<u8, MAX_FRAME>)>,
    entries: Vec<Entry>,
}

impl<'a> Batch<'a> {
    /// A batch whose messages are kept at `time`, in seconds of wall-clock
    /// time when it is known. `handles` maps the engine's handles to the
    /// store's IDs, as the [`Committed`] of earlier commits gave them.
    pub fn new(time: Option<u32>, handles: &'a dyn Fn(MessageHandle) -> Option<MessageId>) -> Self {
        Self {
            time,
            handles,
            checkpoints: Vec::new(),
            archive_deletes: Vec::new(),
            archives: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Take one drained output. `body` resolves the output's body
    /// references, which is [`Engine::body`] while the output is fresh,
    /// and `link` is what the radio said about the frame that produced it,
    /// if a frame did. Returns whether the output was the store's.
    ///
    /// A transmission's payload is kept for resending when it carries an
    /// archive key; the transmission itself is the caller's to hold until
    /// the batch is committed.
    ///
    /// [`Engine::body`]: umsh_text::engine::Engine::body
    pub fn push<'e>(
        &mut self,
        output: &Output,
        body: impl Fn(&BodyRef) -> &'e str,
        link: Option<LinkInfo>,
    ) -> bool {
        match output {
            Output::StoreCheckpoint {
                conversation,
                next_id,
                epoch,
            } => self.checkpoint(StreamCheckpoint {
                conversation: *conversation,
                next_id: *next_id,
                epoch: *epoch,
            }),
            Output::DeleteArchive {
                conversation,
                message_id,
            } => self.archive_deletes.push((*conversation, *message_id)),
            Output::StoreArchive { key, payload } => self.archives.push((*key, payload.clone())),
            Output::Transmit(transmission) => {
                let Some(key) = transmission.archive else {
                    return false;
                };
                self.archives.push((key, transmission.payload.clone()));
            }
            Output::StoreMessage(mutation) => {
                let mutation = Mutation::from_engine(*mutation, body, |_, sender| match sender {
                    SenderScope::Peer(key) => Some(key),
                    SenderScope::Local | SenderScope::ClaimedMember(_) => None,
                });
                self.message(mutation, link);
            }
            Output::Event(Event::DeliveryStateChanged {
                handle,
                fragment,
                state,
            }) => self.delivery(*handle, *fragment, *state),
            Output::Event(_) | Output::LookupOutbound { .. } | Output::Diagnostic(_) => {
                return false;
            }
        }
        true
    }

    /// Take one output the chat facade drained. `link` is what the radio
    /// said about the frame that produced it, for an output that
    /// [describes its receipt](Mutation::describes_receipt). Returns whether
    /// the output was the store's.
    pub fn push_chat(&mut self, output: &ChatOutput, link: Option<LinkInfo>) -> bool {
        match output {
            ChatOutput::Mutation(mutation) => {
                let link = link.filter(|_| mutation.describes_receipt());
                self.message(mutation.clone(), link);
            }
            ChatOutput::Delivery(delivery) => {
                self.delivery(delivery.handle, delivery.fragment, delivery.state);
            }
            ChatOutput::StoreArchive(archive) => {
                let Ok(payload) = heapless::Vec::from_slice(&archive.payload) else {
                    return false;
                };
                self.archives.push((archive.key, payload));
            }
            ChatOutput::DeleteArchive(delete) => {
                self.archive_deletes
                    .push((delete.conversation, delete.message_id));
            }
            ChatOutput::Lookup(_)
            | ChatOutput::SenderResolved(_)
            | ChatOutput::Repeats(_)
            | ChatOutput::Event(_)
            | ChatOutput::Diagnostic(_) => return false,
        }
        true
    }

    /// Take a composed message: its checkpoint, archive deletes, archives,
    /// and transcript, and the deliveries among the rest of what composing
    /// it produced. Its frames are the facade's to release once the batch
    /// is committed.
    pub fn push_composed(&mut self, composed: &PendingBatch) {
        self.checkpoint(composed.checkpoint);
        for delete in &composed.archive_deletes {
            self.archive_deletes
                .push((delete.conversation, delete.message_id));
        }
        for archive in &composed.archives {
            if let Ok(payload) = heapless::Vec::from_slice(&archive.payload) {
                self.archives.push((archive.key, payload));
            }
        }
        for mutation in &composed.mutations {
            self.message(mutation.clone(), None);
        }
        for output in &composed.outputs {
            if let ChatOutput::Delivery(delivery) = output {
                self.delivery(delivery.handle, delivery.fragment, delivery.state);
            }
        }
    }

    fn checkpoint(&mut self, checkpoint: StreamCheckpoint) {
        match self
            .checkpoints
            .iter_mut()
            .find(|kept| kept.conversation == checkpoint.conversation)
        {
            Some(kept) => *kept = checkpoint,
            None => self.checkpoints.push(checkpoint),
        }
    }

    fn message(&mut self, mut mutation: Mutation, link: Option<LinkInfo>) {
        match &mut mutation.change {
            chat::Change::Insert(insert) => {
                cut(&mut insert.body, BODY_MAX);
                if let Some(handle) = &mut insert.sender_handle {
                    cut(handle, NAME_MAX);
                }
            }
            chat::Change::UpdateBody { body, .. } | chat::Change::Edit { body, .. } => {
                cut(body, BODY_MAX);
            }
            chat::Change::Delete { .. } => {}
        }
        self.entries.push(Entry::Message { mutation, link });
    }

    /// Take that the outbound message `message` goes under a session with
    /// forward secrecy, or never does.
    pub fn secrecy(&mut self, message: Subject, forward_secret: bool) {
        self.entries.push(Entry::Secrecy {
            message,
            forward_secret,
        });
    }

    fn delivery(&mut self, handle: MessageHandle, fragment: Option<u8>, state: DeliveryState) {
        self.entries.push(Entry::Delivery {
            handle,
            fragment,
            state,
        });
    }

    /// When the batch's messages were kept.
    pub fn time(&self) -> Option<u32> {
        self.time
    }

    /// The store's ID for a message an earlier commit kept, by the
    /// engine's handle for it.
    pub fn resolve(&self, handle: MessageHandle) -> Option<MessageId> {
        (self.handles)(handle)
    }

    pub fn checkpoints(&self) -> &[StreamCheckpoint] {
        &self.checkpoints
    }

    /// Message IDs whose archived fragments are all to go.
    pub fn archive_deletes(&self) -> &[(ConversationKey, u8)] {
        &self.archive_deletes
    }

    pub fn archives(&self) -> impl Iterator<Item = (&ArchiveKey, &[u8])> + '_ {
        self.archives
            .iter()
            .map(|(key, payload)| (key, payload.as_slice()))
    }

    pub fn changes(&self) -> impl Iterator<Item = Change<'_>> + '_ {
        self.entries.iter().map(|entry| match entry {
            Entry::Message { mutation, link } => Change::Message {
                mutation,
                link: *link,
            },
            Entry::Delivery {
                handle,
                fragment,
                state,
            } => Change::Delivery {
                handle: *handle,
                fragment: *fragment,
                state: *state,
            },
            Entry::Secrecy {
                message,
                forward_secret,
            } => Change::Secrecy {
                message: *message,
                forward_secret: *forward_secret,
            },
        })
    }

    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
            && self.archive_deletes.is_empty()
            && self.archives.is_empty()
            && self.entries.is_empty()
    }
}

/// What a commit did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Committed {
    /// The IDs given to messages the batch inserted, by the engine's
    /// handles for them.
    pub inserted: Vec<(MessageHandle, MessageId)>,
    /// Messages inserted or changed, in the order first touched.
    pub messages: Vec<MessageId>,
    /// Chats made or changed, in the order first touched.
    pub chats: Vec<ChatId>,
}

impl Committed {
    pub(crate) fn touch_message(&mut self, id: MessageId) {
        if !self.messages.contains(&id) {
            self.messages.push(id);
        }
    }

    pub(crate) fn touch_chat(&mut self, id: ChatId) {
        if !self.chats.contains(&id) {
            self.chats.push(id);
        }
    }

    /// The ID this commit gave the message `handle` names.
    pub fn id_of(&self, handle: MessageHandle) -> Option<MessageId> {
        self.inserted
            .iter()
            .find(|(inserted, _)| *inserted == handle)
            .map(|(_, id)| *id)
    }
}

/// Cuts `text` to at most `max` bytes, between grapheme clusters.
fn cut(text: &mut String, max: usize) {
    let len = clip(text, max).len();
    text.truncate(len);
}
