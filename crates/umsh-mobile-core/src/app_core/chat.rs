//! The core's chat commands: sending, resending and asking for missing
//! messages; drafts, reading and clearing; the `EMERGENCY` interlock; and
//! the phone's own share link.
//!
//! A command names a message by its stored reference. The core reads the
//! row in the conversation named, applies the rules for what may be done
//! to it, and builds the engine's reference from it, so no app restates
//! them.
//!
//! Each command writes the store first, raises the flags for what it
//! wrote and what the session stored, and runs every follow-up inside its
//! own job on the worker, so a caller that stops waiting still sees the
//! outcome through the changes.

use umsh_text::reaction::Reaction;

use super::bootstrap::CHANNEL_ADDRESS_PREFIX;
use super::pipeline::carries_this_phone;
use super::records::{MobileAppChangesRecord, MobileAppLifecycle};
use super::routes::checked_conversation_address;
use super::worker::{InFlight, Worker};
use super::{MobileAppCore, MobileAppError, mesh_error};
use crate::mobile_chat::{
    MobileChatDirection, MobileChatOriginalRef, MobileChatPresence, MobileChatRegardingRef,
};
use crate::mobile_mesh::{MobileChatSendError, MobileChatSendRequest};
use crate::radio_driver::MobileRadioStateRecord;
use crate::store::{
    MobileStoredChatDeliveryState, MobileStoredChatMessageRecord, MobileStoredChatMessageRefRecord,
};
use crate::{MobileMeshError, MobileWellKnownChannel, SecretVaultError};

/// How long a message of ours may be edited, or resent as itself, after it
/// was written. Peers keep a bounded window of recent wire IDs, and a
/// stream may have reset since; four hours is well inside what survives.
pub(super) const REVISE_WINDOW_MS: i64 = 4 * 60 * 60 * 1000;

/// A reaction: one of UMSH's emotes, or any other grapheme cluster.
#[derive(Clone, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MobileReaction {
    Heart,
    ThumbsUp,
    ThumbsDown,
    Laugh,
    Exclaim,
    Question,
    Other { cluster: String },
}

impl From<Reaction> for MobileReaction {
    fn from(reaction: Reaction) -> Self {
        match reaction {
            Reaction::Heart => Self::Heart,
            Reaction::ThumbsUp => Self::ThumbsUp,
            Reaction::ThumbsDown => Self::ThumbsDown,
            Reaction::Laugh => Self::Laugh,
            Reaction::Exclaim => Self::Exclaim,
            Reaction::Question => Self::Question,
            Reaction::Other(cluster) => Self::Other {
                cluster: cluster.as_str().to_owned(),
            },
        }
    }
}

/// What a reaction's body reads as: an emote for any of its spellings,
/// otherwise the body's first grapheme cluster, whole however long it is.
/// `None` for a body with nothing in it.
pub(super) fn reaction_from_body(body: &str) -> Option<MobileReaction> {
    match Reaction::from_body(body) {
        Some(reaction) => Some(reaction.into()),
        None => umsh_grapheme::first_cluster(body.trim()).map(|cluster| MobileReaction::Other {
            cluster: cluster.to_owned(),
        }),
    }
}

/// A reaction's body on the air: an emote's token, or the first cluster
/// of what was given, read as [`reaction_from_body`] reads it, so another
/// spelling of an emote goes as its token. `None` when there is nothing to
/// send.
pub(super) fn reaction_body(reaction: &MobileReaction) -> Option<String> {
    let emote = match reaction {
        MobileReaction::Heart => Reaction::Heart,
        MobileReaction::ThumbsUp => Reaction::ThumbsUp,
        MobileReaction::ThumbsDown => Reaction::ThumbsDown,
        MobileReaction::Laugh => Reaction::Laugh,
        MobileReaction::Exclaim => Reaction::Exclaim,
        MobileReaction::Question => Reaction::Question,
        MobileReaction::Other { cluster } => {
            return match reaction_from_body(cluster)? {
                MobileReaction::Other { cluster } => Some(cluster),
                emote => reaction_body(&emote),
            };
        }
    };
    Some(emote.body().to_owned())
}

/// What native code asks to send into a conversation. Text is trimmed;
/// empty text is `InvalidRequest` (a deletion is [`Self::Delete`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAppChatRequest {
    /// Text as the user typed it: a `/me ` prefix makes it status text. To
    /// a peer it goes under a session with forward secrecy, or never under
    /// one, as `forward_secret` says the composer showed it; without, under
    /// one only when one is held.
    Typed {
        text: String,
        forward_secret: Option<bool>,
    },
    /// A reply to either party's message, under forward secrecy as
    /// [`Self::Typed`] goes. Where the target can no longer be named, the
    /// text goes as a plain message.
    Reply {
        target: MobileStoredChatMessageRefRecord,
        text: String,
        forward_secret: Option<bool>,
    },
    /// New text for a message of ours, within its revise window.
    Edit {
        message: MobileStoredChatMessageRefRecord,
        text: String,
    },
    /// A message of ours taken back.
    Delete {
        message: MobileStoredChatMessageRefRecord,
    },
    /// A reaction to either party's message; `None` withdraws this
    /// phone's.
    React {
        message: MobileStoredChatMessageRefRecord,
        reaction: Option<MobileReaction>,
    },
}

impl MobileAppChatRequest {
    /// The request, its text trimmed, when it can be made at all.
    fn checked(self) -> Result<Self, MobileAppError> {
        let trimmed = |text: String| {
            let text = text.trim();
            if text.is_empty() {
                Err(MobileAppError::InvalidRequest)
            } else {
                Ok(text.to_owned())
            }
        };
        Ok(match self {
            Self::Typed {
                text,
                forward_secret,
            } => Self::Typed {
                text: trimmed(text)?,
                forward_secret,
            },
            Self::Reply {
                target,
                text,
                forward_secret,
            } => Self::Reply {
                target,
                text: trimmed(text)?,
                forward_secret,
            },
            Self::Edit { message, text } => Self::Edit {
                message,
                text: trimmed(text)?,
            },
            Self::React {
                message: _,
                reaction: Some(reaction),
            } if reaction_body(&reaction).is_none() => return Err(MobileAppError::InvalidRequest),
            request => request,
        })
    }

    /// Whether this request is what the composer submitted, whose text is
    /// the draft.
    fn is_composed(&self) -> bool {
        matches!(self, Self::Typed { .. } | Self::Reply { .. })
    }
}

/// How a resend went out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAppResent {
    /// As itself, under its own wire ID: the message is where it was.
    InPlace,
    /// As a new message, which replaced the failed one.
    AsNew,
}

/// Whether the radio is attached as this phone's: what every command that
/// transmits needs, so a composer blocks exactly when the core would
/// refuse.
#[uniffi::export]
pub fn radio_carries_this_phone(radio: Option<MobileRadioStateRecord>) -> bool {
    carries_this_phone(radio.as_ref())
}

fn transcript_changed(address: &str) -> MobileAppChangesRecord {
    MobileAppChangesRecord {
        conversations_changed: true,
        transcripts: vec![address.to_owned()],
        ..MobileAppChangesRecord::default()
    }
}

fn conversations_changed() -> MobileAppChangesRecord {
    MobileAppChangesRecord {
        conversations_changed: true,
        ..MobileAppChangesRecord::default()
    }
}

/// A message of ours that delivery gave up on, either way.
fn delivery_failed(row: &MobileStoredChatMessageRecord) -> bool {
    row.outbound
        && matches!(
            row.delivery_state,
            Some(
                MobileStoredChatDeliveryState::Failed | MobileStoredChatDeliveryState::Undelivered
            )
        )
}

/// The engine session a row names, when its session ID is a number. A row
/// written otherwise (a staged transcript names its session) goes as
/// session 0, which no engine session runs as, so only its wire fields can
/// name it.
fn engine_session(row: &MobileStoredChatMessageRecord) -> Option<u64> {
    row.reference.session_id.parse().ok()
}

/// The engine's reference to a message of ours, or `InvalidRequest` when
/// the row can name it neither by a live handle nor on the wire.
fn original_ref(
    row: &MobileStoredChatMessageRecord,
) -> Result<MobileChatOriginalRef, MobileAppError> {
    let session_id = engine_session(row);
    if session_id.is_none() && (row.wire_id.is_none() || row.epoch.is_none()) {
        return Err(MobileAppError::InvalidRequest);
    }
    Ok(MobileChatOriginalRef {
        session_id: session_id.unwrap_or(0),
        handle: row.reference.handle,
        wire_id: row.wire_id,
        epoch: row.epoch,
    })
}

/// The engine's reference to either party's message. Whether it names
/// anything is the engine's to decide.
fn regarding_ref(row: &MobileStoredChatMessageRecord) -> MobileChatRegardingRef {
    MobileChatRegardingRef {
        session_id: engine_session(row).unwrap_or(0),
        handle: row.reference.handle,
        wire_id: row.wire_id,
        direction: Some(if row.outbound {
            MobileChatDirection::Outbound
        } else {
            MobileChatDirection::Inbound
        }),
        sender_hint: row.sender_hint.clone(),
        epoch: row.epoch,
    }
}

/// A failed message claimed by the resend sending it again, released when
/// that resend ends however it ends.
struct ResendClaim<'a> {
    worker: &'a Worker,
    key: (String, MobileStoredChatMessageRefRecord),
}

impl<'a> ResendClaim<'a> {
    /// `None` while another resend holds the message.
    fn take(
        worker: &'a Worker,
        owner: &str,
        message: &MobileStoredChatMessageRefRecord,
    ) -> Option<Self> {
        let key = (owner.to_owned(), message.clone());
        let claimed = worker.resending.borrow_mut().insert(key.clone());
        claimed.then(|| Self { worker, key })
    }
}

impl Drop for ResendClaim<'_> {
    fn drop(&mut self) {
        self.worker.resending.borrow_mut().remove(&self.key);
    }
}

impl Worker {
    /// The owner, when a conversation is stored at `address` for it.
    fn chat_owner(&self, address: &str) -> Result<String, MobileAppError> {
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        if !self.store.conversation_stored(&owner, address)? {
            return Err(MobileAppError::NotFound);
        }
        Ok(owner)
    }

    /// Whether the conversation at `address` is `EMERGENCY`'s, by the
    /// stored channel's canonical name, the rule every app reads. Read from
    /// the store, so a locked vault does not hide it.
    fn is_emergency(&self, owner: &str, address: &str) -> Result<bool, MobileAppError> {
        if !address.starts_with(CHANNEL_ADDRESS_PREFIX) {
            return Ok(false);
        }
        let Some((_, channel_id)) = self.store.channel_conversation_by_address(owner, address)?
        else {
            return Ok(false);
        };
        let channel = self.store.channel_by_id(owner, &channel_id)?;
        Ok(channel
            .and_then(|channel| crate::well_known_channel(channel.canonical_name))
            .is_some_and(|known| known.channel == MobileWellKnownChannel::Emergency))
    }

    /// `EmergencyNotCertified` for a transmission the user starts on
    /// `EMERGENCY` before agreeing to its warning under this owner.
    pub(super) fn emergency_refusal(
        &self,
        owner: &str,
        address: &str,
    ) -> Result<(), MobileAppError> {
        if self.shared.snapshot().emergency_certified || !self.is_emergency(owner, address)? {
            return Ok(());
        }
        Err(MobileAppError::EmergencyNotCertified)
    }

    /// What `UnknownConversation` means for a conversation known to be
    /// stored: a channel whose key the vault has not handed over yet, or
    /// one the session no longer holds.
    fn unknown_conversation(&self, address: &str) -> MobileAppError {
        if address.starts_with(CHANNEL_ADDRESS_PREFIX) && self.channels.borrow().locked {
            MobileAppError::Vault {
                error: SecretVaultError::Unavailable,
            }
        } else {
            MobileAppError::NotFound
        }
    }

    fn chat_send_error(&self, address: &str, error: MobileChatSendError) -> MobileAppError {
        match error {
            MobileChatSendError::NotComposed {
                error: MobileMeshError::UnknownConversation,
            } => self.unknown_conversation(address),
            MobileChatSendError::NotComposed { error } => mesh_error(error),
            MobileChatSendError::NotSaved { error } => MobileAppError::Store { error },
            MobileChatSendError::NotSavedOrReset { error } => {
                log::error!(
                    error:? = error;
                    "a message was not kept, and the session stands ahead of the store until the next start"
                );
                MobileAppError::Store { error }
            }
            MobileChatSendError::NotQueued { .. } => {
                MobileAppError::MessageNotQueued { recorded: true }
            }
            MobileChatSendError::NotQueuedOrRecorded { .. } => {
                MobileAppError::MessageNotQueued { recorded: false }
            }
            MobileChatSendError::NoStore => MobileAppError::NotRunning,
        }
    }

    /// Whether a message written at `created_at_ms` may still be revised.
    fn within_revise_window(&self, created_at_ms: i64) -> bool {
        self.clock.now_ms() <= created_at_ms.saturating_add(REVISE_WINDOW_MS)
    }

    /// The stored row a request names, in this conversation.
    fn named_row(
        &self,
        owner: &str,
        address: &str,
        message: &MobileStoredChatMessageRefRecord,
    ) -> Result<MobileStoredChatMessageRecord, MobileAppError> {
        self.store
            .chat_message(owner, address, message)?
            .ok_or(MobileAppError::NotFound)
    }

    /// The session's request for what native code asked, by the rules for
    /// the row it names.
    fn compose_request(
        &self,
        owner: &str,
        address: &str,
        request: MobileAppChatRequest,
    ) -> Result<MobileChatSendRequest, MobileAppError> {
        Ok(match request {
            MobileAppChatRequest::Typed {
                text,
                forward_secret,
            } => MobileChatSendRequest::Typed {
                text,
                forward_secret,
            },
            // A reply goes whether or not its target can still be named:
            // with no row, as what was written.
            MobileAppChatRequest::Reply {
                target,
                text,
                forward_secret,
            } => match self.store.chat_message(owner, address, &target)? {
                Some(row) => MobileChatSendRequest::Reply {
                    target: regarding_ref(&row),
                    body: text,
                    forward_secret,
                },
                None => MobileChatSendRequest::Typed {
                    text,
                    forward_secret,
                },
            },
            MobileAppChatRequest::Edit { message, text } => {
                let row = self.named_row(owner, address, &message)?;
                if !row.outbound || row.is_deleted || !self.within_revise_window(row.created_at_ms)
                {
                    return Err(MobileAppError::InvalidRequest);
                }
                MobileChatSendRequest::Edit {
                    original: original_ref(&row)?,
                    body: text,
                }
            }
            MobileAppChatRequest::Delete { message } => {
                let row = self.named_row(owner, address, &message)?;
                if !row.outbound || row.is_deleted {
                    return Err(MobileAppError::InvalidRequest);
                }
                MobileChatSendRequest::Delete {
                    original: original_ref(&row)?,
                }
            }
            MobileAppChatRequest::React { message, reaction } => {
                let row = self.named_row(owner, address, &message)?;
                if row.is_deleted
                    || delivery_failed(&row)
                    || (engine_session(&row).is_none() && row.wire_id.is_none())
                {
                    return Err(MobileAppError::InvalidRequest);
                }
                MobileChatSendRequest::Reaction {
                    target: regarding_ref(&row),
                    body: reaction
                        .as_ref()
                        .and_then(reaction_body)
                        .unwrap_or_default(),
                }
            }
        })
    }

    /// See `MobileAppCore::send_chat`.
    async fn send_chat(
        &self,
        address: String,
        request: MobileAppChatRequest,
        clear_draft: Option<String>,
    ) -> Result<(), MobileAppError> {
        let command = self.begin_store_command().await?;
        let owner = self.chat_owner(&address)?;
        let mut changes = MobileAppChangesRecord::default();
        // The words are stored before anything can refuse them, so they
        // survive a refusal, a caller that stopped waiting, or the process.
        if let Some(submitted) = &clear_draft
            && self.store.set_draft(&owner, &address, submitted)?
        {
            changes.conversations_changed = true;
        }
        let result = match command {
            Some(_command) => {
                self.send_running(&owner, &address, request, clear_draft, &mut changes)
                    .await
            }
            None => Err(MobileAppError::NotRunning),
        };
        self.raise(changes);
        result
    }

    async fn send_running(
        &self,
        owner: &str,
        address: &str,
        request: MobileAppChatRequest,
        clear_draft: Option<String>,
        changes: &mut MobileAppChangesRecord,
    ) -> Result<(), MobileAppError> {
        self.emergency_refusal(owner, address)?;
        let session = self.radio_session()?;
        let request = self.compose_request(owner, address, request)?;
        let sent = session.send_chat(address.to_owned(), request).await;
        let kept = matches!(
            sent,
            Ok(())
                | Err(MobileChatSendError::NotQueued { .. }
                    | MobileChatSendError::NotQueuedOrRecorded { .. })
        );
        if kept {
            changes.merge(transcript_changed(address));
            if let Some(submitted) = clear_draft {
                // Words typed since the send changed the draft, and stay.
                match self.clear_submitted_draft(owner, address, &submitted) {
                    Ok(true) => changes.conversations_changed = true,
                    Ok(false) => {}
                    Err(error) => {
                        log::warn!(error:? = error; "a sent message's draft was not cleared");
                    }
                }
            }
        }
        sent.map_err(|error| self.chat_send_error(address, error))
    }

    fn clear_submitted_draft(
        &self,
        owner: &str,
        address: &str,
        submitted: &str,
    ) -> Result<bool, MobileAppError> {
        #[cfg(test)]
        if self
            .hooks
            .fail_draft_clear
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(MobileAppError::Store {
                error: crate::store::MobileStoreError::Failed {
                    code: 0,
                    detail: "refused for a test".to_owned(),
                },
            });
        }
        Ok(self.store.clear_draft_if(owner, address, submitted)?)
    }

    /// See `MobileAppCore::resend`.
    async fn resend(
        &self,
        address: String,
        message: MobileStoredChatMessageRefRecord,
        forward_secret: bool,
    ) -> Result<MobileAppResent, MobileAppError> {
        let command = self.begin_store_command().await?;
        let owner = self.chat_owner(&address)?;
        let Some(_command) = command else {
            return Err(MobileAppError::NotRunning);
        };
        let row = self.named_row(&owner, &address, &message)?;
        if !delivery_failed(&row) {
            return Err(MobileAppError::InvalidRequest);
        }
        // Claimed before the first await, so a second resend of the row
        // while this one runs sends nothing.
        let Some(_claim) = ResendClaim::take(self, &owner, &row.reference) else {
            return Err(MobileAppError::InvalidRequest);
        };
        self.emergency_refusal(&owner, &address)?;
        let session = self.radio_session()?;
        let in_place = match row.wire_id {
            Some(wire_id) if self.within_revise_window(row.created_at_ms) => {
                let frames = self.store.chat_resend_frames(
                    owner.clone(),
                    address.clone(),
                    row.reference.clone(),
                    wire_id,
                )?;
                if frames.is_empty() {
                    false
                } else {
                    let original = MobileChatOriginalRef {
                        session_id: engine_session(&row).unwrap_or(0),
                        handle: row.reference.handle,
                        wire_id: row.wire_id,
                        epoch: row.epoch,
                    };
                    match session
                        .resend_chat(address.clone(), original, frames, forward_secret)
                        .await
                    {
                        Ok(()) => true,
                        // The frames went; only their counters were not
                        // saved, which the next save retries.
                        Err(MobileMeshError::CounterPersistenceFailed) => {
                            log::error!(
                                "a message went out again, but its counters could not be saved"
                            );
                            true
                        }
                        // The stream moved past it: only new words land.
                        Err(MobileMeshError::ChatResendNotInPlace) => false,
                        Err(MobileMeshError::UnknownConversation) => {
                            return Err(self.unknown_conversation(&address));
                        }
                        Err(error) => return Err(mesh_error(error)),
                    }
                }
            }
            _ => false,
        };
        if in_place {
            // The row's delivery is repointed by what the session stores
            // next; a read made after the answer sees it.
            session.flush_chat().await;
            self.raise(transcript_changed(&address));
            return Ok(MobileAppResent::InPlace);
        }
        let sent = session
            .send_chat(
                address.clone(),
                MobileChatSendRequest::Again {
                    body: row.body.clone(),
                    status: row.is_status,
                    forward_secret,
                },
            )
            .await;
        // The new message replaces the old one once it is recorded; one
        // that may read as sending leaves the failed one to say otherwise.
        if matches!(sent, Ok(()) | Err(MobileChatSendError::NotQueued { .. }))
            && let Err(error) = self.store.remove_failed_message(owner, row.reference)
        {
            log::warn!(error:? = error; "a resent message's failed row was not removed");
        }
        if !matches!(sent, Err(MobileChatSendError::NotComposed { .. })) {
            self.raise(transcript_changed(&address));
        }
        sent.map(|()| MobileAppResent::AsNew)
            .map_err(|error| self.chat_send_error(&address, error))
    }

    /// See `MobileAppCore::request_missing`.
    async fn request_missing(
        &self,
        address: String,
        messages: Vec<MobileStoredChatMessageRefRecord>,
    ) -> Result<(), MobileAppError> {
        let command = self.begin_store_command().await?;
        let owner = self.chat_owner(&address)?;
        let Some(_command) = command else {
            return Err(MobileAppError::NotRunning);
        };
        self.emergency_refusal(&owner, &address)?;
        let session = self.radio_session()?;
        let mut lost = Vec::new();
        let mut failure = None;
        for message in messages {
            // Read in this conversation only: a stale screen's row, or
            // another conversation's, is passed over.
            let row = match self.store.chat_message(&owner, &address, &message) {
                Ok(Some(row)) if row.presence == MobileChatPresence::GapIdle => row,
                Ok(_) => continue,
                Err(error) => {
                    failure = Some(error.into());
                    break;
                }
            };
            let Some(session_id) = engine_session(&row) else {
                lost.push(row.reference);
                continue;
            };
            match session
                .request_chat_repair(session_id, row.reference.handle)
                .await
            {
                Ok(true) => {}
                // A gap from an earlier session can never be asked for.
                Ok(false) => lost.push(row.reference),
                Err(error) => {
                    failure = Some(mesh_error(error));
                    break;
                }
            }
        }
        if !lost.is_empty()
            && let Err(error) = self.store.resolve_gaps_unavailable(owner, Some(lost))
        {
            failure.get_or_insert(error.into());
        }
        session.flush_chat().await;
        self.raise(MobileAppChangesRecord {
            transcripts: vec![address],
            ..MobileAppChangesRecord::default()
        });
        failure.map_or(Ok(()), Err)
    }

    /// A store command's owner and conversation, in any lifecycle but
    /// erasing, stopping and stopped.
    async fn store_command(
        &self,
        address: &str,
    ) -> Result<(Option<InFlight>, String), MobileAppError> {
        let command = self.begin_store_command().await?;
        let owner = self.chat_owner(address)?;
        Ok((command, owner))
    }

    async fn save_draft(&self, address: String, text: String) -> Result<(), MobileAppError> {
        let (_command, owner) = self.store_command(&address).await?;
        if self.store.set_draft(&owner, &address, &text)? {
            self.raise(conversations_changed());
        }
        Ok(())
    }

    async fn append_draft(&self, address: String, text: String) -> Result<(), MobileAppError> {
        let (_command, owner) = self.store_command(&address).await?;
        self.store.append_draft(&owner, &address, &text)?;
        self.raise(conversations_changed());
        Ok(())
    }

    async fn mark_read(
        &self,
        address: String,
        through_ms: Option<i64>,
    ) -> Result<(), MobileAppError> {
        let _command = self.begin_store_command().await?;
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let read_at_ms = through_ms.unwrap_or_else(|| self.clock.now_ms());
        if self
            .store
            .mark_read_counting(&owner, &address, read_at_ms, through_ms.is_some())?
        {
            self.raise(conversations_changed());
        }
        Ok(())
    }

    async fn clear_messages(&self, address: String) -> Result<(), MobileAppError> {
        let (_command, owner) = self.store_command(&address).await?;
        self.store
            .clear_conversation_messages(owner, address.clone())?;
        self.raise(transcript_changed(&address));
        Ok(())
    }

    async fn generate_messages(&self, address: String, count: u32) -> Result<(), MobileAppError> {
        let (_command, owner) = self.store_command(&address).await?;
        self.store
            .seed_generated_messages(owner, address.clone(), count, self.clock.now_ms())?;
        self.raise(transcript_changed(&address));
        Ok(())
    }

    /// See `MobileAppCore::identity_share_uri`.
    async fn identity_share_uri(&self) -> Result<String, MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let timestamp = u32::try_from(self.clock.now_ms() / 1000).unwrap_or(u32::MAX);
        let bundle = session
            .sign_identity_bundle(self.advertised_name(), Some(timestamp))
            .await
            .map_err(mesh_error)?;
        Ok(crate::node_uri_with_identity(owner, bundle)?)
    }
}

#[uniffi::export]
impl MobileAppCore {
    /// Send into a stored conversation: typed text, a reply, an edit, a
    /// deletion or a reaction. The message is stored before anything goes
    /// on the air, and the send runs to its end whatever becomes of the
    /// caller.
    ///
    /// `clear_draft`, with `Typed` and `Reply` only, is the composer's text
    /// as submitted: it is stored as the draft first, in every state but
    /// erasing, stopping and stopped, so a refused send keeps it; once the
    /// message is kept, the draft is cleared if it still reads the same.
    ///
    /// `MessageNotQueued` is the only error that means the message was
    /// kept. Refused before anything is composed: `EmergencyNotCertified`
    /// on `EMERGENCY` before `certify_emergency`, then `NoRadio` or
    /// `NotThisPhone` with no radio attached as this phone's.
    pub async fn send_chat(
        &self,
        address: String,
        request: MobileAppChatRequest,
        clear_draft: Option<String>,
    ) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        let request = request.checked()?;
        if clear_draft.is_some() && !request.is_composed() {
            return Err(MobileAppError::InvalidRequest);
        }
        self.on_worker(move |worker| async move {
            worker.send_chat(address, request, clear_draft).await
        })
        .await
    }

    /// Send a message of ours that was not delivered again: as itself,
    /// within its revise window and while its frames can still land, or
    /// otherwise as a new message that replaces it. `forward_secret` is
    /// what the user chose; a channel has none. `InvalidRequest` for a
    /// message that is not failed, or that another resend is sending.
    pub async fn resend(
        &self,
        address: String,
        message: MobileStoredChatMessageRefRecord,
        forward_secret: bool,
    ) -> Result<MobileAppResent, MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move {
            worker.resend(address, message, forward_secret).await
        })
        .await
    }

    /// Ask for the missing messages `messages` names in this conversation.
    /// A gap that can no longer be asked for is marked unavailable, even
    /// when a request fails; rows that are not idle gaps are passed over.
    pub async fn request_missing(
        &self,
        address: String,
        messages: Vec<MobileStoredChatMessageRefRecord>,
    ) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move { worker.request_missing(address, messages).await })
            .await
    }

    /// Keep `text`, as it stands, as a conversation's draft. Kept while
    /// idle or failed too.
    pub async fn save_draft(&self, address: String, text: String) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move { worker.save_draft(address, text).await })
            .await
    }

    /// Keep `text` in a conversation's draft: as the draft when it is
    /// empty, otherwise on a line under it. For a reply that did not go
    /// out. Kept while idle or failed too.
    pub async fn append_draft(&self, address: String, text: String) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move { worker.append_draft(address, text).await })
            .await
    }

    /// Mark a conversation read: as of now, or with `through_ms` as of
    /// then, which never moves its read time back. Kept while idle or
    /// failed too. A conversation not stored is not an error.
    pub async fn mark_read(
        &self,
        address: String,
        through_ms: Option<i64>,
    ) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move { worker.mark_read(address, through_ms).await })
            .await
    }

    /// Erase a conversation's messages, keeping the conversation, its
    /// draft and its place in the wire stream. Local only.
    pub async fn clear_messages(&self, address: String) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move { worker.clear_messages(address).await })
            .await
    }

    /// Fill a conversation with `count` generated messages, for looking at
    /// long transcripts.
    pub async fn generate_messages(
        &self,
        address: String,
        count: u32,
    ) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.on_worker(move |worker| async move { worker.generate_messages(address, count).await })
            .await
    }

    /// The user agreed to `EMERGENCY`'s warning: sends there are taken
    /// from now on, under this owner, until the owner changes or the core
    /// ends. In effect for every command made after it returns.
    pub fn certify_emergency(&self) -> Result<(), MobileAppError> {
        let mut refused = None;
        self.shared.publish(|snapshot| {
            if snapshot.lifecycle == MobileAppLifecycle::Stopped {
                refused = Some(MobileAppError::Stopped);
            } else if snapshot.owner.is_none() {
                refused = Some(MobileAppError::NoOwner);
            } else if !snapshot.emergency_certified {
                snapshot.emergency_certified = true;
                return MobileAppChangesRecord {
                    emergency_certified: Some(true),
                    ..MobileAppChangesRecord::default()
                };
            }
            MobileAppChangesRecord::default()
        });
        refused.map_or(Ok(()), Err)
    }

    /// This phone's link, carrying its identity signed under the name it
    /// advertises and the time now. Never its location. `NotRunning` while
    /// no identity runs: `node_uri_for_address` gives the bare link.
    pub async fn identity_share_uri(&self) -> Result<String, MobileAppError> {
        self.command(|worker| async move { worker.identity_share_uri().await })
            .await
    }
}
