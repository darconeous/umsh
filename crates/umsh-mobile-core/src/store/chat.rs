//! Chat: what the mesh session's chat engine reports, made durable.
//!
//! A message row (`chat_message`) is keyed by the engine handle that wrote
//! it, `(session_id, handle)`: `session_id` is the decimal string of the
//! facade session's u64, which keeps one process's u32 handles from
//! colliding with another's. That key is the message's identity for good;
//! edits, deletes, reactions, and replies name it, and so does the
//! transcript.
//!
//! Delivery evidence is kept per fragment (`chat_delivery_fragment`) and
//! keyed by the *transmission* that earned it. A row reports one
//! transmission at a time through its delivery pointer
//! (`delivery_session_id`, `delivery_handle`): its own compose at first,
//! then whichever edit or resend last put its content on the air. The
//! row's `delivery_state` is always recomputed from the fragments under
//! that pointer, never set by a single record, so evidence can arrive in
//! any order, and twice, and land in the same place.
//!
//! Mutations are made idempotent by `chat_applied_mutation`, a ledger of
//! the newest revision applied per `(session_id, handle)`: a redelivered
//! batch replays nothing it already wrote.
//!
//! A call made with an engine record in hand takes the engine's own
//! `session_id` (a u64) and handle. A call that names a stored message
//! takes its [`MobileStoredChatMessageRefRecord`], whose session ID is the
//! stored text: not every row was written by an engine session, and a
//! staged transcript's session is a name.
//!
//! Callers supply the instant ("now") that rows are stamped with; this
//! store never reads a clock.

use rusqlite::{Connection, OptionalExtension, named_params, params};
use umsh_text::MessageType;

use crate::mobile_chat::{
    CHANNEL_ADDRESS_PREFIX, MobileChatArchiveDeleteRecord, MobileChatArchiveLookupRecord,
    MobileChatArchiveRecord, MobileChatCheckpointRecord, MobileChatComposeBatchRecord,
    MobileChatDeliveryRecord, MobileChatDeliveryState, MobileChatDirection, MobileChatMutationKind,
    MobileChatMutationRecord, MobileChatPresence, MobileChatRepeatRecord, MobileChatResendRecord,
    MobileChatSenderResolutionRecord,
};

use super::{MobileAppStore, MobileStoreError};

/// One stored message's durable identity: the engine handle that wrote it,
/// under the decimal string of its facade session.
#[derive(Clone, Debug, PartialEq, Eq, Hash, uniffi::Record)]
pub struct MobileStoredChatMessageRefRecord {
    pub session_id: String,
    pub handle: u32,
}

/// How far the delivery of one of our messages has got. Stored as lowercase
/// TEXT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileStoredChatDeliveryState {
    /// Nothing has been heard of its frames going out.
    Pending,
    Sent,
    Acknowledged,
    /// It went out unacknowledged, and may have arrived.
    Failed,
    /// It never went out where the peer could read it.
    Undelivered,
}

impl MobileStoredChatDeliveryState {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Acknowledged => "acknowledged",
            Self::Failed => "failed",
            Self::Undelivered => "undelivered",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "sent" => Self::Sent,
            "acknowledged" => Self::Acknowledged,
            "failed" => Self::Failed,
            "undelivered" => Self::Undelivered,
            _ => return None,
        })
    }

    /// The state a column holds, or `None` for no state and for one this
    /// build does not know.
    pub(super) fn stored(value: Option<String>) -> Option<Self> {
        value.as_deref().and_then(Self::parse)
    }

    fn is_failure(self) -> bool {
        matches!(self, Self::Failed | Self::Undelivered)
    }
}

impl From<MobileChatDeliveryState> for MobileStoredChatDeliveryState {
    fn from(state: MobileChatDeliveryState) -> Self {
        match state {
            MobileChatDeliveryState::Sent => Self::Sent,
            MobileChatDeliveryState::Acknowledged => Self::Acknowledged,
            MobileChatDeliveryState::Failed => Self::Failed,
            MobileChatDeliveryState::Undelivered => Self::Undelivered,
        }
    }
}

/// What a notification needs to describe an arrived message, resolved from
/// storage rather than from the mutation that triggered it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatNotificationTargetRecord {
    pub conversation_address: String,
    pub body: String,
    /// The sender's full address, when known. A group message from a
    /// member whose hint has not resolved yet has none.
    pub sender_address: Option<String>,
    /// The sender's claimed hint, for a group message.
    pub sender_hint: Option<Vec<u8>>,
    /// The name the sender attached to the message.
    pub sender_handle: Option<String>,
    /// Status text, which reads as its sender's name followed by its body.
    pub is_status: bool,
}

/// An inbound reaction worth telling the user about: who put what on which
/// message of theirs.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatReactionNotificationTargetRecord {
    pub conversation_address: String,
    /// The reaction body as it arrived: a wire token like `<3`, rendered
    /// to a glyph for display.
    pub body: String,
    /// What the reaction is on, so the notice can quote it.
    pub target_body: String,
    pub sender_address: Option<String>,
    pub sender_hint: Option<Vec<u8>>,
    pub sender_handle: Option<String>,
}

/// An outbound message whose delivery has just been given up on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatDeliveryFailureRecord {
    pub conversation_address: String,
    pub body: String,
    /// It never went out where the peer could read it, rather than going
    /// out and drawing no acknowledgment.
    pub undelivered: bool,
}

#[uniffi::export]
impl MobileAppStore {
    /// The conversation a stored message belongs to, by its durable
    /// identity. What attributes a delivery acknowledgment, which carries
    /// no address of its own, back to a peer.
    pub fn conversation_address_for_message(
        &self,
        owner_identity_id: String,
        session_id: u64,
        handle: u32,
    ) -> Result<Option<String>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT conversation_address FROM chat_message
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?",
                params![owner_identity_id, session_id.to_string(), handle],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// The stored conversation, sender, and body of an inbound message a
    /// person reads, for raising a notification. `None` for outbound rows,
    /// tombstones, gap placeholders, unavailable markers, reactions, and
    /// empty bodies. Everything is read from storage, so a notify carried
    /// on an `UpdateBody`, which omits all of it, still works.
    pub fn chat_notification_target(
        &self,
        owner_identity_id: String,
        session_id: u64,
        handle: u32,
    ) -> Result<Option<MobileStoredChatNotificationTargetRecord>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                &format!(
                    "SELECT conversation_address, body, sender_address, sender_hint,
                        sender_handle, {is_status}
                    FROM chat_message
                    WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                        AND direction = 0 AND deleted = 0 AND presence = 0 AND body <> ''
                        AND is_reaction = 0",
                    is_status = is_status_sql("message_type"),
                ),
                params![owner_identity_id, session_id.to_string(), handle],
                |row| {
                    Ok(MobileStoredChatNotificationTargetRecord {
                        conversation_address: row.get(0)?,
                        body: row.get(1)?,
                        sender_address: row.get(2)?,
                        sender_hint: row.get(3)?,
                        sender_handle: row.get(4)?,
                        // NULL when the message has no type, which is not
                        // status.
                        is_status: row.get::<_, Option<i64>>(5)?.unwrap_or(0) != 0,
                    })
                },
            )
            .optional()?)
    }

    /// The reaction behind a notifying mutation, when it is one and it
    /// lands on a message this phone sent.
    ///
    /// Reactions to someone else's message are somebody else's business: in
    /// a channel they would ping every member for every tapback. A
    /// withdrawal carries an empty body and is not an event to announce.
    pub fn chat_reaction_notification_target(
        &self,
        owner_identity_id: String,
        session_id: u64,
        handle: u32,
    ) -> Result<Option<MobileStoredChatReactionNotificationTargetRecord>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT r.conversation_address, r.body, target.body,
                    r.sender_address, r.sender_hint, r.sender_handle
                FROM chat_message r
                JOIN chat_message target
                    ON target.owner_identity_id = r.owner_identity_id
                    AND target.session_id = r.regarding_target_session_id
                    AND target.handle = r.regarding_target_handle
                WHERE r.owner_identity_id = ? AND r.session_id = ? AND r.handle = ?
                    AND r.direction = 0 AND r.deleted = 0 AND r.is_reaction = 1
                    AND r.body <> ''
                    AND target.direction = 1 AND target.deleted = 0",
                params![owner_identity_id, session_id.to_string(), handle],
                |row| {
                    Ok(MobileStoredChatReactionNotificationTargetRecord {
                        conversation_address: row.get(0)?,
                        body: row.get(1)?,
                        target_body: row.get(2)?,
                        sender_address: row.get(3)?,
                        sender_hint: row.get(4)?,
                        sender_handle: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Fill in the sender of group messages stored before that member's
    /// hint resolved to a full address. Rows that already name a sender are
    /// left alone: the first attribution seen for a hint is the one kept.
    pub fn apply_sender_resolution(
        &self,
        owner_identity_id: String,
        resolution: MobileChatSenderResolutionRecord,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "UPDATE chat_message SET sender_address = ?
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND sender_hint = ? AND sender_address IS NULL",
            params![
                resolution.sender_address,
                owner_identity_id,
                resolution.conversation_address,
                nullable_blob(Some(resolution.sender_hint.as_slice())),
            ],
        )?;
        Ok(())
    }

    /// Every outbound stream's checkpoint, least recently written first:
    /// what a new mesh session resumes each stream from.
    pub fn chat_checkpoints(
        &self,
        owner_identity_id: String,
    ) -> Result<Vec<MobileChatCheckpointRecord>, MobileStoreError> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT conversation_address, next_id, epoch FROM chat_stream_checkpoint
            WHERE owner_identity_id = ? ORDER BY updated_at_ms ASC, conversation_address ASC",
        )?;
        let checkpoints = statement
            .query_map(params![owner_identity_id], |row| {
                Ok(MobileChatCheckpointRecord {
                    conversation_address: row.get(0)?,
                    next_id: row.get(1)?,
                    epoch: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(checkpoints)
    }

    /// Make a compose durable: its stream checkpoint, the exact payloads a
    /// resend would serve, and the rows it writes, in one transaction. The
    /// caller releases the engine's batch only after this returns. Rows are
    /// stamped `now_ms`, as is the checkpoint.
    pub fn commit_chat_compose_batch(
        &self,
        owner_identity_id: String,
        batch: MobileChatComposeBatchRecord,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            let owner = owner_identity_id.as_str();
            upsert_checkpoint(transaction, owner, &batch.checkpoint, now_ms)?;
            // Retirements first: an edit's replacement payloads must land on a
            // clean slate, so no stale fragment of the superseded content can
            // ever be served to a resend request.
            for delete in &batch.archive_deletes {
                delete_archive(transaction, owner, delete)?;
            }
            for archive in &batch.archives {
                upsert_archive(transaction, owner, archive)?;
            }
            // What this phone composes is never a message arriving, so nothing
            // here is silent.
            for mutation in &batch.mutations {
                apply_mutation(transaction, owner, mutation, None, now_ms)?;
            }
            Ok(())
        })
    }

    /// Apply what the engine reported, in one transaction, and return the
    /// mutations that materialized a new message row: an edit whose
    /// original this phone never stored arrives as content rather than a
    /// revision (see `materialize_orphan_edit`). The engine could not flag
    /// those `notify`, since only the store knows the original was missing;
    /// the caller treats them as the arrivals they are.
    ///
    /// A mutation at or below the revision already applied for its message
    /// changes nothing, so a redelivered batch is harmless.
    ///
    /// `silent_tests_in` names `EMERGENCY`'s conversation while its test
    /// messages are to arrive silently: one arriving there is kept and
    /// shown, but never counts as unread. New rows are stamped `now_ms`,
    /// less any time the frame spent queued on the radio.
    #[uniffi::method(default(silent_tests_in = None))]
    pub fn apply_chat_mutations(
        &self,
        owner_identity_id: String,
        mutations: Vec<MobileChatMutationRecord>,
        now_ms: i64,
        silent_tests_in: Option<String>,
    ) -> Result<Vec<MobileChatMutationRecord>, MobileStoreError> {
        self.write(|transaction| {
            let mut materialized = Vec::new();
            for mutation in mutations {
                if apply_mutation(
                    transaction,
                    &owner_identity_id,
                    &mutation,
                    silent_tests_in.as_deref(),
                    now_ms,
                )? {
                    materialized.push(mutation);
                }
            }
            Ok(materialized)
        })
    }

    /// Apply delivery evidence, in one transaction, and report which
    /// messages it just gave up on.
    ///
    /// Only a crossing counts. `delivery_state` is recomputed from every
    /// fragment on each record, so a message already resolved to a failure
    /// recomputes to one again on the next fragment, and a redelivered
    /// batch replays the same records; announcing the state rather than the
    /// transition would announce one failure many times. `now_ms` stamps
    /// the moment a message's first frame is heard of going out.
    pub fn apply_chat_deliveries(
        &self,
        owner_identity_id: String,
        deliveries: Vec<MobileChatDeliveryRecord>,
        now_ms: i64,
    ) -> Result<Vec<MobileStoredChatDeliveryFailureRecord>, MobileStoreError> {
        self.write(|transaction| {
            let owner = owner_identity_id.as_str();
            let mut failures = Vec::new();
            for delivery in &deliveries {
                let session_id = delivery.session_id.to_string();
                let before = delivery_state(transaction, owner, &session_id, delivery.handle)?;
                transaction.execute(
                    "INSERT INTO chat_delivery_fragment (
                        owner_identity_id, session_id, handle, fragment_index, state, via_flood
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(owner_identity_id, session_id, handle, fragment_index)
                    DO UPDATE SET
                    via_flood = MAX(chat_delivery_fragment.via_flood, excluded.via_flood),
                    state = CASE
                        -- A positive ack is definitive proof the frame landed,
                        -- whatever was said of it before or after.
                        WHEN chat_delivery_fragment.state = 'acknowledged'
                            OR excluded.state = 'acknowledged' THEN 'acknowledged'
                        -- Otherwise the latest word stands: a fragment sent
                        -- again is in flight again, whatever became of it the
                        -- last time.
                        ELSE excluded.state
                    END",
                    params![
                        owner,
                        session_id,
                        delivery.handle,
                        fragment_code(delivery.fragment_index),
                        MobileStoredChatDeliveryState::from(delivery.state).as_str(),
                        delivery.via_flood,
                    ],
                )?;
                recompute_delivery_state(transaction, owner, &session_id, delivery.handle, now_ms)?;
                let after = delivery_state(transaction, owner, &session_id, delivery.handle)?;
                if is_failure(before) || !is_failure(after) {
                    continue;
                }
                if let Some(failure) =
                    failed_message(transaction, owner, &session_id, delivery.handle)?
                {
                    failures.push(failure);
                }
            }
            Ok(failures)
        })
    }

    /// Record the repeaters overheard carrying our frames, in one
    /// transaction.
    ///
    /// Each record is one transmission's whole tally, and a fragment sent
    /// again starts a fresh one, so a fragment keeps the union of the
    /// repeaters every transmission of it named (two-byte hints only), and
    /// the most any of them heard anonymously. A message's delivery is
    /// stamped `now_ms` as having moved whenever one of its fragments gains
    /// a repeater; a tally that adds nothing writes nothing.
    pub fn apply_chat_repeats(
        &self,
        owner_identity_id: String,
        repeats: Vec<MobileChatRepeatRecord>,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        if repeats.is_empty() {
            return Ok(());
        }
        self.write(|transaction| {
            let owner = owner_identity_id.as_str();
            for record in &repeats {
                let session_id = record.session_id.to_string();
                let fragment = fragment_code(record.fragment_index);
                let (mut hints, mut anonymous) = transaction
                    .query_row(
                        "SELECT repeaters, anonymous_repeats FROM chat_delivery_fragment
                        WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                            AND fragment_index = ?",
                        params![owner, session_id, record.handle, fragment],
                        |row| {
                            Ok((
                                split_hints(row.get::<_, Option<Vec<u8>>>(0)?.as_deref()),
                                row.get::<_, i64>(1)?,
                            ))
                        },
                    )
                    .optional()?
                    .unwrap_or_default();
                let before = (hints.clone(), anonymous);
                for repeater in &record.repeaters {
                    if repeater.bytes.len() == 2 && !hints.contains(&repeater.bytes) {
                        hints.push(repeater.bytes.clone());
                    }
                }
                anonymous = anonymous.max(i64::from(record.anonymous_repeats));
                if before == (hints.clone(), anonymous) {
                    continue;
                }
                // A repeat is heard only of a frame that went out, so a fragment
                // with no delivery record yet is a sent one.
                let packed = hints.concat();
                transaction.execute(
                    "INSERT INTO chat_delivery_fragment (
                        owner_identity_id, session_id, handle, fragment_index, state,
                        repeaters, anonymous_repeats
                    ) VALUES (?, ?, ?, ?, 'sent', ?, ?)
                    ON CONFLICT(owner_identity_id, session_id, handle, fragment_index)
                    DO UPDATE SET
                        repeaters = excluded.repeaters,
                        anonymous_repeats = excluded.anonymous_repeats",
                    params![
                        owner,
                        session_id,
                        record.handle,
                        fragment,
                        nullable_blob(Some(packed.as_slice())),
                        anonymous,
                    ],
                )?;
                transaction.execute(
                    "UPDATE chat_message SET delivery_progress_at_ms = ?
                    WHERE owner_identity_id = ? AND delivery_session_id = ? AND delivery_handle = ?",
                    params![now_ms, owner, session_id, record.handle],
                )?;
            }
            Ok(())
        })
    }

    /// Mark what a compose wrote undelivered, in one transaction, after the
    /// compose was made durable but the engine could not release its
    /// transmissions (the fail-closed counter store became unavailable,
    /// say). Keeps the optimistic row honest instead of leaving it pending
    /// forever.
    pub fn mark_chat_compose_batch_failed(
        &self,
        owner_identity_id: String,
        batch: MobileChatComposeBatchRecord,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            for mutation in &batch.mutations {
                // A new outbound message is keyed by its own compose; an edit
                // never inserted a row, but the row it revised now points its
                // delivery at the edit's transmissions, the ones that just
                // failed to launch. Either way the row the failure belongs to is
                // the one whose pointer names this mutation.
                let applies = match mutation.kind {
                    MobileChatMutationKind::Insert => {
                        mutation.direction == Some(MobileChatDirection::Outbound)
                    }
                    MobileChatMutationKind::Edit => true,
                    MobileChatMutationKind::UpdateBody | MobileChatMutationKind::Delete => false,
                };
                if !applies {
                    continue;
                }
                transaction.execute(
                    "UPDATE chat_message SET delivery_state = 'undelivered'
                    WHERE owner_identity_id = ? AND delivery_session_id = ?
                        AND delivery_handle = ? AND direction = 1",
                    params![
                        owner_identity_id,
                        mutation.session_id.to_string(),
                        mutation.handle
                    ],
                )?;
            }
            Ok(())
        })
    }

    /// Remove a failed outbound message outright, in one transaction,
    /// because its text just went back on the air as a new message: keeping
    /// the dead row would show the same words twice.
    ///
    /// Local only, and deliberately narrow: anything but a failed outbound
    /// row is left alone, so a stale caller can never take down a message
    /// the mesh knows about. Reactions to the row go with it (nobody ever
    /// received the message they decorate), as does the delivery evidence
    /// under its pointer.
    pub fn remove_failed_message(
        &self,
        owner_identity_id: String,
        message: MobileStoredChatMessageRefRecord,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            // The evidence and the reactions first: both are found through the
            // message.
            transaction.execute(
                "DELETE FROM chat_delivery_fragment
                WHERE owner_identity_id = ?1 AND (session_id, handle) = (
                    SELECT delivery_session_id, delivery_handle FROM chat_message
                    WHERE owner_identity_id = ?1 AND session_id = ?2 AND handle = ?3
                        AND direction = 1 AND delivery_state IN ('failed', 'undelivered')
                )",
                params![owner_identity_id, message.session_id, message.handle],
            )?;
            transaction.execute(
                "DELETE FROM chat_message
                WHERE owner_identity_id = ?1 AND regarding_target_session_id = ?2
                    AND regarding_target_handle = ?3 AND is_reaction = 1
                    AND EXISTS (
                        SELECT 1 FROM chat_message target
                        WHERE target.owner_identity_id = ?1
                            AND target.session_id = ?2 AND target.handle = ?3
                            AND target.direction = 1
                            AND target.delivery_state IN ('failed', 'undelivered')
                    )",
                params![owner_identity_id, message.session_id, message.handle],
            )?;
            transaction.execute(
                "DELETE FROM chat_message
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                    AND direction = 1 AND delivery_state IN ('failed', 'undelivered')",
                params![owner_identity_id, message.session_id, message.handle],
            )?;
            Ok(())
        })
    }

    /// Settle the outbound messages a previous process left awaiting word.
    ///
    /// Their transmissions died with that process, and a new mesh session
    /// issues new session IDs, so no evidence can ever arrive for them. One
    /// still `pending` never went out: `undelivered`. A direct one that
    /// reached `sent` went on the air and may have arrived, but its
    /// acknowledgment can no longer be heard: `failed`. A channel message's
    /// `sent` is already its last word.
    pub fn settle_interrupted_deliveries(
        &self,
        owner_identity_id: String,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "UPDATE chat_message SET delivery_state = CASE delivery_state
                WHEN 'pending' THEN 'undelivered'
                ELSE 'failed'
            END
            WHERE owner_identity_id = ? AND direction = 1
                AND (
                    delivery_state = 'pending'
                    OR (delivery_state = 'sent' AND conversation_address NOT LIKE ?)
                )",
            params![owner_identity_id, format!("{CHANNEL_ADDRESS_PREFIX}%")],
        )?;
        Ok(())
    }

    /// Resolve gap placeholders as unavailable: the named rows, in one
    /// transaction, or every gap the identity holds when `rows` is `None`.
    /// A gap belongs to the mesh session that saw it, so once that session
    /// is gone no repair will ever fill it. Rows that are not gaps are left
    /// alone.
    #[uniffi::method(default(rows = None))]
    pub fn resolve_gaps_unavailable(
        &self,
        owner_identity_id: String,
        rows: Option<Vec<MobileStoredChatMessageRefRecord>>,
    ) -> Result<(), MobileStoreError> {
        let Some(rows) = rows else {
            self.connection().execute(
                "UPDATE chat_message SET presence = 2
                WHERE owner_identity_id = ? AND presence IN (1, 3)",
                params![owner_identity_id],
            )?;
            return Ok(());
        };
        self.write(|transaction| {
            let mut statement = transaction.prepare(
                "UPDATE chat_message SET presence = 2
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                    AND presence IN (1, 3)",
            )?;
            for row in &rows {
                statement.execute(params![owner_identity_id, row.session_id, row.handle])?;
            }
            Ok(())
        })
    }

    /// The archived payload a repair request asks for, if it is still
    /// held.
    pub fn chat_archive(
        &self,
        owner_identity_id: String,
        lookup: MobileChatArchiveLookupRecord,
    ) -> Result<Option<Vec<u8>>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT payload FROM chat_outbound_archive
                WHERE owner_identity_id = ? AND conversation_address = ?
                    AND message_id = ? AND fragment_index = ?",
                params![
                    owner_identity_id,
                    lookup.conversation_address,
                    lookup.message_id,
                    fragment_code(lookup.fragment_index),
                ],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// What a resend of one of our messages puts back on the air: its
    /// archived fragments, in order, less those already acknowledged under
    /// its current delivery pointer. Empty when nothing is archived under
    /// the wire ID the row carries (an edit's content lives under the
    /// edit's own ID, which the row does not keep), so the caller sends it
    /// as a new message instead.
    pub fn chat_resend_frames(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        message: MobileStoredChatMessageRefRecord,
        wire_id: u8,
    ) -> Result<Vec<MobileChatArchiveRecord>, MobileStoreError> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT a.fragment_index, a.payload FROM chat_outbound_archive a
            WHERE a.owner_identity_id = ?1 AND a.conversation_address = ?2
                AND a.message_id = ?5
                AND NOT EXISTS (
                    SELECT 1 FROM chat_message m
                    JOIN chat_delivery_fragment f
                        ON f.owner_identity_id = m.owner_identity_id
                        AND f.session_id = m.delivery_session_id
                        AND f.handle = m.delivery_handle
                    WHERE m.owner_identity_id = ?1 AND m.session_id = ?3 AND m.handle = ?4
                        AND f.fragment_index = a.fragment_index
                        AND f.state = 'acknowledged'
                )
            ORDER BY a.fragment_index",
        )?;
        let frames = statement
            .query_map(
                params![
                    owner_identity_id,
                    conversation_address,
                    message.session_id,
                    message.handle,
                    wire_id
                ],
                |row| {
                    let fragment_index = match row.get::<_, i64>(0)? {
                        UNFRAGMENTED => None,
                        // An index no frame can carry names nothing to
                        // send, so the row is left out.
                        index => match u8::try_from(index) {
                            Ok(index) => Some(index),
                            Err(_) => return Ok(None),
                        },
                    };
                    Ok(Some(MobileChatArchiveRecord {
                        conversation_address: conversation_address.clone(),
                        message_id: wire_id,
                        fragment_index,
                        payload: row.get(1)?,
                    }))
                },
            )?
            .filter_map(Result::transpose)
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(frames)
    }

    /// Point each resent message's delivery at the transmission its frames
    /// went out under again, ahead of any word of them, and record whether
    /// they go under forward secrecy; one transaction. What was
    /// acknowledged stays so; what was last said of the rest no longer
    /// holds. A resend naming no outbound row is skipped.
    pub fn apply_chat_resends(
        &self,
        owner_identity_id: String,
        resends: Vec<MobileChatResendRecord>,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        if resends.is_empty() {
            return Ok(());
        }
        self.write(|transaction| {
            let owner = owner_identity_id.as_str();
            for resend in &resends {
                let Some(target) = transaction
                    .query_row(
                        "SELECT rowid FROM chat_message
                        WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                            AND direction = 1",
                        params![
                            owner,
                            resend.message.session_id.to_string(),
                            resend.message.handle
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                else {
                    continue;
                };
                transaction.execute(
                    "UPDATE chat_message SET forward_secret = ? WHERE rowid = ?",
                    params![resend.forward_secret, target],
                )?;
                let delivery_session_id = resend.delivery_session_id.to_string();
                adopt_delivery(
                    transaction,
                    owner,
                    target,
                    &delivery_session_id,
                    resend.delivery_handle,
                    None,
                    true,
                )?;
                recompute_delivery_state(
                    transaction,
                    owner,
                    &delivery_session_id,
                    resend.delivery_handle,
                    now_ms,
                )?;
            }
            Ok(())
        })
    }
}

/// A nullable blob with nothing in it as NULL, so an absent value has one
/// stored form. That matters where a column is matched with `IS` or merged
/// with `COALESCE`. The Swift store wrote a zero-length blob for one.
pub(super) fn nullable_blob(value: Option<&[u8]>) -> Option<&[u8]> {
    value.filter(|bytes| !bytes.is_empty())
}

/// Route hints are fixed-width and ordered, so they store as one blob
/// rather than a table of their own. No hints store as NULL, as above.
pub(super) fn pack_route_hints(hints: &[Vec<u8>]) -> Option<Vec<u8>> {
    let packed = hints.concat();
    (!packed.is_empty()).then_some(packed)
}

/// A stored run of two-byte hints, split. A trailing odd byte is dropped.
pub(super) fn split_hints(packed: Option<&[u8]>) -> Vec<Vec<u8>> {
    packed
        .unwrap_or_default()
        .chunks_exact(2)
        .map(<[u8]>::to_vec)
        .collect()
}

/// The fragment index the archive and fragment tables hold for a message
/// that was not fragmented.
const UNFRAGMENTED: i64 = -1;

/// A fragment index as the archive and fragment tables key it.
fn fragment_code(index: Option<u8>) -> i64 {
    index.map_or(UNFRAGMENTED, i64::from)
}

/// Whether `column`, a `message_type`, is status text, as an SQL
/// expression: 1 or 0, and NULL for a message with no type.
pub(super) fn is_status_sql(column: &str) -> String {
    format!("{column} = {}", MessageType::Status.to_byte())
}

/// The integer `chat_message.presence` holds.
fn presence_code(presence: MobileChatPresence) -> i64 {
    match presence {
        MobileChatPresence::Present => 0,
        MobileChatPresence::GapPending => 1,
        MobileChatPresence::Unavailable => 2,
        MobileChatPresence::GapIdle => 3,
    }
}

/// The integer a direction column holds: 1 for ours.
fn direction_code(direction: MobileChatDirection) -> i64 {
    match direction {
        MobileChatDirection::Inbound => 0,
        MobileChatDirection::Outbound => 1,
    }
}

fn upsert_checkpoint(
    connection: &Connection,
    owner_identity_id: &str,
    checkpoint: &MobileChatCheckpointRecord,
    now_ms: i64,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "INSERT INTO chat_stream_checkpoint (
            owner_identity_id, conversation_address, next_id, epoch, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(owner_identity_id, conversation_address) DO UPDATE SET
            next_id = excluded.next_id,
            epoch = excluded.epoch,
            updated_at_ms = excluded.updated_at_ms",
        params![
            owner_identity_id,
            checkpoint.conversation_address,
            checkpoint.next_id,
            checkpoint.epoch,
            now_ms
        ],
    )?;
    Ok(())
}

/// Remove every archived fragment stored under one message ID, the
/// unfragmented entry included: its content was superseded by an edit or
/// retracted by a delete and must never be resent.
fn delete_archive(
    connection: &Connection,
    owner_identity_id: &str,
    delete: &MobileChatArchiveDeleteRecord,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "DELETE FROM chat_outbound_archive
        WHERE owner_identity_id = ? AND conversation_address = ? AND message_id = ?",
        params![
            owner_identity_id,
            delete.conversation_address,
            delete.message_id
        ],
    )?;
    Ok(())
}

fn upsert_archive(
    connection: &Connection,
    owner_identity_id: &str,
    archive: &MobileChatArchiveRecord,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "INSERT INTO chat_outbound_archive (
            owner_identity_id, conversation_address, message_id, fragment_index, payload
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(owner_identity_id, conversation_address, message_id, fragment_index)
        DO UPDATE SET payload = excluded.payload",
        params![
            owner_identity_id,
            archive.conversation_address,
            archive.message_id,
            fragment_code(archive.fragment_index),
            // An empty payload is an empty blob: the column refuses NULL.
            archive.payload,
        ],
    )?;
    Ok(())
}

/// Apply one mutation. Returns whether it materialized a new message row
/// instead of revising one (see [`materialize_orphan_edit`]).
fn apply_mutation(
    connection: &Connection,
    owner_identity_id: &str,
    mutation: &MobileChatMutationRecord,
    silent_tests_in: Option<&str>,
    now_ms: i64,
) -> Result<bool, MobileStoreError> {
    let session_id = mutation.session_id.to_string();
    // The ledger moves only forward, so a revision already applied, or an
    // older one arriving late, stops here and writes nothing else.
    let advanced = connection.execute(
        "INSERT INTO chat_applied_mutation (owner_identity_id, session_id, handle, revision)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(owner_identity_id, session_id, handle) DO UPDATE SET
            revision = excluded.revision
        WHERE excluded.revision > chat_applied_mutation.revision",
        params![
            owner_identity_id,
            session_id,
            mutation.handle,
            mutation.revision
        ],
    )? > 0;
    if !advanced {
        return Ok(false);
    }
    match mutation.kind {
        MobileChatMutationKind::Insert => insert_message(
            connection,
            owner_identity_id,
            &session_id,
            mutation,
            silent_tests_in,
            now_ms,
        )
        .map(|()| false),
        MobileChatMutationKind::UpdateBody => update_body(
            connection,
            owner_identity_id,
            &session_id,
            mutation,
            silent_tests_in,
        )
        .map(|()| false),
        MobileChatMutationKind::Edit | MobileChatMutationKind::Delete => {
            revise_message(connection, owner_identity_id, &session_id, mutation, now_ms)
        }
    }
}

/// An `Insert`: a new row, or a placeholder filled in. A record missing
/// its address, direction, or body is dropped.
fn insert_message(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    mutation: &MobileChatMutationRecord,
    silent_tests_in: Option<&str>,
    now_ms: i64,
) -> Result<(), MobileStoreError> {
    let (Some(address), Some(direction), Some(body)) = (
        mutation.conversation_address.as_deref(),
        mutation.direction,
        mutation.body.as_deref(),
    ) else {
        return Ok(());
    };
    let outbound = direction == MobileChatDirection::Outbound;
    // An emote (status text about another message) is a reaction rather
    // than a transcript row of its own; anything else about another
    // message is a reply to it. Resolve what either is about now, while the
    // reference is in hand: the target may be named by a live handle or,
    // far more often, by the wire coordinates of a row stored in some
    // earlier session.
    let is_regarding = mutation.regarding_handle.is_some() || mutation.regarding_wire_id.is_some();
    let is_reaction = mutation.message_type == Some(MessageType::Status.to_byte()) && is_regarding;
    let target = if is_regarding {
        resolve_regarding_target(connection, owner_identity_id, session_id, address, mutation)?
    } else {
        None
    };
    // A message replayed from the radio's offline queue is stamped when it
    // was received off the air, not when the drain landed it here, so a
    // drained backlog sorts and reads correctly.
    let buffered_age_ms = mutation
        .rx
        .as_ref()
        .map_or(0, |rx| i64::from(rx.buffered_age_seconds) * 1_000);
    let silent = !outbound && Some(address) == silent_tests_in && is_test_body(body);
    let rx = mutation.rx.as_ref();
    // Named, so that a column and its value are written side by side: forty
    // positional parameters would let two of a kind change places unseen.
    // A fresh row reports its own transmission until an edit or a resend
    // re-aims it, so its delivery pointer starts as its own identity.
    connection.execute(
        "INSERT INTO chat_message (
            owner_identity_id, session_id, handle, conversation_address, sender_address,
            direction, message_type, wire_id, epoch, client_token,
            sender_handle, regarding_handle, background_color, text_color, body,
            complete, present_fragments, fragment_count, finalized,
            delivery_state, deleted, created_at_ms, presence, received_late,
            sender_hint, rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count,
            rx_route_hints, rx_source_authenticated,
            is_reaction, regarding_wire_id, regarding_direction, regarding_sender_hint,
            regarding_target_session_id, regarding_target_handle,
            delivery_session_id, delivery_handle, silent,
            regarding_unknown, unknown_original, forward_secret
        ) VALUES (
            :owner_identity_id, :session_id, :handle, :conversation_address, :sender_address,
            :direction, :message_type, :wire_id, :epoch, :client_token,
            :sender_handle, :regarding_handle, :background_color, :text_color, :body,
            :complete, :present_fragments, :fragment_count, :finalized,
            :delivery_state, 0, :created_at_ms, :presence, :received_late,
            :sender_hint, :rx_rssi_dbm, :rx_snr_cb, :rx_lqi, :rx_hop_count,
            :rx_route_hints, :rx_source_authenticated,
            :is_reaction, :regarding_wire_id, :regarding_direction, :regarding_sender_hint,
            :regarding_target_session_id, :regarding_target_handle,
            :session_id, :handle, :silent,
            :regarding_unknown, :unknown_original, :forward_secret
        )
        ON CONFLICT(owner_identity_id, session_id, handle) DO UPDATE SET
            body = excluded.body,
            complete = excluded.complete,
            present_fragments = excluded.present_fragments,
            fragment_count = excluded.fragment_count,
            finalized = excluded.finalized,
            message_type = excluded.message_type,
            sender_handle = excluded.sender_handle,
            background_color = excluded.background_color,
            text_color = excluded.text_color,
            presence = excluded.presence,
            received_late = MAX(chat_message.received_late, excluded.received_late),
            regarding_unknown = MAX(chat_message.regarding_unknown, excluded.regarding_unknown),
            unknown_original = MAX(chat_message.unknown_original, excluded.unknown_original),
            -- A placeholder filled in later carries the metadata of the
            -- frame that filled it; keep whichever row has any.
            sender_hint = COALESCE(excluded.sender_hint, chat_message.sender_hint),
            rx_rssi_dbm = COALESCE(excluded.rx_rssi_dbm, chat_message.rx_rssi_dbm),
            rx_snr_cb = COALESCE(excluded.rx_snr_cb, chat_message.rx_snr_cb),
            rx_lqi = COALESCE(excluded.rx_lqi, chat_message.rx_lqi),
            rx_hop_count = COALESCE(excluded.rx_hop_count, chat_message.rx_hop_count),
            rx_route_hints = COALESCE(excluded.rx_route_hints, chat_message.rx_route_hints),
            rx_source_authenticated = COALESCE(
                excluded.rx_source_authenticated, chat_message.rx_source_authenticated
            ),
            -- So does what it is about: a repaired gap may turn out to be a
            -- reply or a reaction.
            is_reaction = MAX(chat_message.is_reaction, excluded.is_reaction),
            regarding_handle = COALESCE(excluded.regarding_handle, chat_message.regarding_handle),
            regarding_wire_id =
                COALESCE(excluded.regarding_wire_id, chat_message.regarding_wire_id),
            regarding_direction =
                COALESCE(excluded.regarding_direction, chat_message.regarding_direction),
            regarding_sender_hint =
                COALESCE(excluded.regarding_sender_hint, chat_message.regarding_sender_hint),
            regarding_target_session_id = COALESCE(
                excluded.regarding_target_session_id, chat_message.regarding_target_session_id
            ),
            regarding_target_handle = COALESCE(
                excluded.regarding_target_handle, chat_message.regarding_target_handle
            ),
            silent = MAX(chat_message.silent, excluded.silent),
            forward_secret = COALESCE(excluded.forward_secret, chat_message.forward_secret)",
        named_params! {
            ":owner_identity_id": owner_identity_id,
            ":session_id": session_id,
            ":handle": mutation.handle,
            ":conversation_address": address,
            ":sender_address": mutation.sender_address,
            ":direction": direction_code(direction),
            ":message_type": mutation.message_type,
            ":wire_id": mutation.wire_id,
            ":epoch": mutation.epoch,
            ":client_token": mutation.client_token,
            ":sender_handle": mutation.sender_handle,
            ":regarding_handle": mutation.regarding_handle,
            ":background_color": nullable_blob(mutation.background_color.as_deref()),
            ":text_color": nullable_blob(mutation.text_color.as_deref()),
            ":body": body,
            ":complete": mutation.complete,
            ":present_fragments": mutation.present_fragments,
            ":fragment_count": mutation.fragment_count,
            ":finalized": mutation.finalized,
            ":delivery_state": outbound.then_some(MobileStoredChatDeliveryState::Pending.as_str()),
            ":created_at_ms": now_ms - buffered_age_ms,
            ":presence": presence_code(mutation.presence),
            ":received_late": mutation.received_late,
            ":sender_hint": nullable_blob(mutation.sender_hint.as_deref()),
            ":rx_rssi_dbm": rx.and_then(|rx| rx.rssi_dbm),
            ":rx_snr_cb": rx.and_then(|rx| rx.snr_centibels),
            ":rx_lqi": rx.and_then(|rx| rx.lqi),
            ":rx_hop_count": rx.and_then(|rx| rx.hop_count),
            ":rx_route_hints": rx.and_then(|rx| pack_route_hints(&rx.route_hints)),
            ":rx_source_authenticated": rx.map(|rx| rx.source_authenticated),
            ":is_reaction": is_reaction,
            ":regarding_wire_id": mutation.regarding_wire_id,
            ":regarding_direction": mutation.regarding_direction.map(direction_code),
            ":regarding_sender_hint": nullable_blob(mutation.regarding_sender_hint.as_deref()),
            ":regarding_target_session_id": target.as_ref().map(|target| target.session_id.as_str()),
            ":regarding_target_handle": target.as_ref().map(|target| target.handle),
            ":silent": silent,
            ":regarding_unknown": mutation.regarding_unknown,
            ":unknown_original": mutation.unknown_original,
            ":forward_secret": mutation.forward_secret,
        },
    )?;
    // A reaction or a reply can outrun the message it is about: repaired
    // gaps and channel-group reordering both do it. Whenever a real message
    // lands, adopt whatever was already waiting on it.
    if !is_reaction && let Some(wire_id) = mutation.wire_id {
        bind_pending_regarding(
            connection,
            owner_identity_id,
            session_id,
            mutation.handle,
            address,
            wire_id,
            outbound,
            nullable_blob(mutation.sender_hint.as_deref()),
        )?;
    }
    Ok(())
}

/// An `UpdateBody`: a fragmented message completing, or its notify
/// deadline passing. Presence is left as it is, and a late flag is never
/// cleared. A row that is not there is not an error.
fn update_body(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    mutation: &MobileChatMutationRecord,
    silent_tests_in: Option<&str>,
) -> Result<(), MobileStoreError> {
    let Some(body) = mutation.body.as_deref() else {
        return Ok(());
    };
    let rx = mutation.rx.as_ref();
    connection.execute(
        "UPDATE chat_message SET body = ?1, complete = ?2, present_fragments = ?3,
            fragment_count = ?4, finalized = ?5,
            received_late = MAX(received_late, ?6),
            rx_rssi_dbm = COALESCE(?7, rx_rssi_dbm),
            rx_snr_cb = COALESCE(?8, rx_snr_cb),
            rx_lqi = COALESCE(?9, rx_lqi),
            rx_hop_count = COALESCE(?10, rx_hop_count),
            rx_route_hints = COALESCE(?11, rx_route_hints),
            rx_source_authenticated = COALESCE(?12, rx_source_authenticated),
            -- What completes in EMERGENCY's conversation, inbound, as a
            -- test message no one asked to hear of.
            silent = MAX(silent, direction = 0 AND conversation_address IS ?13 AND ?14)
        WHERE owner_identity_id = ?15 AND session_id = ?16 AND handle = ?17",
        params![
            body,
            mutation.complete,
            mutation.present_fragments,
            mutation.fragment_count,
            mutation.finalized,
            mutation.received_late,
            rx.and_then(|rx| rx.rssi_dbm),
            rx.and_then(|rx| rx.snr_centibels),
            rx.and_then(|rx| rx.lqi),
            rx.and_then(|rx| rx.hop_count),
            rx.and_then(|rx| pack_route_hints(&rx.route_hints)),
            rx.map(|rx| rx.source_authenticated),
            silent_tests_in,
            is_test_body(body),
            owner_identity_id,
            session_id,
            mutation.handle,
        ],
    )?;
    Ok(())
}

/// An `Edit` or a `Delete`. A delete leaves a tombstone: the row stays,
/// with its body emptied and `deleted` set, so the transcript can say a
/// message was taken back. Returns whether an edit of a message this phone
/// never stored was materialized as that message.
fn revise_message(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    mutation: &MobileChatMutationRecord,
    now_ms: i64,
) -> Result<bool, MobileStoreError> {
    let is_edit = mutation.kind == MobileChatMutationKind::Edit;
    let body = if is_edit {
        mutation.body.as_deref().unwrap_or("")
    } else {
        ""
    };
    let Some(target) = edit_target_rowid(connection, owner_identity_id, session_id, mutation)?
    else {
        // The edit names a message this phone never stored. That is not
        // stray metadata: it is how a resend arrives when both the original
        // and the engine's chance to open a gap for it are gone (a new
        // conversation, or any app relaunch, since inbound stream state is
        // engine memory). The edit carries the message's whole current
        // content, so it is kept as the message rather than thrown away. A
        // delete of nothing stays a no-op.
        return materialize_orphan_edit(
            connection,
            owner_identity_id,
            session_id,
            mutation,
            now_ms,
        );
    };
    // The first edit of the sender's own message keeps its pre-edit text
    // (`body` on the right-hand side reads the row before this update), so
    // the sender can still review it; the resend archive only ever holds
    // the edited content.
    //
    // An edit that leaves the text exactly as it stands changed nothing,
    // and is not marked as an edit: that is the shape a resend takes on the
    // wire, and there is no earlier version for anyone to go back to.
    //
    // An edit of ours says whether what the message now reads went under a
    // session with forward secrecy.
    connection.execute(
        "UPDATE chat_message SET
            original_body = CASE WHEN ?1 = 1 AND direction = 1 AND body <> ?2
                THEN COALESCE(original_body, body)
                ELSE original_body END,
            body = ?2, deleted = ?3,
            edited = MAX(edited, CASE WHEN ?1 = 1 AND body <> ?2 THEN 1 ELSE 0 END),
            forward_secret = COALESCE(?4, forward_secret)
        WHERE rowid = ?5",
        params![is_edit, body, !is_edit, mutation.forward_secret, target],
    )?;
    if is_edit {
        adopt_delivery(
            connection,
            owner_identity_id,
            target,
            session_id,
            mutation.handle,
            mutation.fragment_count,
            false,
        )?;
    }
    Ok(false)
}

/// Store an inbound edit whose original this phone never had as the
/// message itself, returning whether it did.
///
/// An edit can reach a receiver holding nothing for it to revise: the
/// original never arrived, and no gap placeholder was reserved when the
/// edit's own sequence advance set a fresh baseline. The row is keyed by
/// the edit's own session and handle (its only durable identity here) but
/// carries the *original's* wire ID, so later edits, deletes, and
/// reactions naming that ID resolve to it, and reactions already waiting
/// on it are adopted the way any late message adopts them. It is marked
/// received late, which it is, and as an edit of something unknown, which
/// is what its bubble says.
///
/// Inbound originals only: an unresolved edit of one of our own messages
/// describes a message this identity never sent, and is dropped. An empty
/// body has nothing to keep.
fn materialize_orphan_edit(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    mutation: &MobileChatMutationRecord,
    now_ms: i64,
) -> Result<bool, MobileStoreError> {
    let (MobileChatMutationKind::Edit, Some(body), Some(MobileChatDirection::Inbound)) = (
        mutation.kind,
        mutation.body.as_deref(),
        mutation.original_direction,
    ) else {
        return Ok(false);
    };
    let (false, Some(wire_id), Some(address)) = (
        body.is_empty(),
        mutation.original_wire_id,
        mutation.conversation_address.as_deref(),
    ) else {
        return Ok(false);
    };
    let sender_hint = nullable_blob(mutation.original_sender_hint.as_deref());
    let inserted = connection.execute(
        "INSERT OR IGNORE INTO chat_message (
            owner_identity_id, session_id, handle, conversation_address,
            direction, wire_id, sender_hint, body, complete,
            deleted, created_at_ms, presence, received_late, is_reaction,
            delivery_session_id, delivery_handle, unknown_original
        ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, 1, 0, ?8, 0, 1, 0, ?2, ?3, 1)",
        params![
            owner_identity_id,
            session_id,
            mutation.handle,
            address,
            wire_id,
            sender_hint,
            body,
            now_ms
        ],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    bind_pending_regarding(
        connection,
        owner_identity_id,
        session_id,
        mutation.handle,
        address,
        wire_id,
        false,
        sender_hint,
    )?;
    Ok(true)
}

/// Which stored row an edit or a delete revises.
///
/// A live handle names a row this facade session wrote. Otherwise the
/// engine exported the original's wire reference, and the row it names is
/// the newest with that ID on that stream: wire IDs recycle serially
/// within a stream, so the newest epoch and row is the one still
/// referenceable.
fn edit_target_rowid(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    mutation: &MobileChatMutationRecord,
) -> Result<Option<i64>, MobileStoreError> {
    if let Some(original) = mutation.original_handle {
        return Ok(connection
            .query_row(
                "SELECT rowid FROM chat_message
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?",
                params![owner_identity_id, session_id, original],
                |row| row.get(0),
            )
            .optional()?);
    }
    let (Some(wire_id), Some(direction), Some(address)) = (
        mutation.original_wire_id,
        mutation.original_direction,
        mutation.conversation_address.as_deref(),
    ) else {
        return Ok(None);
    };
    Ok(connection
        .query_row(
            "SELECT rowid FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND direction = ? AND wire_id = ?
            ORDER BY epoch DESC, created_at_ms DESC, rowid DESC
            LIMIT 1",
            params![
                owner_identity_id,
                address,
                direction_code(direction),
                wire_id
            ],
            |row| row.get(0),
        )
        .optional()?)
}

/// Aim an outbound message's delivery pointer at a new transmission of it:
/// an edit's frames, now carrying the row's content, or the frames a resend
/// put back on the air.
///
/// An edit inserts no row: it revises the original's stored body. Its
/// frames, though, are tracked under the edit's own engine handle, so
/// without this the row would keep waiting on evidence for a transmission
/// nobody is making any more, and an edit that failed could never say so.
/// A resend after a restart is tracked under the handle the engine took the
/// message back as. Only the pointer moves: the row's key is its compose
/// identity, which further edits and reactions still name.
///
/// An edit's superseded attempt goes with it whole. A resend sends only
/// what was not acknowledged, so with `keeping_acknowledged` the fragments
/// already acknowledged move to the new pointer and only the rest are
/// forgotten, under either pointer: replaying the move lands in the same
/// place.
///
/// Scoped to outbound rows in SQL: an inbound edit only ever revises its
/// own sender's inbound rows, which carry no delivery state.
///
/// `fragment_count` is how many frames an edit put in flight. Its content
/// is fragmented under its own encoding overhead, so the count the
/// original compose stamped no longer describes what is on the air.
fn adopt_delivery(
    connection: &Connection,
    owner_identity_id: &str,
    target_rowid: i64,
    session_id: &str,
    handle: u32,
    fragment_count: Option<u8>,
    keeping_acknowledged: bool,
) -> Result<(), MobileStoreError> {
    if keeping_acknowledged {
        connection.execute(
            "UPDATE OR REPLACE chat_delivery_fragment SET session_id = ?, handle = ?
            WHERE owner_identity_id = ? AND state = 'acknowledged'
                AND (session_id, handle) = (
                    SELECT delivery_session_id, delivery_handle FROM chat_message
                    WHERE rowid = ? AND direction = 1
                )",
            params![session_id, handle, owner_identity_id, target_rowid],
        )?;
    }
    connection.execute(
        "DELETE FROM chat_delivery_fragment
        WHERE owner_identity_id = ?1
            AND (?3 = 0 OR state <> 'acknowledged')
            AND (
                (session_id, handle) = (
                    SELECT delivery_session_id, delivery_handle FROM chat_message
                    WHERE rowid = ?2 AND direction = 1
                )
                OR (?3 = 1 AND session_id = ?4 AND handle = ?5)
            )",
        params![
            owner_identity_id,
            target_rowid,
            keeping_acknowledged,
            session_id,
            handle
        ],
    )?;
    connection.execute(
        "UPDATE chat_message
        SET delivery_session_id = ?, delivery_handle = ?,
            delivery_state = 'pending', delivered_late = 0, delivered_flooded = 0,
            fragment_count = COALESCE(?, fragment_count)
        WHERE rowid = ? AND direction = 1",
        params![session_id, handle, fragment_count, target_rowid],
    )?;
    Ok(())
}

/// Resolve one message's delivery state from the fragment evidence now
/// recorded against the transmission it reports. The keys are always
/// transmission keys, matched through the delivery pointer, never assumed
/// to be a row's own.
///
/// Every fragment acknowledged wins over any earlier failure, so a
/// late-acknowledged message recovers to `acknowledged`, and one that
/// recovers from a failure is flagged delivered late. Short of that, one
/// fragment that never went out where the peer could read it
/// (`undelivered`) means the message did not arrive, which outranks one
/// that went out unacknowledged (`failed`) and may have.
///
/// SQLite evaluates every SET right-hand side against the row before the
/// update, so `delivery_state` below reads the old value while the counts
/// read the fragments as they now stand. `now_ms` restamps the progress
/// instant while nothing has been sent, so it holds the moment the first
/// frame was.
fn recompute_delivery_state(
    connection: &Connection,
    owner_identity_id: &str,
    delivery_session_id: &str,
    delivery_handle: u32,
    now_ms: i64,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "UPDATE chat_message SET
            delivery_progress_at_ms = CASE
                WHEN chat_message.delivery_state = 'pending' THEN ?4
                ELSE chat_message.delivery_progress_at_ms
            END,
            delivered_flooded = EXISTS (
                SELECT 1 FROM chat_delivery_fragment f
                WHERE f.owner_identity_id = chat_message.owner_identity_id
                    AND f.session_id = chat_message.delivery_session_id
                    AND f.handle = chat_message.delivery_handle
                    AND f.state = 'acknowledged'
                    AND f.via_flood = 1
            ),
            delivered_late = CASE
                WHEN chat_message.delivery_state IN ('failed', 'undelivered')
                    AND (
                        SELECT COUNT(*) FROM chat_delivery_fragment f
                        WHERE f.owner_identity_id = chat_message.owner_identity_id
                            AND f.session_id = chat_message.delivery_session_id
                            AND f.handle = chat_message.delivery_handle
                            AND f.state = 'acknowledged'
                    ) >= COALESCE(chat_message.fragment_count, 1) THEN 1
                ELSE chat_message.delivered_late
            END,
            delivery_state = CASE
            WHEN (
                SELECT COUNT(*) FROM chat_delivery_fragment f
                WHERE f.owner_identity_id = chat_message.owner_identity_id
                    AND f.session_id = chat_message.delivery_session_id
                    AND f.handle = chat_message.delivery_handle
                    AND f.state = 'acknowledged'
            ) >= COALESCE(chat_message.fragment_count, 1) THEN 'acknowledged'
            WHEN EXISTS (
                SELECT 1 FROM chat_delivery_fragment f
                WHERE f.owner_identity_id = chat_message.owner_identity_id
                    AND f.session_id = chat_message.delivery_session_id
                    AND f.handle = chat_message.delivery_handle
                    AND f.state = 'undelivered'
            ) THEN 'undelivered'
            WHEN EXISTS (
                SELECT 1 FROM chat_delivery_fragment f
                WHERE f.owner_identity_id = chat_message.owner_identity_id
                    AND f.session_id = chat_message.delivery_session_id
                    AND f.handle = chat_message.delivery_handle
                    AND f.state = 'failed'
            ) THEN 'failed'
            WHEN EXISTS (
                SELECT 1 FROM chat_delivery_fragment f
                WHERE f.owner_identity_id = chat_message.owner_identity_id
                    AND f.session_id = chat_message.delivery_session_id
                    AND f.handle = chat_message.delivery_handle
                    AND f.state IN ('sent', 'acknowledged')
            ) THEN 'sent'
            ELSE 'pending'
        END
        WHERE owner_identity_id = ?1 AND delivery_session_id = ?2 AND delivery_handle = ?3",
        params![
            owner_identity_id,
            delivery_session_id,
            delivery_handle,
            now_ms
        ],
    )?;
    Ok(())
}

/// The delivery state of whichever row now reports this transmission,
/// matched through the delivery pointer: evidence always arrives keyed by
/// the transmission that earned it.
fn delivery_state(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    handle: u32,
) -> Result<Option<MobileStoredChatDeliveryState>, MobileStoreError> {
    Ok(connection
        .query_row(
            "SELECT delivery_state FROM chat_message
            WHERE owner_identity_id = ? AND delivery_session_id = ? AND delivery_handle = ?",
            params![owner_identity_id, session_id, handle],
            |row| row.get(0).map(MobileStoredChatDeliveryState::stored),
        )
        .optional()?
        .flatten())
}

/// Whether a delivery state is one of the two that give up: `undelivered`
/// (it did not arrive) or `failed` (it went out unacknowledged and may
/// have).
fn is_failure(state: Option<MobileStoredChatDeliveryState>) -> bool {
    state.is_some_and(MobileStoredChatDeliveryState::is_failure)
}

/// What a just-failed message was, when it is worth a notice. A reaction
/// that never landed is not: nobody wrote it as a message, and it cannot
/// usefully be resent.
fn failed_message(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    handle: u32,
) -> Result<Option<MobileStoredChatDeliveryFailureRecord>, MobileStoreError> {
    Ok(connection
        .query_row(
            "SELECT conversation_address, body, delivery_state = 'undelivered' FROM chat_message
            WHERE owner_identity_id = ? AND delivery_session_id = ? AND delivery_handle = ?
                AND direction = 1 AND deleted = 0 AND is_reaction = 0 AND body <> ''",
            params![owner_identity_id, session_id, handle],
            |row| {
                Ok(MobileStoredChatDeliveryFailureRecord {
                    conversation_address: row.get(0)?,
                    body: row.get(1)?,
                    undelivered: row.get::<_, Option<i64>>(2)?.unwrap_or(0) != 0,
                })
            },
        )
        .optional()?)
}

/// Which stored row a reaction or a reply is about.
///
/// A live handle names a row this session wrote. Otherwise the reference
/// arrives as wire coordinates, and the row it names is the newest
/// non-reaction message holding that ID on that stream: wire IDs recycle
/// serially, so the newest is the only one still referenceable. `None`
/// when the target has not been stored yet; [`bind_pending_regarding`]
/// adopts those once it is.
///
/// A sender that predates the two-octet form names its own messages in the
/// form that means ours, so a one-to-one reference to our own stream that
/// matches nothing there means theirs. Inbound rows without a hint are
/// one-to-one only. This goes when those senders do.
fn resolve_regarding_target(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    conversation_address: &str,
    mutation: &MobileChatMutationRecord,
) -> Result<Option<MobileStoredChatMessageRefRecord>, MobileStoreError> {
    if let Some(handle) = mutation.regarding_handle {
        return Ok(Some(MobileStoredChatMessageRefRecord {
            session_id: session_id.to_owned(),
            handle,
        }));
    }
    let (Some(wire_id), Some(direction)) =
        (mutation.regarding_wire_id, mutation.regarding_direction)
    else {
        return Ok(None);
    };
    let found = regarding_target_row(
        connection,
        owner_identity_id,
        conversation_address,
        direction,
        wire_id,
        nullable_blob(mutation.regarding_sender_hint.as_deref()),
    )?;
    if found.is_some() || direction != MobileChatDirection::Outbound {
        return Ok(found);
    }
    regarding_target_row(
        connection,
        owner_identity_id,
        conversation_address,
        MobileChatDirection::Inbound,
        wire_id,
        None,
    )
}

/// The newest non-reaction row holding `wire_id` on one stream.
fn regarding_target_row(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
    direction: MobileChatDirection,
    wire_id: u8,
    sender_hint: Option<&[u8]>,
) -> Result<Option<MobileStoredChatMessageRefRecord>, MobileStoreError> {
    // `IS` rather than `=`, so a conversation without hints (every direct
    // one, and our own side of a group) matches NULL against NULL.
    Ok(connection
        .query_row(
            "SELECT session_id, handle FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND direction = ? AND wire_id = ? AND is_reaction = 0
                AND sender_hint IS ?
            ORDER BY epoch DESC, created_at_ms DESC, rowid DESC
            LIMIT 1",
            params![
                owner_identity_id,
                conversation_address,
                direction_code(direction),
                wire_id,
                sender_hint
            ],
            |row| {
                Ok(MobileStoredChatMessageRefRecord {
                    session_id: row.get(0)?,
                    handle: row.get(1)?,
                })
            },
        )
        .optional()?)
}

/// Adopt the reactions and replies that arrived before the message they
/// are about, now that it has: every row still waiting on this wire ID, on
/// this stream, from this sender.
#[allow(clippy::too_many_arguments)]
fn bind_pending_regarding(
    connection: &Connection,
    owner_identity_id: &str,
    session_id: &str,
    handle: u32,
    conversation_address: &str,
    wire_id: u8,
    outbound: bool,
    sender_hint: Option<&[u8]>,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "UPDATE chat_message
        SET regarding_target_session_id = ?1, regarding_target_handle = ?2
        WHERE owner_identity_id = ?3 AND conversation_address = ?4
            AND regarding_target_session_id IS NULL
            AND regarding_wire_id = ?5 AND regarding_direction = ?6
            AND regarding_sender_hint IS ?7
            AND NOT (session_id = ?1 AND handle = ?2)",
        params![
            session_id,
            handle,
            owner_identity_id,
            conversation_address,
            wire_id,
            outbound,
            sender_hint
        ],
    )?;
    Ok(())
}

/// Whether a body marks a message on `EMERGENCY` as a test message.
fn is_test_body(body: &str) -> bool {
    umsh_text::text_message::is_test_body(body.as_bytes())
}

#[cfg(test)]
mod tests;
