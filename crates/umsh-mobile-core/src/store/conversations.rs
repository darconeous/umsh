//! Conversations: one per peer (`direct_conversation`) and one per channel
//! (`channel_conversation`), each with its draft and read cursor, and the
//! list rows' previews and unread counts.
//!
//! A conversation's messages are keyed by its address, not its row: a
//! direct conversation's address is the peer's public address, a channel
//! conversation's the address the mesh engine derived from the channel's
//! key. So deleting a conversation purges its history by address, and the
//! calls that serve both kinds take the address.

use rusqlite::{Connection, OptionalExtension, params};

use super::channels::{canonical_uuid, channel_id, channels};
use super::chat::is_status_sql;
use super::peers::{COMPANION_RADIO, NODE_COLUMN_COUNT, list_nodes, node_columns, stored_node};
use super::repeaters::all_peer_repeater_entries;
use super::{
    MobileAppStore, MobileStoreError, MobileStoredChannelRecord, MobileStoredNodeRecord,
    MobileStoredPeerRepeaterReportRecord,
};

/// The newest message in a conversation, reduced to what a list row draws.
///
/// This is the literal last row in transcript order, tombstones and gap
/// placeholders included: a list preview says what the bottom of the
/// transcript is, and a deleted last message reads as "Message deleted"
/// rather than silently promoting the one before it. Reactions are not
/// rows of the transcript and never are the preview.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredConversationPreviewRecord {
    pub created_at_ms: i64,
    pub body: String,
    pub is_outbound: bool,
    pub is_deleted: bool,
    /// Who sent it, for a group conversation: the resolved address once
    /// known, and the hint the wire always carries.
    pub sender_address: Option<String>,
    pub sender_hint: Option<Vec<u8>>,
    /// Status text, which reads as its sender's name followed by its body.
    pub is_status: bool,
}

/// A conversation with one peer.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredDirectConversationRecord {
    pub id: i64,
    pub node: MobileStoredNodeRecord,
    pub draft_text: String,
    /// When this conversation was last read. Messages newer than this are
    /// unread; a conversation the user has never opened reads as all-unread
    /// from its first message.
    pub last_read_at_ms: i64,
    /// When the conversation row was created—the activity time of a
    /// conversation that has no messages yet.
    pub created_at_ms: i64,
    /// Whether this conversation may raise a notification. Defaults on,
    /// unlike a channel's, which defaults off.
    pub notifications_enabled: bool,
    pub last_message: Option<MobileStoredConversationPreviewRecord>,
    /// Inbound messages newer than the read cursor that a person reads:
    /// not deleted, not a gap or unavailable marker, not a reaction, not
    /// silent.
    pub unread_count: i64,
}

/// A channel's group conversation. Its other end is a channel rather than a
/// node, which is why it is not a row in `direct_conversation`.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChannelConversationRecord {
    pub id: i64,
    /// The channel's ID, uppercase.
    pub channel_id: String,
    /// The address the mesh engine keys this conversation's records by.
    pub conversation_address: String,
    pub draft_text: String,
    pub last_read_at_ms: i64,
    /// When the conversation row was created—the activity time of a
    /// conversation that has no messages yet.
    pub created_at_ms: i64,
    pub last_message: Option<MobileStoredConversationPreviewRecord>,
    /// Counted as a direct conversation's is.
    pub unread_count: i64,
}

/// Everything the interface lists for an identity, read in one
/// transaction.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileApplicationRecords {
    pub peers: Vec<MobileStoredNodeRecord>,
    pub channels: Vec<MobileStoredChannelRecord>,
    pub conversations: Vec<MobileStoredDirectConversationRecord>,
    pub channel_conversations: Vec<MobileStoredChannelConversationRecord>,
    pub reports: Vec<MobileStoredPeerRepeaterReportRecord>,
}

#[uniffi::export]
impl MobileAppStore {
    /// One read transaction over every list: a concurrent writer cannot
    /// produce a mixture of old and new lists for the interface. With
    /// `conversations_only`, `peers` and `reports` are left empty and are
    /// not read.
    #[uniffi::method(default(conversations_only = false))]
    pub fn application_records(
        &self,
        owner_identity_id: String,
        conversations_only: bool,
    ) -> Result<MobileApplicationRecords, MobileStoreError> {
        self.read(|transaction| {
            let owner = owner_identity_id.as_str();
            let records = MobileApplicationRecords {
                peers: if conversations_only {
                    Vec::new()
                } else {
                    list_nodes(transaction, owner)?
                },
                channels: channels(transaction, owner)?,
                conversations: list_direct_conversations(transaction, owner)?,
                channel_conversations: list_channel_conversations(transaction, owner)?,
                reports: if conversations_only {
                    Vec::new()
                } else {
                    all_peer_repeater_entries(transaction, owner)?
                },
            };
            Ok(records)
        })
    }

    /// The conversation with a peer, created if there is none, and its ID.
    /// `created_at_ms` is used only when it is created. Fails with
    /// [`MobileStoreError::RecordNotFound`] when the identity has no row
    /// for the peer.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn ensure_direct_conversation(
        &self,
        owner_identity_id: String,
        peer_address: String,
        created_at_ms: i64,
    ) -> Result<i64, MobileStoreError> {
        self.write(|transaction| {
            transaction.execute(
            "INSERT OR IGNORE INTO direct_conversation (owner_identity_id, node_id, created_at_ms)
            SELECT ?1, id, ?2 FROM node
            WHERE owner_identity_id = ?1 AND public_address = ?3",
            params![owner_identity_id, created_at_ms, peer_address],
        )?;
            let id = transaction
                .query_row(
                    "SELECT c.id FROM direct_conversation c JOIN node n ON n.id = c.node_id
                    WHERE c.owner_identity_id = ? AND n.public_address = ?",
                    params![owner_identity_id, peer_address],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(MobileStoreError::RecordNotFound)?;
            Ok(id)
        })
    }

    /// Every direct conversation of the identity, newest first, each with
    /// its peer, preview, and unread count.
    pub fn list_direct_conversations(
        &self,
        owner_identity_id: String,
    ) -> Result<Vec<MobileStoredDirectConversationRecord>, MobileStoreError> {
        list_direct_conversations(&self.connection(), &owner_identity_id)
    }

    /// The channel conversation for a channel, created if this is the first
    /// time the user has entered it, and its ID. Channels are joined without
    /// a chat; the conversation appears when someone asks for one, or when
    /// a message arrives. An existing conversation keeps its address and
    /// creation time. Fails with [`MobileStoreError::RecordNotFound`] when
    /// there is no such channel.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn ensure_channel_conversation(
        &self,
        owner_identity_id: String,
        channel_id: String,
        conversation_address: String,
        created_at_ms: i64,
    ) -> Result<i64, MobileStoreError> {
        let channel_id = self::channel_id(&channel_id)?;
        self.write(|transaction| {
            let known = transaction
                .query_row(
                    "SELECT 1 FROM channel WHERE id = ?",
                    params![channel_id],
                    |_| Ok(()),
                )
                .optional()?;
            if known.is_none() {
                return Err(MobileStoreError::RecordNotFound);
            }
            transaction.execute(
                "INSERT OR IGNORE INTO channel_conversation (
                    owner_identity_id, channel_id, conversation_address, created_at_ms
                ) VALUES (?, ?, ?, ?)",
                params![
                    owner_identity_id,
                    channel_id,
                    conversation_address,
                    created_at_ms
                ],
            )?;
            let id = transaction.query_row(
            "SELECT id FROM channel_conversation WHERE owner_identity_id = ? AND channel_id = ?",
            params![owner_identity_id, channel_id],
            |row| row.get(0),
        )?;
            Ok(id)
        })
    }

    /// Every channel conversation of the identity, newest first, each with
    /// its preview and unread count. A row whose channel ID is not a UUID
    /// is left out.
    pub fn list_channel_conversations(
        &self,
        owner_identity_id: String,
    ) -> Result<Vec<MobileStoredChannelConversationRecord>, MobileStoreError> {
        list_channel_conversations(&self.connection(), &owner_identity_id)
    }

    /// Remove a channel conversation and its local transcript. Leaving a
    /// group chat is not leaving the channel: the key stays, so traffic
    /// still arrives and a later message opens the conversation again. A
    /// conversation that does not exist is not an error.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn delete_channel_conversation(
        &self,
        owner_identity_id: String,
        conversation_id: i64,
    ) -> Result<(), MobileStoreError> {
        self.erase(|transaction| {
            let Some(address) = transaction
                .query_row(
                    "SELECT conversation_address FROM channel_conversation
                    WHERE id = ? AND owner_identity_id = ?",
                    params![conversation_id, owner_identity_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            else {
                return Ok(());
            };
            purge_conversation_history(transaction, &owner_identity_id, &address)?;
            transaction.execute(
                "DELETE FROM channel_conversation WHERE id = ? AND owner_identity_id = ?",
                params![conversation_id, owner_identity_id],
            )?;
            Ok(())
        })
    }

    /// Erase a conversation's messages while keeping the conversation
    /// itself. Addressed rather than keyed by row so one call serves both
    /// kinds.
    ///
    /// Outbound stream checkpoints are kept, for the same reason deleting a
    /// conversation keeps them: sequence continuity with the far end has to
    /// outlive the transcript, or the next message would announce a
    /// Sequence Reset. Archived outbound payloads do go, so a later resend
    /// request for a cleared message is answered Unavailable—the protocol
    /// handles that, and keeping erased content on disk would not be
    /// acceptable.
    pub fn clear_conversation_messages(
        &self,
        owner_identity_id: String,
        conversation_address: String,
    ) -> Result<(), MobileStoreError> {
        self.erase(|transaction| {
            purge_conversation_history(transaction, &owner_identity_id, &conversation_address)?;
            Ok(())
        })
    }

    /// Fails with [`MobileStoreError::RecordNotFound`] when the identity
    /// has no such channel conversation.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn update_channel_draft(
        &self,
        owner_identity_id: String,
        conversation_id: i64,
        text: String,
    ) -> Result<(), MobileStoreError> {
        let changes = self.connection().execute(
            "UPDATE channel_conversation SET draft_text = ?
            WHERE id = ? AND owner_identity_id = ?",
            params![text, conversation_id, owner_identity_id],
        )?;
        if changes != 1 {
            return Err(MobileStoreError::RecordNotFound);
        }
        Ok(())
    }

    /// Mark everything in a conversation read as of `read_at_ms`.
    /// Addressed rather than keyed by row so one call serves both kinds of
    /// conversation. An address with no conversation is not an error.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn mark_conversation_read(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        read_at_ms: i64,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            transaction.execute(
                "UPDATE direct_conversation SET last_read_at_ms = ?1
                WHERE owner_identity_id = ?2 AND node_id IN (
                    SELECT id FROM node
                    WHERE owner_identity_id = ?2 AND public_address = ?3
                )",
                params![read_at_ms, owner_identity_id, conversation_address],
            )?;
            transaction.execute(
                "UPDATE channel_conversation SET last_read_at_ms = ?1
                WHERE owner_identity_id = ?2 AND conversation_address = ?3",
                params![read_at_ms, owner_identity_id, conversation_address],
            )?;
            Ok(())
        })
    }

    /// Remove a direct conversation and its local history; the peer's row
    /// stays. Outbound stream checkpoints are deliberately retained:
    /// sequence continuity with the peer must survive the transcript, or
    /// the next message would announce a Sequence Reset. Archived outbound
    /// payloads go with the history, so a late resend request for them is
    /// answered Unavailable—the protocol handles that; keeping deleted
    /// content on disk would not be acceptable. A conversation that does
    /// not exist is not an error.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn delete_direct_conversation(
        &self,
        owner_identity_id: String,
        conversation_id: i64,
    ) -> Result<(), MobileStoreError> {
        self.erase(|transaction| {
            let Some(peer_address) = transaction
                .query_row(
                    "SELECT n.public_address FROM direct_conversation c
                    JOIN node n ON n.id = c.node_id
                    WHERE c.id = ? AND c.owner_identity_id = ?",
                    params![conversation_id, owner_identity_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            else {
                return Ok(());
            };
            purge_conversation_history(transaction, &owner_identity_id, &peer_address)?;
            transaction.execute(
                "DELETE FROM direct_conversation WHERE id = ? AND owner_identity_id = ?",
                params![conversation_id, owner_identity_id],
            )?;
            Ok(())
        })
    }

    /// Delete a peer together with its conversation and local history, in
    /// one transaction. Returns whether there was a peer to delete. Stream
    /// checkpoints are retained (see `delete_direct_conversation`); the
    /// companion radio is refused, returning `false`. What hangs off the
    /// node row—its manual route, management card, cached properties, and
    /// repeater listing—goes with it.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn delete_peer_and_conversation(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<bool, MobileStoreError> {
        self.erase(|transaction| {
            let Some(node_id) = transaction
                .query_row(
                    "SELECT id FROM node
                    WHERE owner_identity_id = ? AND public_address = ?
                        AND (system_role IS NULL OR system_role <> ?)",
                    params![owner_identity_id, public_address, COMPANION_RADIO],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
            else {
                return Ok(false);
            };
            purge_conversation_history(transaction, &owner_identity_id, &public_address)?;
            // The conversation first: it holds the node with ON DELETE RESTRICT.
            transaction.execute(
                "DELETE FROM direct_conversation WHERE owner_identity_id = ? AND node_id = ?",
                params![owner_identity_id, node_id],
            )?;
            transaction.execute("DELETE FROM node WHERE id = ?", params![node_id])?;
            Ok(true)
        })
    }

    /// Turn notifications for one direct conversation on or off. A
    /// conversation that does not exist is not an error.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn set_direct_conversation_notifications(
        &self,
        owner_identity_id: String,
        conversation_id: i64,
        enabled: bool,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "UPDATE direct_conversation SET notifications_enabled = ?
            WHERE id = ? AND owner_identity_id = ?",
            params![enabled, conversation_id, owner_identity_id],
        )?;
        Ok(())
    }

    /// Fails with [`MobileStoreError::RecordNotFound`] when the identity
    /// has no such direct conversation.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn update_draft(
        &self,
        owner_identity_id: String,
        conversation_id: i64,
        text: String,
    ) -> Result<(), MobileStoreError> {
        let changes = self.connection().execute(
            "UPDATE direct_conversation SET draft_text = ?
            WHERE id = ? AND owner_identity_id = ?",
            params![text, conversation_id, owner_identity_id],
        )?;
        if changes != 1 {
            return Err(MobileStoreError::RecordNotFound);
        }
        Ok(())
    }
}

/// The two statements that write a conversation's draft by address, one
/// per kind: `?1` is what the draft becomes, `?2` the owner, `?3` the
/// address. Each appends `condition` to its `WHERE`.
fn draft_updates(set: &str, condition: &str) -> [String; 2] {
    [
        format!(
            "UPDATE direct_conversation SET draft_text = {set}
            WHERE owner_identity_id = ?2 AND node_id IN (
                SELECT id FROM node WHERE owner_identity_id = ?2 AND public_address = ?3
            ) {condition}"
        ),
        format!(
            "UPDATE channel_conversation SET draft_text = {set}
            WHERE owner_identity_id = ?2 AND conversation_address = ?3 {condition}"
        ),
    ]
}

/// A conversation's draft and read time, by address; `None` with no
/// conversation there.
fn draft_and_read_at(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
) -> Result<Option<(String, i64)>, MobileStoreError> {
    Ok(connection
        .query_row(
            "SELECT c.draft_text, c.last_read_at_ms FROM direct_conversation c
                JOIN node n ON n.id = c.node_id
            WHERE c.owner_identity_id = ?1 AND n.owner_identity_id = ?1
                AND n.public_address = ?2
            UNION ALL
            SELECT draft_text, last_read_at_ms FROM channel_conversation
            WHERE owner_identity_id = ?1 AND conversation_address = ?2
            LIMIT 1",
            params![owner_identity_id, conversation_address],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

/// How many messages in a conversation read as unread after `read_at_ms`,
/// counted as the list rows count them.
fn unread_after(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
    read_at_ms: i64,
) -> Result<i64, MobileStoreError> {
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM chat_message
        WHERE owner_identity_id = ? AND conversation_address = ?
            AND direction = 0 AND deleted = 0 AND presence = 0
            AND is_reaction = 0 AND silent = 0
            AND created_at_ms > ?",
        params![owner_identity_id, conversation_address, read_at_ms],
        |row| row.get(0),
    )?)
}

impl MobileAppStore {
    /// Whether a conversation is stored under `conversation_address`: a
    /// direct conversation, or the conversation of a channel the phone has
    /// joined.
    pub(crate) fn conversation_stored(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
    ) -> Result<bool, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT 1 FROM direct_conversation c JOIN node n ON n.id = c.node_id
                WHERE c.owner_identity_id = ?1 AND n.owner_identity_id = ?1
                    AND n.public_address = ?2
                UNION ALL
                SELECT 1 FROM channel_conversation c JOIN channel ch
                    ON ch.id = c.channel_id AND ch.owner_identity_id = c.owner_identity_id
                WHERE c.owner_identity_id = ?1 AND c.conversation_address = ?2
                    AND ch.joined_phone = 1
                LIMIT 1",
                params![owner_identity_id, conversation_address],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// A conversation's draft, by address; `None` with no conversation
    /// there.
    #[cfg(test)]
    pub(crate) fn draft(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
    ) -> Result<Option<String>, MobileStoreError> {
        Ok(
            draft_and_read_at(&self.connection(), owner_identity_id, conversation_address)?
                .map(|(draft, _)| draft),
        )
    }

    /// Make `text` a conversation's draft, as it stands. Whether the stored
    /// text changed; [`MobileStoreError::RecordNotFound`] with no
    /// conversation there.
    pub(crate) fn set_draft(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
        text: &str,
    ) -> Result<bool, MobileStoreError> {
        self.write(|transaction| {
            let Some((stored, _)) =
                draft_and_read_at(transaction, owner_identity_id, conversation_address)?
            else {
                return Err(MobileStoreError::RecordNotFound);
            };
            if stored == text {
                return Ok(false);
            }
            for statement in draft_updates("?1", "") {
                transaction.execute(
                    &statement,
                    params![text, owner_identity_id, conversation_address],
                )?;
            }
            Ok(true)
        })
    }

    /// Keep `text` in a conversation's draft: as the draft when it is
    /// empty, otherwise on a line of its own under it. One statement per
    /// kind, so no other write lands between the read and the write.
    /// [`MobileStoreError::RecordNotFound`] with no conversation there.
    pub(crate) fn append_draft(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
        text: &str,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            let mut changed = 0;
            for statement in draft_updates(
                "CASE WHEN draft_text = '' THEN ?1 ELSE draft_text || char(10) || ?1 END",
                "",
            ) {
                changed += transaction.execute(
                    &statement,
                    params![text, owner_identity_id, conversation_address],
                )?;
            }
            if changed == 0 {
                return Err(MobileStoreError::RecordNotFound);
            }
            Ok(())
        })
    }

    /// Empty a conversation's draft if it still reads `text`. Whether it
    /// did.
    pub(crate) fn clear_draft_if(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
        text: &str,
    ) -> Result<bool, MobileStoreError> {
        self.write(|transaction| {
            let mut changed = 0;
            for statement in draft_updates("''", "AND draft_text = ?1") {
                changed += transaction.execute(
                    &statement,
                    params![text, owner_identity_id, conversation_address],
                )?;
            }
            Ok(changed > 0)
        })
    }

    /// Mark a conversation read as of `read_at_ms`, or with
    /// `never_backward` only when that is later than its read time now.
    /// Whether its unread count changed. An address with no conversation is
    /// not an error, and changes nothing.
    pub(crate) fn mark_read_counting(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
        read_at_ms: i64,
        never_backward: bool,
    ) -> Result<bool, MobileStoreError> {
        self.write(|transaction| {
            let Some((_, read_before)) =
                draft_and_read_at(transaction, owner_identity_id, conversation_address)?
            else {
                return Ok(false);
            };
            let read_at_ms = if never_backward {
                read_at_ms.max(read_before)
            } else {
                read_at_ms
            };
            if read_at_ms == read_before {
                return Ok(false);
            }
            let unread_before = unread_after(
                transaction,
                owner_identity_id,
                conversation_address,
                read_before,
            )?;
            transaction.execute(
                "UPDATE direct_conversation SET last_read_at_ms = ?1
                WHERE owner_identity_id = ?2 AND node_id IN (
                    SELECT id FROM node
                    WHERE owner_identity_id = ?2 AND public_address = ?3
                )",
                params![read_at_ms, owner_identity_id, conversation_address],
            )?;
            transaction.execute(
                "UPDATE channel_conversation SET last_read_at_ms = ?1
                WHERE owner_identity_id = ?2 AND conversation_address = ?3",
                params![read_at_ms, owner_identity_id, conversation_address],
            )?;
            let unread_now = unread_after(
                transaction,
                owner_identity_id,
                conversation_address,
                read_at_ms,
            )?;
            Ok(unread_before != unread_now)
        })
    }
}

impl MobileAppStore {
    /// As [`Self::ensure_channel_conversation`], only while the phone has
    /// joined the channel, as an arrival's conversation is: `None` when it
    /// has not, or there is no such channel. Otherwise whether the
    /// conversation is new.
    pub(crate) fn open_joined_channel_conversation(
        &self,
        owner_identity_id: &str,
        channel_id: &str,
        conversation_address: &str,
        created_at_ms: i64,
    ) -> Result<Option<bool>, MobileStoreError> {
        let channel_id = self::channel_id(channel_id)?;
        self.write(|transaction| {
            let joined = transaction
                .query_row(
                    "SELECT 1 FROM channel
                    WHERE id = ? AND owner_identity_id = ? AND joined_phone = 1",
                    params![channel_id, owner_identity_id],
                    |_| Ok(()),
                )
                .optional()?;
            if joined.is_none() {
                return Ok(None);
            }
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO channel_conversation (
                    owner_identity_id, channel_id, conversation_address, created_at_ms
                ) VALUES (?, ?, ?, ?)",
                params![
                    owner_identity_id,
                    channel_id,
                    conversation_address,
                    created_at_ms
                ],
            )?;
            Ok(Some(inserted > 0))
        })
    }

    /// The ID of the identity's conversation with a peer, or `None`.
    pub(crate) fn direct_conversation_id(
        &self,
        owner_identity_id: &str,
        peer_address: &str,
    ) -> Result<Option<i64>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT c.id FROM direct_conversation c JOIN node n ON n.id = c.node_id
                WHERE c.owner_identity_id = ? AND n.public_address = ?",
                params![owner_identity_id, peer_address],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// The ID and channel of the identity's channel conversation kept under
    /// `conversation_address`, or `None`.
    pub(crate) fn channel_conversation_by_address(
        &self,
        owner_identity_id: &str,
        conversation_address: &str,
    ) -> Result<Option<(i64, String)>, MobileStoreError> {
        let row = self
            .connection()
            .query_row(
                "SELECT id, channel_id FROM channel_conversation
                WHERE owner_identity_id = ? AND conversation_address = ?",
                params![owner_identity_id, conversation_address],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(id, channel_id)| Some((id, canonical_uuid(&channel_id)?))))
    }
}

fn list_direct_conversations(
    connection: &Connection,
    owner_identity_id: &str,
) -> Result<Vec<MobileStoredDirectConversationRecord>, MobileStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT c.id, {node}, c.draft_text, c.last_read_at_ms, c.created_at_ms,
            c.notifications_enabled, {tail}
        FROM direct_conversation c JOIN node n ON n.id = c.node_id
        {join}
        WHERE c.owner_identity_id = ? ORDER BY c.created_at_ms DESC, c.id DESC",
        node = node_columns("n."),
        tail = tail_columns("c.owner_identity_id", "n.public_address"),
        join = tail_join("c.owner_identity_id", "n.public_address"),
    ))?;
    let conversations = statement
        .query_map(params![owner_identity_id], |row| {
            // The conversation's own columns follow the node's.
            let own = 1 + NODE_COLUMN_COUNT;
            let (last_message, unread_count) = conversation_tail(row, own + 4)?;
            Ok(MobileStoredDirectConversationRecord {
                id: row.get(0)?,
                node: stored_node(row, 1)?,
                draft_text: row.get(own)?,
                last_read_at_ms: row.get(own + 1)?,
                created_at_ms: row.get(own + 2)?,
                notifications_enabled: row.get::<_, i64>(own + 3)? != 0,
                last_message,
                unread_count,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(conversations)
}

fn list_channel_conversations(
    connection: &Connection,
    owner_identity_id: &str,
) -> Result<Vec<MobileStoredChannelConversationRecord>, MobileStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT c.id, c.channel_id, c.conversation_address, c.draft_text,
            c.last_read_at_ms, c.created_at_ms, {tail}
        FROM channel_conversation c
        {join}
        WHERE c.owner_identity_id = ?
        ORDER BY c.created_at_ms DESC, c.id DESC",
        tail = tail_columns("c.owner_identity_id", "c.conversation_address"),
        join = tail_join("c.owner_identity_id", "c.conversation_address"),
    ))?;
    let conversations = statement
        .query_map(params![owner_identity_id], |row| {
            let Some(channel_id) = canonical_uuid(&row.get::<_, String>(1)?) else {
                return Ok(None);
            };
            let (last_message, unread_count) = conversation_tail(row, 6)?;
            Ok(Some(MobileStoredChannelConversationRecord {
                id: row.get(0)?,
                channel_id,
                conversation_address: row.get(2)?,
                draft_text: row.get(3)?,
                last_read_at_ms: row.get(4)?,
                created_at_ms: row.get(5)?,
                last_message,
                unread_count,
            }))
        })?
        .filter_map(Result::transpose)
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(conversations)
}

/// The last message and unread count a list row needs, as SQL expressions
/// against a conversation already joined as `c` and its last message as
/// `lm` (see [`tail_join`]).
///
/// Both are per-conversation index seeks rather than scans: the last
/// message resolves a rowid at the end of one index range and then fetches
/// that one row, and the unread count starts at the read cursor instead of
/// the beginning of history. Deliberately absent is a total message
/// count—it is the one aggregate that must walk the whole range, and
/// nothing in a list row asks for it.
///
/// `owner` and `address` are the outer query's own column references, so
/// this reads the same for a direct chat keyed by peer address and a
/// channel chat keyed by its derived address.
fn tail_columns(owner: &str, address: &str) -> String {
    format!(
        "lm.created_at_ms, lm.body, lm.direction, lm.deleted,
        lm.sender_address, lm.sender_hint, {is_status},
        (SELECT COUNT(*) FROM chat_message u
          WHERE u.owner_identity_id = {owner}
            AND u.conversation_address = {address}
            AND u.direction = 0 AND u.deleted = 0 AND u.presence = 0
            AND u.is_reaction = 0 AND u.silent = 0
            AND u.created_at_ms > c.last_read_at_ms)",
        is_status = is_status_sql("lm.message_type"),
    )
}

/// Joins a conversation's last message, in transcript order and reactions
/// aside, as `lm`. A conversation with no messages joins nothing.
fn tail_join(owner: &str, address: &str) -> String {
    format!(
        "LEFT JOIN chat_message lm ON lm.rowid = (
            SELECT m.rowid FROM chat_message m
            WHERE m.owner_identity_id = {owner} AND m.conversation_address = {address}
                AND m.is_reaction = 0
            ORDER BY m.created_at_ms DESC, m.rowid DESC
            LIMIT 1
        )"
    )
}

/// The eight columns [`tail_columns`] selects, read from `offset`: the
/// preview, absent when the conversation has no messages (a NULL
/// timestamp), and the unread count.
fn conversation_tail(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<(Option<MobileStoredConversationPreviewRecord>, i64)> {
    let unread = row.get(offset + 7)?;
    let Some(created_at_ms) = row.get::<_, Option<i64>>(offset)? else {
        return Ok((None, unread));
    };
    Ok((
        Some(MobileStoredConversationPreviewRecord {
            created_at_ms,
            body: row.get(offset + 1)?,
            is_outbound: row.get::<_, i64>(offset + 2)? == 1,
            is_deleted: row.get::<_, i64>(offset + 3)? != 0,
            sender_address: row.get(offset + 4)?,
            sender_hint: row.get(offset + 5)?,
            // NULL when the message has no type, which is not status.
            is_status: row.get::<_, Option<i64>>(offset + 6)?.unwrap_or(0) != 0,
        }),
        unread,
    ))
}

/// Remove a conversation's message history, outbound archive, and
/// delivery fragments. Runs inside a caller-held transaction; the
/// conversation row itself is the caller's to delete. Stream checkpoints
/// stay (see `clear_conversation_messages`).
pub(super) fn purge_conversation_history(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
) -> Result<(), MobileStoreError> {
    // The fragments first: they are found through the messages.
    connection.execute(
        "DELETE FROM chat_delivery_fragment
        WHERE owner_identity_id = ?1 AND (session_id, handle) IN (
            SELECT delivery_session_id, delivery_handle FROM chat_message
            WHERE owner_identity_id = ?1 AND conversation_address = ?2
        )",
        params![owner_identity_id, conversation_address],
    )?;
    for table in ["chat_message", "chat_outbound_archive"] {
        connection.execute(
            &format!(
                "DELETE FROM {table} WHERE owner_identity_id = ? AND conversation_address = ?"
            ),
            params![owner_identity_id, conversation_address],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
