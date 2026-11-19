//! Reading a conversation's transcript: bounded pages keyed by cursor,
//! each message carrying the reactions about it and the quote of what it
//! replies to.
//!
//! A transcript's order is `(created_at_ms, rowid)`, so a cursor names a
//! row rather than an offset: a page boundary stays put when older messages
//! are repaired in behind it. The rowid half is load-bearing rather than
//! defensive, since a mutation batch is stamped from one instant and
//! several messages sharing a millisecond is the normal case.
//!
//! Reactions are messages, but never transcript rows: every read here
//! leaves them out, and folds them onto the messages they are about.

use std::collections::{HashMap, HashSet};

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};

use crate::mobile_chat::MobileChatPresence;

use super::chat::{
    MobileStoredChatDeliveryState, MobileStoredChatMessageRefRecord, is_status_sql, split_hints,
};
use super::{MobileAppStore, MobileStoreError, narrowed};

/// How many messages a transcript read returns in one page, whatever the
/// caller asks for. A page is a view per row on the way to the screen, so
/// an unbounded request is a mistake the store can see and the caller
/// usually cannot.
const PAGE_LIMIT: u32 = 500;

/// How many targets one annotation statement binds: two parameters each,
/// well inside SQLite's limit while keeping the statements few.
const ANNOTATION_CHUNK: usize = 200;

/// Where one message sits in its conversation's order.
///
/// Rowids are reused after a transcript is cleared, so two messages in one
/// conversation and one millisecond either side of a clear could compare in
/// storage order rather than arrival order; the transcript's order has
/// always been ambiguous in exactly that case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, uniffi::Record)]
pub struct MobileStoredChatCursorRecord {
    pub created_at_ms: i64,
    pub row_id: i64,
}

/// What the radio observed of the frame a message arrived on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatReceptionRecord {
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
    /// Radio links crossed on the way here; a frame heard directly from its
    /// sender is one hop.
    pub hop_count: Option<u8>,
    /// Two-byte repeater hints in trace-route order: nearest this phone
    /// first, nearest the sender last.
    pub route_hints: Vec<Vec<u8>>,
    pub source_authenticated: bool,
}

/// The repeaters overheard carrying an outbound message.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatRepeatsRecord {
    /// Two-byte hints of the repeaters that named themselves, first heard
    /// first.
    pub repeaters: Vec<Vec<u8>>,
    /// Repeaters heard that did not: the most any one fragment heard.
    pub anonymous: i64,
    /// When the message's delivery last moved: its first frame going out,
    /// or a repeater being heard.
    pub progress_at_ms: i64,
}

/// One person's reaction to one message.
///
/// Carries its own durable identity because it is a message: the sender may
/// replace it, and one of ours is delivered and acknowledged like anything
/// else.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatReactionRecord {
    /// The emote body as it arrived: a short token, not necessarily an
    /// emoji.
    pub body: String,
    pub outbound: bool,
    pub sender_address: Option<String>,
    pub sender_hint: Option<Vec<u8>>,
    pub reference: MobileStoredChatMessageRefRecord,
    pub wire_id: Option<u8>,
    pub epoch: Option<u16>,
    pub created_at_ms: i64,
    pub delivery_state: Option<MobileStoredChatDeliveryState>,
    /// Ours, and it went under a session with forward secrecy.
    pub forward_secret: bool,
}

/// The message a reply quotes, as it reads now.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatQuotedMessageRecord {
    pub reference: MobileStoredChatMessageRefRecord,
    pub body: String,
    pub outbound: bool,
    pub is_deleted: bool,
    pub sender_address: Option<String>,
    pub sender_hint: Option<Vec<u8>>,
    pub sender_handle: Option<String>,
}

/// What a reply quotes of the message it answers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatQuoteRecord {
    /// The original, while it is stored and present; `None` when it never
    /// arrived, is no longer kept, or was lost to a gap.
    pub original: Option<MobileStoredChatQuotedMessageRecord>,
}

/// One message of a transcript.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatMessageRecord {
    /// The message's durable identity.
    pub reference: MobileStoredChatMessageRefRecord,
    pub body: String,
    pub outbound: bool,
    /// For a message of ours.
    pub delivery_state: Option<MobileStoredChatDeliveryState>,
    pub is_deleted: bool,
    pub created_at_ms: i64,
    /// The durable wire identity, for naming this message after the
    /// session that composed it is gone.
    pub wire_id: Option<u8>,
    pub epoch: Option<u16>,
    pub is_edited: bool,
    /// A code this store never writes reads as present.
    pub presence: MobileChatPresence,
    /// It filled a gap out of order.
    pub received_late: bool,
    /// Ours, failed, and later acknowledged after all.
    pub delivered_late: bool,
    /// Our own edited message's pre-edit text, kept for review.
    pub original_body: Option<String>,
    /// Who sent it, for a group message: the full address once known, the
    /// claimed hint the wire always carries, and the name the sender put in
    /// the message.
    pub sender_address: Option<String>,
    pub sender_hint: Option<Vec<u8>>,
    pub sender_handle: Option<String>,
    /// Absent for ours, and for anything stored without it.
    pub reception: Option<MobileStoredChatReceptionRecord>,
    /// With `created_at_ms`, this message's cursor. An ordering key only:
    /// `reference` is the durable identity.
    pub row_id: i64,
    /// Ours, and its acknowledgment came back through the flood that
    /// followed a missed route.
    pub delivered_flooded: bool,
    /// At most one per sender, oldest first.
    pub reactions: Vec<MobileStoredChatReactionRecord>,
    pub is_reply: bool,
    /// Came as an edit of a message this phone does not hold.
    pub is_edit_of_unknown: bool,
    /// Status text, which reads as its sender's name followed by its body,
    /// with no bubble.
    pub is_status: bool,
    /// Ours, and what it reads went under a session with forward secrecy.
    pub is_forward_secret: bool,
    /// The stored row it replies to, once that has been found.
    pub reply_target: Option<MobileStoredChatMessageRefRecord>,
    /// What it replies to, as that reads now, for a reply: an edit or a
    /// deletion of the original shows in every quote of it.
    pub quote: Option<MobileStoredChatQuoteRecord>,
    /// Ours, once any of it has been sent.
    pub repeats: Option<MobileStoredChatRepeatsRecord>,
}

impl MobileStoredChatMessageRecord {
    pub(super) fn cursor(&self) -> MobileStoredChatCursorRecord {
        MobileStoredChatCursorRecord {
            created_at_ms: self.created_at_ms,
            row_id: self.row_id,
        }
    }
}

/// One slice of a transcript, oldest first. The flags say whether storage
/// holds more beyond it in either direction.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChatMessagePageRecord {
    pub messages: Vec<MobileStoredChatMessageRecord>,
    pub has_older: bool,
    pub has_newer: bool,
}

#[uniffi::export]
impl MobileAppStore {
    /// The newest `limit` messages in a conversation. `limit` is held to
    /// between 1 and 500.
    pub fn chat_message_page_newest(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        limit: u32,
    ) -> Result<MobileStoredChatMessagePageRecord, MobileStoreError> {
        self.read(|transaction| {
            descending_page(
                transaction,
                &owner_identity_id,
                &conversation_address,
                None,
                limit,
            )
        })
    }

    /// The `limit` messages immediately older than `cursor`.
    pub fn chat_message_page_before(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        cursor: MobileStoredChatCursorRecord,
        limit: u32,
    ) -> Result<MobileStoredChatMessagePageRecord, MobileStoreError> {
        self.read(|transaction| {
            descending_page(
                transaction,
                &owner_identity_id,
                &conversation_address,
                Some(cursor),
                limit,
            )
        })
    }

    /// The `limit` messages immediately newer than `cursor`, or starting at
    /// it when `including` is set, which is how a window re-reads the
    /// extent it already holds.
    #[uniffi::method(default(including = false))]
    pub fn chat_message_page_after(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        cursor: MobileStoredChatCursorRecord,
        limit: u32,
        including: bool,
    ) -> Result<MobileStoredChatMessagePageRecord, MobileStoreError> {
        self.read(|transaction| {
            ascending_page(
                transaction,
                &owner_identity_id,
                &conversation_address,
                cursor,
                including,
                limit,
            )
        })
    }

    /// The transcript around one message, for opening a search result in
    /// context: up to `radius` messages either side of it. `None` when that
    /// message is not in this conversation, a stale hit against a cleared
    /// transcript, which is not an error.
    pub fn chat_message_window(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        message: MobileStoredChatMessageRefRecord,
        radius: u32,
    ) -> Result<Option<MobileStoredChatMessagePageRecord>, MobileStoreError> {
        let owner = owner_identity_id.as_str();
        let address = conversation_address.as_str();
        self.read(|transaction| {
            let Some(anchor) = message_cursor(transaction, owner, address, &message)? else {
                return Ok(None);
            };
            let older = descending_page(transaction, owner, address, Some(anchor), radius)?;
            // Including the anchor keeps the centered message in the window
            // even when nothing follows it.
            let newer = ascending_page(
                transaction,
                owner,
                address,
                anchor,
                true,
                radius.saturating_add(1),
            )?;
            let mut messages = older.messages;
            messages.extend(newer.messages);
            Ok(Some(MobileStoredChatMessagePageRecord {
                messages,
                has_older: older.has_older,
                has_newer: newer.has_newer,
            }))
        })
    }

    /// Where a message sits in its conversation's order, by its durable
    /// identity.
    pub fn chat_message_cursor(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        message: MobileStoredChatMessageRefRecord,
    ) -> Result<Option<MobileStoredChatCursorRecord>, MobileStoreError> {
        message_cursor(
            &self.connection(),
            &owner_identity_id,
            &conversation_address,
            &message,
        )
    }

    /// How many messages a conversation holds, reactions aside.
    /// Deliberately a call of its own: it is the one aggregate that walks
    /// the whole range, so it belongs where something asked for it rather
    /// than on the conversation list.
    pub fn chat_message_count(
        &self,
        owner_identity_id: String,
        conversation_address: String,
    ) -> Result<i64, MobileStoreError> {
        Ok(self.connection().query_row(
            "SELECT COUNT(*) FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ? AND is_reaction = 0",
            params![owner_identity_id, conversation_address],
            |row| row.get(0),
        )?)
    }
}

/// The columns every transcript read selects. [`stored_chat_message`]
/// reads them by name, so the two agree on what each is whatever order
/// they are listed in.
fn message_columns() -> String {
    format!(
        "session_id, handle, body, direction, delivery_state, deleted, created_at_ms,
        wire_id, epoch, edited, presence, received_late, delivered_late, original_body,
        sender_address, sender_hint, sender_handle,
        rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count,
        rx_route_hints, rx_source_authenticated, rowid AS row_id, delivered_flooded,
        (regarding_handle IS NOT NULL OR regarding_wire_id IS NOT NULL
            OR regarding_unknown <> 0) AS is_reply,
        regarding_target_session_id, regarding_target_handle,
        delivery_progress_at_ms,
        (SELECT group_concat(hex(f.repeaters), ',') FROM chat_delivery_fragment f
            WHERE f.owner_identity_id = chat_message.owner_identity_id
                AND f.session_id = chat_message.delivery_session_id
                AND f.handle = chat_message.delivery_handle
                AND f.repeaters IS NOT NULL
            ORDER BY f.fragment_index) AS repeater_runs,
        (SELECT MAX(f.anonymous_repeats) FROM chat_delivery_fragment f
            WHERE f.owner_identity_id = chat_message.owner_identity_id
                AND f.session_id = chat_message.delivery_session_id
                AND f.handle = chat_message.delivery_handle) AS anonymous_repeats,
        unknown_original,
        {is_status} AS is_status,
        COALESCE(forward_secret, 0) AS is_forward_secret",
        is_status = is_status_sql("message_type"),
    )
}

/// A requested page size, held to what the store serves.
fn bounded(limit: u32) -> usize {
    limit.clamp(1, PAGE_LIMIT) as usize
}

/// Both newest-first reads, the newest page and the one before a cursor:
/// take the page off the end of the index range, then reverse it into the
/// transcript's own order.
fn descending_page(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
    before: Option<MobileStoredChatCursorRecord>,
    limit: u32,
) -> Result<MobileStoredChatMessagePageRecord, MobileStoreError> {
    let bounded = bounded(limit);
    let mut arguments = vec![
        Value::Text(owner_identity_id.to_owned()),
        Value::Text(conversation_address.to_owned()),
    ];
    if let Some(cursor) = before {
        arguments.push(Value::Integer(cursor.created_at_ms));
        arguments.push(Value::Integer(cursor.row_id));
    }
    // One past the page answers "is there more" without a second statement.
    arguments.push(Value::Integer(bounded as i64 + 1));
    let mut statement = connection.prepare(&format!(
        "SELECT {columns}
        FROM chat_message
        WHERE owner_identity_id = ? AND conversation_address = ?
            AND is_reaction = 0
            {cursor}
        ORDER BY created_at_ms DESC, rowid DESC
        LIMIT ?",
        columns = message_columns(),
        cursor = if before.is_some() {
            "AND (created_at_ms, rowid) < (?, ?)"
        } else {
            ""
        },
    ))?;
    let mut messages = statement
        .query_map(params_from_iter(arguments), stored_chat_message)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_older = messages.len() > bounded;
    messages.truncate(bounded);
    messages.reverse();
    with_annotations(
        connection,
        owner_identity_id,
        MobileStoredChatMessagePageRecord {
            messages,
            has_older,
            // Everything a cursor came from is newer than the page before it.
            has_newer: before.is_some(),
        },
    )
}

fn ascending_page(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
    after: MobileStoredChatCursorRecord,
    including: bool,
    limit: u32,
) -> Result<MobileStoredChatMessagePageRecord, MobileStoreError> {
    let bounded = bounded(limit);
    let mut statement = connection.prepare(&format!(
        "SELECT {columns}
        FROM chat_message
        WHERE owner_identity_id = ? AND conversation_address = ?
            AND is_reaction = 0
            AND (created_at_ms, rowid) {comparison} (?, ?)
        ORDER BY created_at_ms ASC, rowid ASC
        LIMIT ?",
        columns = message_columns(),
        comparison = if including { ">=" } else { ">" },
    ))?;
    let mut messages = statement
        .query_map(
            params![
                owner_identity_id,
                conversation_address,
                after.created_at_ms,
                after.row_id,
                bounded as i64 + 1
            ],
            stored_chat_message,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_newer = messages.len() > bounded;
    messages.truncate(bounded);
    // A forward read sees nothing behind where it started, so it asks.
    // Reporting "no older messages" on a hunch is the one wrong answer with
    // teeth: it tells the transcript its history is complete and retires
    // the only affordance that would have proved otherwise.
    let has_older = match messages.first() {
        Some(first) => has_messages_before(
            connection,
            owner_identity_id,
            conversation_address,
            first.cursor(),
        )?,
        None => false,
    };
    with_annotations(
        connection,
        owner_identity_id,
        MobileStoredChatMessagePageRecord {
            messages,
            has_older,
            has_newer,
        },
    )
}

/// Whether anything sits behind `cursor` in this conversation. One index
/// seek, so a forward read can answer for the side it did not look at.
fn has_messages_before(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
    cursor: MobileStoredChatCursorRecord,
) -> Result<bool, MobileStoreError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND is_reaction = 0
                AND (created_at_ms, rowid) < (?, ?)
            LIMIT 1",
            params![
                owner_identity_id,
                conversation_address,
                cursor.created_at_ms,
                cursor.row_id
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn message_cursor(
    connection: &Connection,
    owner_identity_id: &str,
    conversation_address: &str,
    message: &MobileStoredChatMessageRefRecord,
) -> Result<Option<MobileStoredChatCursorRecord>, MobileStoreError> {
    Ok(connection
        .query_row(
            "SELECT created_at_ms, rowid FROM chat_message
            WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                AND conversation_address = ?",
            params![
                owner_identity_id,
                message.session_id,
                message.handle,
                conversation_address
            ],
            |row| {
                Ok(MobileStoredChatCursorRecord {
                    created_at_ms: row.get(0)?,
                    row_id: row.get(1)?,
                })
            },
        )
        .optional()?)
}

/// One message as [`message_columns`] selects it, without what other rows
/// carry about it (see [`with_annotations`]).
fn stored_chat_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<MobileStoredChatMessageRecord> {
    // A flag column this old a row may hold as NULL reads as unset.
    let flag = |column: &str| -> rusqlite::Result<bool> {
        Ok(row.get::<_, Option<i64>>(column)?.unwrap_or(0) != 0)
    };
    Ok(MobileStoredChatMessageRecord {
        reference: MobileStoredChatMessageRefRecord {
            session_id: row.get("session_id")?,
            handle: row.get("handle")?,
        },
        body: row.get("body")?,
        outbound: row.get::<_, i64>("direction")? == 1,
        delivery_state: MobileStoredChatDeliveryState::stored(row.get("delivery_state")?),
        is_deleted: flag("deleted")?,
        created_at_ms: row.get("created_at_ms")?,
        wire_id: narrowed(row.get("wire_id")?),
        epoch: narrowed(row.get("epoch")?),
        is_edited: flag("edited")?,
        presence: presence(row.get("presence")?),
        received_late: flag("received_late")?,
        delivered_late: flag("delivered_late")?,
        original_body: row.get("original_body")?,
        sender_address: row.get("sender_address")?,
        sender_hint: row.get("sender_hint")?,
        sender_handle: row.get("sender_handle")?,
        reception: reception(row)?,
        row_id: row.get("row_id")?,
        delivered_flooded: flag("delivered_flooded")?,
        reactions: Vec::new(),
        is_reply: flag("is_reply")?,
        is_edit_of_unknown: flag("unknown_original")?,
        is_status: flag("is_status")?,
        is_forward_secret: flag("is_forward_secret")?,
        reply_target: stored_reference(
            row.get("regarding_target_session_id")?,
            row.get("regarding_target_handle")?,
        ),
        quote: None,
        repeats: repeats(row)?,
    })
}

/// The message two reference columns name, when both are there and the
/// handle is one a message can have.
fn stored_reference(
    session_id: Option<String>,
    handle: Option<i64>,
) -> Option<MobileStoredChatMessageRefRecord> {
    Some(MobileStoredChatMessageRefRecord {
        session_id: session_id?,
        handle: narrowed(handle)?,
    })
}

fn presence(code: i64) -> MobileChatPresence {
    match code {
        1 => MobileChatPresence::GapPending,
        2 => MobileChatPresence::Unavailable,
        3 => MobileChatPresence::GapIdle,
        _ => MobileChatPresence::Present,
    }
}

/// What the radio measured, when the row has any of it. Whether the
/// authentication flag is set at all is what tells "no frame recorded"
/// from a frame that reported no signal figures.
fn reception(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<MobileStoredChatReceptionRecord>> {
    let Some(authenticated) = row.get::<_, Option<i64>>("rx_source_authenticated")? else {
        return Ok(None);
    };
    Ok(Some(MobileStoredChatReceptionRecord {
        rssi_dbm: narrowed(row.get("rx_rssi_dbm")?),
        snr_centibels: narrowed(row.get("rx_snr_cb")?),
        lqi: narrowed(row.get("rx_lqi")?),
        hop_count: narrowed(row.get("rx_hop_count")?),
        route_hints: split_hints(row.get::<_, Option<Vec<u8>>>("rx_route_hints")?.as_deref()),
        source_authenticated: authenticated != 0,
    }))
}

/// The repeaters heard carrying a message, from the progress stamp and the
/// per-fragment tallies [`message_columns`] folds in. Fragments are each
/// heard by much the same repeaters, so named ones are merged and
/// anonymous ones are counted as the most any fragment heard.
fn repeats(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<MobileStoredChatRepeatsRecord>> {
    let Some(progress_at_ms) = row.get::<_, Option<i64>>("delivery_progress_at_ms")? else {
        return Ok(None);
    };
    let mut repeaters: Vec<Vec<u8>> = Vec::new();
    let runs = row
        .get::<_, Option<String>>("repeater_runs")?
        .unwrap_or_default();
    for run in runs.split(',').filter(|run| !run.is_empty()) {
        for hint in split_hints(Some(&hex_bytes(run))) {
            if !repeaters.contains(&hint) {
                repeaters.push(hint);
            }
        }
    }
    Ok(Some(MobileStoredChatRepeatsRecord {
        repeaters,
        anonymous: row.get::<_, Option<i64>>("anonymous_repeats")?.unwrap_or(0),
        progress_at_ms,
    }))
}

/// The bytes SQLite's `hex()` spelled out, up to the first pair that is
/// not hex.
fn hex_bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map_while(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Attach what a page's messages carry from other rows: the reactions
/// about them, and the quotes of what they reply to.
fn with_annotations(
    connection: &Connection,
    owner_identity_id: &str,
    mut page: MobileStoredChatMessagePageRecord,
) -> Result<MobileStoredChatMessagePageRecord, MobileStoreError> {
    attach_reactions(connection, owner_identity_id, &mut page.messages)?;
    attach_quotes(connection, owner_identity_id, &mut page.messages)?;
    Ok(page)
}

/// Attach the quote each reply carries of its original.
///
/// The original may sit anywhere in history, so, like reactions, this is
/// a second read keyed by identity. A reply whose original has not been
/// found, or is no longer stored or present, quotes it as unavailable.
fn attach_quotes(
    connection: &Connection,
    owner_identity_id: &str,
    messages: &mut [MobileStoredChatMessageRecord],
) -> Result<(), MobileStoreError> {
    if !messages.iter().any(|message| message.is_reply) {
        return Ok(());
    }
    let targets: Vec<&MobileStoredChatMessageRefRecord> = messages
        .iter()
        .filter_map(|message| message.reply_target.as_ref())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let mut originals = HashMap::new();
    for chunk in targets.chunks(ANNOTATION_CHUNK) {
        let mut statement = connection.prepare(&format!(
            "SELECT session_id, handle, body, direction, deleted,
                sender_address, sender_hint, sender_handle
            FROM chat_message
            WHERE owner_identity_id = ? AND presence = 0
                AND (session_id, handle) IN ({tuples})",
            tuples = vec!["(?, ?)"; chunk.len()].join(", "),
        ))?;
        let rows = statement.query_map(
            params_from_iter(identity_arguments(owner_identity_id, chunk)),
            |row| {
                Ok(MobileStoredChatQuotedMessageRecord {
                    reference: MobileStoredChatMessageRefRecord {
                        session_id: row.get(0)?,
                        handle: row.get(1)?,
                    },
                    body: row.get(2)?,
                    outbound: row.get::<_, i64>(3)? == 1,
                    is_deleted: row.get::<_, i64>(4)? != 0,
                    sender_address: row.get(5)?,
                    sender_hint: row.get(6)?,
                    sender_handle: row.get(7)?,
                })
            },
        )?;
        for original in rows {
            let original = original?;
            originals.insert(original.reference.clone(), original);
        }
    }
    for message in messages.iter_mut().filter(|message| message.is_reply) {
        message.quote = Some(MobileStoredChatQuoteRecord {
            original: message
                .reply_target
                .as_ref()
                .and_then(|target| originals.get(target).cloned()),
        });
    }
    Ok(())
}

/// Attach each message's live reactions.
///
/// A sender has one reaction per message: the newest emote they sent about
/// it wins, and if that one has no body it is a withdrawal and they have
/// none. Both rules are settled here rather than on the wire, where every
/// emote is just another message. Reactions are not transcript rows, and
/// the messages they are about may sit anywhere in history, so this is a
/// second read keyed by the page's own identities.
fn attach_reactions(
    connection: &Connection,
    owner_identity_id: &str,
    messages: &mut [MobileStoredChatMessageRecord],
) -> Result<(), MobileStoreError> {
    if messages.is_empty() {
        return Ok(());
    }
    let targets: Vec<&MobileStoredChatMessageRefRecord> =
        messages.iter().map(|message| &message.reference).collect();
    // Newest per sender needs arrival order, and a withdrawal has to be
    // able to erase what came before it, so this folds rather than
    // aggregates: each target's senders in the order first heard, and each
    // sender's newest reaction.
    let mut folded: HashMap<
        MobileStoredChatMessageRefRecord,
        Vec<(String, MobileStoredChatReactionRecord)>,
    > = HashMap::new();
    for chunk in targets.chunks(ANNOTATION_CHUNK) {
        let mut statement = connection.prepare(&format!(
            "SELECT regarding_target_session_id, regarding_target_handle,
                body, direction, sender_address, sender_hint,
                session_id, handle, wire_id, epoch, created_at_ms, delivery_state,
                COALESCE(forward_secret, 0)
            FROM chat_message
            WHERE owner_identity_id = ? AND is_reaction = 1 AND deleted = 0
                AND (regarding_target_session_id, regarding_target_handle) IN ({tuples})
            ORDER BY created_at_ms ASC, rowid ASC",
            tuples = vec!["(?, ?)"; chunk.len()].join(", "),
        ))?;
        let rows = statement.query_map(
            params_from_iter(identity_arguments(owner_identity_id, chunk)),
            |row| {
                let outbound = row.get::<_, i64>(3)? == 1;
                let sender_address: Option<String> = row.get(4)?;
                let sender_hint: Option<Vec<u8>> = row.get(5)?;
                // Whoever sent it, however little is known of them: our own
                // reactions collapse to one sender, and a member not yet
                // named is still distinct by hint.
                let sender = if outbound {
                    "me".to_owned()
                } else if let Some(address) = &sender_address {
                    address.clone()
                } else if let Some(hint) = &sender_hint {
                    hint.iter().map(|byte| format!("{byte:02x}")).collect()
                } else {
                    "peer".to_owned()
                };
                Ok((
                    MobileStoredChatMessageRefRecord {
                        session_id: row.get(0)?,
                        handle: row.get(1)?,
                    },
                    sender,
                    MobileStoredChatReactionRecord {
                        body: row.get(2)?,
                        outbound,
                        sender_address,
                        sender_hint,
                        reference: MobileStoredChatMessageRefRecord {
                            session_id: row.get(6)?,
                            handle: row.get(7)?,
                        },
                        wire_id: narrowed(row.get(8)?),
                        epoch: narrowed(row.get(9)?),
                        created_at_ms: row.get(10)?,
                        delivery_state: MobileStoredChatDeliveryState::stored(row.get(11)?),
                        forward_secret: outbound && row.get::<_, i64>(12)? != 0,
                    },
                ))
            },
        )?;
        for row in rows {
            let (target, sender, reaction) = row?;
            let senders = folded.entry(target).or_default();
            match senders.iter_mut().find(|(known, _)| *known == sender) {
                Some((_, newest)) => *newest = reaction,
                None => senders.push((sender, reaction)),
            }
        }
    }
    for message in messages.iter_mut() {
        if let Some(senders) = folded.remove(&message.reference) {
            message.reactions = senders
                .into_iter()
                .map(|(_, reaction)| reaction)
                .filter(|reaction| !reaction.body.is_empty())
                .collect();
        }
    }
    Ok(())
}

/// The owner, then each identity's two halves, as an annotation read binds
/// them.
fn identity_arguments(
    owner_identity_id: &str,
    identities: &[&MobileStoredChatMessageRefRecord],
) -> Vec<Value> {
    std::iter::once(Value::Text(owner_identity_id.to_owned()))
        .chain(identities.iter().flat_map(|identity| {
            [
                Value::Text(identity.session_id.clone()),
                Value::Integer(i64::from(identity.handle)),
            ]
        }))
        .collect()
}

#[cfg(test)]
mod tests;
