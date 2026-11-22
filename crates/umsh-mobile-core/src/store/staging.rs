//! Transcripts written to order, for staging mode and for exercising a
//! transcript at sizes no test account reaches by hand.
//!
//! Both write straight to `chat_message` rather than through
//! `apply_chat_mutations`: that path stamps every row in a batch with one
//! instant, and a staged transcript needs a timeline of its own. Always
//! compiled; whether to offer staging is the platform's decision.

use rusqlite::{Statement, params};

use super::chat::{MobileStoredChatDeliveryState, nullable_blob, pack_route_hints};
use super::transcript::MobileStoredChatReceptionRecord;
use super::{MobileAppStore, MobileStoreError};

/// Handles at or above this belong to staged reaction rows: far above any
/// handle a staged transcript gives its messages, so the two ranges cannot
/// meet however long a staged conversation grows.
const STAGED_REACTION_HANDLE_BASE: u32 = 1_000_000;

/// What a staged reply answers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileStagedChatRegarding {
    /// Another message of the same staged transcript, by handle.
    Message { handle: u32 },
    /// One this phone never stored.
    Missing,
}

/// One reaction about a staged message. Its handle is the writer's to
/// allocate, since nothing outside refers to a reaction by name.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStagedChatReactionRecord {
    pub body: String,
    pub outbound: bool,
    pub created_at_ms: i64,
    #[uniffi(default)]
    pub sender_address: Option<String>,
    #[uniffi(default)]
    pub sender_hint: Option<Vec<u8>>,
}

/// One message a staged transcript is to contain, stated outright.
///
/// Everything a real message derives from the wire is dictated here
/// instead: the point of a staged transcript is that it reads a particular
/// way, down to who said what, when, and how it arrived.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStagedChatMessageRecord {
    pub handle: u32,
    pub body: String,
    pub outbound: bool,
    pub created_at_ms: i64,
    /// Who sent it, for a channel message. Absent in a direct conversation,
    /// where the conversation's address already says.
    #[uniffi(default)]
    pub sender_address: Option<String>,
    #[uniffi(default)]
    pub sender_hint: Option<Vec<u8>>,
    /// The name the sender put in the message, as a group message carries
    /// it.
    #[uniffi(default)]
    pub sender_handle: Option<String>,
    /// Ours only.
    #[uniffi(default)]
    pub delivery_state: Option<MobileStoredChatDeliveryState>,
    #[uniffi(default)]
    pub reception: Option<MobileStoredChatReceptionRecord>,
    #[uniffi(default)]
    pub reactions: Vec<MobileStagedChatReactionRecord>,
    /// What it replies to, when it is a reply.
    #[uniffi(default)]
    pub regarding: Option<MobileStagedChatRegarding>,
    /// Taken back by its sender: a tombstone, with nothing left to say.
    #[uniffi(default)]
    pub is_deleted: bool,
    /// The wire ID it went under, which names it to the other side.
    #[uniffi(default)]
    pub wire_id: Option<u8>,
    /// Its stream's epoch, for one of ours; `None` for one that arrived,
    /// whose epoch only the session that heard it knew.
    #[uniffi(default)]
    pub epoch: Option<u16>,
}

#[uniffi::export]
impl MobileAppStore {
    /// Write one staged transcript exactly as described, reactions
    /// included, in one transaction. A row already at a staged handle is
    /// replaced.
    ///
    /// When messages of ours carry a wire ID and an epoch, the
    /// conversation's outbound stream is set to continue after the newest
    /// of them, unless it already has a place: a stream the user advanced
    /// is never rewound.
    ///
    /// Separate from `seed_generated_messages` because the two answer
    /// different questions: that one wants volume and does not care what
    /// it says, this one wants a specific conversation to read plausibly in
    /// a screenshot, so every body, sender, and instant is the caller's.
    pub fn seed_staged_transcript(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        session_id: String,
        messages: Vec<MobileStagedChatMessageRecord>,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            {
                let mut statement = transaction.prepare(
                    "INSERT OR REPLACE INTO chat_message (
                        owner_identity_id, session_id, handle, conversation_address,
                        sender_address, sender_hint, sender_handle,
                        direction, body, deleted, created_at_ms, presence, delivery_state,
                        rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count, rx_route_hints,
                        rx_source_authenticated,
                        is_reaction, regarding_target_session_id, regarding_target_handle,
                        regarding_handle, regarding_wire_id, wire_id, epoch
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14,
                        ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
                )?;
                let row = StagedRow {
                    owner_identity_id: &owner_identity_id,
                    conversation_address: &conversation_address,
                    session_id: &session_id,
                };
                let mut reaction_handle = STAGED_REACTION_HANDLE_BASE;
                for message in &messages {
                    row.write(
                        &mut statement,
                        message.handle,
                        if message.is_deleted {
                            ""
                        } else {
                            &message.body
                        },
                        message.is_deleted,
                        message.outbound,
                        message.created_at_ms,
                        (
                            message.sender_address.as_deref(),
                            message.sender_hint.as_deref(),
                            message.sender_handle.as_deref(),
                        ),
                        message.delivery_state,
                        message.reception.as_ref(),
                        false,
                        message.regarding.as_ref(),
                        (message.wire_id, message.epoch),
                    )?;
                    let about = MobileStagedChatRegarding::Message {
                        handle: message.handle,
                    };
                    for reaction in &message.reactions {
                        row.write(
                            &mut statement,
                            reaction_handle,
                            &reaction.body,
                            false,
                            reaction.outbound,
                            reaction.created_at_ms,
                            (
                                reaction.sender_address.as_deref(),
                                reaction.sender_hint.as_deref(),
                                None,
                            ),
                            reaction
                                .outbound
                                .then_some(MobileStoredChatDeliveryState::Acknowledged),
                            None,
                            true,
                            Some(&about),
                            (None, None),
                        )?;
                        reaction_handle += 1;
                    }
                }
            }
            // The newest of ours, by when it was written, then by handle.
            let newest = messages
                .iter()
                .filter(|message| message.outbound)
                .filter_map(|message| {
                    Some((
                        (message.created_at_ms, message.handle),
                        message.wire_id?,
                        message.epoch?,
                    ))
                })
                .max_by_key(|(order, _, _)| *order);
            if let Some(((created_at_ms, _), wire_id, epoch)) = newest {
                transaction.execute(
                    "INSERT OR IGNORE INTO chat_stream_checkpoint (
                        owner_identity_id, conversation_address, next_id, epoch, updated_at_ms
                    ) VALUES (?, ?, ?, ?, ?)",
                    params![
                        owner_identity_id,
                        conversation_address,
                        wire_id.wrapping_add(1),
                        epoch,
                        created_at_ms
                    ],
                )?;
            }
            Ok(())
        })
    }

    /// Fill a conversation with `count` generated messages, in one
    /// transaction, for exercising a transcript at a size no test account
    /// reaches by hand.
    ///
    /// Instants run back from `now_ms` in one-minute steps, in occasional
    /// same-millisecond clusters, which is what a real batch produces, with
    /// a lull of several hours every so often, so the transcript spans days
    /// and carries the date separators a real one does. The newest message
    /// lands on `now_ms`. Every third message is ours and delivered.
    pub fn seed_generated_messages(
        &self,
        owner_identity_id: String,
        conversation_address: String,
        count: u32,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        // The timeline is laid out first so the newest message still lands
        // on now: the lulls make the whole span depend on the pattern, not
        // on the count alone.
        let mut offsets = Vec::with_capacity(count as usize);
        let mut offset: i64 = 0;
        let mut cluster_remaining = 0;
        let mut clusters = 0;
        for index in 0..count {
            if cluster_remaining == 0 {
                cluster_remaining = 3 + index % 5;
                if index > 0 {
                    // Counted in clusters rather than messages: cluster
                    // lengths vary, so a condition on the message index
                    // would land on a cluster boundary only by chance.
                    offset += if clusters % 9 == 0 {
                        5 * 3_600_000
                    } else {
                        60_000
                    };
                }
                clusters += 1;
            }
            cluster_remaining -= 1;
            offsets.push(offset);
        }
        let start = now_ms - offsets.last().copied().unwrap_or(0);
        // Not a number, so no engine session can be taken to have written
        // them: they carry no wire ID either, so nothing can name them.
        let session_id = format!("generated-{}", now_ms.rem_euclid(1_000_000));

        self.write(|transaction| {
            {
                let mut statement = transaction.prepare(
                    "INSERT OR REPLACE INTO chat_message (
                        owner_identity_id, session_id, handle, conversation_address,
                        direction, body, deleted, created_at_ms, presence, delivery_state
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, ?)",
                )?;
                for (index, offset) in (0..count).zip(offsets) {
                    let outbound = index % 3 == 0;
                    let body = format!(
                        "Seeded message {} of {count}. {}",
                        index + 1,
                        "Filler text. ".repeat(1 + (index % 6) as usize)
                    );
                    statement.execute(params![
                        owner_identity_id,
                        session_id,
                        index,
                        conversation_address,
                        outbound,
                        body,
                        start + offset,
                        // Acknowledged is delivered; one with no state would
                        // read as still sending.
                        outbound.then_some(MobileStoredChatDeliveryState::Acknowledged.as_str()),
                    ])?;
                }
            }
            Ok(())
        })
    }
}

/// What every row of one staged transcript shares.
struct StagedRow<'a> {
    owner_identity_id: &'a str,
    conversation_address: &'a str,
    session_id: &'a str,
}

impl StagedRow<'_> {
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        statement: &mut Statement<'_>,
        handle: u32,
        body: &str,
        is_deleted: bool,
        outbound: bool,
        created_at_ms: i64,
        (sender_address, sender_hint, sender_handle): (Option<&str>, Option<&[u8]>, Option<&str>),
        delivery_state: Option<MobileStoredChatDeliveryState>,
        reception: Option<&MobileStoredChatReceptionRecord>,
        is_reaction: bool,
        regarding: Option<&MobileStagedChatRegarding>,
        (wire_id, epoch): (Option<u8>, Option<u16>),
    ) -> Result<(), MobileStoreError> {
        // A resolved reference names its target the way a live handle
        // would; a missing one keeps only wire coordinates, which is what
        // leaves its target unfound.
        let target = match regarding {
            Some(MobileStagedChatRegarding::Message { handle }) => Some(*handle),
            _ => None,
        };
        let missing = matches!(regarding, Some(MobileStagedChatRegarding::Missing));
        statement.execute(params![
            self.owner_identity_id,
            self.session_id,
            handle,
            self.conversation_address,
            sender_address,
            nullable_blob(sender_hint),
            sender_handle,
            outbound,
            body,
            is_deleted,
            created_at_ms,
            delivery_state.map(MobileStoredChatDeliveryState::as_str),
            reception.and_then(|reception| reception.rssi_dbm),
            reception.and_then(|reception| reception.snr_centibels),
            reception.and_then(|reception| reception.lqi),
            reception.and_then(|reception| reception.hop_count),
            reception.and_then(|reception| pack_route_hints(&reception.route_hints)),
            reception.map(|reception| reception.source_authenticated),
            is_reaction,
            target.map(|_| self.session_id),
            target,
            target,
            missing.then_some(0),
            wire_id,
            epoch,
        ])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
