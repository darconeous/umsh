//! One batch of the chat engine's effects, made durable whole.
//!
//! Everything a batch says is written in one transaction: the messages,
//! the conversations they open, senders resolved, resends, delivery
//! evidence, repeats, and the peers it shows were heard. What the app has to
//! hear about it (the transcripts to redraw, the notifications to raise) is
//! read inside the same transaction, so it describes exactly what was
//! written.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusqlite::{Connection, params};

use crate::mobile_chat::{
    CHANNEL_ADDRESS_PREFIX, MobileChatArchiveLookupRecord, MobileChatDeliveryRecord,
    MobileChatDeliveryState, MobileChatDirection, MobileChatMutationRecord, MobileChatRepeatRecord,
    MobileChatResendRecord, MobileChatSenderResolutionRecord,
};

use super::chat::{
    MobileStoredChatDeliveryFailureRecord, MobileStoredChatNotificationTargetRecord,
    MobileStoredChatReactionNotificationTargetRecord, apply_deliveries, apply_mutations,
    apply_repeats, apply_resends, apply_sender_resolution, chat_archive, chat_notification_target,
    chat_reaction_notification_target, conversation_address_for_message,
};
use super::peers::touch_last_heard;
use super::{MobileAppStore, MobileStoreError};

/// What stored chat effects changed, for the app to show.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobileChatChangesRecord {
    /// The conversations whose transcripts changed.
    pub conversations: Vec<String>,
    /// Something changed that could not be placed in a conversation, so any
    /// transcript may be out of date.
    pub all_conversations: bool,
    /// Arrivals worth telling the user about, in the order they arrived.
    /// Whether one is shown is the app's to decide.
    pub notifications: Vec<MobileChatNotificationRecord>,
    /// Messages of ours that were just given up on.
    pub delivery_failures: Vec<MobileStoredChatDeliveryFailureRecord>,
    /// Peers whose watch for being heard was just set off.
    pub heard_watches: Vec<String>,
}

/// An arrival worth telling the user about.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatNotificationRecord {
    Message {
        target: MobileStoredChatNotificationTargetRecord,
    },
    Reaction {
        target: MobileStoredChatReactionNotificationTargetRecord,
    },
}

impl MobileChatChangesRecord {
    /// Add `later`'s changes to these.
    pub(crate) fn merge(&mut self, later: Self) {
        for address in later.conversations {
            if !self.conversations.contains(&address) {
                self.conversations.push(address);
            }
        }
        self.all_conversations |= later.all_conversations;
        self.notifications.extend(later.notifications);
        self.delivery_failures.extend(later.delivery_failures);
        for address in later.heard_watches {
            if !self.heard_watches.contains(&address) {
                self.heard_watches.push(address);
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// One batch of the chat engine's effects, sorted by kind.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChatBatchEffects {
    pub mutations: Vec<MobileChatMutationRecord>,
    pub resends: Vec<MobileChatResendRecord>,
    pub deliveries: Vec<MobileChatDeliveryRecord>,
    pub repeats: Vec<MobileChatRepeatRecord>,
    pub archive_lookups: Vec<MobileChatArchiveLookupRecord>,
    pub sender_resolutions: Vec<MobileChatSenderResolutionRecord>,
}

/// What the session needs to know about where its effects went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppliedChatBatch {
    pub changes: MobileChatChangesRecord,
    /// The payload each archive lookup asked for, when it is still held.
    pub archive_answers: Vec<(u32, Option<Vec<u8>>)>,
}

/// Where the batch is stored, and what it is stored against.
pub(crate) struct ChatBatchContext<'a> {
    pub owner_identity_id: &'a str,
    /// The key digest of each channel the session holds a key for, by the
    /// address of its group conversation.
    pub channel_digests: &'a HashMap<String, String>,
    /// `EMERGENCY`'s conversation, while its test messages arrive silently.
    pub silent_tests_in: Option<&'a str>,
    pub now_ms: i64,
}

impl MobileAppStore {
    /// Store one batch whole, in one transaction, and report what it
    /// changed. Storing the same batch again changes nothing more, so a
    /// batch whose storing failed can simply be stored again.
    pub(crate) fn apply_chat_batch(
        &self,
        context: &ChatBatchContext<'_>,
        effects: &ChatBatchEffects,
    ) -> Result<AppliedChatBatch, MobileStoreError> {
        self.write(|transaction| apply_batch(transaction, context, effects))
    }
}

fn apply_batch(
    transaction: &Connection,
    context: &ChatBatchContext<'_>,
    effects: &ChatBatchEffects,
) -> Result<AppliedChatBatch, MobileStoreError> {
    let owner = context.owner_identity_id;
    let now_ms = context.now_ms;
    // Edits whose originals this phone never stored become messages of
    // their own here; the engine could not flag them to notify, so they are
    // flagged below by hand.
    let materialized: HashSet<(u64, u32)> = apply_mutations(
        transaction,
        owner,
        &effects.mutations,
        context.silent_tests_in,
        now_ms,
    )?
    .into_iter()
    .map(|mutation| (mutation.session_id, mutation.handle))
    .collect();
    let mut opened = BTreeSet::new();
    for address in effects
        .mutations
        .iter()
        .filter_map(|mutation| mutation.conversation_address.as_deref())
    {
        if opened.insert(address) {
            open_conversation(transaction, context, address)?;
        }
    }
    for resolution in &effects.sender_resolutions {
        apply_sender_resolution(transaction, owner, resolution)?;
    }
    // Ahead of the deliveries: a resend's frames are reported under the
    // handle it names, and what was last said of them before no longer
    // holds.
    apply_resends(transaction, owner, &effects.resends, now_ms)?;
    let delivery_failures = apply_deliveries(transaction, owner, &effects.deliveries, now_ms)?;
    apply_repeats(transaction, owner, &effects.repeats, now_ms)?;

    let (conversations, all_conversations) = changed_conversations(transaction, owner, effects)?;
    let mut archive_answers = Vec::with_capacity(effects.archive_lookups.len());
    for lookup in &effects.archive_lookups {
        archive_answers.push((lookup.request_id, chat_archive(transaction, owner, lookup)?));
    }
    let mut heard_watches = Vec::new();
    for address in heard_from(transaction, owner, effects)? {
        if touch_last_heard(transaction, owner, &address, now_ms)? {
            heard_watches.push(address);
        }
    }
    let mut notifications = Vec::new();
    for mutation in &effects.mutations {
        let key = (mutation.session_id, mutation.handle);
        if !mutation.notify && !materialized.contains(&key) {
            continue;
        }
        if let Some(target) =
            chat_notification_target(transaction, owner, mutation.session_id, mutation.handle)?
        {
            notifications.push(MobileChatNotificationRecord::Message { target });
        } else if let Some(target) = chat_reaction_notification_target(
            transaction,
            owner,
            mutation.session_id,
            mutation.handle,
        )? {
            notifications.push(MobileChatNotificationRecord::Reaction { target });
        }
    }
    Ok(AppliedChatBatch {
        changes: MobileChatChangesRecord {
            conversations,
            all_conversations,
            notifications,
            delivery_failures,
            heard_watches,
        },
        archive_answers,
    })
}

fn is_channel_address(address: &str) -> bool {
    address.starts_with(CHANNEL_ADDRESS_PREFIX)
}

/// Open the conversation a message landed in, if it is not open: a direct
/// one with a peer this phone stores, or the group conversation of a
/// channel the phone has joined. Traffic from anyone else stays in the
/// transcript without a conversation to list it.
fn open_conversation(
    transaction: &Connection,
    context: &ChatBatchContext<'_>,
    address: &str,
) -> Result<(), MobileStoreError> {
    if is_channel_address(address) {
        let Some(digest) = context.channel_digests.get(address) else {
            return Ok(());
        };
        transaction.execute(
            "INSERT OR IGNORE INTO channel_conversation (
                owner_identity_id, channel_id, conversation_address, created_at_ms
            )
            SELECT ?1, id, ?2, ?3 FROM channel
            WHERE owner_identity_id = ?1 AND key_digest = ?4 AND joined_phone = 1",
            params![context.owner_identity_id, address, context.now_ms, digest],
        )?;
    } else {
        transaction.execute(
            "INSERT OR IGNORE INTO direct_conversation (owner_identity_id, node_id, created_at_ms)
            SELECT ?1, id, ?2 FROM node
            WHERE owner_identity_id = ?1 AND public_address = ?3",
            params![context.owner_identity_id, context.now_ms, address],
        )?;
    }
    Ok(())
}

/// The conversations whose transcripts the batch changed, and whether any
/// change landed on a message no stored row places.
fn changed_conversations(
    transaction: &Connection,
    owner: &str,
    effects: &ChatBatchEffects,
) -> Result<(Vec<String>, bool), MobileStoreError> {
    let mut addresses = BTreeSet::new();
    let mut unplaced = BTreeSet::new();
    for mutation in &effects.mutations {
        match &mutation.conversation_address {
            Some(address) => {
                addresses.insert(address.clone());
            }
            None => {
                unplaced.insert((mutation.session_id, mutation.handle));
            }
        }
    }
    for resolution in &effects.sender_resolutions {
        addresses.insert(resolution.conversation_address.clone());
    }
    unplaced.extend(
        effects
            .resends
            .iter()
            .map(|resend| (resend.message.session_id, resend.message.handle)),
    );
    unplaced.extend(
        effects
            .deliveries
            .iter()
            .map(|delivery| (delivery.session_id, delivery.handle)),
    );
    unplaced.extend(
        effects
            .repeats
            .iter()
            .map(|repeat| (repeat.session_id, repeat.handle)),
    );
    let mut all = false;
    for (session_id, handle) in unplaced {
        match conversation_address_for_message(transaction, owner, session_id, handle)? {
            Some(address) => {
                addresses.insert(address);
            }
            None => all = true,
        }
    }
    Ok((addresses.into_iter().collect(), all))
}

/// The peers the batch shows were heard from: the sender of each message
/// that arrived, and the peer of each direct conversation an
/// acknowledgment came back from. A channel is not a peer; a member of one
/// is, once their hint has resolved.
fn heard_from(
    transaction: &Connection,
    owner: &str,
    effects: &ChatBatchEffects,
) -> Result<BTreeSet<String>, MobileStoreError> {
    let mut heard = BTreeSet::new();
    for mutation in &effects.mutations {
        if mutation.direction != Some(MobileChatDirection::Inbound) {
            continue;
        }
        if let Some(address) = &mutation.sender_address {
            heard.insert(address.clone());
        } else if let Some(address) = &mutation.conversation_address
            && !is_channel_address(address)
        {
            heard.insert(address.clone());
        }
    }
    for delivery in &effects.deliveries {
        if delivery.state != MobileChatDeliveryState::Acknowledged {
            continue;
        }
        if let Some(address) = conversation_address_for_message(
            transaction,
            owner,
            delivery.session_id,
            delivery.handle,
        )? && !is_channel_address(&address)
        {
            heard.insert(address);
        }
    }
    Ok(heard)
}

#[cfg(test)]
mod tests;
