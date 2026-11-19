//! What the chat domain's tests share: a store, and mutations shaped the
//! way the engine reports them.

use std::sync::Arc;

use rusqlite::types::FromSql;

use crate::mobile_chat::{
    MobileChatDeliveryRecord, MobileChatDeliveryState, MobileChatDirection, MobileChatMutationKind,
    MobileChatMutationRecord, MobileChatPresence,
};

use super::{MobileAppStore, MobileStoredChatMessageRecord, MobileStoredChatMessageRefRecord};

pub(super) const OWNER: &str = "alice";
/// The instant the tests apply things at.
pub(super) const NOW: i64 = 1_800_000_000_000;

pub(super) fn open() -> (tempfile::TempDir, Arc<MobileAppStore>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("application.sqlite")
        .display()
        .to_string();
    let store = MobileAppStore::open(path).unwrap();
    store
        .insert_identity(OWNER.into(), "alice-public".into(), 1)
        .unwrap();
    (directory, store)
}

/// A present, complete, one-frame `Insert` in `address`, with no body.
pub(super) fn insert(
    session_id: u64,
    handle: u32,
    address: &str,
    direction: MobileChatDirection,
) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        session_id,
        handle,
        revision: 0,
        kind: MobileChatMutationKind::Insert,
        conversation_address: Some(address.into()),
        sender_address: None,
        sender_hint: None,
        direction: Some(direction),
        message_type: Some(0),
        wire_id: None,
        epoch: Some(0),
        client_token: None,
        sender_handle: None,
        regarding_handle: None,
        regarding_wire_id: None,
        regarding_direction: None,
        regarding_sender_hint: None,
        regarding_unknown: false,
        unknown_original: false,
        background_color: None,
        text_color: None,
        original_handle: None,
        original_wire_id: None,
        original_direction: None,
        original_sender_hint: None,
        body: Some(String::new()),
        complete: Some(true),
        present_fragments: Some(1),
        fragment_count: Some(1),
        finalized: Some(true),
        presence: MobileChatPresence::Present,
        received_late: false,
        notify: false,
        rx: None,
        forward_secret: None,
    }
}

/// An inbound message in `address` with a wire ID and a body.
pub(super) fn inbound(
    session_id: u64,
    handle: u32,
    address: &str,
    wire_id: u8,
    body: &str,
) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        wire_id: Some(wire_id),
        body: Some(body.into()),
        ..insert(session_id, handle, address, MobileChatDirection::Inbound)
    }
}

/// One of ours in `address` with a wire ID and a body.
pub(super) fn outbound(
    session_id: u64,
    handle: u32,
    address: &str,
    wire_id: u8,
    body: &str,
) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        wire_id: Some(wire_id),
        body: Some(body.into()),
        ..insert(session_id, handle, address, MobileChatDirection::Outbound)
    }
}

/// A revision of another mutation's message: an `Edit` or a `Delete`
/// written under its own handle, naming the original by live handle.
pub(super) fn revision(
    kind: MobileChatMutationKind,
    session_id: u64,
    handle: u32,
    address: &str,
    original_handle: u32,
    body: Option<&str>,
) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        kind,
        direction: None,
        original_handle: Some(original_handle),
        body: body.map(str::to_owned),
        ..insert(session_id, handle, address, MobileChatDirection::Outbound)
    }
}

pub(super) fn apply(
    store: &MobileAppStore,
    mutations: Vec<MobileChatMutationRecord>,
) -> Vec<MobileChatMutationRecord> {
    store
        .apply_chat_mutations(OWNER.into(), mutations, NOW, None)
        .unwrap()
}

pub(super) fn delivery(
    session_id: u64,
    handle: u32,
    fragment_index: Option<u8>,
    state: MobileChatDeliveryState,
) -> MobileChatDeliveryRecord {
    MobileChatDeliveryRecord {
        session_id,
        handle,
        fragment_index,
        state,
        via_flood: false,
    }
}

/// Every message in a conversation, oldest first.
pub(super) fn transcript(
    store: &MobileAppStore,
    address: &str,
) -> Vec<MobileStoredChatMessageRecord> {
    store
        .chat_message_page_newest(OWNER.into(), address.into(), 500)
        .unwrap()
        .messages
}

/// The one message in `address` with `body`.
pub(super) fn message(
    store: &MobileAppStore,
    address: &str,
    body: &str,
) -> MobileStoredChatMessageRecord {
    let mut found = transcript(store, address)
        .into_iter()
        .filter(|message| message.body == body);
    let message = found
        .next()
        .unwrap_or_else(|| panic!("no message {body:?}"));
    assert!(found.next().is_none(), "two messages {body:?}");
    message
}

/// A stored message's identity.
pub(super) fn reference(session_id: &str, handle: u32) -> MobileStoredChatMessageRefRecord {
    MobileStoredChatMessageRefRecord {
        session_id: session_id.into(),
        handle,
    }
}

/// One value read straight from the database.
pub(super) fn scalar<T: FromSql>(store: &MobileAppStore, sql: &str) -> T {
    store
        .connection()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}
