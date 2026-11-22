use std::sync::Arc;

use super::super::{MobilePeerUpsertRecord, MobileStoredChannelKind};
use super::*;

const OWNER: &str = "alice";
const CHANNEL: &str = "0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6";
const CHANNEL_ADDRESS: &str = "channel-address";

fn open() -> (tempfile::TempDir, Arc<MobileAppStore>) {
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

fn peer(store: &MobileAppStore, address: &str) {
    store
        .upsert_peer(
            OWNER.into(),
            address.into(),
            MobilePeerUpsertRecord {
                alias: Some(address.to_uppercase()),
                is_saved: true,
                ..MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
}

fn direct(store: &MobileAppStore, address: &str, at_ms: i64) -> i64 {
    store
        .ensure_direct_conversation(OWNER.into(), address.into(), at_ms)
        .unwrap()
}

fn add_channel(store: &MobileAppStore, id: &str, digest: &str) {
    store
        .insert_channel(
            MobileStoredChannelRecord {
                id: id.into(),
                owner_identity_id: OWNER.into(),
                kind: MobileStoredChannelKind::Named,
                canonical_name: Some("bench".into()),
                name: Some("Bench".into()),
                alias: None,
                channel_id_hex: "beef".into(),
                tint: vec![0xBE, 0xEF, 0x01],
                region_code: None,
                max_flood_hops: None,
                joined_phone: true,
                joined_device: false,
                notifications_enabled: true,
                joined_at_ms: None,
            },
            digest.into(),
            1,
        )
        .unwrap();
}

/// One `chat_message` row as the chat domain writes it; the defaults are an
/// inbound, readable, plain message.
struct Message<'a> {
    address: &'a str,
    handle: i64,
    created_at_ms: i64,
    body: &'a str,
    outbound: bool,
    deleted: bool,
    presence: i64,
    is_reaction: bool,
    silent: bool,
    message_type: Option<i64>,
    sender_address: Option<&'a str>,
    sender_hint: Option<&'a [u8]>,
    /// The delivery this message tracks, whose fragments a purge removes.
    delivery: Option<(&'a str, i64)>,
}

impl<'a> Message<'a> {
    fn new(address: &'a str, handle: i64, created_at_ms: i64) -> Self {
        Self {
            address,
            handle,
            created_at_ms,
            body: "body",
            outbound: false,
            deleted: false,
            presence: 0,
            is_reaction: false,
            silent: false,
            message_type: None,
            sender_address: None,
            sender_hint: None,
            delivery: None,
        }
    }

    fn insert(self, store: &MobileAppStore) {
        store
            .connection()
            .execute(
                "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                    conversation_address, direction, body, deleted, created_at_ms, presence,
                    is_reaction, silent, message_type, sender_address, sender_hint,
                    delivery_session_id, delivery_handle)
                VALUES ('alice', ?1, ?2, ?1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    // One session per address keeps (session, handle) unique.
                    self.address,
                    self.handle,
                    self.outbound,
                    self.body,
                    self.deleted,
                    self.created_at_ms,
                    self.presence,
                    self.is_reaction,
                    self.silent,
                    self.message_type,
                    self.sender_address,
                    self.sender_hint,
                    self.delivery.map(|(session, _)| session),
                    self.delivery.map(|(_, handle)| handle),
                ],
            )
            .unwrap();
    }
}

/// A conversation's whole footprint besides its row: a message tracking a
/// delivery, that delivery's fragment, an archived payload, and the stream
/// checkpoint.
fn add_history(store: &MobileAppStore, address: &str, session: &str) {
    Message {
        outbound: true,
        delivery: Some((session, 1)),
        ..Message::new(address, 1, 10)
    }
    .insert(store);
    let connection = store.connection();
    connection
        .execute(
            "INSERT INTO chat_delivery_fragment (owner_identity_id, session_id, handle,
                fragment_index, state)
            VALUES ('alice', ?, 1, 0, 'sent')",
            params![session],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO chat_outbound_archive (owner_identity_id, conversation_address,
                message_id, fragment_index, payload)
            VALUES ('alice', ?, 6, 0, x'010203')",
            params![address],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO chat_stream_checkpoint (owner_identity_id, conversation_address,
                next_id, epoch, updated_at_ms)
            VALUES ('alice', ?, 7, 2, 1)",
            params![address],
        )
        .unwrap();
}

/// How many messages, fragments, archived payloads, and checkpoints remain
/// for an address. Fragments are counted by the session `add_history` gave
/// them.
fn footprint(store: &MobileAppStore, address: &str, session: &str) -> [i64; 4] {
    let connection = store.connection();
    let count = |sql: &str, key: &str| -> i64 {
        connection
            .query_row(sql, params![key], |row| row.get(0))
            .unwrap()
    };
    [
        count(
            "SELECT count(*) FROM chat_message WHERE conversation_address = ?",
            address,
        ),
        count(
            "SELECT count(*) FROM chat_delivery_fragment WHERE session_id = ?",
            session,
        ),
        count(
            "SELECT count(*) FROM chat_outbound_archive WHERE conversation_address = ?",
            address,
        ),
        count(
            "SELECT count(*) FROM chat_stream_checkpoint WHERE conversation_address = ?",
            address,
        ),
    ]
}

fn directs(store: &MobileAppStore) -> Vec<MobileStoredDirectConversationRecord> {
    store.list_direct_conversations(OWNER.into()).unwrap()
}

fn channel_conversations(store: &MobileAppStore) -> Vec<MobileStoredChannelConversationRecord> {
    store.list_channel_conversations(OWNER.into()).unwrap()
}

fn addresses(store: &MobileAppStore) -> Vec<String> {
    store
        .list_nodes(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|node| node.public_address)
        .collect()
}

// The persistence smoke test's conversation checks, in its order.

#[test]
fn the_smoke_test_s_conversation_sequence() {
    let (_directory, store) = open();
    peer(&store, "peer-saved");

    // Delete refuses a peer with a conversation; the combined delete works
    // and removes both.
    let conversation = direct(&store, "peer-saved", 1);
    store
        .update_draft(OWNER.into(), conversation, "Draft survives relaunch".into())
        .unwrap();
    let conversations = directs(&store);
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].draft_text, "Draft survives relaunch");
    assert_eq!(
        store.delete_peer(OWNER.into(), "peer-saved".into()),
        Ok(false)
    );
    assert_eq!(
        store.delete_peer_and_conversation(OWNER.into(), "peer-saved".into()),
        Ok(true)
    );
    assert!(!addresses(&store).contains(&"peer-saved".into()));
    assert_eq!(directs(&store), vec![]);

    // Retention never evicts a row with a conversation.
    for index in 0..3 {
        let address = format!("flood-{index}");
        store
            .upsert_peer(
                OWNER.into(),
                address.clone(),
                MobilePeerUpsertRecord::default(),
            )
            .unwrap();
        store
            .touch_last_heard(OWNER.into(), address, 1_000_000 + index * 1_000)
            .unwrap();
    }
    direct(&store, "flood-0", 2);
    store.enforce_transient_retention(OWNER.into(), 1).unwrap();
    let mut surviving = addresses(&store);
    surviving.sort();
    assert_eq!(surviving, ["flood-0", "flood-2"]);
    store.clear_transient_peers(OWNER.into()).unwrap();
    assert_eq!(addresses(&store), ["flood-0"]);
}

#[test]
fn the_smoke_test_s_list_tail_checks() {
    let (_directory, store) = open();
    peer(&store, "deep");
    peer(&store, "empty");
    direct(&store, "deep", 1);
    add_channel(&store, CHANNEL, "digest");
    store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 1)
        .unwrap();
    // Inbound, outbound, a tombstone, a gap placeholder, an unavailable
    // marker; the last row is deleted.
    Message::new("deep", 0, 100).insert(&store);
    Message {
        outbound: true,
        ..Message::new("deep", 1, 200)
    }
    .insert(&store);
    Message {
        presence: 1,
        ..Message::new("deep", 2, 300)
    }
    .insert(&store);
    Message {
        presence: 2,
        ..Message::new("deep", 3, 400)
    }
    .insert(&store);
    Message::new("deep", 4, 500).insert(&store);
    Message {
        deleted: true,
        body: "",
        ..Message::new("deep", 5, 600)
    }
    .insert(&store);
    Message {
        sender_address: Some("member"),
        sender_hint: Some(&[1, 2, 3]),
        ..Message::new(CHANNEL_ADDRESS, 0, 100)
    }
    .insert(&store);

    // The preview is the literal last row, tombstones included.
    let deep = directs(&store)
        .into_iter()
        .find(|conversation| conversation.node.public_address == "deep")
        .unwrap();
    assert_eq!(
        deep.last_message,
        Some(MobileStoredConversationPreviewRecord {
            created_at_ms: 600,
            body: "".into(),
            is_outbound: false,
            is_deleted: true,
            sender_address: None,
            sender_hint: None,
            is_status: false,
        })
    );
    // Never opened, so everything inbound and readable is unread.
    assert_eq!(deep.unread_count, 2);

    // A conversation with no messages reports no preview and nothing
    // unread, rather than a zero-valued one.
    direct(&store, "empty", 2);
    let empty = directs(&store)
        .into_iter()
        .find(|conversation| conversation.node.public_address == "empty")
        .unwrap();
    assert_eq!((empty.last_message, empty.unread_count), (None, 0));

    // Marking read clears the badge without touching the preview.
    store
        .mark_conversation_read(OWNER.into(), "deep".into(), 1_000)
        .unwrap();
    let read = directs(&store)
        .into_iter()
        .find(|conversation| conversation.node.public_address == "deep")
        .unwrap();
    assert_eq!(read.unread_count, 0);
    assert_eq!(read.last_read_at_ms, 1_000);
    assert_eq!(read.last_message, deep.last_message);

    // The channel tail carries the hint its bubble would show.
    let channel = &channel_conversations(&store)[0];
    assert_eq!(channel.unread_count, 1);
    let preview = channel.last_message.as_ref().unwrap();
    assert_eq!(preview.sender_hint.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(preview.sender_address.as_deref(), Some("member"));
    store
        .mark_conversation_read(OWNER.into(), CHANNEL_ADDRESS.into(), 1_000)
        .unwrap();
    assert_eq!(channel_conversations(&store)[0].unread_count, 0);
}

#[test]
fn the_tail_skips_reactions_and_unread_skips_what_a_person_does_not_read() {
    let (_directory, store) = open();
    peer(&store, "peer");
    direct(&store, "peer", 1);
    Message::new("peer", 0, 100).insert(&store);
    Message {
        message_type: Some(1),
        body: "is out",
        ..Message::new("peer", 1, 200)
    }
    .insert(&store);
    // Newer than the status, but none of these is the preview or unread.
    Message {
        is_reaction: true,
        body: "<3",
        ..Message::new("peer", 2, 300)
    }
    .insert(&store);
    // Silent rows are transcript rows: the preview, but never unread.
    Message {
        silent: true,
        body: "silent",
        ..Message::new("peer", 3, 250)
    }
    .insert(&store);
    let conversation = &directs(&store)[0];
    let preview = conversation.last_message.as_ref().unwrap();
    assert_eq!(
        (preview.body.as_str(), preview.is_status),
        ("silent", false)
    );
    assert_eq!(conversation.unread_count, 2);

    // The same instant: the later row is the newer.
    Message {
        message_type: Some(1),
        body: "status",
        ..Message::new("peer", 4, 250)
    }
    .insert(&store);
    let preview = directs(&store)[0].last_message.clone().unwrap();
    assert_eq!((preview.body.as_str(), preview.is_status), ("status", true));

    // Only messages after the read cursor count.
    store
        .mark_conversation_read(OWNER.into(), "peer".into(), 100)
        .unwrap();
    assert_eq!(directs(&store)[0].unread_count, 2);
    store
        .mark_conversation_read(OWNER.into(), "peer".into(), 200)
        .unwrap();
    assert_eq!(directs(&store)[0].unread_count, 1);
}

#[test]
fn a_direct_conversation_is_ensured_once_per_peer() {
    let (_directory, store) = open();
    peer(&store, "peer");
    let id = direct(&store, "peer", 10);
    assert_eq!(direct(&store, "peer", 20), id);
    let conversation = &directs(&store)[0];
    assert_eq!(conversation.id, id);
    assert_eq!(conversation.created_at_ms, 10);
    assert_eq!(conversation.last_read_at_ms, 0);
    assert_eq!(conversation.draft_text, "");
    // A direct conversation may notify until told otherwise.
    assert!(conversation.notifications_enabled);
    assert_eq!(conversation.node.public_address, "peer");
    assert_eq!(conversation.node.alias.as_deref(), Some("PEER"));

    // A peer this identity has no row for has no conversation.
    assert_eq!(
        store.ensure_direct_conversation(OWNER.into(), "stranger".into(), 1),
        Err(MobileStoreError::RecordNotFound)
    );
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    assert_eq!(
        store.ensure_direct_conversation("bob".into(), "peer".into(), 1),
        Err(MobileStoreError::RecordNotFound)
    );
}

#[test]
fn direct_conversations_list_newest_first_and_only_the_identity_s_own() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    for address in ["a", "b", "c"] {
        peer(&store, address);
    }
    direct(&store, "a", 10);
    direct(&store, "b", 30);
    // The same instant as b and created after it: the ID breaks the tie.
    direct(&store, "c", 30);
    store
        .upsert_peer("bob".into(), "a".into(), MobilePeerUpsertRecord::default())
        .unwrap();
    store
        .ensure_direct_conversation("bob".into(), "a".into(), 99)
        .unwrap();
    let order: Vec<String> = directs(&store)
        .into_iter()
        .map(|conversation| conversation.node.public_address)
        .collect();
    assert_eq!(order, ["c", "b", "a"]);
}

#[test]
fn drafts_and_notifications_are_per_conversation_and_per_identity() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    peer(&store, "peer");
    let id = direct(&store, "peer", 1);
    store
        .update_draft(OWNER.into(), id, "half a thought".into())
        .unwrap();
    assert_eq!(directs(&store)[0].draft_text, "half a thought");
    store.update_draft(OWNER.into(), id, "".into()).unwrap();
    assert_eq!(directs(&store)[0].draft_text, "");
    assert_eq!(
        store.update_draft(OWNER.into(), id + 1, "x".into()),
        Err(MobileStoreError::RecordNotFound)
    );
    assert_eq!(
        store.update_draft("bob".into(), id, "x".into()),
        Err(MobileStoreError::RecordNotFound)
    );

    store
        .set_direct_conversation_notifications(OWNER.into(), id, false)
        .unwrap();
    assert!(!directs(&store)[0].notifications_enabled);
    // Another identity's call, or a missing row, changes nothing and is
    // not an error.
    store
        .set_direct_conversation_notifications("bob".into(), id, true)
        .unwrap();
    store
        .set_direct_conversation_notifications(OWNER.into(), id + 1, true)
        .unwrap();
    assert!(!directs(&store)[0].notifications_enabled);
    store
        .set_direct_conversation_notifications(OWNER.into(), id, true)
        .unwrap();
    assert!(directs(&store)[0].notifications_enabled);
}

#[test]
fn deleting_a_direct_conversation_purges_its_history_and_keeps_the_peer() {
    let (_directory, store) = open();
    peer(&store, "peer");
    peer(&store, "other");
    let id = direct(&store, "peer", 1);
    direct(&store, "other", 2);
    add_history(&store, "peer", "s-peer");
    add_history(&store, "other", "s-other");

    // Another identity's ID changes nothing.
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store.delete_direct_conversation("bob".into(), id).unwrap();
    assert_eq!(directs(&store).len(), 2);

    store.delete_direct_conversation(OWNER.into(), id).unwrap();
    let left: Vec<String> = directs(&store)
        .into_iter()
        .map(|conversation| conversation.node.public_address)
        .collect();
    assert_eq!(left, ["other"]);
    // The checkpoint outlives the transcript; nothing else does.
    assert_eq!(footprint(&store, "peer", "s-peer"), [0, 0, 0, 1]);
    assert_eq!(footprint(&store, "other", "s-other"), [1, 1, 1, 1]);
    assert!(addresses(&store).contains(&"peer".into()));
    // With the conversation gone, the peer can be deleted on its own.
    assert_eq!(store.delete_peer(OWNER.into(), "peer".into()), Ok(true));
    // A conversation that is not there is not an error.
    store.delete_direct_conversation(OWNER.into(), id).unwrap();
}

#[test]
fn deleting_a_peer_with_its_conversation_takes_everything_but_the_checkpoint() {
    let (_directory, store) = open();
    peer(&store, "peer");
    direct(&store, "peer", 1);
    add_history(&store, "peer", "s-peer");
    let node_id: i64 = store
        .connection()
        .query_row(
            "SELECT id FROM node WHERE public_address = 'peer'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    {
        let connection = store.connection();
        for sql in [
            "INSERT INTO node_manual_route (node_id, hints, hold_until_ms) VALUES (?, x'', 1)",
            "INSERT INTO node_mgmt_card (node_id, capabilities, fetched_at_ms) VALUES (?, x'', 1)",
            "INSERT INTO node_prop_cache (node_id, property_id, value, fetched_at_ms)
                VALUES (?, 1, x'', 1)",
            "INSERT INTO node_peer_repeaters (node_id, as_of_ms) VALUES (?, 1)",
            "INSERT INTO node_peer_repeater_entry (node_id, hint, position, reported_at_ms)
                VALUES (?, x'0102', 0, 1)",
        ] {
            connection.execute(sql, params![node_id]).unwrap();
        }
    }
    assert_eq!(
        store.delete_peer_and_conversation(OWNER.into(), "peer".into()),
        Ok(true)
    );
    assert_eq!(addresses(&store), Vec::<String>::new());
    assert_eq!(directs(&store), vec![]);
    assert_eq!(footprint(&store, "peer", "s-peer"), [0, 0, 0, 1]);
    for table in [
        "node_manual_route",
        "node_mgmt_card",
        "node_prop_cache",
        "node_peer_repeaters",
        "node_peer_repeater_entry",
    ] {
        let rows: i64 = store
            .connection()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0, "{table}");
    }

    // A peer without a conversation goes too; one that is not there is
    // reported, as is the companion radio, which stays.
    peer(&store, "lonely");
    assert_eq!(
        store.delete_peer_and_conversation(OWNER.into(), "lonely".into()),
        Ok(true)
    );
    assert_eq!(
        store.delete_peer_and_conversation(OWNER.into(), "lonely".into()),
        Ok(false)
    );
    store
        .upsert_ulcp_device_peer(OWNER.into(), "radio".into(), None, "R".into())
        .unwrap();
    direct(&store, "radio", 3);
    add_history(&store, "radio", "s-radio");
    assert_eq!(
        store.delete_peer_and_conversation(OWNER.into(), "radio".into()),
        Ok(false)
    );
    assert_eq!(addresses(&store), ["radio"]);
    assert_eq!(directs(&store).len(), 1);
    assert_eq!(footprint(&store, "radio", "s-radio"), [1, 1, 1, 1]);
}

#[test]
fn clearing_messages_keeps_the_conversation_its_draft_and_its_checkpoint() {
    let (_directory, store) = open();
    peer(&store, "peer");
    peer(&store, "other");
    let id = direct(&store, "peer", 1);
    direct(&store, "other", 1);
    store.update_draft(OWNER.into(), id, "kept".into()).unwrap();
    add_history(&store, "peer", "s-peer");
    add_history(&store, "other", "s-other");
    store
        .clear_conversation_messages(OWNER.into(), "peer".into())
        .unwrap();
    assert_eq!(footprint(&store, "peer", "s-peer"), [0, 0, 0, 1]);
    assert_eq!(footprint(&store, "other", "s-other"), [1, 1, 1, 1]);
    let conversation = directs(&store)
        .into_iter()
        .find(|conversation| conversation.id == id)
        .unwrap();
    assert_eq!(conversation.draft_text, "kept");
    assert_eq!(conversation.last_message, None);

    // Another identity's history at the same address is not this one's.
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store
        .clear_conversation_messages("bob".into(), "other".into())
        .unwrap();
    assert_eq!(footprint(&store, "other", "s-other"), [1, 1, 1, 1]);

    // A channel conversation clears the same way.
    add_channel(&store, CHANNEL, "digest");
    store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 1)
        .unwrap();
    add_history(&store, CHANNEL_ADDRESS, "s-channel");
    store
        .clear_conversation_messages(OWNER.into(), CHANNEL_ADDRESS.into())
        .unwrap();
    assert_eq!(
        footprint(&store, CHANNEL_ADDRESS, "s-channel"),
        [0, 0, 0, 1]
    );
    assert_eq!(channel_conversations(&store).len(), 1);
}

#[test]
fn a_channel_conversation_is_ensured_once_per_channel_in_any_case() {
    let (_directory, store) = open();
    add_channel(&store, CHANNEL, "digest");
    let id = store
        .ensure_channel_conversation(
            OWNER.into(),
            CHANNEL.to_ascii_lowercase(),
            CHANNEL_ADDRESS.into(),
            10,
        )
        .unwrap();
    // A second call keeps the first one's address and creation time.
    assert_eq!(
        store.ensure_channel_conversation(OWNER.into(), CHANNEL.into(), "other".into(), 20),
        Ok(id)
    );
    assert_eq!(
        channel_conversations(&store),
        vec![MobileStoredChannelConversationRecord {
            id,
            channel_id: CHANNEL.into(),
            conversation_address: CHANNEL_ADDRESS.into(),
            draft_text: "".into(),
            last_read_at_ms: 0,
            created_at_ms: 10,
            last_message: None,
            unread_count: 0,
        }]
    );
    let stored: String = store
        .connection()
        .query_row("SELECT channel_id FROM channel_conversation", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored, CHANNEL);

    assert_eq!(
        store.ensure_channel_conversation(
            OWNER.into(),
            "00000000-0000-0000-0000-000000000000".into(),
            "nowhere".into(),
            1
        ),
        Err(MobileStoreError::RecordNotFound)
    );
    assert_eq!(
        store.ensure_channel_conversation(OWNER.into(), "nope".into(), "nowhere".into(), 1),
        Err(MobileStoreError::InvalidArgument)
    );
}

#[test]
fn only_a_joined_channel_s_conversation_opens() {
    let (_directory, store) = open();
    add_channel(&store, CHANNEL, "digest");
    let open = |at| store.open_joined_channel_conversation(OWNER, CHANNEL, CHANNEL_ADDRESS, at);
    assert_eq!(open(10), Ok(Some(true)));
    assert_eq!(open(20), Ok(Some(false)), "open already");
    assert_eq!(channel_conversations(&store)[0].created_at_ms, 10);

    store.set_channel_joined_phone(CHANNEL, false, 30).unwrap();
    assert_eq!(open(30), Ok(None), "left");
    assert_eq!(
        store.open_joined_channel_conversation(
            OWNER,
            "00000000-0000-0000-0000-000000000000",
            "nowhere",
            1
        ),
        Ok(None)
    );
}

#[test]
fn channel_conversations_list_newest_first_and_skip_unreadable_ids() {
    let (_directory, store) = open();
    let second = "00000000-0000-0000-0000-000000000002";
    add_channel(&store, CHANNEL, "first");
    add_channel(&store, second, "second");
    store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), "first-address".into(), 10)
        .unwrap();
    store
        .ensure_channel_conversation(OWNER.into(), second.into(), "second-address".into(), 20)
        .unwrap();
    {
        let connection = store.connection();
        connection
            .execute(
                "INSERT INTO channel (id, owner_identity_id, kind, channel_id_hex, tint,
                    key_digest, created_at_ms)
                VALUES ('not-a-uuid', 'alice', 'named', 'beef', x'BEEF01', 'bad', 1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO channel_conversation (owner_identity_id, channel_id,
                    conversation_address, created_at_ms)
                VALUES ('alice', 'not-a-uuid', 'bad-address', 30)",
                [],
            )
            .unwrap();
    }
    let listed: Vec<(String, String)> = channel_conversations(&store)
        .into_iter()
        .map(|conversation| (conversation.channel_id, conversation.conversation_address))
        .collect();
    assert_eq!(
        listed,
        [
            (second.into(), "second-address".into()),
            (CHANNEL.into(), "first-address".into()),
        ]
    );
}

#[test]
fn a_channel_draft_needs_its_conversation() {
    let (_directory, store) = open();
    // Each table numbers its own rows, so a spare direct conversation first
    // keeps the two IDs below from coinciding.
    peer(&store, "spare");
    direct(&store, "spare", 1);
    add_channel(&store, CHANNEL, "digest");
    let id = store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 1)
        .unwrap();
    store
        .update_channel_draft(OWNER.into(), id, "to the group".into())
        .unwrap();
    assert_eq!(channel_conversations(&store)[0].draft_text, "to the group");
    assert_eq!(
        store.update_channel_draft(OWNER.into(), id + 1, "x".into()),
        Err(MobileStoreError::RecordNotFound)
    );
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    assert_eq!(
        store.update_channel_draft("bob".into(), id, "x".into()),
        Err(MobileStoreError::RecordNotFound)
    );
    // A direct conversation's ID is not a channel conversation's.
    peer(&store, "peer");
    let direct_id = direct(&store, "peer", 1);
    assert_ne!(direct_id, id);
    assert_eq!(
        store.update_channel_draft(OWNER.into(), direct_id, "x".into()),
        Err(MobileStoreError::RecordNotFound)
    );
}

#[test]
fn deleting_a_channel_conversation_purges_it_and_keeps_the_channel() {
    let (_directory, store) = open();
    add_channel(&store, CHANNEL, "digest");
    let id = store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 1)
        .unwrap();
    add_history(&store, CHANNEL_ADDRESS, "s-channel");
    peer(&store, "peer");
    direct(&store, "peer", 1);
    add_history(&store, "peer", "s-peer");

    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store.delete_channel_conversation("bob".into(), id).unwrap();
    assert_eq!(channel_conversations(&store).len(), 1);

    store.delete_channel_conversation(OWNER.into(), id).unwrap();
    assert_eq!(channel_conversations(&store), vec![]);
    assert_eq!(
        footprint(&store, CHANNEL_ADDRESS, "s-channel"),
        [0, 0, 0, 1]
    );
    assert_eq!(footprint(&store, "peer", "s-peer"), [1, 1, 1, 1]);
    // Leaving the chat is not leaving the channel.
    assert_eq!(store.channels(OWNER.into()).unwrap().len(), 1);
    // Entering it again opens a new conversation.
    let again = store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 2)
        .unwrap();
    assert_ne!(again, id);
    store.delete_channel_conversation(OWNER.into(), id).unwrap();
    assert_eq!(channel_conversations(&store).len(), 1);
}

#[test]
fn marking_read_reaches_both_kinds_by_address_and_only_the_identity_s_own() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    peer(&store, "peer");
    direct(&store, "peer", 1);
    store
        .upsert_peer(
            "bob".into(),
            "peer".into(),
            MobilePeerUpsertRecord::default(),
        )
        .unwrap();
    store
        .ensure_direct_conversation("bob".into(), "peer".into(), 1)
        .unwrap();
    add_channel(&store, CHANNEL, "digest");
    store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 1)
        .unwrap();

    store
        .mark_conversation_read(OWNER.into(), "peer".into(), 500)
        .unwrap();
    assert_eq!(directs(&store)[0].last_read_at_ms, 500);
    assert_eq!(channel_conversations(&store)[0].last_read_at_ms, 0);
    let bobs: i64 = store
        .connection()
        .query_row(
            "SELECT last_read_at_ms FROM direct_conversation WHERE owner_identity_id = 'bob'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bobs, 0);

    store
        .mark_conversation_read(OWNER.into(), CHANNEL_ADDRESS.into(), 600)
        .unwrap();
    assert_eq!(channel_conversations(&store)[0].last_read_at_ms, 600);
    assert_eq!(directs(&store)[0].last_read_at_ms, 500);
    // An address with no conversation is not an error.
    store
        .mark_conversation_read(OWNER.into(), "nobody".into(), 700)
        .unwrap();
}

#[test]
fn application_records_read_every_list_or_only_the_conversations() {
    let (_directory, store) = open();
    peer(&store, "peer");
    direct(&store, "peer", 1);
    add_channel(&store, CHANNEL, "digest");
    store
        .ensure_channel_conversation(OWNER.into(), CHANNEL.into(), CHANNEL_ADDRESS.into(), 1)
        .unwrap();
    let node_id = store.list_nodes(OWNER.into()).unwrap()[0].id;
    store
        .connection()
        .execute(
            "INSERT INTO node_peer_repeater_entry (node_id, hint, position, reported_at_ms)
            VALUES (?, x'0102', 0, 1)",
            params![node_id],
        )
        .unwrap();

    let records = store.application_records(OWNER.into(), false).unwrap();
    assert_eq!(
        records,
        MobileApplicationRecords {
            peers: store.list_nodes(OWNER.into()).unwrap(),
            channels: store.channels(OWNER.into()).unwrap(),
            conversations: directs(&store),
            channel_conversations: channel_conversations(&store),
            reports: store.all_peer_repeater_entries(OWNER.into()).unwrap(),
        }
    );
    assert_eq!(
        (
            records.peers.len(),
            records.channels.len(),
            records.conversations.len(),
            records.channel_conversations.len(),
            records.reports.len(),
        ),
        (1, 1, 1, 1, 1)
    );

    let conversations_only = store.application_records(OWNER.into(), true).unwrap();
    assert_eq!(
        conversations_only,
        MobileApplicationRecords {
            peers: vec![],
            reports: vec![],
            ..records
        }
    );
}
