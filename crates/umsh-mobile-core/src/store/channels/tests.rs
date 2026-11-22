use std::sync::Arc;

use super::*;

const OWNER: &str = "alice";
const ID: &str = "0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6";

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

fn channel(id: &str) -> MobileStoredChannelRecord {
    MobileStoredChannelRecord {
        id: id.into(),
        owner_identity_id: OWNER.into(),
        kind: MobileStoredChannelKind::Named,
        canonical_name: Some("ridge".into()),
        name: Some("Ridge".into()),
        alias: None,
        channel_id_hex: "beef".into(),
        tint: vec![0xBE, 0xEF, 0x01],
        region_code: None,
        max_flood_hops: None,
        joined_phone: true,
        joined_device: false,
        notifications_enabled: false,
        joined_at_ms: None,
    }
}

fn insert(store: &MobileAppStore, channel: MobileStoredChannelRecord, digest: &str, at_ms: i64) {
    store.insert_channel(channel, digest.into(), at_ms).unwrap();
}

fn only(store: &MobileAppStore) -> MobileStoredChannelRecord {
    let mut channels = store.channels(OWNER.into()).unwrap();
    assert_eq!(channels.len(), 1);
    channels.remove(0)
}

#[test]
fn a_channel_round_trips_with_every_field() {
    let (_directory, store) = open();
    let full = MobileStoredChannelRecord {
        kind: MobileStoredChannelKind::PrivateKey,
        canonical_name: None,
        alias: Some("Ops".into()),
        region_code: Some(vec![0x55, 0x53]),
        max_flood_hops: Some(5),
        joined_device: true,
        notifications_enabled: true,
        joined_at_ms: Some(1_700_000_000_123),
        ..channel(ID)
    };
    insert(&store, full.clone(), "digest", 10);
    assert_eq!(only(&store), full);
    assert_eq!(store.channel(OWNER.into(), "digest".into()), Ok(Some(full)));
}

#[test]
fn columns_hold_the_swift_store_s_encodings() {
    let (_directory, store) = open();
    insert(
        &store,
        MobileStoredChannelRecord {
            kind: MobileStoredChannelKind::PrivateKey,
            region_code: Some(vec![0x55, 0x53]),
            joined_device: true,
            ..channel(&ID.to_ascii_lowercase())
        },
        "digest",
        10,
    );
    let row: (String, String, String, String, String, i64, i64, i64, i64) = store
        .connection()
        .query_row(
            "SELECT id, kind, typeof(tint), typeof(region_code), typeof(created_at_ms),
                joined_phone, joined_device, notifications_enabled, created_at_ms
            FROM channel",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            ID.into(),
            "private".into(),
            "blob".into(),
            "blob".into(),
            "integer".into(),
            1,
            1,
            0,
            10
        )
    );
    for (kind, text) in [
        (MobileStoredChannelKind::Builtin, "builtin"),
        (MobileStoredChannelKind::Named, "named"),
        (MobileStoredChannelKind::PrivateKey, "private"),
    ] {
        assert_eq!(kind.as_str(), text);
        assert_eq!(MobileStoredChannelKind::parse(text), Some(kind));
    }
}

#[test]
fn channels_list_oldest_first_and_only_the_identity_s_own() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    let b = "00000000-0000-0000-0000-00000000000B";
    let a = "00000000-0000-0000-0000-00000000000A";
    let c = "00000000-0000-0000-0000-00000000000C";
    insert(&store, channel(b), "b", 20);
    insert(&store, channel(c), "c", 10);
    // The same instant as b: the ID breaks the tie.
    insert(&store, channel(a), "a", 20);
    insert(
        &store,
        MobileStoredChannelRecord {
            owner_identity_id: "bob".into(),
            ..channel("00000000-0000-0000-0000-000000000000")
        },
        "bob",
        0,
    );
    let ids: Vec<String> = store
        .channels(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|channel| channel.id)
        .collect();
    assert_eq!(ids, [c, a, b]);
    assert_eq!(store.channels("nobody".into()), Ok(vec![]));
}

#[test]
fn a_channel_is_found_by_its_key_digest_within_its_identity() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    insert(&store, channel(ID), "digest", 10);
    assert_eq!(
        store
            .channel(OWNER.into(), "digest".into())
            .unwrap()
            .map(|channel| channel.id),
        Some(ID.into())
    );
    assert_eq!(store.channel(OWNER.into(), "other".into()), Ok(None));
    assert_eq!(store.channel("bob".into(), "digest".into()), Ok(None));
}

#[test]
fn an_identity_holds_one_channel_per_id_and_per_key() {
    let (_directory, store) = open();
    insert(&store, channel(ID), "digest", 10);
    // The same ID in another case is the same channel.
    assert!(matches!(
        store.insert_channel(channel(&ID.to_ascii_lowercase()), "other".into(), 11),
        Err(MobileStoreError::Failed { .. })
    ));
    assert!(matches!(
        store.insert_channel(
            channel("00000000-0000-0000-0000-000000000001"),
            "digest".into(),
            11
        ),
        Err(MobileStoreError::Failed { .. })
    ));
    // A channel needs its identity.
    assert!(matches!(
        store.insert_channel(
            MobileStoredChannelRecord {
                owner_identity_id: "nobody".into(),
                ..channel("00000000-0000-0000-0000-000000000002")
            },
            "nobody".into(),
            11
        ),
        Err(MobileStoreError::Failed { .. })
    ));
    assert_eq!(store.channels(OWNER.into()).unwrap().len(), 1);
}

#[test]
fn ids_are_stored_uppercase_and_matched_in_any_case() {
    let (_directory, store) = open();
    let lower = ID.to_ascii_lowercase();
    insert(&store, channel(&lower), "digest", 10);
    assert_eq!(only(&store).id, ID);

    store
        .update_channel_details(lower.clone(), Some("Ops".into()), None, None, true)
        .unwrap();
    assert_eq!(only(&store).alias.as_deref(), Some("Ops"));
    store
        .set_channel_membership(lower.clone(), false, true, 50)
        .unwrap();
    assert!(only(&store).joined_device);
    // Mixed case, as typed.
    let mixed: String = ID
        .chars()
        .enumerate()
        .map(|(index, c)| {
            if index % 2 == 0 {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    store.delete_channel(mixed).unwrap();
    assert_eq!(store.channels(OWNER.into()), Ok(vec![]));
}

#[test]
fn an_id_that_is_not_a_uuid_is_refused() {
    let (_directory, store) = open();
    for bad in [
        "",
        "not-a-uuid",
        // No hyphens, braces, a non-hex digit, one digit short.
        "0F8E2D4C1B3A4C5D9E8FA1B2C3D4E5F6",
        "{0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6}",
        "0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5FG",
        "0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F",
    ] {
        assert_eq!(
            store.insert_channel(channel(bad), "digest".into(), 1),
            Err(MobileStoreError::InvalidArgument),
            "{bad:?}"
        );
        assert_eq!(
            store.update_channel_details(bad.into(), None, None, None, false),
            Err(MobileStoreError::InvalidArgument)
        );
        assert_eq!(
            store.set_channel_membership(bad.into(), true, true, 1),
            Err(MobileStoreError::InvalidArgument)
        );
        assert_eq!(
            store.delete_channel(bad.into()),
            Err(MobileStoreError::InvalidArgument)
        );
    }
    assert_eq!(store.channels(OWNER.into()), Ok(vec![]));
}

#[test]
fn details_change_only_what_the_user_controls() {
    let (_directory, store) = open();
    let original = MobileStoredChannelRecord {
        joined_device: true,
        joined_at_ms: Some(5),
        region_code: Some(vec![1, 2]),
        max_flood_hops: Some(3),
        ..channel(ID)
    };
    insert(&store, original.clone(), "digest", 10);
    store
        .update_channel_details(
            ID.into(),
            Some("Ops".into()),
            Some(vec![9, 9]),
            Some(7),
            true,
        )
        .unwrap();
    assert_eq!(
        only(&store),
        MobileStoredChannelRecord {
            alias: Some("Ops".into()),
            region_code: Some(vec![9, 9]),
            max_flood_hops: Some(7),
            notifications_enabled: true,
            ..original.clone()
        }
    );
    // Absent values clear: this is a setter, not a merge.
    store
        .update_channel_details(ID.into(), None, None, None, false)
        .unwrap();
    assert_eq!(
        only(&store),
        MobileStoredChannelRecord {
            region_code: None,
            max_flood_hops: None,
            ..original
        }
    );
    // A channel that is not there is not an error.
    store
        .update_channel_details(
            "00000000-0000-0000-0000-000000000000".into(),
            None,
            None,
            None,
            true,
        )
        .unwrap();
}

#[test]
fn membership_stamps_the_first_phone_join_and_keeps_it() {
    let (_directory, store) = open();
    insert(
        &store,
        MobileStoredChannelRecord {
            joined_phone: false,
            ..channel(ID)
        },
        "digest",
        10,
    );
    assert_eq!(only(&store).joined_at_ms, None);

    // The device joining alone is not the phone joining.
    store
        .set_channel_membership(ID.into(), false, true, 100)
        .unwrap();
    let stored = only(&store);
    assert!(!stored.joined_phone && stored.joined_device);
    assert_eq!(stored.joined_at_ms, None);

    store
        .set_channel_membership(ID.into(), true, true, 200)
        .unwrap();
    let stored = only(&store);
    assert!(stored.joined_phone && stored.joined_device);
    assert_eq!(stored.joined_at_ms, Some(200));

    // Leaving keeps the stamp, and so does rejoining.
    store
        .set_channel_membership(ID.into(), false, false, 300)
        .unwrap();
    let stored = only(&store);
    assert!(!stored.joined_phone && !stored.joined_device);
    assert_eq!(stored.joined_at_ms, Some(200));
    store
        .set_channel_membership(ID.into(), true, false, 400)
        .unwrap();
    assert_eq!(only(&store).joined_at_ms, Some(200));

    // A stamp the insert carried is kept as well.
    let other = "00000000-0000-0000-0000-000000000001";
    insert(
        &store,
        MobileStoredChannelRecord {
            joined_at_ms: Some(7),
            ..channel(other)
        },
        "other",
        11,
    );
    store
        .set_channel_membership(other.into(), true, false, 500)
        .unwrap();
    let joined: Vec<Option<i64>> = store
        .channels(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|channel| channel.joined_at_ms)
        .collect();
    assert_eq!(joined, [Some(200), Some(7)]);
}

#[test]
fn deleting_a_channel_takes_its_conversation_row_but_not_its_transcript() {
    let (_directory, store) = open();
    insert(&store, channel(ID), "digest", 10);
    store
        .ensure_channel_conversation(OWNER.into(), ID.into(), "channel-address".into(), 20)
        .unwrap();
    store
        .connection()
        .execute(
            "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                conversation_address, direction, body, created_at_ms)
            VALUES ('alice', 's', 1, 'channel-address', 0, 'hello', 30)",
            [],
        )
        .unwrap();
    store.delete_channel(ID.into()).unwrap();
    assert_eq!(store.channels(OWNER.into()), Ok(vec![]));
    assert_eq!(store.list_channel_conversations(OWNER.into()), Ok(vec![]));
    // The caller purges the transcript first, through
    // delete_channel_conversation, as the Swift store's callers do.
    let messages: i64 = store
        .connection()
        .query_row("SELECT count(*) FROM chat_message", [], |row| row.get(0))
        .unwrap();
    assert_eq!(messages, 1);
    // Deleting what is not there is not an error.
    store.delete_channel(ID.into()).unwrap();
}

#[test]
fn rows_this_build_cannot_read_are_left_out() {
    let (_directory, store) = open();
    insert(&store, channel(ID), "digest", 10);
    let connection = store.connection();
    let raw = |id: &str, kind: &str, digest: &str| {
        connection
            .execute(
                "INSERT INTO channel (id, owner_identity_id, kind, channel_id_hex, tint,
                    key_digest, created_at_ms)
                VALUES (?, 'alice', ?, 'beef', x'BEEF01', ?, 5)",
                params![id, kind, digest],
            )
            .unwrap();
    };
    raw("not-a-uuid", "named", "bad-id");
    raw("00000000-0000-0000-0000-000000000001", "secret", "bad-kind");
    // A lowercase ID the Swift store never wrote still reads, uppercase.
    raw(
        "abcdef00-0000-0000-0000-000000000002",
        "builtin",
        "lowercase",
    );
    drop(connection);
    let ids: Vec<String> = store
        .channels(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|channel| channel.id)
        .collect();
    assert_eq!(ids, ["ABCDEF00-0000-0000-0000-000000000002", ID]);
    assert_eq!(store.channel(OWNER.into(), "bad-id".into()), Ok(None));
    assert_eq!(store.channel(OWNER.into(), "bad-kind".into()), Ok(None));
    assert_eq!(
        store
            .channel(OWNER.into(), "lowercase".into())
            .unwrap()
            .map(|channel| channel.kind),
        Some(MobileStoredChannelKind::Builtin)
    );
}

#[test]
fn the_uuid_form_is_foundation_s() {
    assert_eq!(
        canonical_uuid("0f8e2d4c-1b3a-4c5d-9e8f-a1b2c3d4e5f6").as_deref(),
        Some(ID)
    );
    assert_eq!(canonical_uuid(ID).as_deref(), Some(ID));
    assert_eq!(
        canonical_uuid(" 0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6"),
        None
    );
    assert_eq!(
        canonical_uuid("0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6 "),
        None
    );
    assert_eq!(canonical_uuid("0F8E2D4C-1B3A-4C5D-9E8FA-1B2C3D4E5F6"), None);
    // Multi-byte text of the right byte length is not hex.
    assert_eq!(canonical_uuid("0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5é"), None);
}

fn messages(store: &MobileAppStore) -> i64 {
    store
        .connection()
        .query_row("SELECT count(*) FROM chat_message", [], |row| row.get(0))
        .unwrap()
}

fn with_conversation(store: &MobileAppStore, id: &str, address: &str) {
    store
        .ensure_channel_conversation(OWNER.into(), id.into(), address.into(), 20)
        .unwrap();
    store
        .connection()
        .execute(
            "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                conversation_address, direction, body, created_at_ms)
            VALUES ('alice', 's', 1, ?, 0, 'hello', 30)",
            [address],
        )
        .unwrap();
}

#[test]
fn leaving_deletes_the_row_and_purges_the_conversation() {
    let (_directory, store) = open();
    insert(
        &store,
        MobileStoredChannelRecord {
            joined_device: true,
            ..channel(ID)
        },
        "digest",
        10,
    );
    with_conversation(&store, ID, "channel-address");
    assert_eq!(
        store.leave_channel(OWNER, &ID.to_ascii_lowercase()),
        Ok(Some(LeftChannel {
            deleted: true,
            conversation_address: Some("channel-address".into()),
        }))
    );
    assert_eq!(store.channels(OWNER.into()), Ok(vec![]));
    assert_eq!(store.list_channel_conversations(OWNER.into()), Ok(vec![]));
    assert_eq!(messages(&store), 0);
    assert_eq!(store.leave_channel(OWNER, ID), Ok(None));
}

#[test]
fn leaving_a_built_in_channel_keeps_its_row() {
    let (_directory, store) = open();
    insert(
        &store,
        MobileStoredChannelRecord {
            kind: MobileStoredChannelKind::Builtin,
            joined_at_ms: Some(5),
            ..channel(ID)
        },
        "digest",
        10,
    );
    assert_eq!(
        store.leave_channel(OWNER, ID),
        Ok(Some(LeftChannel {
            deleted: false,
            conversation_address: None,
        }))
    );
    let stored = only(&store);
    assert!(!stored.joined_phone);
    assert_eq!(stored.joined_at_ms, Some(5));
    // Another identity's channel is not this one's to leave.
    assert_eq!(store.leave_channel("bob", ID), Ok(None));
}

#[test]
fn the_core_s_writes_change_one_thing_each() {
    let (_directory, store) = open();
    insert(
        &store,
        MobileStoredChannelRecord {
            joined_phone: false,
            ..channel(ID)
        },
        "digest",
        10,
    );
    assert_eq!(
        store.channel_by_id(OWNER, "bad"),
        Err(MobileStoreError::InvalidArgument)
    );
    assert_eq!(store.channel_by_id("bob", ID), Ok(None));

    store.set_channel_alias(ID, Some("Mine".into())).unwrap();
    store.set_channel_notifications(ID, true).unwrap();
    store.set_channel_joined_phone(ID, true, 100).unwrap();
    store
        .set_channel_routing(ID, Some(vec![0x55, 0x53]), Some(4))
        .unwrap();
    let stored = store
        .channel_by_id(OWNER, &ID.to_ascii_lowercase())
        .unwrap()
        .unwrap();
    assert_eq!(stored.alias.as_deref(), Some("Mine"));
    assert!(stored.notifications_enabled && stored.joined_phone && !stored.joined_device);
    assert_eq!(stored.joined_at_ms, Some(100));
    assert_eq!(stored.region_code, Some(vec![0x55, 0x53]));
    assert_eq!(stored.max_flood_hops, Some(4));
    // The stamp is kept through a leave and a rejoin.
    store.set_channel_joined_phone(ID, false, 200).unwrap();
    store.set_channel_joined_phone(ID, true, 300).unwrap();
    assert_eq!(only(&store).joined_at_ms, Some(100));
}
