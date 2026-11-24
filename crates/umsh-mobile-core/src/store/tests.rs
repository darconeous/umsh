use std::sync::Arc;

use super::*;

fn path_in(directory: &tempfile::TempDir) -> String {
    directory
        .path()
        .join("application.sqlite")
        .display()
        .to_string()
}

/// The database's schema objects, in exactly the form `schema_v31.sql`
/// holds them below its header.
fn dump(connection: &Connection) -> String {
    let mut out = String::new();
    let mut statement = connection
        .prepare(
            "SELECT sql FROM sqlite_master \
             WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' \
             ORDER BY CASE type \
                 WHEN 'table' THEN 0 WHEN 'index' THEN 1 \
                 WHEN 'trigger' THEN 2 ELSE 3 END, \
                 name",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap();
    for sql in rows {
        out.push('\n');
        out.push_str(&sql.unwrap());
        out.push_str(";\n");
    }
    out
}

/// The schema objects a database holds after `steps` of the ladder: the
/// Swift store's baseline with those migrations after it.
fn schema_after(steps: &[Migration]) -> String {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(BASELINE).unwrap();
    for step in steps {
        connection.execute_batch(step.sql).unwrap();
    }
    dump(&connection)
}

fn baseline_schema() -> String {
    schema_after(&[])
}

fn current_schema() -> String {
    schema_after(MIGRATIONS)
}

/// The version a database ends at once the store opens it.
fn current_version() -> i64 {
    MIGRATIONS
        .last()
        .map_or(BASELINE_VERSION, |step| step.version)
}

fn raw(path: &str) -> Connection {
    Connection::open(path).unwrap()
}

#[test]
fn a_new_file_gets_the_swift_schema_and_every_migration() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    let store = MobileAppStore::open(path.clone()).unwrap();
    assert_eq!(store.schema_version(), Ok(current_version()));
    // Same CREATE text for every object means the same columns, types,
    // defaults, constraints, and indexes as a migrated Swift database.
    assert_eq!(dump(&store.connection()), current_schema());
}

#[test]
fn the_connection_is_configured_as_the_swift_store_configures_it() {
    let directory = tempfile::tempdir().unwrap();
    let store = MobileAppStore::open(path_in(&directory)).unwrap();
    let connection = store.connection();
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    // 2 is FULL.
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    let busy_timeout: i64 = connection
        .pragma_query_value(None, "busy_timeout", |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    assert_eq!(foreign_keys, 1);
    assert_eq!(synchronous, 2);
    assert_eq!(busy_timeout, 5_000);
    // Set, not left to how the platform's SQLite was built.
    let secure_delete: i64 = connection
        .pragma_query_value(None, "secure_delete", |row| row.get(0))
        .unwrap();
    assert_eq!(secure_delete, 1);
}

#[test]
fn a_database_the_swift_store_left_at_v31_migrates_with_its_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    {
        // What the Swift store leaves: its schema, its version, and data.
        let connection = raw(&path);
        connection.execute_batch(BASELINE).unwrap();
        connection
            .pragma_update(None, "user_version", BASELINE_VERSION)
            .unwrap();
        connection
            .execute(
                "INSERT INTO local_identity (id, public_address, created_at_ms) \
                 VALUES ('alice', 'alice-public', 1)",
                [],
            )
            .unwrap();
    }
    let store = MobileAppStore::open(path).unwrap();
    assert_eq!(store.schema_version(), Ok(current_version()));
    let connection = store.connection();
    assert_eq!(dump(&connection), current_schema());
    let address: String = connection
        .query_row(
            "SELECT public_address FROM local_identity WHERE id = 'alice'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(address, "alice-public");
}

#[test]
fn reopening_keeps_the_schema_and_the_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    {
        let store = MobileAppStore::open(path.clone()).unwrap();
        store
            .connection()
            .execute(
                "INSERT INTO local_identity (id, public_address, created_at_ms) \
                 VALUES ('alice', 'alice-public', 1)",
                [],
            )
            .unwrap();
    }
    let store = MobileAppStore::open(path).unwrap();
    assert_eq!(dump(&store.connection()), current_schema());
    let count: i64 = store
        .connection()
        .query_row("SELECT count(*) FROM local_identity", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn a_newer_database_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    drop(MobileAppStore::open(path.clone()).unwrap());
    raw(&path)
        .pragma_update(None, "user_version", current_version() + 1)
        .unwrap();
    assert_eq!(
        MobileAppStore::open(path).err(),
        Some(MobileStoreError::UnsupportedSchema {
            version: current_version() + 1
        })
    );
}

/// Leave a file at `version` the way the Swift store did: its ladder run
/// from nothing, one step at a time.
fn swift_store_at(path: &str, version: i64) -> Connection {
    let connection = raw(path);
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for step in SWIFT_LADDER.iter().take_while(|s| s.version <= version) {
        connection.execute_batch(step.sql).unwrap();
        connection
            .pragma_update(None, "user_version", step.version)
            .unwrap();
    }
    connection
}

#[test]
fn the_swift_ladder_builds_the_baseline_exactly() {
    let connection = Connection::open_in_memory().unwrap();
    for step in SWIFT_LADDER {
        connection.execute_batch(step.sql).unwrap();
    }
    assert_eq!(dump(&connection), baseline_schema());
}

#[test]
fn the_swift_ladder_builds_what_the_swift_store_wrote() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    std::fs::write(&path, SWIFT_STORE_V31).unwrap();
    let written = dump(&raw(&path));
    let connection = Connection::open_in_memory().unwrap();
    for step in SWIFT_LADDER {
        connection.execute_batch(step.sql).unwrap();
    }
    assert_eq!(dump(&connection), written);
}

#[test]
fn every_version_the_swift_store_left_opens_at_the_current_schema() {
    for version in 1..=BASELINE_VERSION {
        let directory = tempfile::tempdir().unwrap();
        let path = path_in(&directory);
        drop(swift_store_at(&path, version));
        let store =
            MobileAppStore::open(path).unwrap_or_else(|error| panic!("v{version}: {error:?}"));
        assert_eq!(store.schema_version(), Ok(current_version()), "v{version}");
        assert_eq!(dump(&store.connection()), current_schema(), "v{version}");
    }
}

#[test]
fn a_first_build_database_keeps_its_records_under_its_address() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    {
        // The earliest store: everything under the 'primary' slot.
        let connection = swift_store_at(&path, 2);
        connection
            .execute_batch(
                "INSERT INTO local_identity (id, public_address, created_at_ms)
                    VALUES ('primary', 'me-public', 1);
                INSERT INTO node (owner_identity_id, public_address, alias, alias_search)
                    VALUES ('primary', 'peer-public', 'Émile', 'emile');
                INSERT INTO direct_conversation (owner_identity_id, node_id, created_at_ms)
                    VALUES ('primary', 1, 2);",
            )
            .unwrap();
    }
    let store = MobileAppStore::open(path).unwrap();
    assert_eq!(store.schema_version(), Ok(current_version()));
    let connection = store.connection();
    let owners: Vec<String> = connection
        .prepare(
            "SELECT id FROM local_identity
            UNION ALL SELECT owner_identity_id FROM node
            UNION ALL SELECT owner_identity_id FROM direct_conversation",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(owners, ["me-public", "me-public", "me-public"]);
    let alias: String = connection
        .query_row("SELECT alias FROM node", [], |row| row.get(0))
        .unwrap();
    assert_eq!(alias, "Émile");
    let violations: i64 = connection
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
}

#[test]
fn a_store_without_a_legacy_slot_is_untouched_by_the_re_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    {
        let connection = swift_store_at(&path, BASELINE_VERSION);
        connection
            .execute_batch(
                "INSERT INTO local_identity (id, public_address, created_at_ms)
                    VALUES ('me-public', 'me-public', 1);
                INSERT INTO node (owner_identity_id, public_address, alias_search)
                    VALUES ('me-public', 'peer-public', '');",
            )
            .unwrap();
    }
    let store = MobileAppStore::open(path).unwrap();
    let owner: String = store
        .connection()
        .query_row("SELECT owner_identity_id FROM node", [], |row| row.get(0))
        .unwrap();
    assert_eq!(owner, "me-public");
}

#[test]
fn a_file_that_is_not_the_store_is_refused_and_left_alone() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    raw(&path)
        .execute_batch("CREATE TABLE something_else (x)")
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        MobileAppStore::open(path.clone()).err(),
        Some(MobileStoreError::UnsupportedSchema { version: 0 })
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn the_ladder_runs_each_step_once_and_refuses_what_it_does_not_reach() {
    const LADDER: &[Migration] = &[
        Migration {
            version: 32,
            sql: "CREATE TABLE added_at_32 (x INTEGER);
                INSERT INTO added_at_32 (x) VALUES (32);",
        },
        Migration {
            version: 33,
            sql: "INSERT INTO added_at_32 (x) VALUES (33);",
        },
    ];
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    let mut connection = raw(&path);
    assert_eq!(migrate(&mut connection, &[]), Ok(BASELINE_VERSION));

    assert_eq!(migrate(&mut connection, LADDER), Ok(33));
    assert_eq!(migrate(&mut connection, LADDER), Ok(33));
    let rows: Vec<i64> = connection
        .prepare("SELECT x FROM added_at_32 ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(rows, [32, 33], "a step ran twice or out of order");

    // A new file climbs the whole ladder from the baseline.
    let fresh = tempfile::tempdir().unwrap();
    let mut new_file = raw(&path_in(&fresh));
    assert_eq!(migrate(&mut new_file, LADDER), Ok(33));

    // A build whose ladder stops short refuses the newer file.
    assert_eq!(
        migrate(&mut connection, &LADDER[..1]),
        Err(MobileStoreError::UnsupportedSchema { version: 33 })
    );
}

#[test]
fn a_failing_step_leaves_the_database_where_it_was() {
    // The step's first statement succeeds; its second fails.
    const LADDER: &[Migration] = &[Migration {
        version: 32,
        sql: "CREATE TABLE added_at_32 (x INTEGER);
            INSERT INTO no_such_table (x) VALUES (1);",
    }];
    let directory = tempfile::tempdir().unwrap();
    let mut connection = raw(&path_in(&directory));
    assert_eq!(migrate(&mut connection, &[]), Ok(BASELINE_VERSION));
    let Err(MobileStoreError::Failed { code, detail }) = migrate(&mut connection, LADDER) else {
        panic!("a failing step must fail the open");
    };
    // SQLite's own report survives into the error.
    assert_eq!(code, rusqlite::ffi::SQLITE_ERROR);
    assert!(detail.contains("no_such_table"), "{detail}");
    assert_eq!(user_version(&connection).unwrap(), BASELINE_VERSION);
    assert_eq!(dump(&connection), baseline_schema());
}

#[test]
fn the_ladder_is_consecutive_from_the_baseline() {
    for (offset, step) in MIGRATIONS.iter().enumerate() {
        assert_eq!(step.version, BASELINE_VERSION + 1 + offset as i64);
    }
}

#[test]
fn the_swift_ladder_is_consecutive_from_one_to_the_baseline() {
    for (offset, step) in SWIFT_LADDER.iter().enumerate() {
        assert_eq!(step.version, 1 + offset as i64);
    }
    assert_eq!(SWIFT_LADDER.last().unwrap().version, BASELINE_VERSION);
}

/// A store whose `node` table comes first in the schema, as no real store
/// has it: emptying it before `direct_conversation` trips that table's
/// RESTRICT unless the checks are deferred.
fn store_with_node_table_first(directory: &tempfile::TempDir) -> Arc<MobileAppStore> {
    let path = path_in(directory);
    let start = BASELINE.find("CREATE TABLE node (").unwrap();
    let end = start + BASELINE[start..].find(");\n").unwrap() + 3;
    let node_table = &BASELINE[start..end];
    {
        let connection = raw(&path);
        connection.execute_batch(node_table).unwrap();
        connection
            .execute_batch(&BASELINE.replacen(node_table, "", 1))
            .unwrap();
        connection
            .pragma_update(None, "user_version", BASELINE_VERSION)
            .unwrap();
    }
    MobileAppStore::open(path).unwrap()
}

/// One row in every table, through the store where it can write one.
fn fill_every_table(store: &MobileAppStore) {
    store
        .insert_identity("alice".into(), "alice-public".into(), 1)
        .unwrap();
    store
        .upsert_peer(
            "alice".into(),
            "peer".into(),
            MobilePeerUpsertRecord::default(),
        )
        .unwrap();
    store
        .ensure_direct_conversation("alice".into(), "peer".into(), 1)
        .unwrap();
    let channel = "0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6";
    store
        .insert_channel(
            MobileStoredChannelRecord {
                id: channel.into(),
                owner_identity_id: "alice".into(),
                kind: MobileStoredChannelKind::Named,
                canonical_name: None,
                name: None,
                alias: None,
                channel_id_hex: "beef".into(),
                tint: vec![1, 2, 3],
                region_code: None,
                max_flood_hops: None,
                joined_phone: true,
                joined_device: false,
                notifications_enabled: false,
                joined_at_ms: None,
            },
            "digest".into(),
            1,
        )
        .unwrap();
    store
        .ensure_channel_conversation("alice".into(), channel.into(), "channel".into(), 1)
        .unwrap();
    store
        .save_management_card(
            "alice".into(),
            "peer".into(),
            MobileStoredManagementCardRecord {
                capabilities: vec![1],
                device_version: None,
                device_model: None,
                device_name: None,
                fetched_at_ms: 1,
            },
        )
        .unwrap();
    store
        .save_cached_properties(
            "alice".into(),
            "peer".into(),
            [(1, vec![1])].into_iter().collect(),
            1,
        )
        .unwrap();
    store
        .save_manual_route(
            "alice".into(),
            "peer".into(),
            vec![vec![1, 2]],
            1,
            2,
            None,
            None,
            None,
        )
        .unwrap();
    store
        .record_claimed_radio("alice".into(), "radio".into(), None, 1)
        .unwrap();
    store
        .save_peer_repeater_page(
            "alice".into(),
            "peer".into(),
            vec![MobileStoredPeerRepeaterEntryRecord {
                hint: vec![1, 2],
                name: None,
                rssi_dbm: None,
                snr_quarter_db: None,
                last_heard_minutes: None,
                latitude: None,
                longitude: None,
                location_precision: None,
                region_codes: vec![],
                reported_at_ms: 1,
            }],
            None,
            None,
            true,
            1,
        )
        .unwrap();
    // The chat domain's tables, through its compose and delivery paths.
    let mut mutation = super::chat_test_support::outbound(1, 1, "peer", 1, "hi");
    mutation.fragment_count = Some(1);
    store
        .commit_chat_compose_batch(
            "alice".into(),
            crate::MobileChatComposeBatchRecord {
                batch_id: 1,
                checkpoint: crate::MobileChatCheckpointRecord {
                    conversation_address: "peer".into(),
                    next_id: 2,
                    epoch: 1,
                },
                archive_deletes: vec![],
                archives: vec![crate::MobileChatArchiveRecord {
                    conversation_address: "peer".into(),
                    message_id: 1,
                    fragment_index: None,
                    payload: vec![1],
                }],
                mutations: vec![mutation],
            },
            1,
        )
        .unwrap();
    store
        .apply_chat_deliveries(
            "alice".into(),
            vec![crate::MobileChatDeliveryRecord {
                session_id: 1,
                handle: 1,
                fragment_index: None,
                state: crate::MobileChatDeliveryState::Sent,
                via_flood: false,
            }],
            1,
        )
        .unwrap();
}

fn row_counts(connection: &Connection) -> Vec<(String, i64)> {
    table_names(connection)
        .unwrap()
        .into_iter()
        .map(|table| {
            let rows = connection
                .query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |row| {
                    row.get(0)
                })
                .unwrap();
            (table, rows)
        })
        .collect()
}

#[test]
fn erasing_empties_every_table_whatever_order_the_schema_lists_them_in() {
    let directory = tempfile::tempdir().unwrap();
    let store = store_with_node_table_first(&directory);
    let tables = table_names(&store.connection()).unwrap();
    let position = |name: &str| tables.iter().position(|table| table == name).unwrap();
    assert!(position("node") < position("direct_conversation"));
    assert!(position("node") < position("local_identity"));

    fill_every_table(&store);
    let filled = row_counts(&store.connection());
    // Every table holds a row, so a table the erasure missed would show.
    assert!(
        filled.iter().all(|(_, rows)| *rows > 0),
        "a table was left unfilled: {filled:?}"
    );

    store.erase_all_content().unwrap();
    let connection = store.connection();
    let erased = row_counts(&connection);
    assert!(
        erased.iter().all(|(_, rows)| *rows == 0),
        "rows survived: {erased:?}"
    );
    assert_eq!(erased.len(), filled.len());
    // The schema and its version stay. (The dump orders by name, so the
    // layout reads as the baseline's.)
    assert_eq!(user_version(&connection).unwrap(), current_version());
    assert_eq!(dump(&connection), current_schema());
}

#[test]
fn erased_content_is_gone_from_the_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    let store = MobileAppStore::open(path.clone()).unwrap();
    let marker = "erased-content-marker";
    store
        .connection()
        .execute(
            "INSERT INTO local_identity (id, public_address, created_at_ms, advertised_name)
             VALUES ('alice', 'alice-address', 0, ?)",
            [marker],
        )
        .unwrap();
    // Into the database file itself, not only the log.
    store
        .connection()
        .pragma_update(None, "wal_checkpoint", "TRUNCATE")
        .unwrap();

    store.erase_all_content().unwrap();
    for file in [path.clone(), format!("{path}-wal")] {
        let bytes = std::fs::read(&file).unwrap_or_default();
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "{file} still holds the erased text"
        );
    }
}

#[test]
fn erasing_keeps_sqlite_s_row_id_sequences() {
    let directory = tempfile::tempdir().unwrap();
    let store = MobileAppStore::open(path_in(&directory)).unwrap();
    fill_every_table(&store);
    store.erase_all_content().unwrap();
    store
        .insert_identity("alice".into(), "alice-public".into(), 1)
        .unwrap();
    store
        .upsert_peer(
            "alice".into(),
            "peer".into(),
            MobilePeerUpsertRecord::default(),
        )
        .unwrap();
    let id: i64 = store
        .connection()
        .query_row("SELECT id FROM node", [], |row| row.get(0))
        .unwrap();
    assert_eq!(id, 2);
}

#[test]
fn a_failed_write_carries_sqlite_s_code_and_message() {
    let directory = tempfile::tempdir().unwrap();
    let store = MobileAppStore::open(path_in(&directory)).unwrap();
    store
        .insert_identity("alice".into(), "alice-public".into(), 1)
        .unwrap();
    let error = store
        .insert_identity("alice".into(), "other-public".into(), 2)
        .unwrap_err();
    let MobileStoreError::Failed { code, detail } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(*code, rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY);
    assert!(detail.contains("local_identity.id"), "{detail}");
    assert_eq!(
        error.to_string(),
        format!("{} ({code}): {detail}", error.diagnostic_code())
    );
}

/// A database the Swift store wrote before iOS moved onto this one, every
/// table filled through that store's own calls. It holds what only that
/// store produced, which the v32 migration converts: sort keys folded by
/// Foundation, heard-at times in seconds with fractions of a millisecond,
/// zero-length blobs. That store is gone, so the file cannot be made
/// again; do not replace it.
const SWIFT_STORE_V31: &[u8] = include_bytes!("swift_store_v31.sqlite");

#[test]
fn a_database_the_swift_store_wrote_migrates_and_reads_whole() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    std::fs::write(&path, SWIFT_STORE_V31).unwrap();
    let store = MobileAppStore::open(path.clone()).unwrap();
    assert_eq!(store.schema_version(), Ok(current_version()));
    assert_eq!(dump(&store.connection()), current_schema());
    let owner = || "alice".to_string();

    let nodes = store.list_nodes(owner()).unwrap();
    assert_eq!(nodes.len(), 13);
    let node = |address: &str| {
        nodes
            .iter()
            .find(|node| node.public_address == address)
            .unwrap()
    };
    let emile = node("peer-a");
    assert_eq!(emile.alias.as_deref(), Some("Émile Zola"));
    assert_eq!(emile.node_kind, Some(MobileStoredNodeKind::Chat));
    assert_eq!(emile.advertisement, Some(vec![9]));
    // Stored as 1780000021.123056 seconds.
    assert_eq!(emile.last_heard_at_ms, Some(1_780_000_021_123));
    let bravo = node("peer-b");
    assert_eq!(bravo.alias.as_deref(), Some("ÀB ç Straße"));
    assert_eq!(
        bravo.system_role,
        Some(MobileStoredSystemRole::CompanionRadio)
    );
    assert_eq!(bravo.node_kind, Some(MobileStoredNodeKind::Repeater));
    assert!(bravo.is_favorite);
    assert_eq!(
        node("peer-c").advertisement_received_at_ms,
        Some(1_780_000_012_123)
    );

    let channels = store.channels(owner()).unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].id, "11111111-2222-3333-4444-AAAAAAAAAAAA");
    assert_eq!(channels[0].tint, [1, 2, 3]);
    assert_eq!(channels[0].joined_at_ms, Some(1_780_000_030_679));

    let listing = store
        .peer_repeater_listing(owner(), "peer-b".into())
        .unwrap()
        .unwrap();
    let hints: Vec<_> = listing.entries.iter().map(|e| e.hint.clone()).collect();
    assert_eq!(hints, [vec![1, 2], vec![3, 4, 5], vec![7, 8]]);
    assert_eq!(
        listing.entries[2].region_codes,
        [vec![0x55, 0x53], vec![1, 2]]
    );
    assert_eq!(listing.entries[2].last_heard_minutes, Some(65_535));
    // The Swift store wrote this listing's cursor as a zero-length blob.
    let partial = store
        .peer_repeater_listing(owner(), "peer-c".into())
        .unwrap()
        .unwrap();
    assert_eq!((partial.total, partial.next_cursor), (Some(9), None));

    let checkpoints: Vec<_> = store
        .chat_checkpoints(owner())
        .unwrap()
        .into_iter()
        .map(|c| (c.conversation_address, c.next_id, c.epoch))
        .collect();
    assert_eq!(
        checkpoints,
        [
            ("peer-a".to_string(), 13, 2),
            ("peer-clear".to_string(), 3, 0)
        ]
    );

    let page = store
        .chat_message_page_newest(owner(), "peer-a".into(), 100)
        .unwrap();
    let bodies: Vec<_> = page.messages.iter().map(|m| m.body.as_str()).collect();
    assert_eq!(
        bodies,
        [
            "Late one",
            "Hello (rev 1)",
            "Hi back",
            "status text",
            "",
            "",
            "Multi fragment",
            "Unread one",
            "Composed, edited",
        ]
    );
    let hello = &page.messages[1];
    let reception = hello.reception.as_ref().unwrap();
    assert_eq!(reception.rssi_dbm, Some(-101));
    assert_eq!(reception.route_hints, [vec![1, 2], vec![3, 4]]);
    assert_eq!(hello.reactions.len(), 1);
    assert_eq!(hello.reactions[0].body, "<3");

    // A staged transcript's session is a name, not a number.
    let staged = store
        .chat_message_page_newest(owner(), "peer-staged".into(), 100)
        .unwrap();
    assert_eq!(staged.messages.len(), 7);
    assert!(
        staged
            .messages
            .iter()
            .all(|m| m.reference.session_id == "staging-7")
    );
}
