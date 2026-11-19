use std::sync::Arc;

use super::*;

fn path_in(directory: &tempfile::TempDir) -> String {
    directory
        .path()
        .join("application.sqlite")
        .display()
        .to_string()
}

/// The database's schema objects, in exactly the form
/// `scripts/ios/store-schema-dump.swift` writes them below its header.
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

/// [`BASELINE`]'s schema objects, without the header that names its
/// version. The ladder's steps so far rewrite data only, so every version
/// has this schema.
fn baseline_schema() -> &'static str {
    BASELINE.split_once("do not edit.\n").unwrap().1
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
fn a_new_file_gets_exactly_the_swift_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    let store = MobileAppStore::open(path.clone()).unwrap();
    assert_eq!(store.schema_version(), Ok(current_version()));
    // Same CREATE text for every object means the same columns, types,
    // defaults, constraints, and indexes as a Swift-migrated database.
    assert_eq!(dump(&store.connection()), baseline_schema());
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
    assert_eq!(journal, "wal");
    assert_eq!(foreign_keys, 1);
    assert_eq!(synchronous, 2);
}

#[test]
fn a_database_the_swift_store_left_at_v31_opens_with_its_schema_and_data() {
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
    assert_eq!(dump(&connection), baseline_schema());
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
    assert_eq!(dump(&store.connection()), baseline_schema());
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

#[test]
fn a_database_below_the_swift_store_s_last_migration_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    {
        let connection = raw(&path);
        connection
            .execute_batch("CREATE TABLE local_identity (id TEXT PRIMARY KEY)")
            .unwrap();
        connection.pragma_update(None, "user_version", 30).unwrap();
    }
    assert_eq!(
        MobileAppStore::open(path.clone()).err(),
        Some(MobileStoreError::UnsupportedSchema { version: 30 })
    );
    // Refusing leaves it for a Swift-migrating build to finish.
    assert_eq!(user_version(&raw(&path)).unwrap(), 30);
}

#[test]
fn a_file_that_is_not_the_store_is_refused_and_left_alone() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    raw(&path)
        .execute_batch("CREATE TABLE something_else (x)")
        .unwrap();
    assert_eq!(
        MobileAppStore::open(path.clone()).err(),
        Some(MobileStoreError::UnsupportedSchema { version: 0 })
    );
    let objects: i64 = raw(&path)
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .unwrap();
    assert_eq!(objects, 1);
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
    assert_eq!(dump(&connection), baseline_schema());
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
