use std::sync::Arc;

use super::super::MobilePeerUpsertRecord;
use super::*;

const OWNER: &str = "alice";

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

/// The node row ID of a new peer.
fn repeater(store: &MobileAppStore, owner: &str, address: &str) -> i64 {
    store
        .upsert_peer(
            owner.into(),
            address.into(),
            MobilePeerUpsertRecord::default(),
        )
        .unwrap();
    store
        .connection()
        .query_row(
            "SELECT id FROM node WHERE owner_identity_id = ? AND public_address = ?",
            params![owner, address],
            |row| row.get(0),
        )
        .unwrap()
}

fn entry(store: &MobileAppStore, node: i64, hint: &[u8], position: i64) {
    store
        .connection()
        .execute(
            "INSERT INTO node_peer_repeater_entry (node_id, hint, position, reported_at_ms)
            VALUES (?, ?, ?, ?)",
            params![node, hint, position, 1_000 + position],
        )
        .unwrap();
}

#[test]
fn entries_list_by_repeater_then_listing_order_for_the_identity_only() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    let first = repeater(&store, OWNER, "repeater-a");
    let second = repeater(&store, OWNER, "repeater-b");
    let bobs = repeater(&store, "bob", "repeater-a");
    entry(&store, second, &[0xB0, 0x01], 0);
    entry(&store, first, &[0xA0, 0x02], 1);
    entry(&store, first, &[0xA0, 0x01], 0);
    entry(&store, bobs, &[0xFF, 0xFF], 0);
    let listed: Vec<(i64, Vec<u8>, i64)> = store
        .all_peer_repeater_entries(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|report| {
            (
                report.reporter_node_id,
                report.entry.hint,
                report.entry.reported_at_ms,
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            (first, vec![0xA0, 0x01], 1_000),
            (first, vec![0xA0, 0x02], 1_001),
            (second, vec![0xB0, 0x01], 1_000),
        ]
    );
}

#[test]
fn an_entry_reads_back_decoded_and_clamped() {
    let (_directory, store) = open();
    let node = repeater(&store, OWNER, "repeater");
    store
        .connection()
        .execute(
            "INSERT INTO node_peer_repeater_entry (node_id, hint, position, name, rssi_dbm,
                snr_quarter_db, last_heard_min, latitude, longitude, location_precision,
                region_codes, reported_at_ms)
            VALUES (?, x'010203', 0, 'Ridge', -40000, 40000, -1, 45.5, -122.25, 300,
                x'5553434101', 1700000000123)",
            params![node],
        )
        .unwrap();
    entry(&store, node, &[4, 5], 1);
    let reports = store.all_peer_repeater_entries(OWNER.into()).unwrap();
    assert_eq!(
        reports[0].entry,
        MobileStoredPeerRepeaterEntryRecord {
            hint: vec![1, 2, 3],
            name: Some("Ridge".into()),
            // Saturated at the field's bounds, as Swift's clamping init.
            rssi_dbm: Some(i16::MIN),
            snr_quarter_db: Some(i16::MAX),
            last_heard_minutes: Some(0),
            latitude: Some(45.5),
            longitude: Some(-122.25),
            location_precision: Some(u8::MAX),
            // The trailing odd octet is no code.
            region_codes: vec![vec![0x55, 0x53], vec![0x43, 0x41]],
            reported_at_ms: 1_700_000_000_123,
        }
    );
    // Nothing optional stored reads as nothing, and no codes as none.
    assert_eq!(
        reports[1].entry,
        MobileStoredPeerRepeaterEntryRecord {
            hint: vec![4, 5],
            name: None,
            rssi_dbm: None,
            snr_quarter_db: None,
            last_heard_minutes: None,
            latitude: None,
            longitude: None,
            location_precision: None,
            region_codes: vec![],
            reported_at_ms: 1_001,
        }
    );
}

fn neighbor(hint: &[u8], name: &str, reported_at_ms: i64) -> MobileStoredPeerRepeaterEntryRecord {
    MobileStoredPeerRepeaterEntryRecord {
        hint: hint.to_vec(),
        name: Some(name.into()),
        rssi_dbm: Some(-90),
        snr_quarter_db: Some(-12),
        last_heard_minutes: Some(5),
        latitude: Some(45.5),
        longitude: Some(-122.25),
        location_precision: Some(4),
        region_codes: vec![vec![0x55, 0x53], vec![0x43, 0x41]],
        reported_at_ms,
    }
}

fn save_page(
    store: &MobileAppStore,
    owner: &str,
    address: &str,
    entries: Vec<MobileStoredPeerRepeaterEntryRecord>,
    next_cursor: Option<&[u8]>,
    replacing: bool,
    at_ms: i64,
) -> Result<(), MobileStoreError> {
    store.save_peer_repeater_page(
        owner.into(),
        address.into(),
        entries,
        Some(3),
        next_cursor.map(<[u8]>::to_vec),
        replacing,
        at_ms,
    )
}

fn listing(store: &MobileAppStore, address: &str) -> Option<MobileStoredPeerRepeaterListingRecord> {
    store
        .peer_repeater_listing(OWNER.into(), address.into())
        .unwrap()
}

fn names(listing: &MobileStoredPeerRepeaterListingRecord) -> Vec<&str> {
    listing
        .entries
        .iter()
        .map(|entry| entry.name.as_deref().unwrap())
        .collect()
}

#[test]
fn a_repeater_never_asked_or_not_stored_has_no_listing() {
    let (_directory, store) = open();
    repeater(&store, OWNER, "repeater");
    assert_eq!(listing(&store, "repeater"), None);
    assert_eq!(listing(&store, "stranger"), None);
    // A stranger's page has nowhere to go.
    save_page(
        &store,
        OWNER,
        "stranger",
        vec![neighbor(&[1, 2], "A", 1)],
        None,
        true,
        1,
    )
    .unwrap();
    let pages: i64 = store
        .connection()
        .query_row("SELECT count(*) FROM node_peer_repeaters", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(pages, 0);
}

#[test]
fn a_first_page_round_trips_in_listing_order() {
    let (_directory, store) = open();
    repeater(&store, OWNER, "repeater");
    let entries = vec![
        neighbor(&[0xB0, 0x01], "B", 10),
        neighbor(&[0xA0, 0x01, 0x02], "A", 11),
    ];
    save_page(
        &store,
        OWNER,
        "repeater",
        entries.clone(),
        Some(&[0, 1, 2]),
        true,
        20,
    )
    .unwrap();
    assert_eq!(
        listing(&store, "repeater"),
        Some(MobileStoredPeerRepeaterListingRecord {
            entries,
            total: Some(3),
            next_cursor: Some(vec![0, 1, 2]),
            as_of_ms: 20,
        })
    );
}

#[test]
fn a_following_page_appends_and_a_repeated_neighbor_updates_in_place() {
    let (_directory, store) = open();
    repeater(&store, OWNER, "repeater");
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[1, 1], "one", 10), neighbor(&[2, 2], "two", 10)],
        Some(&[1]),
        true,
        10,
    )
    .unwrap();
    store
        .save_peer_repeater_page(
            OWNER.into(),
            "repeater".into(),
            vec![
                neighbor(&[3, 3], "three", 20),
                neighbor(&[1, 1], "one again", 20),
            ],
            None,
            None,
            false,
            20,
        )
        .unwrap();
    let held = listing(&store, "repeater").unwrap();
    assert_eq!(names(&held), ["one again", "two", "three"]);
    assert_eq!(held.entries[0].reported_at_ms, 20);
    assert_eq!(held.entries[1].reported_at_ms, 10);
    // The header is the latest page's, absent fields included.
    assert_eq!(
        (held.total, held.next_cursor, held.as_of_ms),
        (None, None, 20)
    );

    // A fresh listing starts over.
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[4, 4], "four", 30)],
        None,
        true,
        30,
    )
    .unwrap();
    assert_eq!(names(&listing(&store, "repeater").unwrap()), ["four"]);
}

#[test]
fn a_page_appends_after_the_highest_position_held() {
    let (_directory, store) = open();
    let node = repeater(&store, OWNER, "repeater");
    save_page(&store, OWNER, "repeater", vec![], Some(&[1]), true, 1).unwrap();
    entry(&store, node, &[9, 9], 7);
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[1, 1], "next", 2)],
        None,
        false,
        2,
    )
    .unwrap();
    let position: i64 = store
        .connection()
        .query_row(
            "SELECT position FROM node_peer_repeater_entry WHERE hint = x'0101'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(position, 8);
}

#[test]
fn listings_belong_to_their_identity() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    repeater(&store, OWNER, "repeater");
    repeater(&store, "bob", "repeater");
    save_page(
        &store,
        "bob",
        "repeater",
        vec![neighbor(&[1, 1], "bob's", 1)],
        None,
        true,
        1,
    )
    .unwrap();
    assert_eq!(listing(&store, "repeater"), None);
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[2, 2], "mine", 2)],
        None,
        true,
        2,
    )
    .unwrap();
    assert_eq!(names(&listing(&store, "repeater").unwrap()), ["mine"]);
    let bobs = store
        .peer_repeater_listing("bob".into(), "repeater".into())
        .unwrap()
        .unwrap();
    assert_eq!(names(&bobs), ["bob's"]);
}

#[test]
fn a_page_is_stored_as_the_swift_store_stores_it() {
    let (_directory, store) = open();
    repeater(&store, OWNER, "repeater");
    let mut bare = neighbor(&[2, 2], "bare", 5);
    bare.region_codes = vec![];
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[1, 1], "coded", 5), bare],
        Some(&[]),
        true,
        5,
    )
    .unwrap();
    let connection = store.connection();
    let codes: Vec<Option<Vec<u8>>> = connection
        .prepare("SELECT region_codes FROM node_peer_repeater_entry ORDER BY position")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    // Codes back to back; none is NULL, not an empty blob.
    assert_eq!(codes, [Some(vec![0x55, 0x53, 0x43, 0x41]), None]);
    let (rssi, snr, minutes, precision): (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT rssi_dbm, snr_quarter_db, last_heard_min, location_precision
            FROM node_peer_repeater_entry WHERE position = 0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!((rssi, snr, minutes, precision), (-90, -12, 5, 4));
    // An empty cursor is stored as none, so the listing reads complete.
    let cursor: Option<Vec<u8>> = connection
        .query_row("SELECT next_cursor FROM node_peer_repeaters", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(cursor, None);
}

#[test]
fn an_entry_with_no_hint_refuses_the_whole_page() {
    let (_directory, store) = open();
    repeater(&store, OWNER, "repeater");
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[1, 1], "kept", 1)],
        Some(&[1]),
        true,
        1,
    )
    .unwrap();
    assert!(matches!(
        save_page(
            &store,
            OWNER,
            "repeater",
            vec![neighbor(&[2, 2], "new", 2), neighbor(&[], "hintless", 2)],
            None,
            true,
            2,
        ),
        Err(MobileStoreError::Failed { .. })
    ));
    let held = listing(&store, "repeater").unwrap();
    assert_eq!(names(&held), ["kept"]);
    assert_eq!((held.next_cursor, held.as_of_ms), (Some(vec![1]), 1));
}

#[test]
fn deleting_the_repeater_takes_its_listing() {
    let (_directory, store) = open();
    repeater(&store, OWNER, "repeater");
    save_page(
        &store,
        OWNER,
        "repeater",
        vec![neighbor(&[1, 1], "A", 1)],
        None,
        true,
        1,
    )
    .unwrap();
    assert!(store.delete_peer(OWNER.into(), "repeater".into()).unwrap());
    let connection = store.connection();
    for table in ["node_peer_repeaters", "node_peer_repeater_entry"] {
        let rows: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0, "{table}");
    }
}
