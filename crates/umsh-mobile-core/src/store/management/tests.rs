use std::sync::Arc;

use super::super::MobilePeerUpsertRecord;
use super::*;

const OWNER: &str = "alice";
const DEVICE: &str = "device";

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
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    (directory, store)
}

fn peer(store: &MobileAppStore, owner: &str, address: &str) {
    store
        .upsert_peer(
            owner.into(),
            address.into(),
            MobilePeerUpsertRecord::default(),
        )
        .unwrap();
}

fn card(version: Option<&str>, fetched_at_ms: i64) -> MobileStoredManagementCardRecord {
    MobileStoredManagementCardRecord {
        capabilities: vec![0x81, 0x02],
        device_version: version.map(Into::into),
        device_model: Some("T1000-E".into()),
        device_name: Some("Ridge".into()),
        fetched_at_ms,
    }
}

fn save_card(store: &MobileAppStore, owner: &str, card: MobileStoredManagementCardRecord) {
    store
        .save_management_card(owner.into(), DEVICE.into(), card)
        .unwrap();
}

fn save_values(store: &MobileAppStore, owner: &str, values: &[(u32, &[u8])], at_ms: i64) {
    store
        .save_cached_properties(
            owner.into(),
            DEVICE.into(),
            values
                .iter()
                .map(|(id, value)| (*id, value.to_vec()))
                .collect(),
            at_ms,
        )
        .unwrap();
}

fn cached(store: &MobileAppStore, owner: &str, ids: &[u32]) -> Vec<(u32, Vec<u8>, i64)> {
    let mut values: Vec<_> = store
        .cached_properties(owner.into(), DEVICE.into(), ids.to_vec())
        .unwrap()
        .into_iter()
        .map(|(id, property)| (id, property.value, property.fetched_at_ms))
        .collect();
    values.sort();
    values
}

fn rows(store: &MobileAppStore, table: &str) -> i64 {
    store
        .connection()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn a_card_round_trips_for_its_own_identity_only() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    peer(&store, "bob", DEVICE);
    assert_eq!(
        store.management_card(OWNER.into(), DEVICE.into()).unwrap(),
        None
    );
    save_card(&store, OWNER, card(Some("1.2"), 1_700_000_000_123));
    assert_eq!(
        store.management_card(OWNER.into(), DEVICE.into()).unwrap(),
        Some(card(Some("1.2"), 1_700_000_000_123))
    );
    assert_eq!(
        store.management_card("bob".into(), DEVICE.into()).unwrap(),
        None
    );

    // A second read replaces every field, absent ones included.
    let blank = MobileStoredManagementCardRecord {
        capabilities: vec![0x01],
        device_version: None,
        device_model: None,
        device_name: None,
        fetched_at_ms: 9,
    };
    save_card(&store, OWNER, blank.clone());
    assert_eq!(
        store.management_card(OWNER.into(), DEVICE.into()).unwrap(),
        Some(blank)
    );
}

#[test]
fn nothing_is_kept_about_a_device_with_no_row() {
    let (_directory, store) = open();
    save_card(&store, OWNER, card(Some("1.2"), 1));
    save_values(&store, OWNER, &[(7, b"x")], 1);
    assert_eq!(rows(&store, "node_mgmt_card"), 0);
    assert_eq!(rows(&store, "node_prop_cache"), 0);
    assert_eq!(
        store.management_card(OWNER.into(), DEVICE.into()).unwrap(),
        None
    );
    assert!(cached(&store, OWNER, &[7]).is_empty());
    store
        .forget_management_cache(OWNER.into(), DEVICE.into())
        .unwrap();
}

#[test]
fn new_firmware_discards_the_cached_values_and_the_same_firmware_keeps_them() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    // Values cached before the first card stay: there was no firmware to
    // supersede.
    save_values(&store, OWNER, &[(1, b"a")], 1);
    save_card(&store, OWNER, card(Some("1.2"), 2));
    assert_eq!(cached(&store, OWNER, &[1]), [(1, b"a".to_vec(), 1)]);

    save_card(&store, OWNER, card(Some("1.2"), 3));
    assert_eq!(cached(&store, OWNER, &[1]), [(1, b"a".to_vec(), 1)]);

    save_card(&store, OWNER, card(Some("1.3"), 4));
    assert!(cached(&store, OWNER, &[1]).is_empty());

    // An unknown version is a different firmware from a known one, either
    // way round, and the same as another unknown one.
    save_values(&store, OWNER, &[(1, b"b")], 5);
    save_card(&store, OWNER, card(None, 6));
    assert!(cached(&store, OWNER, &[1]).is_empty());
    save_values(&store, OWNER, &[(1, b"c")], 7);
    save_card(&store, OWNER, card(None, 8));
    assert_eq!(cached(&store, OWNER, &[1]), [(1, b"c".to_vec(), 7)]);
    save_card(&store, OWNER, card(Some("1.3"), 9));
    assert!(cached(&store, OWNER, &[1]).is_empty());
}

#[test]
fn a_new_firmware_discards_only_that_device_s_values() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    peer(&store, "bob", DEVICE);
    save_card(&store, OWNER, card(Some("1.2"), 1));
    save_card(&store, "bob", card(Some("1.2"), 1));
    save_values(&store, OWNER, &[(1, b"a")], 1);
    save_values(&store, "bob", &[(1, b"b")], 1);
    save_card(&store, OWNER, card(Some("2.0"), 2));
    assert!(cached(&store, OWNER, &[1]).is_empty());
    assert_eq!(cached(&store, "bob", &[1]), [(1, b"b".to_vec(), 1)]);
}

#[test]
fn forgetting_drops_the_card_and_the_values_of_that_device_only() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    peer(&store, "bob", DEVICE);
    for owner in [OWNER, "bob"] {
        save_card(&store, owner, card(Some("1.2"), 1));
        save_values(&store, owner, &[(1, b"a"), (2, b"b")], 1);
    }
    store
        .forget_management_cache(OWNER.into(), DEVICE.into())
        .unwrap();
    assert_eq!(
        store.management_card(OWNER.into(), DEVICE.into()).unwrap(),
        None
    );
    assert!(cached(&store, OWNER, &[1, 2]).is_empty());
    assert!(
        store
            .management_card("bob".into(), DEVICE.into())
            .unwrap()
            .is_some()
    );
    assert_eq!(cached(&store, "bob", &[1, 2]).len(), 2);
}

#[test]
fn cached_properties_answer_only_what_was_asked_for_and_held() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    peer(&store, "bob", DEVICE);
    save_values(
        &store,
        OWNER,
        &[(1, b"one"), (2, b"two"), (70_000, b"big")],
        10,
    );
    save_values(&store, "bob", &[(3, b"bob's")], 10);
    assert_eq!(
        cached(&store, OWNER, &[2, 3, 70_000, 4]),
        [(2, b"two".to_vec(), 10), (70_000, b"big".to_vec(), 10)]
    );
    // Asking twice for one property answers it once.
    assert_eq!(cached(&store, OWNER, &[1, 1]), [(1, b"one".to_vec(), 10)]);
    assert!(cached(&store, OWNER, &[]).is_empty());
}

#[test]
fn saving_a_value_again_replaces_it_and_its_instant() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    save_values(&store, OWNER, &[(1, b"old"), (2, b"kept")], 10);
    save_values(&store, OWNER, &[(1, b"new")], 20);
    assert_eq!(
        cached(&store, OWNER, &[1, 2]),
        [(1, b"new".to_vec(), 20), (2, b"kept".to_vec(), 10)]
    );
    // An empty batch is nothing to save.
    save_values(&store, OWNER, &[], 30);
    assert_eq!(rows(&store, "node_prop_cache"), 2);
}

#[test]
fn an_empty_value_or_capability_set_is_kept_as_an_empty_blob() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    save_values(&store, OWNER, &[(1, b""), (2, b"x")], 10);
    assert_eq!(
        cached(&store, OWNER, &[1, 2]),
        [(1, vec![], 10), (2, b"x".to_vec(), 10)]
    );
    let empty = MobileStoredManagementCardRecord {
        capabilities: vec![],
        ..card(Some("1.2"), 1)
    };
    save_card(&store, OWNER, empty.clone());
    assert_eq!(
        store.management_card(OWNER.into(), DEVICE.into()).unwrap(),
        Some(empty)
    );
    let kinds: Vec<String> = store
        .connection()
        .prepare(
            "SELECT typeof(value) FROM node_prop_cache WHERE property_id = 1
            UNION ALL SELECT typeof(capabilities) FROM node_mgmt_card",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(kinds, ["blob", "blob"]);
}

#[test]
fn values_and_card_are_stored_as_the_swift_store_stores_them() {
    let (_directory, store) = open();
    peer(&store, OWNER, DEVICE);
    save_card(&store, OWNER, card(Some("1.2"), 1_700_000_000_123));
    save_values(&store, OWNER, &[(4_850, &[0xDE, 0xAD])], 1_700_000_000_456);
    let connection = store.connection();
    let (property, value, at): (i64, Vec<u8>, i64) = connection
        .query_row(
            "SELECT property_id, value, fetched_at_ms FROM node_prop_cache",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (property, value, at),
        (4_850, vec![0xDE, 0xAD], 1_700_000_000_456)
    );
    let (capabilities, version, at): (Vec<u8>, String, i64) = connection
        .query_row(
            "SELECT capabilities, device_version, fetched_at_ms FROM node_mgmt_card",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (capabilities, version.as_str(), at),
        (vec![0x81, 0x02], "1.2", 1_700_000_000_123)
    );
}
