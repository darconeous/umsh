use std::sync::Arc;

use super::*;

const OWNER: &str = "alice";
/// 1_800_000_000 s, the persistence smoke test's start.
const START: i64 = 1_800_000_000_000;

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

fn record(store: &MobileAppStore, owner: &str, address: &str, name: Option<&str>, at_ms: i64) {
    store
        .record_claimed_radio(owner.into(), address.into(), name.map(Into::into), at_ms)
        .unwrap();
}

fn addresses(store: &MobileAppStore, owner: &str, now_ms: i64) -> Vec<String> {
    store
        .claimed_radios(owner.into(), now_ms)
        .unwrap()
        .into_iter()
        .map(|radio| radio.device_address)
        .collect()
}

#[test]
fn the_lapse_is_the_twelve_hour_device_lease() {
    assert_eq!(claimed_radio_lapse_ms(), 12 * 60 * 60 * 1_000);
}

/// `checkClaimedRadios` in `scripts/ios/persistence-smoke.swift`: a radio
/// left holding the identity is remembered until it is cleared or its
/// record lapses, and an attach refreshes it.
#[test]
fn a_claimed_radio_is_remembered_until_cleared_or_lapsed() {
    let (_directory, store) = open();
    record(&store, OWNER, "radio-a", Some("Ridge"), START);
    record(&store, OWNER, "radio-b", None, START + 60_000);
    let radios = store.claimed_radios(OWNER.into(), START).unwrap();
    assert_eq!(
        radios,
        [
            MobileStoredClaimedRadioRecord {
                device_address: "radio-b".into(),
                name: None,
                attached_at_ms: START + 60_000,
            },
            MobileStoredClaimedRadioRecord {
                device_address: "radio-a".into(),
                name: Some("Ridge".into()),
                attached_at_ms: START,
            },
        ]
    );

    // Attaching again moves the lapse out.
    let later = START + LAPSE_MS - 1_000;
    record(&store, OWNER, "radio-a", Some("Ridge"), later);
    assert_eq!(
        addresses(&store, OWNER, START + LAPSE_MS + 60_000),
        ["radio-a"]
    );

    store
        .clear_claimed_radio(OWNER.into(), "radio-a".into())
        .unwrap();
    assert!(addresses(&store, OWNER, later).is_empty());
}

#[test]
fn a_record_lapses_exactly_one_lease_after_its_attach() {
    let (_directory, store) = open();
    record(&store, OWNER, "radio", None, START);
    assert_eq!(addresses(&store, OWNER, START + LAPSE_MS - 1), ["radio"]);
    assert!(addresses(&store, OWNER, START + LAPSE_MS).is_empty());
    // Lapsed is forgotten, not merely hidden.
    assert!(addresses(&store, OWNER, START).is_empty());
}

#[test]
fn recording_again_replaces_the_name_and_the_instant() {
    let (_directory, store) = open();
    record(&store, OWNER, "radio", Some("Old"), START);
    record(&store, OWNER, "radio", None, START + 5);
    assert_eq!(
        store.claimed_radios(OWNER.into(), START).unwrap(),
        [MobileStoredClaimedRadioRecord {
            device_address: "radio".into(),
            name: None,
            attached_at_ms: START + 5,
        }]
    );
}

#[test]
fn records_belong_to_their_identity() {
    let (_directory, store) = open();
    let attached = START - LAPSE_MS;
    record(&store, OWNER, "radio", None, attached);
    record(&store, "bob", "radio", None, attached);
    // Bob's listing forgets his lapsed record and leaves Alice's.
    assert!(addresses(&store, "bob", START).is_empty());
    assert_eq!(addresses(&store, OWNER, START - 1), ["radio"]);
    record(&store, "bob", "radio", None, START);
    store
        .clear_claimed_radio("bob".into(), "radio".into())
        .unwrap();
    assert_eq!(addresses(&store, OWNER, START - 1), ["radio"]);
}
