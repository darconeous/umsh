use std::sync::Arc;

use super::super::MobilePeerUpsertRecord;
use super::*;

const OWNER: &str = "alice";
const PEER: &str = "peer";
const NOW: i64 = 1_800_000_000_000;
const HOUR: i64 = 3_600_000;

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
            MobilePeerUpsertRecord {
                alias: Some("Peer".into()),
                is_saved: true,
                ..MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
}

fn save(store: &MobileAppStore, owner: &str, address: &str, hints: &[&[u8]], until: i64) {
    store
        .save_manual_route(
            owner.into(),
            address.into(),
            hints.iter().map(|hint| hint.to_vec()).collect(),
            1,
            until,
            None,
            None,
            None,
        )
        .unwrap();
}

fn route(
    store: &MobileAppStore,
    address: &str,
    now_ms: i64,
) -> Option<MobileStoredManualRouteRecord> {
    store
        .manual_route(OWNER.into(), address.into(), now_ms)
        .unwrap()
}

fn held(store: &MobileAppStore, owner: &str, now_ms: i64) -> Vec<String> {
    let mut addresses: Vec<String> = store
        .manual_routes(owner.into(), now_ms)
        .unwrap()
        .into_iter()
        .map(|route| route.public_address)
        .collect();
    addresses.sort();
    addresses
}

fn stored_rows(store: &MobileAppStore) -> i64 {
    store
        .connection()
        .query_row("SELECT count(*) FROM node_manual_route", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// The iOS suite's `savedPathRoundTripsUntilItsHoldEnds`.
#[test]
fn a_saved_path_round_trips_until_its_hold_ends() {
    let (_directory, store) = open();
    peer(&store, OWNER, PEER);
    let hints = vec![vec![0x5E, 0xBD], vec![0xED, 0xBC]];
    store
        .save_manual_route(
            OWNER.into(),
            PEER.into(),
            hints.clone(),
            3,
            NOW + HOUR,
            Some(44.05),
            Some(-123.09),
            Some(12.0),
        )
        .unwrap();
    store
        .settle_manual_route_prompt(OWNER.into(), PEER.into())
        .unwrap();
    assert_eq!(
        route(&store, PEER, NOW),
        Some(MobileStoredManualRouteRecord {
            public_address: PEER.into(),
            hints,
            flood_hops: 3,
            hold_until_ms: NOW + HOUR,
            saved_latitude: Some(44.05),
            saved_longitude: Some(-123.09),
            saved_accuracy: Some(12.0),
            prompt_settled: true,
        })
    );
    assert_eq!(held(&store, OWNER, NOW), [PEER]);

    // Saving again is a new choice: the declined offer does not carry over.
    store
        .save_manual_route(
            OWNER.into(),
            PEER.into(),
            vec![],
            0,
            NOW + HOUR,
            None,
            None,
            None,
        )
        .unwrap();
    let direct = route(&store, PEER, NOW).unwrap();
    assert!(!direct.prompt_settled);
    assert!(direct.hints.is_empty());
    assert_eq!(direct.flood_hops, 0);
    assert_eq!(direct.saved_latitude, None);

    // Listing after the hold forgets the path, so it is gone even at an
    // instant that was still inside the hold.
    assert!(held(&store, OWNER, NOW + HOUR + 1_000).is_empty());
    assert_eq!(route(&store, PEER, NOW), None);
}

/// The iOS suite's `clearingForgetsThePath`.
#[test]
fn clearing_forgets_the_path() {
    let (_directory, store) = open();
    peer(&store, OWNER, PEER);
    save(&store, OWNER, PEER, &[&[1, 2]], NOW + 60_000);
    store.clear_manual_route(OWNER.into(), PEER.into()).unwrap();
    assert_eq!(route(&store, PEER, NOW), None);
    assert_eq!(stored_rows(&store), 0);
}

#[test]
fn a_path_is_held_until_its_instant_and_not_at_it() {
    let (_directory, store) = open();
    peer(&store, OWNER, PEER);
    save(&store, OWNER, PEER, &[&[1, 2]], NOW);
    assert!(route(&store, PEER, NOW - 1).is_some());
    assert_eq!(route(&store, PEER, NOW), None);
    // Reading one path does not forget it; listing does.
    assert_eq!(stored_rows(&store), 1);
    assert_eq!(held(&store, OWNER, NOW - 1), [PEER]);
    assert!(held(&store, OWNER, NOW).is_empty());
    assert_eq!(stored_rows(&store), 0);
}

#[test]
fn listing_forgets_only_this_identity_s_ended_paths() {
    let (_directory, store) = open();
    for address in ["early", "late"] {
        peer(&store, OWNER, address);
        peer(&store, "bob", address);
    }
    save(&store, OWNER, "early", &[], NOW);
    save(&store, OWNER, "late", &[], NOW + HOUR);
    save(&store, "bob", "early", &[], NOW);
    assert_eq!(held(&store, OWNER, NOW), ["late"]);
    // Bob's ended path is his own listing's to forget.
    assert_eq!(stored_rows(&store), 2);
    assert!(held(&store, "bob", NOW).is_empty());
    assert_eq!(stored_rows(&store), 1);
}

#[test]
fn routes_belong_to_their_identity() {
    let (_directory, store) = open();
    peer(&store, OWNER, PEER);
    peer(&store, "bob", PEER);
    save(&store, "bob", PEER, &[&[9, 9]], NOW + HOUR);
    assert_eq!(route(&store, PEER, NOW), None);
    assert!(held(&store, OWNER, NOW).is_empty());

    save(&store, OWNER, PEER, &[&[1, 1]], NOW + HOUR);
    store
        .settle_manual_route_prompt(OWNER.into(), PEER.into())
        .unwrap();
    store.clear_manual_route("bob".into(), PEER.into()).unwrap();
    let mine = route(&store, PEER, NOW).unwrap();
    assert_eq!(mine.hints, [vec![1, 1]]);
    assert!(mine.prompt_settled);
    let bobs = store.manual_route("bob".into(), PEER.into(), NOW).unwrap();
    assert_eq!(bobs, None);
}

#[test]
fn a_peer_with_no_row_has_nowhere_to_keep_a_path() {
    let (_directory, store) = open();
    save(&store, OWNER, "stranger", &[&[1, 2]], NOW + HOUR);
    assert_eq!(stored_rows(&store), 0);
    store
        .settle_manual_route_prompt(OWNER.into(), "stranger".into())
        .unwrap();
    store
        .clear_manual_route(OWNER.into(), "stranger".into())
        .unwrap();
}

#[test]
fn hints_are_stored_back_to_back_and_a_direct_path_as_an_empty_blob() {
    let (_directory, store) = open();
    peer(&store, OWNER, "routed");
    peer(&store, OWNER, "direct");
    save(
        &store,
        OWNER,
        "routed",
        &[&[0x5E, 0xBD], &[0xED, 0xBC]],
        NOW,
    );
    save(&store, OWNER, "direct", &[], NOW);
    let stored = |address: &str| -> (String, Vec<u8>, i64, i64) {
        store
            .connection()
            .query_row(
                "SELECT typeof(r.hints), r.hints, r.flood_hops, r.prompt_settled
                FROM node_manual_route r JOIN node n ON n.id = r.node_id
                WHERE n.public_address = ?",
                params![address],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    };
    assert_eq!(
        stored("routed"),
        ("blob".into(), vec![0x5E, 0xBD, 0xED, 0xBC], 1, 0)
    );
    assert_eq!(stored("direct"), ("blob".into(), vec![], 1, 0));
}

#[test]
fn a_stored_path_reads_back_in_whole_hints_and_clamped_flood_hops() {
    let (_directory, store) = open();
    peer(&store, OWNER, PEER);
    save(&store, OWNER, PEER, &[], NOW + HOUR);
    store
        .connection()
        .execute(
            "UPDATE node_manual_route SET hints = x'0102030405', flood_hops = 300",
            [],
        )
        .unwrap();
    let read = route(&store, PEER, NOW).unwrap();
    // The trailing octet is no hint.
    assert_eq!(read.hints, [vec![1, 2], vec![3, 4]]);
    assert_eq!(read.flood_hops, u8::MAX);
}
