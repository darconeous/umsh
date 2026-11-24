use std::sync::Arc;

use rusqlite::Connection;

use super::super::{BASELINE, BASELINE_VERSION, MIGRATIONS, ladder_top};
use super::*;

const OWNER: &str = "alice";

fn open() -> (tempfile::TempDir, Arc<MobileAppStore>) {
    let directory = tempfile::tempdir().unwrap();
    let store = MobileAppStore::open(path_in(&directory)).unwrap();
    store
        .insert_identity(OWNER.into(), "alice-public".into(), 1)
        .unwrap();
    (directory, store)
}

fn path_in(directory: &tempfile::TempDir) -> String {
    directory
        .path()
        .join("application.sqlite")
        .display()
        .to_string()
}

fn named(alias: Option<&str>, advertised_name: Option<&str>) -> MobilePeerUpsertRecord {
    MobilePeerUpsertRecord {
        alias: alias.map(Into::into),
        advertised_name: advertised_name.map(Into::into),
        ..MobilePeerUpsertRecord::default()
    }
}

fn upsert(store: &MobileAppStore, address: &str, peer: MobilePeerUpsertRecord) {
    store
        .upsert_peer(OWNER.into(), address.into(), peer)
        .unwrap();
}

fn nodes(store: &MobileAppStore) -> Vec<MobileStoredNodeRecord> {
    store.list_nodes(OWNER.into()).unwrap()
}

fn node(store: &MobileAppStore, address: &str) -> MobileStoredNodeRecord {
    nodes(store)
        .into_iter()
        .find(|node| node.public_address == address)
        .unwrap_or_else(|| panic!("no node {address}"))
}

fn addresses(store: &MobileAppStore) -> Vec<String> {
    nodes(store)
        .into_iter()
        .map(|node| node.public_address)
        .collect()
}

/// What `ensureDirectConversation` writes, which this domain only needs to
/// exist.
fn add_conversation(store: &MobileAppStore, address: &str) {
    store
        .connection()
        .execute(
            "INSERT INTO direct_conversation (owner_identity_id, node_id, created_at_ms)
            SELECT owner_identity_id, id, 1 FROM node
            WHERE owner_identity_id = ? AND public_address = ?",
            params![OWNER, address],
        )
        .unwrap();
}

// Identities

#[test]
fn identities_insert_once_and_upsert_moves_only_the_address() {
    let (_directory, store) = open();
    assert!(matches!(
        store.insert_identity(OWNER.into(), "other-public".into(), 2),
        Err(MobileStoreError::Failed { .. })
    ));
    store
        .upsert_identity(OWNER.into(), "alice-moved".into(), 99)
        .unwrap();
    store
        .upsert_identity("bob".into(), "bob-public".into(), 5)
        .unwrap();
    let rows: Vec<(String, String, i64)> = store
        .connection()
        .prepare("SELECT id, public_address, created_at_ms FROM local_identity ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        rows,
        [
            ("alice".into(), "alice-moved".into(), 1),
            ("bob".into(), "bob-public".into(), 5),
        ]
    );
}

#[test]
fn an_identity_is_known_by_its_id_or_its_legacy_primary_slot() {
    let (_directory, store) = open();
    assert!(
        store
            .knows_identity(OWNER.into(), "anything".into())
            .unwrap()
    );
    assert!(
        !store
            .knows_identity("legacy-public".into(), "legacy-public".into())
            .unwrap()
    );
    store
        .insert_identity("primary".into(), "legacy-public".into(), 1)
        .unwrap();
    assert!(
        store
            .knows_identity("legacy-public".into(), "legacy-public".into())
            .unwrap()
    );
    // The legacy slot is someone else's when its key differs.
    assert!(
        !store
            .knows_identity("other-public".into(), "other-public".into())
            .unwrap()
    );
}

#[test]
fn the_local_advertised_name_round_trips_and_needs_its_identity() {
    let (_directory, store) = open();
    assert_eq!(store.local_advertised_name(OWNER.into()), Ok(None));
    assert_eq!(store.local_advertised_name("nobody".into()), Ok(None));
    store
        .update_local_advertised_name(OWNER.into(), Some("Ridge".into()))
        .unwrap();
    assert_eq!(
        store.local_advertised_name(OWNER.into()),
        Ok(Some("Ridge".into()))
    );
    store
        .update_local_advertised_name(OWNER.into(), None)
        .unwrap();
    assert_eq!(store.local_advertised_name(OWNER.into()), Ok(None));
    assert_eq!(
        store.update_local_advertised_name("nobody".into(), Some("x".into())),
        Err(MobileStoreError::RecordNotFound)
    );
}

// Peers: the persistence smoke test's tier, delete/demote, retention, and
// device-identity checks, in its order.

#[test]
fn the_smoke_test_s_peer_sequence() {
    let (_directory, store) = open();

    // A user-initiated import is saved.
    upsert(
        &store,
        "peer-saved",
        MobilePeerUpsertRecord {
            is_saved: true,
            ..named(Some("Ridge Medic"), None)
        },
    );
    // An over-the-air advertisement lands in the transient tier.
    upsert(&store, "peer-transient", named(None, Some("Roaming Node")));
    assert!(node(&store, "peer-saved").is_saved);
    assert!(!node(&store, "peer-transient").is_saved);

    // A background advertisement upsert must never demote a saved peer.
    upsert(&store, "peer-saved", named(None, Some("Ridge Medic Node")));
    assert!(node(&store, "peer-saved").is_saved);

    // Promote a transient; favorite it (favoriting implies saved).
    store
        .promote_peer_to_saved(OWNER.into(), "peer-transient".into())
        .unwrap();
    assert!(node(&store, "peer-transient").is_saved);
    store
        .set_peer_favorite(OWNER.into(), "peer-transient".into(), true)
        .unwrap();
    assert!(node(&store, "peer-transient").is_favorite);

    // Demote clears favorite and alias but keeps the row.
    store
        .set_peer_favorite(OWNER.into(), "peer-saved".into(), true)
        .unwrap();
    assert!(node(&store, "peer-saved").is_favorite);
    store
        .demote_peer_to_transient(OWNER.into(), "peer-saved".into())
        .unwrap();
    assert!(!node(&store, "peer-saved").is_saved);
    assert!(!node(&store, "peer-saved").is_favorite);
    assert_eq!(node(&store, "peer-saved").alias, None);
    store
        .promote_peer_to_saved(OWNER.into(), "peer-saved".into())
        .unwrap();

    // Delete refuses a peer with a conversation.
    add_conversation(&store, "peer-saved");
    assert_eq!(
        store.delete_peer(OWNER.into(), "peer-saved".into()),
        Ok(false)
    );
    assert!(addresses(&store).contains(&"peer-saved".into()));

    // Plain delete works for a peer without a conversation.
    assert_eq!(
        store.delete_peer(OWNER.into(), "peer-transient".into()),
        Ok(true)
    );
    assert!(!addresses(&store).contains(&"peer-transient".into()));

    // The companion radio row is protected from delete and demote.
    store
        .upsert_ulcp_device_peer(
            OWNER.into(),
            "radio-peer".into(),
            Some("Tracker".into()),
            "AAAA".into(),
        )
        .unwrap();
    assert_eq!(
        store.delete_peer(OWNER.into(), "radio-peer".into()),
        Ok(false)
    );
    store
        .demote_peer_to_transient(OWNER.into(), "radio-peer".into())
        .unwrap();
    assert!(node(&store, "radio-peer").is_saved);

    // Retention keeps the newest-heard transients up to the cap; rows with
    // a conversation are never evicted. clear_transient_peers drops the rest.
    for index in 0..5 {
        let address = format!("flood-{index}");
        upsert(&store, &address, named(None, None));
        store
            .touch_last_heard(OWNER.into(), address, 1_000_000 + index * 1_000)
            .unwrap();
    }
    add_conversation(&store, "flood-0");
    store.enforce_transient_retention(OWNER.into(), 2).unwrap();
    let mut surviving: Vec<String> = addresses(&store)
        .into_iter()
        .filter(|address| address.starts_with("flood-"))
        .collect();
    surviving.sort();
    // flood-0 survives via its conversation; flood-4 and flood-3 are the
    // two newest-heard evictable rows.
    assert_eq!(surviving, ["flood-0", "flood-3", "flood-4"]);
    store.clear_transient_peers(OWNER.into()).unwrap();
    let surviving: Vec<String> = addresses(&store)
        .into_iter()
        .filter(|address| address.starts_with("flood-"))
        .collect();
    assert_eq!(surviving, ["flood-0"]);

    // Device-identity reconcile: the device's read-back is authority.
    // Known keys gain the flag, unknown keys gain a transient row, and
    // keys absent from the list lose the flag (rows survive).
    store
        .reconcile_device_identity_peers(
            OWNER.into(),
            vec!["flood-0".into(), "device-only-peer".into()],
        )
        .unwrap();
    assert!(node(&store, "flood-0").on_device_identity);
    let device_only = node(&store, "device-only-peer");
    assert!(device_only.on_device_identity && !device_only.is_saved);
    store
        .reconcile_device_identity_peers(OWNER.into(), vec![])
        .unwrap();
    assert!(nodes(&store).iter().all(|node| !node.on_device_identity));
    assert!(addresses(&store).contains(&"device-only-peer".into()));
    // The single-flag cache setter round-trips too.
    store
        .set_peer_on_device_identity(OWNER.into(), "flood-0".into(), true)
        .unwrap();
    assert!(node(&store, "flood-0").on_device_identity);
    store
        .set_peer_on_device_identity(OWNER.into(), "flood-0".into(), false)
        .unwrap();
    assert!(!node(&store, "flood-0").on_device_identity);
    assert_eq!(
        store.delete_peer(OWNER.into(), "device-only-peer".into()),
        Ok(true)
    );
}

#[test]
fn an_upsert_adds_what_it_knows_and_keeps_what_it_does_not() {
    let (_directory, store) = open();
    upsert(
        &store,
        "peer",
        MobilePeerUpsertRecord {
            alias: Some("Ridge".into()),
            advertised_name: Some("Ridge Node".into()),
            is_saved: true,
            node_kind: Some(MobileStoredNodeKind::Tracker),
            system_role: None,
            radio_identifier: Some("R1".into()),
            advertisement: Some(vec![1, 2, 3]),
            advertisement_authenticated: true,
            advertisement_received_at_ms: Some(1_700_000_000_123),
        },
    );
    // Nothing but the address: every stored field survives, and `is_saved`
    // cannot fall.
    upsert(&store, "peer", MobilePeerUpsertRecord::default());
    let stored = node(&store, "peer");
    assert_eq!(
        stored,
        MobileStoredNodeRecord {
            id: stored.id,
            owner_identity_id: OWNER.into(),
            public_address: "peer".into(),
            alias: Some("Ridge".into()),
            advertised_name: Some("Ridge Node".into()),
            system_role: None,
            node_kind: Some(MobileStoredNodeKind::Tracker),
            advertisement: Some(vec![1, 2, 3]),
            advertisement_authenticated: true,
            last_heard_at_ms: None,
            is_saved: true,
            is_favorite: false,
            on_device_identity: false,
            notify_when_heard: false,
            advertisement_received_at_ms: Some(1_700_000_000_123),
        }
    );
    let radio_identifier: Option<String> = store
        .connection()
        .query_row(
            "SELECT radio_identifier FROM node WHERE public_address = 'peer'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(radio_identifier.as_deref(), Some("R1"));

    // Provenance moves with the bundle: a new, imported advertisement
    // replaces the flag and the instant together.
    upsert(
        &store,
        "peer",
        MobilePeerUpsertRecord {
            advertisement: Some(vec![9]),
            ..MobilePeerUpsertRecord::default()
        },
    );
    let stored = node(&store, "peer");
    assert_eq!(stored.advertisement, Some(vec![9]));
    assert!(!stored.advertisement_authenticated);
    assert_eq!(stored.advertisement_received_at_ms, None);
}

#[test]
fn an_alias_is_set_kept_and_cleared() {
    let (_directory, store) = open();
    upsert(&store, "peer", named(Some("Ridge Medic"), Some("Name")));
    // A new name does not displace the alias.
    upsert(&store, "peer", named(None, Some("Other")));
    assert_eq!(node(&store, "peer").alias.as_deref(), Some("Ridge Medic"));

    store
        .update_node_alias(OWNER.into(), "peer".into(), Some("Zoë".into()))
        .unwrap();
    assert_eq!(node(&store, "peer").alias.as_deref(), Some("Zoë"));
    store
        .update_node_alias(OWNER.into(), "peer".into(), None)
        .unwrap();
    assert_eq!(node(&store, "peer").alias, None);
    // A missing row is not an error.
    store
        .update_node_alias(OWNER.into(), "nobody".into(), Some("x".into()))
        .unwrap();

    // Demoting clears the alias.
    store
        .update_node_alias(OWNER.into(), "peer".into(), Some("Alias".into()))
        .unwrap();
    store
        .demote_peer_to_transient(OWNER.into(), "peer".into())
        .unwrap();
    let demoted = node(&store, "peer");
    assert_eq!(demoted.alias, None);
    assert!(!demoted.is_saved);
}

#[test]
fn favoriting_saves_and_unfavoriting_keeps_the_row_saved() {
    let (_directory, store) = open();
    upsert(&store, "peer", named(None, Some("Node")));
    store
        .set_peer_favorite(OWNER.into(), "peer".into(), true)
        .unwrap();
    let stored = node(&store, "peer");
    assert!(stored.is_favorite && stored.is_saved);
    store
        .set_peer_favorite(OWNER.into(), "peer".into(), false)
        .unwrap();
    let stored = node(&store, "peer");
    assert!(!stored.is_favorite && stored.is_saved);
}

#[test]
fn a_watch_fires_once_and_protects_its_row_from_retention() {
    let (_directory, store) = open();
    upsert(&store, "watched", named(None, None));
    store
        .set_notify_when_heard(OWNER.into(), "watched".into(), true)
        .unwrap();
    assert!(node(&store, "watched").notify_when_heard);
    // Neither the cap nor clearing removes an armed row.
    store.enforce_transient_retention(OWNER.into(), 0).unwrap();
    store.clear_transient_peers(OWNER.into()).unwrap();
    assert_eq!(addresses(&store), ["watched"]);

    assert_eq!(
        store.touch_last_heard(OWNER.into(), "watched".into(), 5_000),
        Ok(true)
    );
    assert_eq!(
        store.touch_last_heard(OWNER.into(), "watched".into(), 6_000),
        Ok(false)
    );
    let stored = node(&store, "watched");
    assert!(!stored.notify_when_heard);
    assert_eq!(stored.last_heard_at_ms, Some(6_000));

    // Disarmed by hand, nothing fires.
    store
        .set_notify_when_heard(OWNER.into(), "watched".into(), true)
        .unwrap();
    store
        .set_notify_when_heard(OWNER.into(), "watched".into(), false)
        .unwrap();
    assert_eq!(
        store.touch_last_heard(OWNER.into(), "watched".into(), 7_000),
        Ok(false)
    );

    // An unknown peer has nothing to touch and gains no row.
    assert_eq!(
        store.touch_last_heard(OWNER.into(), "stranger".into(), 7_000),
        Ok(false)
    );
    assert_eq!(addresses(&store), ["watched"]);
}

#[test]
fn retention_and_clearing_spare_saved_device_and_system_rows() {
    let (_directory, store) = open();
    upsert(
        &store,
        "saved",
        MobilePeerUpsertRecord {
            is_saved: true,
            ..MobilePeerUpsertRecord::default()
        },
    );
    store
        .set_peer_on_device_identity(OWNER.into(), "on-device".into(), true)
        .unwrap();
    store
        .upsert_ulcp_device_peer(OWNER.into(), "radio".into(), None, "R".into())
        .unwrap();
    // A system row that is not saved: only its role spares it.
    upsert(
        &store,
        "system",
        MobilePeerUpsertRecord {
            system_role: Some(MobileStoredSystemRole::CompanionRadio),
            ..MobilePeerUpsertRecord::default()
        },
    );
    assert!(!node(&store, "system").is_saved);
    upsert(&store, "transient", named(None, None));
    store.enforce_transient_retention(OWNER.into(), 0).unwrap();
    let mut remaining = addresses(&store);
    remaining.sort();
    assert_eq!(remaining, ["on-device", "radio", "saved", "system"]);
    upsert(&store, "transient", named(None, None));
    store.clear_transient_peers(OWNER.into()).unwrap();
    let mut remaining = addresses(&store);
    remaining.sort();
    assert_eq!(remaining, ["on-device", "radio", "saved", "system"]);
}

#[test]
fn retention_evicts_the_never_heard_before_the_oldest_heard() {
    let (_directory, store) = open();
    upsert(&store, "never", named(None, None));
    upsert(&store, "old", named(None, None));
    upsert(&store, "new", named(None, None));
    store
        .touch_last_heard(OWNER.into(), "old".into(), 1_000)
        .unwrap();
    store
        .touch_last_heard(OWNER.into(), "new".into(), 2_000)
        .unwrap();
    // NULL sorts last under DESC, so a row never heard goes first.
    store.enforce_transient_retention(OWNER.into(), 2).unwrap();
    let mut remaining = addresses(&store);
    remaining.sort();
    assert_eq!(remaining, ["new", "old"]);
    store.enforce_transient_retention(OWNER.into(), 1).unwrap();
    assert_eq!(addresses(&store), ["new"]);
}

#[test]
fn the_companion_radio_role_belongs_to_one_row() {
    let (_directory, store) = open();
    store
        .upsert_ulcp_device_peer(
            OWNER.into(),
            "radio-a".into(),
            Some("Tracker".into()),
            "AAAA".into(),
        )
        .unwrap();
    let radio = node(&store, "radio-a");
    assert_eq!(
        radio.system_role,
        Some(MobileStoredSystemRole::CompanionRadio)
    );
    assert!(radio.is_saved);
    assert_eq!(radio.advertised_name.as_deref(), Some("Tracker"));

    store
        .upsert_ulcp_device_peer(OWNER.into(), "radio-b".into(), None, "BBBB".into())
        .unwrap();
    let roles: Vec<(String, Option<String>, Option<String>)> = store
        .connection()
        .prepare(
            "SELECT public_address, system_role, radio_identifier FROM node
            ORDER BY public_address",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        roles,
        [
            ("radio-a".into(), None, None),
            (
                "radio-b".into(),
                Some("companion_radio".into()),
                Some("BBBB".into())
            ),
        ]
    );
    // The former radio stays saved and is an ordinary peer now.
    assert!(node(&store, "radio-a").is_saved);
    assert_eq!(store.delete_peer(OWNER.into(), "radio-a".into()), Ok(true));
}

#[test]
fn nodes_list_system_rows_first_then_by_id() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    upsert(&store, "zulu", named(Some("Zulu"), None));
    upsert(&store, "alpha-2", named(Some("alpha"), None));
    upsert(&store, "alpha-1", named(Some("Álpha"), None));
    upsert(&store, "bravo", named(None, Some("bravo")));
    store
        .upsert_ulcp_device_peer(OWNER.into(), "radio".into(), Some("Zz".into()), "R".into())
        .unwrap();
    store
        .upsert_peer("bob".into(), "bobs-peer".into(), named(Some("A"), None))
        .unwrap();
    // The platforms sort names by the reader's locale.
    assert_eq!(
        addresses(&store),
        ["radio", "zulu", "alpha-2", "alpha-1", "bravo"]
    );
}

#[test]
fn a_peer_needs_its_identity() {
    let (_directory, store) = open();
    assert!(matches!(
        store.upsert_peer("nobody".into(), "peer".into(), named(None, None)),
        Err(MobileStoreError::Failed { .. })
    ));
}

#[test]
fn heard_instants_are_milliseconds() {
    let (_directory, store) = open();
    upsert(
        &store,
        "peer",
        MobilePeerUpsertRecord {
            advertisement: Some(vec![1]),
            advertisement_received_at_ms: Some(1_700_000_000_123),
            ..MobilePeerUpsertRecord::default()
        },
    );
    store
        .touch_last_heard(OWNER.into(), "peer".into(), 1_700_000_001_999)
        .unwrap();
    let stored = node(&store, "peer");
    assert_eq!(stored.last_heard_at_ms, Some(1_700_000_001_999));
    assert_eq!(stored.advertisement_received_at_ms, Some(1_700_000_000_123));
}

// Files the Swift store wrote

#[test]
fn a_swift_store_migrates_its_nodes() {
    let directory = tempfile::tempdir().unwrap();
    let path = path_in(&directory);
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(BASELINE).unwrap();
        connection
            .pragma_update(None, "user_version", BASELINE_VERSION)
            .unwrap();
        connection
            .execute_batch(
                "INSERT INTO local_identity (id, public_address, created_at_ms)
                    VALUES ('alice', 'alice-public', 1);
                -- What the Swift store wrote: a Date's full-precision
                -- seconds, and a folded sort key.
                INSERT INTO node (owner_identity_id, public_address, alias, alias_search,
                    last_heard_at, advertisement_received_at)
                    VALUES ('alice', 'peer', 'Straße', 'strasse',
                        1700000002.12349, 1700000002.12351);",
            )
            .unwrap();
    }
    let store = MobileAppStore::open(path).unwrap();
    assert_eq!(store.schema_version(), Ok(ladder_top(MIGRATIONS)));
    let stored = node(&store, "peer");
    assert_eq!(stored.alias.as_deref(), Some("Straße"));
    assert_eq!(stored.last_heard_at_ms, Some(1_700_000_002_123));
    assert_eq!(stored.advertisement_received_at_ms, Some(1_700_000_002_124));
}
