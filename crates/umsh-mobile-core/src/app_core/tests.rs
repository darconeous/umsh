use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::mapping::PeerIndex;
use super::*;
use crate::store::{
    MobilePeerUpsertRecord, MobileStoredChannelKind, MobileStoredChannelRecord,
    MobileStoredNodeKind, claimed_radio_lapse_ms,
};
use crate::{NodeIdentityProfileRecord, public_identity_record, signed_node_identity_bundle};

const NOW_MS: i64 = 1_790_000_000_000;

struct ManualClock(AtomicI64);

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Counting(AtomicUsize);

impl MobileAppCoreListener for Counting {
    fn on_changes_pending(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn address(seed: u8) -> String {
    let identity = umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32]);
    public_identity_record(umsh_crypto::NodeIdentity::public_key(&identity)).canonical_address
}

struct Fixture {
    directory: tempfile::TempDir,
    store: Arc<MobileAppStore>,
    clock: Arc<ManualClock>,
    core: Arc<MobileAppCore>,
    owner: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = MobileAppStore::open(directory.path().join("app.sqlite").display().to_string())
            .unwrap();
        let owner = address(1);
        store
            .insert_identity(owner.clone(), owner.clone(), 1)
            .unwrap();
        let clock = Arc::new(ManualClock(AtomicI64::new(NOW_MS)));
        let core = MobileAppCore::with_clock(store.clone(), clock.clone()).unwrap();
        core.set_owner(Some(owner.clone())).unwrap();
        core.poll_changes();
        Self {
            directory,
            store,
            clock,
            core,
            owner,
        }
    }

    /// A second connection, for doing to the file what the store would not.
    fn sql(&self, statement: &str) {
        rusqlite::Connection::open(self.directory.path().join("app.sqlite"))
            .unwrap()
            .execute_batch(statement)
            .unwrap();
    }

    fn peer(
        &self,
        address: &str,
        kind: Option<MobileStoredNodeKind>,
        advertisement: Option<Vec<u8>>,
    ) {
        self.store
            .upsert_peer(
                self.owner.clone(),
                address.to_owned(),
                MobilePeerUpsertRecord {
                    is_saved: true,
                    node_kind: kind,
                    advertisement,
                    ..MobilePeerUpsertRecord::default()
                },
            )
            .unwrap();
    }

    fn channel(&self, id: &str, name: Option<&str>, alias: Option<&str>, digest: &str) {
        self.store
            .insert_channel(
                MobileStoredChannelRecord {
                    id: id.to_owned(),
                    owner_identity_id: self.owner.clone(),
                    kind: MobileStoredChannelKind::Named,
                    canonical_name: name.map(str::to_lowercase),
                    name: name.map(str::to_owned),
                    alias: alias.map(str::to_owned),
                    channel_id_hex: "abcd".to_owned(),
                    tint: vec![1, 2, 3],
                    region_code: None,
                    max_flood_hops: None,
                    joined_phone: true,
                    joined_device: false,
                    notifications_enabled: false,
                    joined_at_ms: None,
                },
                digest.to_owned(),
                1,
            )
            .unwrap();
    }
}

#[test]
fn queries_need_an_owner() {
    let fixture = Fixture::new();
    fixture.core.set_owner(None).unwrap();
    assert_eq!(fixture.core.state(false), Err(MobileAppError::NoOwner));
    assert_eq!(
        fixture.core.message_count("x".into()),
        Err(MobileAppError::NoOwner)
    );
    assert_eq!(
        fixture.core.status(),
        Ok(MobileAppStatusRecord {
            lifecycle: MobileAppLifecycle::Idle
        })
    );
}

#[test]
fn setting_the_owner_raises_every_list_once() {
    let fixture = Fixture::new();
    let listener = Arc::new(Counting(AtomicUsize::new(0)));
    fixture.core.set_listener(listener.clone());
    fixture.core.set_owner(Some("a".into())).unwrap();
    fixture.core.set_owner(Some("b".into())).unwrap();
    assert_eq!(listener.0.load(Ordering::SeqCst), 1, "coalesced");
    assert_eq!(
        fixture.core.poll_changes(),
        MobileAppChangesRecord {
            lifecycle: None,
            peers_changed: true,
            channels_changed: true,
            conversations_changed: true,
        }
    );
    assert_eq!(
        fixture.core.poll_changes(),
        MobileAppChangesRecord::default()
    );
    fixture.core.set_owner(None).unwrap();
    assert_eq!(listener.0.load(Ordering::SeqCst), 2, "re-armed by the poll");
}

#[test]
fn while_stopping_queries_are_busy_and_status_answers() {
    let fixture = Fixture::new();
    fixture.core.shared.enter(MobileAppLifecycle::Stopping);
    assert_eq!(fixture.core.state(false), Err(MobileAppError::Busy));
    assert_eq!(fixture.core.claimed_radios(), Err(MobileAppError::Busy));
    assert_eq!(
        fixture.core.forget_management_cache(address(2)),
        Err(MobileAppError::Busy)
    );
    assert_eq!(
        fixture.core.status(),
        Ok(MobileAppStatusRecord {
            lifecycle: MobileAppLifecycle::Stopping
        })
    );
    // Kept, for when the core runs again.
    assert_eq!(fixture.core.set_owner(None), Ok(()));
}

#[tokio::test]
async fn a_stopped_core_answers_nothing() {
    let fixture = Fixture::new();
    fixture.core.stop().await;
    assert_eq!(
        fixture.core.poll_changes().lifecycle,
        Some(MobileAppLifecycle::Stopped)
    );
    assert_eq!(fixture.core.status(), Err(MobileAppError::Stopped));
    assert_eq!(fixture.core.state(true), Err(MobileAppError::Stopped));
    assert_eq!(
        fixture.core.set_owner(Some("a".into())),
        Err(MobileAppError::Stopped)
    );
    // Again does nothing, and does not wait.
    fixture.core.stop().await;
    assert_eq!(
        fixture.core.poll_changes(),
        MobileAppChangesRecord::default()
    );
}

#[test]
fn dropping_the_core_ends_its_worker() {
    let fixture = Fixture::new();
    let shared = fixture.core.shared.clone();
    drop(fixture.core);
    let deadline = Instant::now() + Duration::from_secs(5);
    while shared.snapshot().lifecycle != MobileAppLifecycle::Stopped {
        assert!(Instant::now() < deadline, "the worker is still running");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_failed_read_is_an_error() {
    let fixture = Fixture::new();
    fixture.sql("ALTER TABLE channel RENAME TO hidden_channel");
    assert!(matches!(
        fixture.core.state(true),
        Err(MobileAppError::Store { .. })
    ));
}

#[test]
fn a_conversations_only_read_leaves_peers_and_reports_unread() {
    let fixture = Fixture::new();
    let peer = address(2);
    fixture.peer(&peer, None, None);
    fixture
        .store
        .ensure_direct_conversation(fixture.owner.clone(), peer.clone(), 1)
        .unwrap();
    fixture.sql("ALTER TABLE node_peer_repeater_entry RENAME TO hidden_entries");

    let state = fixture.core.state(true).unwrap();
    assert_eq!(state.peers, None);
    assert_eq!(state.neighbor_reports, None);
    assert_eq!(state.direct_conversations.len(), 1);
    assert_eq!(
        state.direct_conversations[0]
            .peer
            .identity
            .canonical_address,
        peer
    );
    assert!(matches!(
        fixture.core.state(false),
        Err(MobileAppError::Store { .. })
    ));
}

#[test]
fn a_hint_names_the_one_likely_repeater_else_the_one_candidate() {
    let fixture = Fixture::new();
    let nodes = [address(2), address(3), address(4)];
    fixture.peer(&nodes[0], Some(MobileStoredNodeKind::Chat), None);
    fixture.peer(&nodes[1], Some(MobileStoredNodeKind::Bridge), None);
    // An advertisement that does not decode falls back to the stored kind.
    fixture.peer(
        &nodes[2],
        Some(MobileStoredNodeKind::Chat),
        Some(vec![0xFF]),
    );
    let index = PeerIndex::of_nodes(fixture.store.list_nodes(fixture.owner.clone()).unwrap());
    let hint = |address: &str| {
        crate::inspect_public_identity(address.to_owned())
            .unwrap()
            .hint
            .bytes
    };

    for node in &nodes {
        assert_eq!(index.named(&hint(node)).as_deref(), Some(node.as_str()));
        assert_eq!(
            index.named(&hint(node)[..2]).as_deref(),
            Some(node.as_str())
        );
    }
    // Every node's hint starts with the empty hint: one is a bridge.
    assert_eq!(index.named(&[]).as_deref(), Some(nodes[1].as_str()));
    assert_eq!(index.named(&[0, 0, 0, 0]), None);
}

#[tokio::test]
async fn an_advertisement_that_forwards_outranks_the_stored_kind() {
    let fixture = Fixture::new();
    let identity = umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[5; 32]);
    let repeater = address(5);
    let bundle = signed_node_identity_bundle(
        &identity,
        NodeIdentityProfileRecord {
            role_code: umsh_node::NodeRole::Repeater.as_byte(),
            capability_bits: umsh_node::NodeCapabilities::REPEATER.bits(),
            name: None,
            latitude: None,
            longitude: None,
            location_precision: None,
            altitude_m: None,
            timestamp: None,
        },
    )
    .await
    .unwrap();
    fixture.peer(&repeater, Some(MobileStoredNodeKind::Chat), Some(bundle));
    fixture.peer(&address(6), Some(MobileStoredNodeKind::Bridge), None);
    let nodes = fixture.store.list_nodes(fixture.owner.clone()).unwrap();
    let from_nodes = PeerIndex::of_nodes(nodes.clone());
    let peers: Vec<_> = nodes.into_iter().filter_map(super::mapping::peer).collect();
    let from_peers = PeerIndex::of_peers(&peers);
    // Two likely repeaters share the empty hint, so it names nobody.
    assert_eq!(from_nodes.named(&[]), None);
    let hint = crate::inspect_public_identity(repeater.clone())
        .unwrap()
        .hint
        .bytes;
    assert_eq!(from_nodes.named(&hint).as_deref(), Some(repeater.as_str()));
    assert_eq!(from_peers.named(&hint).as_deref(), Some(repeater.as_str()));
    assert!(peers.iter().any(|peer| {
        peer.advertised_identity
            .as_ref()
            .is_some_and(|identity| identity.forwards)
    }));
}

#[test]
fn a_channel_preview_finds_its_stored_channel_and_a_name_conflict() {
    let fixture = Fixture::new();
    let preview = crate::inspect_channel_name("Bay Net".into()).unwrap();
    let digest = crate::channel_key_digest(preview.key.clone());
    let same = "00000000-0000-8000-8000-000000000001";
    let other = "00000000-0000-8000-8000-000000000002";
    let nameless = "00000000-0000-8000-8000-000000000003";
    fixture.channel(same, Some("Bay Net"), None, &digest);
    fixture.channel(other, Some("Elsewhere"), Some("BAY NET"), "other");
    fixture.channel(nameless, None, Some(""), "nameless");

    let answer = fixture.core.preview_channel("  bay net \n".into()).unwrap();
    assert_eq!(
        answer.existing.map(|channel| channel.id).as_deref(),
        Some(same)
    );
    assert_eq!(
        answer.name_conflict.map(|channel| channel.id).as_deref(),
        Some(other)
    );

    let answer = fixture.core.preview_channel("Fresh".into()).unwrap();
    assert_eq!(answer.existing, None);
    assert_eq!(answer.name_conflict, None);

    assert_eq!(
        fixture.core.preview_channel(" ".into()),
        Err(MobileAppError::InvalidInput {
            error: MobileError::InvalidUri
        })
    );
    assert_eq!(
        fixture.core.preview_channel("UMSH:nonsense".into()),
        Err(MobileAppError::InvalidInput {
            error: MobileError::InvalidUri
        })
    );
}

#[test]
fn stranded_radios_leave_out_the_attached_host_and_lapsed_claims() {
    let fixture = Fixture::new();
    let owner = || fixture.owner.clone();
    let (attached, elsewhere, lapsed) = (address(2), address(3), address(4));
    let lapse = claimed_radio_lapse_ms();
    fixture
        .store
        .record_claimed_radio(owner(), lapsed.clone(), None, NOW_MS - lapse)
        .unwrap();
    fixture
        .store
        .record_claimed_radio(owner(), elsewhere.clone(), Some("Old".into()), NOW_MS - 2)
        .unwrap();
    fixture
        .store
        .record_claimed_radio(owner(), attached.clone(), None, NOW_MS - 1)
        .unwrap();
    fixture.core.shared.publish(|snapshot| {
        snapshot.attached_host = Some(attached.clone());
        MobileAppChangesRecord::default()
    });

    let claimed: Vec<String> = fixture
        .core
        .claimed_radios()
        .unwrap()
        .into_iter()
        .map(|radio| radio.device_address)
        .collect();
    assert_eq!(claimed, [attached.clone(), elsewhere.clone()]);
    let stranded: Vec<String> = fixture
        .core
        .stranded_radios()
        .unwrap()
        .into_iter()
        .map(|radio| radio.device_address)
        .collect();
    assert_eq!(stranded, [elsewhere]);

    fixture.clock.0.store(NOW_MS + lapse, Ordering::SeqCst);
    assert_eq!(fixture.core.claimed_radios(), Ok(Vec::new()));
}

#[test]
fn cached_properties_are_stamped_by_the_clock() {
    let fixture = Fixture::new();
    let device = address(2);
    fixture.peer(&device, None, None);
    fixture
        .core
        .save_cached_properties(device.clone(), HashMap::from([(7, vec![1, 2])]))
        .unwrap();
    let cached = fixture.core.cached_properties(device, vec![7, 8]).unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[&7].value, [1, 2]);
    assert_eq!(cached[&7].fetched_at_ms, NOW_MS);
}

#[test]
fn the_phone_node_key_is_the_owner_address_decoded() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.core.phone_node_key(),
        Ok(crate::public_identity_bytes(fixture.owner.clone()).unwrap())
    );
    fixture
        .core
        .set_owner(Some("not an address".into()))
        .unwrap();
    assert!(matches!(
        fixture.core.phone_node_key(),
        Err(MobileAppError::InvalidInput { .. })
    ));
}
