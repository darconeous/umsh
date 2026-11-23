//! The core over the staging air: a real radio driver on a soft device,
//! and staged peers that talk to the phone. Real time throughout.

use std::sync::Arc;
use std::time::Duration;

use umsh_ulcp::ids::prop;

use super::test_support::{Core, NOW_MS, identity};
use super::{
    MobileAppChangesRecord, MobileAppLearnedPathOffer, MobileAppPingResult,
    MobileNotificationEventRecord, MobilePositionRecord,
};
use crate::mobile_mesh::{MobileMeshExplicitPath, MobileMeshRouteKind};
use crate::radio_driver::MobileRadioPhase;
use crate::staging::{MobileStagingAir, MobileStagingAirError, staged_speaker_address};
use crate::store::MobileStoredSystemRole;

/// The phone's identity secret.
const PHONE_SEED: u8 = 0x09;

/// A running core whose radio is the staged one, over a staged store.
struct Staged {
    core: Core,
    air: Arc<MobileStagingAir>,
    _air_dir: tempfile::TempDir,
    owner: String,
    /// Every change drained so far, merged.
    seen: std::cell::RefCell<MobileAppChangesRecord>,
}

impl Staged {
    async fn new() -> Self {
        Self::with_vault(false).await
    }

    /// Started with the vault locked, as a phone not yet unlocked since it
    /// booted.
    async fn locked() -> Self {
        Self::with_vault(true).await
    }

    async fn with_vault(locked: bool) -> Self {
        let core = Core::new();
        let owner = identity(PHONE_SEED).public_identity().canonical_address;
        crate::seed_staging(
            core.store.clone(),
            core.vault.clone(),
            owner.clone(),
            super::test_support::NOW_MS,
        )
        .await
        .unwrap();
        core.vault.set_locked(locked);
        let air_dir = tempfile::tempdir().unwrap();
        let air = MobileStagingAir::start(air_dir.path().display().to_string(), false).unwrap();
        core.core.use_radio(Some(air.radio())).await.unwrap();
        core.start(PHONE_SEED).await;
        air.connect();
        let staged = Self {
            core,
            air,
            _air_dir: air_dir,
            owner,
            seen: std::cell::RefCell::new(MobileAppChangesRecord::default()),
        };
        staged
            .until("the staged radio attached", |changes| {
                changes
                    .radio
                    .as_ref()
                    .is_some_and(|radio| radio.phase == MobileRadioPhase::Attached)
            })
            .await;
        staged.knows_the_phone().await;
        staged
    }

    /// Drain the core's changes into `seen` until `done` holds of them.
    async fn until(&self, what: &str, mut done: impl FnMut(&MobileAppChangesRecord) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let changes = self.core.core.poll_changes();
            self.seen.borrow_mut().merge(changes);
            if done(&self.seen.borrow()) {
                return;
            }
            assert!(tokio::time::Instant::now() < deadline, "never: {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Forget what was seen.
    fn reset(&self) {
        self.core.core.poll_changes();
        *self.seen.borrow_mut() = MobileAppChangesRecord::default();
    }

    /// Wait until the staged peers know the phone.
    async fn knows_the_phone(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            match self.air.peer_reacts("+1".to_owned()).await {
                Err(MobileStagingAirError::NoPhone) => {}
                _ => return,
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the peers never learned the phone"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[tokio::test]
async fn an_attached_radio_gets_its_peer_row_and_its_claim() {
    let staged = Staged::new().await;
    let owner = staged.owner.clone();
    let store = staged.core.store.clone();
    staged
        .core
        .until("the radio's peer row", |_| {
            store
                .list_nodes(owner.clone())
                .unwrap()
                .iter()
                .any(|node| node.system_role == Some(MobileStoredSystemRole::CompanionRadio))
        })
        .await;
    staged
        .core
        .until("the radio's claim", |core| {
            core.claimed_radios().is_ok_and(|claims| claims.len() == 1)
        })
        .await;
    assert_eq!(
        staged.core.core.stranded_radios().unwrap(),
        Vec::new(),
        "the attached radio is not stranded"
    );
}

#[tokio::test]
async fn a_direct_message_notifies_and_names_its_transcript() {
    let staged = Staged::new().await;
    staged.reset();
    let speaker = staged_speaker_address();
    staged
        .air
        .peer_says("Trailhead at noon?".to_owned(), false)
        .await
        .unwrap();
    staged
        .until("the message's notification", |changes| {
            changes.transcripts.contains(&speaker)
                && changes.notifications.iter().any(|event| {
                    matches!(event, MobileNotificationEventRecord::Message {
                        conversation, body, channel_id: None, ..
                    } if conversation == &speaker && body == "Trailhead at noon?")
                })
        })
        .await;
    assert!(staged.seen.borrow().conversations_changed);
}

/// A phone whose store holds none of the staged mesh: only its own
/// identity, the radio it is given, and what arrives.
async fn unseeded() -> (Core, Arc<MobileStagingAir>, tempfile::TempDir, String) {
    let core = Core::new();
    let owner = identity(PHONE_SEED).public_identity().canonical_address;
    let air_dir = tempfile::tempdir().unwrap();
    let air = MobileStagingAir::start(air_dir.path().display().to_string(), false).unwrap();
    core.core.use_radio(Some(air.radio())).await.unwrap();
    core.start(PHONE_SEED).await;
    air.connect();
    (core, air, air_dir, owner)
}

/// The first message from a peer the phone has never heard of (no
/// advertisement, no exchange, never saved): it is stored under the
/// sender's address, but no conversation lists it until the peer is
/// stored. Saving the peer and opening the conversation shows it.
#[tokio::test]
async fn an_unsolicited_direct_message_waits_for_its_sender_to_be_stored() {
    let (core, air, _air_dir, owner) = unseeded().await;
    let speaker = staged_speaker_address();
    let is_speaker = |node: &crate::store::MobileStoredNodeRecord| node.public_address == speaker;
    assert!(
        !core
            .store
            .list_nodes(owner.clone())
            .unwrap()
            .iter()
            .any(is_speaker)
    );
    let started = tokio::time::Instant::now();
    loop {
        match air.peer_says("Who's on the ridge?".to_owned(), false).await {
            Err(MobileStagingAirError::NoPhone) => {}
            answer => {
                answer.unwrap();
                break;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the speaker never learned the phone"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stored = |core: &Core| {
        core.store
            .chat_message_page_newest(owner.clone(), speaker.clone(), 10)
            .unwrap()
            .messages
            .iter()
            .any(|message| message.body == "Who's on the ridge?")
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !stored(&core) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the message was never stored"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let state = core.core.state(false).unwrap();
    assert!(
        state.direct_conversations.is_empty(),
        "no conversation without its peer"
    );
    assert!(
        !state
            .peers
            .unwrap()
            .iter()
            .any(|peer| peer.identity.canonical_address == speaker)
    );

    // Stored by its key, the sender's conversation opens on the message.
    core.core
        .save_peer(speaker.clone(), None, true)
        .await
        .unwrap();
    let address = core.core.start_conversation(speaker.clone()).await.unwrap();
    assert_eq!(address, speaker);
    let state = core.core.state(true).unwrap();
    let conversation = state
        .direct_conversations
        .iter()
        .find(|conversation| conversation.peer.identity.canonical_address == speaker)
        .unwrap();
    assert_eq!(
        conversation
            .last_message
            .as_ref()
            .map(|message| message.stored.body.as_str()),
        Some("Who's on the ridge?")
    );
}

#[tokio::test]
async fn a_muted_conversation_stores_the_message_and_says_nothing() {
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    let store = &staged.core.store;
    let conversation = store
        .list_direct_conversations(staged.owner.clone())
        .unwrap()
        .into_iter()
        .find(|conversation| conversation.node.public_address == speaker)
        .expect("the staged speaker has a conversation");
    store
        .set_direct_conversation_notifications(staged.owner.clone(), conversation.id, false)
        .unwrap();
    staged.reset();
    staged
        .air
        .peer_says("Quiet, please".to_owned(), false)
        .await
        .unwrap();
    staged
        .until("the transcript change", |changes| {
            changes.transcripts.contains(&speaker)
        })
        .await;
    // Give a notification a moment to follow, should one be coming.
    tokio::time::sleep(Duration::from_millis(200)).await;
    staged.until("drained", |_| true).await;
    assert!(
        !staged
            .seen
            .borrow()
            .notifications
            .iter()
            .any(|event| matches!(event, MobileNotificationEventRecord::Message { .. })),
        "{:?}",
        staged.seen.borrow().notifications
    );
}

#[tokio::test]
async fn a_channel_message_notifies_under_its_channel() {
    let staged = Staged::new().await;
    staged.reset();
    staged
        .air
        .peer_says("Anyone on the ridge?".to_owned(), true)
        .await
        .unwrap();
    staged
        .until("the channel message's notification", |changes| {
            changes.notifications.iter().any(|event| {
                matches!(event, MobileNotificationEventRecord::Message {
                    channel_id: Some(_), body, ..
                } if body == "Anyone on the ridge?")
            })
        })
        .await;
}

/// How many receive filters the staged radio holds: it filters, rather
/// than holding host keys, so each phone-joined channel is one.
fn radio_filters(staged: &Staged) -> Option<u32> {
    staged
        .air
        .radio()
        .state()
        .provisioning
        .and_then(|sync| sync.filter_count)
}

#[tokio::test]
async fn a_locked_vault_holds_the_channels_back_until_it_opens() {
    let staged = Staged::locked().await;
    // Nothing is sent while the keys cannot be read.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(radio_filters(&staged), Some(0));

    staged.core.vault.set_locked(false);
    staged.core.core.resumed();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    // Public, EMERGENCY, and the two staged channels.
    while radio_filters(&staged) != Some(4) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the radio never got the channels: {:?}",
            radio_filters(&staged)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The staged repeater the phone manages: Tallac Ridge.
const MANAGED_SEED: u8 = 0x22;

fn address_of(seed: u8) -> String {
    identity(seed).public_identity().canonical_address
}

#[tokio::test]
async fn a_ping_to_a_staged_peer_is_answered() {
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    let result = staged.core.core.ping(speaker, None).await.unwrap();
    let MobileAppPingResult::Reply { reply } = result else {
        panic!("no reply: {result:?}");
    };
    assert_eq!(
        reply.hop_count,
        Some(1),
        "the speaker is in range of the radio"
    );
}

#[tokio::test]
async fn a_locked_vault_never_sheds_the_channels_a_radio_holds() {
    let staged = Staged::new().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while radio_filters(&staged) != Some(4) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the radio never got the channels"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // A new session with the radio while the keys cannot be read.
    staged.core.vault.set_locked(true);
    staged.core.core.use_radio(None).await.unwrap();
    staged
        .core
        .core
        .use_radio(Some(staged.air.radio()))
        .await
        .unwrap();
    staged
        .until("the radio attached again", |changes| {
            changes
                .radio
                .as_ref()
                .is_some_and(|radio| radio.phase == MobileRadioPhase::Attached)
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(radio_filters(&staged), Some(4));
}

#[tokio::test]
async fn a_manual_path_is_held_kept_and_cleared() {
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    let position = MobilePositionRecord {
        latitude_degrees: 38.9,
        longitude_degrees: -120.1,
        accuracy_meters: Some(12.0),
    };
    let direct = MobileMeshExplicitPath {
        hints: Vec::new(),
        flood_hops: 1,
    };
    assert!(
        staged
            .core
            .core
            .set_manual_path(speaker.clone(), direct, 600_000, Some(position))
            .await
            .unwrap()
    );
    let kept = staged
        .core
        .store
        .manual_route(staged.owner.clone(), speaker.clone(), NOW_MS)
        .unwrap()
        .expect("the path is kept");
    assert_eq!(kept.hold_until_ms, NOW_MS + 600_000);
    assert_eq!(kept.saved_accuracy, Some(12.0));
    let route = staged.core.core.peer_route(speaker.clone()).await.unwrap();
    assert_eq!(route.kind, MobileMeshRouteKind::Direct);
    assert!(route.hold_remaining_ms.is_some());
    assert_eq!(
        staged
            .core
            .core
            .learned_path_offer(speaker.clone(), None)
            .await
            .unwrap(),
        MobileAppLearnedPathOffer::None,
        "nothing learned to offer"
    );

    assert!(
        staged
            .core
            .core
            .clear_manual_path(speaker.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        staged
            .core
            .store
            .manual_route(staged.owner.clone(), speaker.clone(), NOW_MS)
            .unwrap(),
        None
    );
    let route = staged.core.core.peer_route(speaker).await.unwrap();
    assert_eq!(route.hold_remaining_ms, None);
}

/// The managed repeater, across the mesh, with its card read.
async fn managed_repeater(staged: &Staged) -> Arc<crate::MobileManagedDevice> {
    let device = staged
        .core
        .core
        .manage_device(address_of(MANAGED_SEED), false)
        .await
        .unwrap();
    assert_eq!(
        device.load_card().await,
        Ok(crate::MobileManagementOutcome::Done)
    );
    device
}

#[tokio::test]
async fn a_canceled_mesh_exchange_ends_at_once() {
    use crate::MobileManagementOutcome;
    use crate::ulcp::UlcpManageCategory;
    let staged = Staged::new().await;
    let device = managed_repeater(&staged).await;

    // Unreachable, so the read would wait out the MAC's retries.
    staged.air.set_remote_device_reachable(false);
    let started = tokio::time::Instant::now();
    let (read, ()) = tokio::join!(
        device.refresh_category(UlcpManageCategory::Identity),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            device.cancel();
        }
    );
    assert_eq!(read, Ok(MobileManagementOutcome::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// Firmware update entry across the mesh: the soft device refuses with
/// `UNIMPLEMENTED`, and an unreachable device never confirms. The
/// statuses the soft device cannot answer are `dfu_outcome`'s own table
/// test.
#[tokio::test]
async fn mesh_dfu_entry_answers_by_the_device_status() {
    use crate::{MobileManagementOutcome, MobileManagementProblem, UlcpDfuMode};
    let staged = Staged::new().await;
    let device = managed_repeater(&staged).await;
    assert_eq!(
        device.enter_dfu(UlcpDfuMode::Default).await,
        Ok(MobileManagementOutcome::Failed {
            problem: MobileManagementProblem::DfuUnsupported
        })
    );

    staged.air.set_remote_device_reachable(false);
    assert_eq!(
        device.enter_dfu(UlcpDfuMode::Ble).await,
        Ok(MobileManagementOutcome::Failed {
            problem: MobileManagementProblem::DfuUnconfirmed
        })
    );
}

/// Bond clearing across the mesh: the managed repeater clears its bonds
/// and echoes the count, and an unreachable device is unreachable. The
/// soft device cannot refuse a zero bond count it supports, so a refusal
/// is `bonds_cleared`'s own table test.
#[tokio::test]
async fn mesh_bond_clearing_answers_by_the_device_echo() {
    use crate::ulcp::UlcpManageCategory;
    use crate::{MobileManagementOutcome, MobileManagementProblem};
    let staged = Staged::new().await;
    let device = managed_repeater(&staged).await;
    assert_eq!(
        device.clear_bluetooth_pairings().await,
        Ok(MobileManagementOutcome::Done)
    );
    // Read again from the device, not from what the write meant.
    assert_eq!(
        device.refresh_category(UlcpManageCategory::Bluetooth).await,
        Ok(MobileManagementOutcome::Done)
    );
    let bluetooth = device
        .snapshot()
        .readings
        .into_iter()
        .find(|reading| reading.category == UlcpManageCategory::Bluetooth)
        .unwrap();
    assert!(bluetooth.is_fresh);
    assert_eq!(
        bluetooth.properties.ble_bond_count,
        Some(0),
        "the bonds are gone"
    );

    staged.air.set_remote_device_reachable(false);
    assert_eq!(
        device.clear_bluetooth_pairings().await,
        Ok(MobileManagementOutcome::Failed {
            problem: MobileManagementProblem::Unreachable
        })
    );
}

/// The managed repeater through the managed-device engine: read, applied
/// and saved, opened again from the cache without asking, scanned by
/// polling, joined to a network, and unreachable.
#[tokio::test]
async fn the_managed_repeater_is_managed_across_the_mesh() {
    use crate::ulcp::{UlcpDevicePropertiesRecord, UlcpManageCategory};
    use crate::{
        MobileApplyOutcome, MobileApplyResult, MobileManagementLink, MobileManagementOutcome,
        MobileManagementProblem, MobileWifiOutcome,
    };

    let staged = Staged::new().await;
    let tallac = address_of(MANAGED_SEED);
    let identity_name = |device: &crate::MobileManagedDevice| {
        device
            .snapshot()
            .readings
            .into_iter()
            .find(|reading| reading.category == UlcpManageCategory::Identity)
            .map(|reading| (reading.properties.device_name, reading.is_fresh))
    };
    let device = staged
        .core
        .core
        .manage_device(tallac.clone(), false)
        .await
        .unwrap();
    assert_eq!(device.snapshot().link, MobileManagementLink::Mesh);
    assert_eq!(device.load_card().await, Ok(MobileManagementOutcome::Done));
    assert!(device.snapshot().card_is_fresh);
    assert_eq!(
        device.refresh_category(UlcpManageCategory::Identity).await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        device
            .apply_properties(
                UlcpManageCategory::Identity,
                UlcpDevicePropertiesRecord {
                    device_name: Some("Ridge Camp".to_owned()),
                    ..UlcpDevicePropertiesRecord::default()
                },
                vec![prop::DEV_NAME],
                true,
            )
            .await,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Applied
        })
    );
    device.release();

    // Opened again, it comes from the cache and asks nothing.
    let device = staged
        .core
        .core
        .manage_device(tallac.clone(), false)
        .await
        .unwrap();
    assert_eq!(device.load_card().await, Ok(MobileManagementOutcome::Done));
    assert!(device.snapshot().card.is_some());
    assert!(!device.snapshot().card_is_fresh, "the card is the cache's");
    device
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(
        identity_name(&device),
        Some((Some("Ridge Camp".to_owned()), false))
    );

    // A scan is followed by reading its flag; the core's clock paces it.
    // The station scans only while it is on.
    device
        .refresh_category(UlcpManageCategory::Wifi)
        .await
        .unwrap();
    assert_eq!(
        device
            .apply_properties(
                UlcpManageCategory::Wifi,
                UlcpDevicePropertiesRecord {
                    wifi_enabled: Some(true),
                    ..UlcpDevicePropertiesRecord::default()
                },
                vec![prop::WIFI_ENABLED],
                false,
            )
            .await
            .map(|outcome| outcome.result),
        Ok(MobileApplyResult::Applied)
    );
    let scan = device.scan_networks();
    tokio::pin!(scan);
    let scanned = loop {
        tokio::select! {
            scanned = &mut scan => break scanned,
            () = tokio::time::sleep(Duration::from_millis(50)) => staged.core.clock.advance(2_000),
        }
    };
    assert_eq!(scanned, Ok(MobileManagementOutcome::Done));
    let heard = device.snapshot().heard_networks;
    assert!(
        heard
            .iter()
            .any(|heard| heard.result.ssid == b"Field Office"),
        "the table the flag's end delivered: {heard:?}"
    );
    let offered = heard
        .iter()
        .find(|heard| heard.result.ssid == b"Field Office")
        .map(|heard| heard.result.modes);
    assert_eq!(
        device
            .join_network(
                b"Field Office".to_vec(),
                2,
                false,
                b"fieldwork".to_vec(),
                offered
            )
            .await,
        Ok(MobileWifiOutcome::Done)
    );
    let wifi = device
        .snapshot()
        .readings
        .into_iter()
        .find(|reading| reading.category == UlcpManageCategory::Wifi)
        .unwrap();
    assert_eq!(wifi.properties.wifi_enabled, Some(true));
    assert!(
        wifi.properties
            .wifi_networks
            .unwrap_or_default()
            .iter()
            .any(|network| network.ssid == b"Field Office")
    );

    staged.air.set_remote_device_reachable(false);
    assert_eq!(
        device.refresh_category(UlcpManageCategory::Identity).await,
        Ok(MobileManagementOutcome::Failed {
            problem: MobileManagementProblem::Unreachable
        })
    );
    assert_eq!(
        device.snapshot().problem,
        Some(MobileManagementProblem::Unreachable)
    );
}

/// The staged named channel's ID and conversation address.
fn trail_crew(staged: &Staged) -> (String, String) {
    let key = crate::inspect_channel_name("Trail Crew".to_owned())
        .unwrap()
        .key;
    let id = staged
        .core
        .store
        .channel(staged.owner.clone(), crate::channel_key_digest(key.clone()))
        .unwrap()
        .expect("staging joins Trail Crew")
        .id;
    (id, crate::channel_conversation_address(key).unwrap())
}

#[tokio::test]
async fn a_left_channel_is_no_longer_heard_and_keeps_no_row() {
    let staged = Staged::new().await;
    let (id, address) = trail_crew(&staged);
    let owner = staged.owner.clone();
    staged.core.core.leave_channel(id.clone()).await.unwrap();
    assert_eq!(staged.core.store.channel_by_id(&owner, &id).unwrap(), None);
    assert!(!staged.core.vault.accounts().contains(&id));
    assert_eq!(
        staged
            .core
            .store
            .chat_message_count(owner.clone(), address.clone())
            .unwrap(),
        0
    );
    staged.reset();
    staged
        .air
        .peer_says("Anyone on the ridge?".to_owned(), true)
        .await
        .unwrap();
    // A direct message after it, so the channel's had its chance.
    let speaker = staged_speaker_address();
    staged
        .air
        .peer_says("Still there?".to_owned(), false)
        .await
        .unwrap();
    staged
        .until("the direct message", |changes| {
            changes.transcripts.contains(&speaker)
        })
        .await;
    assert!(!staged.seen.borrow().transcripts.contains(&address));
    assert_eq!(
        staged
            .core
            .store
            .chat_message_count(owner, address)
            .unwrap(),
        0
    );
}

/// Wait until a staged node's identity, heard after the clock moved, is
/// stored.
async fn identity_heard(staged: &Staged, what: &str, address: Option<&str>) {
    let store = staged.core.store.clone();
    let owner = staged.owner.clone();
    let since = super::Clock::now_ms(&*staged.core.clock);
    staged
        .core
        .until(what, |_| {
            store.list_nodes(owner.clone()).unwrap().iter().any(|node| {
                address.is_none_or(|address| node.public_address == address)
                    && node.advertisement_received_at_ms == Some(since)
            })
        })
        .await;
}

#[tokio::test]
async fn a_staged_node_answers_identify_and_discover() {
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();

    staged.core.clock.advance(1_000);
    staged
        .core
        .core
        .fetch_identity(speaker.clone())
        .await
        .unwrap();
    identity_heard(&staged, "the speaker's identity", Some(&speaker)).await;

    staged.core.clock.advance(1_000);
    staged
        .core
        .core
        .discover(None, None, Vec::new())
        .await
        .unwrap();
    identity_heard(&staged, "a nearby identity", None).await;
}

#[tokio::test]
async fn a_channel_member_answers_by_its_hint() {
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    staged.core.clock.advance(1_000);
    let (_, address) = trail_crew(&staged);
    let hint = crate::inspect_public_identity(speaker.clone())
        .unwrap()
        .hint
        .bytes;
    staged
        .core
        .core
        .request_member_identity(address, hint)
        .await
        .unwrap();
    identity_heard(&staged, "the member's identity", Some(&speaker)).await;
}

// --- Chat over the air. ---

/// The stored messages of the phone's conversation at `address`.
fn stored_messages(staged: &Staged, address: &str) -> Vec<crate::MobileStoredChatMessageRecord> {
    staged
        .core
        .store
        .chat_message_page_newest(staged.owner.clone(), address.to_owned(), 50)
        .unwrap()
        .messages
}

/// Wait, in real time, until the phone's conversation at `address` holds
/// a message `found` picks.
async fn until_stored(
    staged: &Staged,
    address: &str,
    what: &str,
    mut found: impl FnMut(&crate::MobileStoredChatMessageRecord) -> bool,
) -> crate::MobileStoredChatMessageRecord {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(message) = stored_messages(staged, address)
            .into_iter()
            .find(&mut found)
        {
            return message;
        }
        assert!(tokio::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_phone_message_reaches_a_peer_and_its_answers_name_each_other() {
    use super::{MobileAppChatRequest, MobileReaction};
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    staged
        .core
        .core
        .send_chat(
            speaker.clone(),
            MobileAppChatRequest::Typed {
                text: "On my way".into(),
                forward_secret: None,
            },
            Some("On my way".into()),
        )
        .await
        .unwrap();
    staged.reset();
    // The peer reacts to what it heard, which it can only name once it has
    // it: the notification says which emote.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while staged.air.peer_reacts("+1".to_owned()).await
        == Err(MobileStagingAirError::NothingToAnswer)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer never heard it"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    staged
        .until("the reaction's notification", |changes| {
            changes.notifications.iter().any(|event| {
                matches!(event, MobileNotificationEventRecord::Message {
                    reaction: Some(reaction), ..
                } if reaction.reaction == Some(MobileReaction::ThumbsUp))
            })
        })
        .await;
    staged
        .air
        .peer_replies("See you there".to_owned())
        .await
        .unwrap();
    let theirs = until_stored(&staged, &speaker, "the peer's reply", |message| {
        !message.outbound && message.body == "See you there"
    })
    .await;
    // The phone answers that message by its stored reference.
    for request in [
        MobileAppChatRequest::Reply {
            target: theirs.reference.clone(),
            text: "Great".into(),
            forward_secret: None,
        },
        MobileAppChatRequest::React {
            message: theirs.reference.clone(),
            reaction: Some(MobileReaction::Heart),
        },
    ] {
        staged
            .core
            .core
            .send_chat(speaker.clone(), request, None)
            .await
            .unwrap();
    }
    let reply = until_stored(&staged, &speaker, "the phone's reply", |message| {
        message.outbound && message.body == "Great"
    })
    .await;
    assert!(reply.is_reply);
    let page = staged
        .core
        .core
        .transcript_newest(speaker.clone(), 50)
        .unwrap();
    let answered = page
        .messages
        .iter()
        .find(|message| message.stored.reference == theirs.reference)
        .unwrap();
    assert_eq!(answered.reactions, [Some(MobileReaction::Heart)]);
    assert!(answered.stored.reactions[0].outbound);
}

#[tokio::test]
async fn a_failed_message_resent_in_place_is_moved_before_the_answer() {
    use super::{MobileAppChatRequest, MobileAppResent};
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    staged.air.set_transmissions_failing(true);
    staged
        .core
        .core
        .send_chat(
            speaker.clone(),
            MobileAppChatRequest::Typed {
                text: "Anyone there?".into(),
                forward_secret: Some(false),
            },
            None,
        )
        .await
        .unwrap();
    let failed = until_stored(&staged, &speaker, "the message failing", |message| {
        message.outbound
            && matches!(
                message.delivery_state,
                Some(
                    crate::MobileStoredChatDeliveryState::Failed
                        | crate::MobileStoredChatDeliveryState::Undelivered
                )
            )
    })
    .await;
    staged.air.set_transmissions_failing(false);
    assert_eq!(
        staged
            .core
            .core
            .resend(speaker.clone(), failed.reference.clone(), false)
            .await,
        Ok(MobileAppResent::InPlace)
    );
    // Read at once: the row already follows the frames that went again.
    let resent = staged
        .core
        .store
        .chat_message(&staged.owner, &speaker, &failed.reference)
        .unwrap()
        .unwrap();
    assert!(!matches!(
        resent.delivery_state,
        Some(
            crate::MobileStoredChatDeliveryState::Failed
                | crate::MobileStoredChatDeliveryState::Undelivered
        )
    ));
    until_stored(&staged, &speaker, "the resend acknowledged", |message| {
        message.reference == failed.reference
            && message.delivery_state == Some(crate::MobileStoredChatDeliveryState::Acknowledged)
    })
    .await;
}

const HOUR_MS: i64 = 60 * 60 * 1000;

/// `EMERGENCY`'s conversation on the staged phone, opened, and agreed to.
fn emergency(staged: &Staged) -> String {
    let id = staged
        .core
        .store
        .channels(staged.owner.clone())
        .unwrap()
        .into_iter()
        .find(|channel| channel.canonical_name.as_deref() == Some("emergency"))
        .unwrap()
        .id;
    let key = crate::inspect_channel_name("emergency".to_owned())
        .unwrap()
        .key;
    let address = crate::channel_conversation_address(key).unwrap();
    staged
        .core
        .store
        .ensure_channel_conversation(staged.owner.clone(), id, address.clone(), NOW_MS)
        .unwrap();
    staged.core.core.certify_emergency().unwrap();
    address
}

/// A message on `EMERGENCY` resent in place keeps it another day, as a send does.
#[tokio::test]
async fn a_resend_in_place_on_emergency_keeps_it_another_day() {
    use super::{MobileAppChatRequest, MobileAppResent};
    let staged = Staged::new().await;
    let emergency = emergency(&staged);
    staged.core.clock.advance(23 * HOUR_MS);
    staged.air.set_transmissions_failing(true);
    staged
        .core
        .core
        .send_chat(
            emergency.clone(),
            MobileAppChatRequest::Typed {
                text: "TEST: radio check".into(),
                forward_secret: None,
            },
            None,
        )
        .await
        .unwrap();
    let failed = until_stored(&staged, &emergency, "the message failing", |message| {
        message.outbound
            && matches!(
                message.delivery_state,
                Some(
                    crate::MobileStoredChatDeliveryState::Failed
                        | crate::MobileStoredChatDeliveryState::Undelivered
                )
            )
    })
    .await;
    staged.air.set_transmissions_failing(false);
    // Inside the revise window, so it goes in place.
    staged.core.clock.advance(3 * HOUR_MS);
    assert_eq!(
        staged
            .core
            .core
            .resend(emergency.clone(), failed.reference, false)
            .await,
        Ok(MobileAppResent::InPlace)
    );
    // A day after the send, but not after the resend.
    staged.core.clock.advance(22 * HOUR_MS);
    assert!(staged.core.core.status().unwrap().emergency_certified);
}

/// Asking for a message missed on `EMERGENCY` keeps it another day: the request goes out there.
#[tokio::test]
async fn a_repair_asked_on_emergency_keeps_it_another_day() {
    let staged = Staged::new().await;
    let emergency = emergency(&staged);
    staged.core.clock.advance(23 * HOUR_MS);
    staged
        .air
        .peer_says_losing_one_on(
            emergency.clone(),
            "First".to_owned(),
            "Lost".to_owned(),
            "Last".to_owned(),
        )
        .await
        .unwrap();
    let gap = until_stored(&staged, &emergency, "the gap", |message| {
        message.presence == crate::mobile_chat::MobileChatPresence::GapIdle
    })
    .await;
    staged
        .core
        .core
        .request_missing(emergency.clone(), vec![gap.reference])
        .await
        .unwrap();
    staged.core.clock.advance(2 * HOUR_MS);
    assert!(staged.core.core.status().unwrap().emergency_certified);
    until_stored(&staged, &emergency, "the lost message", |message| {
        message.body == "Lost"
    })
    .await;
}

#[tokio::test]
async fn a_lost_channel_message_is_asked_for_and_arrives() {
    let staged = Staged::new().await;
    staged.reset();
    staged
        .air
        .peer_says_losing_one("First".to_owned(), "Lost".to_owned(), "Last".to_owned())
        .await
        .unwrap();
    staged
        .until("the channel's transcript", |changes| {
            changes
                .transcripts
                .iter()
                .any(|address| address.starts_with("ch:"))
        })
        .await;
    let channel = staged
        .seen
        .borrow()
        .transcripts
        .iter()
        .find(|address| address.starts_with("ch:"))
        .unwrap()
        .clone();
    let gap = until_stored(&staged, &channel, "the gap", |message| {
        message.presence == crate::mobile_chat::MobileChatPresence::GapIdle
    })
    .await;
    staged
        .core
        .core
        .request_missing(channel.clone(), vec![gap.reference])
        .await
        .unwrap();
    until_stored(&staged, &channel, "the lost message", |message| {
        message.body == "Lost"
    })
    .await;
}

#[tokio::test]
async fn the_phone_s_first_message_continues_the_staged_stream() {
    use super::MobileAppChatRequest;
    let staged = Staged::new().await;
    let speaker = staged_speaker_address();
    staged
        .core
        .core
        .send_chat(
            speaker.clone(),
            MobileAppChatRequest::Typed {
                text: "Back at the trailhead".into(),
                forward_secret: None,
            },
            None,
        )
        .await
        .unwrap();
    let sent = until_stored(&staged, &speaker, "the message", |message| {
        message.outbound && message.body == "Back at the trailhead"
    })
    .await;
    // The staged messages of ours end at 255; no Sequence Reset between.
    assert_eq!((sent.wire_id, sent.epoch), (Some(0), Some(0)));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while staged.air.peer_reacts("+1".to_owned()).await
        == Err(MobileStagingAirError::NothingToAnswer)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer never heard it"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn staged_messages_are_answered_edited_and_taken_back() {
    use super::{MobileAppChatRequest, MobileReaction};
    let staged = Staged::new().await;
    let core = &staged.core.core;
    let speaker = staged_speaker_address();
    let trail_crew = core
        .state(true)
        .unwrap()
        .channel_conversations
        .into_iter()
        .find(|conversation| conversation.channel.name.as_deref() == Some("Trail Crew"))
        .unwrap()
        .conversation_address;
    let direct = stored_messages(&staged, &speaker);
    let newest = |outbound: bool| {
        direct
            .iter()
            .rev()
            .find(|message| message.outbound == outbound && !message.is_deleted)
            .unwrap()
            .reference
            .clone()
    };
    let (theirs, ours) = (newest(false), newest(true));
    let older_ours = direct
        .iter()
        .rev()
        .filter(|message| message.outbound && !message.is_deleted)
        .nth(1)
        .unwrap()
        .reference
        .clone();
    let member = stored_messages(&staged, &trail_crew)
        .into_iter()
        .rev()
        .find(|message| !message.outbound && message.sender_hint.is_some())
        .unwrap()
        .reference;

    // A reaction to theirs, ours and a member's, each under its row.
    for (address, message, reaction) in [
        (&speaker, &theirs, MobileReaction::ThumbsUp),
        (&speaker, &ours, MobileReaction::Heart),
        (&trail_crew, &member, MobileReaction::Heart),
    ] {
        core.send_chat(
            address.clone(),
            MobileAppChatRequest::React {
                message: message.clone(),
                reaction: Some(reaction.clone()),
            },
            None,
        )
        .await
        .unwrap();
        let page = core.transcript_newest(address.clone(), 100).unwrap();
        let row = page
            .messages
            .iter()
            .find(|row| &row.stored.reference == message)
            .unwrap();
        let mine: Vec<_> = row
            .stored
            .reactions
            .iter()
            .filter(|stored| stored.outbound)
            .map(|stored| crate::app_core::chat::reaction_from_body(&stored.body))
            .collect();
        assert_eq!(mine, [Some(reaction)], "{message:?}");
    }

    // A reply quotes what it answers.
    core.send_chat(
        speaker.clone(),
        MobileAppChatRequest::Reply {
            target: theirs.clone(),
            text: "Copy that".into(),
            forward_secret: None,
        },
        None,
    )
    .await
    .unwrap();
    let reply = until_stored(&staged, &speaker, "the reply", |message| {
        message.outbound && message.body == "Copy that"
    })
    .await;
    assert!(reply.is_reply);
    assert_eq!(
        reply
            .quote
            .and_then(|quote| quote.original)
            .map(|original| original.reference),
        Some(theirs)
    );

    // Ours are edited and taken back.
    core.send_chat(
        speaker.clone(),
        MobileAppChatRequest::Edit {
            message: ours.clone(),
            text: "Agreed. Flag both approaches.".into(),
        },
        None,
    )
    .await
    .unwrap();
    until_stored(&staged, &speaker, "the edit", |message| {
        message.reference == ours && message.is_edited
    })
    .await;
    core.send_chat(
        speaker.clone(),
        MobileAppChatRequest::Delete {
            message: older_ours.clone(),
        },
        None,
    )
    .await
    .unwrap();
    until_stored(&staged, &speaker, "the deletion", |message| {
        message.reference == older_ours && message.is_deleted
    })
    .await;
}
