//! The core over the staging air: a real radio driver on a soft device,
//! and staged peers that talk to the phone. Real time throughout.

use std::sync::Arc;
use std::time::Duration;

use umsh_ulcp::ids::prop;

use super::test_support::{Core, NOW_MS, identity};
use super::{
    MobileAppChangesRecord, MobileAppError, MobileAppLearnedPathOffer, MobileAppPingResult,
    MobileNotificationEventRecord, MobileOperation, MobilePositionRecord,
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

#[tokio::test]
async fn the_managed_repeater_is_read_under_an_operation() {
    let staged = Staged::new().await;
    let tallac = address_of(MANAGED_SEED);
    let operation = MobileOperation::new();
    let answers = staged
        .core
        .core
        .remote_fetch(
            operation.clone(),
            tallac.clone(),
            vec![prop::DEV_KEY, prop::DEV_NAME],
            true,
        )
        .await
        .unwrap();
    let key = answers
        .iter()
        .find(|answer| answer.property_id == prop::DEV_KEY)
        .and_then(|answer| answer.value.clone());
    assert_eq!(
        key,
        Some(crate::public_identity_bytes(tallac.clone()).unwrap())
    );
    assert_eq!(
        staged
            .core
            .core
            .remote_fetch(operation, tallac, vec![prop::DEV_NAME], true)
            .await,
        Err(MobileAppError::OperationReused)
    );
}

#[tokio::test]
async fn a_cancelled_operation_ends_at_once() {
    let staged = Staged::new().await;
    let tallac = address_of(MANAGED_SEED);

    let early = MobileOperation::new();
    early.cancel();
    assert_eq!(
        staged.core.core.remote_save(early, tallac.clone()).await,
        Err(MobileAppError::Cancelled),
        "cancelled before it began, nothing is sent"
    );

    // Unreachable, so the save would wait out the MAC's retries.
    staged.air.set_remote_device_reachable(false);
    let operation = MobileOperation::new();
    let started = tokio::time::Instant::now();
    let (saved, ()) = tokio::join!(
        staged.core.core.remote_save(operation.clone(), tallac),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            operation.cancel();
        }
    );
    assert_eq!(saved, Err(MobileAppError::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(5));
}
