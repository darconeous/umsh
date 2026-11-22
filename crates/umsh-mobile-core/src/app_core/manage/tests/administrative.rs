//! The administrative link against a soft device behind a real
//! administrative driver, which native code owns and drains.

use std::sync::Arc;
use std::time::Duration;

use umsh_ulcp::ids::prop;

use super::{OWNER_SEED, reading, until};
use crate::app_core::MobileAppError;
use crate::app_core::manage::MobileManagedDevice;
use crate::app_core::manage::records::{
    MobileApplyOutcome, MobileApplyResult, MobileKeyTable, MobileManagementLink,
    MobileManagementOutcome, MobileManagementProblem as Problem,
};
use crate::app_core::manage::setup::{
    MobileSetupGoal, MobileSetupProfile, MobileSetupRadioParameter, MobileSetupRefusal,
    MobileSetupResult, setup_set_radio_parameter,
};
use crate::app_core::test_support::{Core, NOW_MS};
use crate::radio_driver::{MobileRadioDriver, MobileRadioPhase};
use crate::test_support::{
    DeviceLink, administrative_linked_driver, administrative_whole_driver, linked_driver,
};
use crate::ulcp::{UlcpDevicePropertiesRecord, UlcpDfuMode, UlcpManageCategory};
use umsh_ulcp_simdev::soft::SoftPlatform;
use umsh_ulcp_simdev::{DutyLedger, full_config};

/// This phone's key on the administered device, as the setup flow knows it.
const PHONE_KEY: [u8; 32] = [0x5a; 32];

/// Hand the device what its driver pushed since the last drain, as native
/// code does, once there is something.
async fn forward_pushes(driver: &MobileRadioDriver, device: &MobileManagedDevice) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let update = driver.poll_update();
        if !update.pushed_properties.is_empty() {
            device.receive_pushes(update.pushed_properties, update.pushed_properties_dropped);
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "nothing pushed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn ble_enabled(device: &MobileManagedDevice) -> Option<bool> {
    reading(&device.snapshot(), UlcpManageCategory::Bluetooth)
        .and_then(|reading| reading.properties.ble_enabled)
}

#[tokio::test]
async fn an_administered_device_is_read_applied_and_edited() {
    let core = Core::new();
    let (link, driver) = administrative_linked_driver();
    let device = core
        .core
        .manage_administered(driver.clone(), Some(PHONE_KEY.to_vec()), true)
        .await
        .unwrap();
    let same = core
        .core
        .manage_administered(driver.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(same.id(), device.id(), "one device per driver");
    let snapshot = device.snapshot();
    assert_eq!(snapshot.link, MobileManagementLink::Administrative);
    assert!(snapshot.uses_bluetooth);

    assert_eq!(device.load_card().await, Ok(MobileManagementOutcome::Done));
    let snapshot = device.snapshot();
    assert_eq!(snapshot.address, None, "storeless");
    assert!(snapshot.card_is_fresh);
    assert_eq!(snapshot.phone_node_key, Some(PHONE_KEY.to_vec()));
    assert_eq!(
        device.load_category(UlcpManageCategory::Identity).await,
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
    assert_eq!(
        link.device.lock().unwrap().session().device_name(),
        "Ridge Camp"
    );

    // A table edit, kept by the session's own save.
    device
        .load_category(UlcpManageCategory::PeerNodes)
        .await
        .unwrap();
    assert_eq!(
        device
            .set_keys(MobileKeyTable::Peers, vec![vec![0xc1; 32]])
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        link.device
            .lock()
            .unwrap()
            .session()
            .dev_peers()
            .collect::<Vec<_>>(),
        vec![[0xc1; 32]]
    );

    // What the driver pushes reaches the device once native code hands it
    // over.
    device
        .load_category(UlcpManageCategory::Bluetooth)
        .await
        .unwrap();
    let before = ble_enabled(&device);
    assert!(before.is_some());
    driver.poll_update();
    link.device.lock().unwrap().toggle_ble();
    link.deliver();
    forward_pushes(&driver, &device).await;
    until("the pushed value arrived", || {
        ble_enabled(&device) != before
    })
    .await;

    // A drain that lost pushes reads every category held again.
    core.clock.advance(60_000);
    let now = crate::app_core::clock::Clock::now_ms(&*core.clock);
    device.receive_pushes(Vec::new(), 1);
    until("every held category read again", || {
        device
            .snapshot()
            .readings
            .iter()
            .all(|reading| reading.as_of_ms == Some(now))
    })
    .await;

    // The soft device has no bootloader: nothing entered, the queue still
    // runs.
    assert_eq!(
        device.enter_dfu(UlcpDfuMode::Default).await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::DfuUnsupported
        })
    );
    assert!(!device.snapshot().entered_dfu);
    assert_eq!(
        device.refresh_card().await,
        Ok(MobileManagementOutcome::Done)
    );
    driver.stop();
}

/// The core's radio and an administered device, each loaded with its
/// Bluetooth reading.
async fn both() -> (
    Core,
    (Arc<DeviceLink>, Arc<MobileManagedDevice>),
    Arc<MobileManagedDevice>,
) {
    let core = Core::new();
    let (link, driver) = linked_driver();
    core.core.use_radio(Some(driver)).await.unwrap();
    core.start(OWNER_SEED).await;
    core.until("the core saw the attach", |core| {
        core.status()
            .unwrap()
            .radio
            .is_some_and(|radio| radio.phase == MobileRadioPhase::Attached)
    })
    .await;
    let companion = core.core.manage_radio(false).await.unwrap();
    let (_admin_link, admin_driver) = administrative_linked_driver();
    let administered = core
        .core
        .manage_administered(admin_driver, None, true)
        .await
        .unwrap();
    for device in [&companion, &administered] {
        device.load_card().await.unwrap();
        device
            .load_category(UlcpManageCategory::Bluetooth)
            .await
            .unwrap();
    }
    (core, (link, companion), administered)
}

#[tokio::test]
async fn the_radios_pushes_reach_only_devices_bound_to_it() {
    let (_core, (link, companion), administered) = both().await;
    let companion_before = ble_enabled(&companion);
    let administered_before = administered.snapshot();
    link.device.lock().unwrap().toggle_ble();
    link.deliver();
    until("the radio's push arrived", || {
        ble_enabled(&companion) != companion_before
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(administered.snapshot(), administered_before);
}

/// The phone's zone as setup is handed it.
const ZONE: &str = "PST8PDT,M3.2.0,M11.1.0";

/// A core attached to a radio of its own, as the phone's.
async fn with_radio() -> (Core, Arc<DeviceLink>) {
    let core = Core::new();
    let (link, driver) = linked_driver();
    core.core.use_radio(Some(driver)).await.unwrap();
    core.start(OWNER_SEED).await;
    core.until("the core's radio attached", |core| {
        core.status()
            .unwrap()
            .radio
            .is_some_and(|radio| radio.phase == MobileRadioPhase::Attached)
    })
    .await;
    (core, link)
}

/// A soft device's whole configuration, with or without forwarding.
fn soft_config(forwards: bool) -> umsh_ulcp_device::SessionConfig {
    let mut config = full_config(Box::leak(Box::new(DutyLedger::new())), None);
    config.mac_node = forwards;
    config
}

#[tokio::test]
async fn a_tracker_is_set_up_on_a_soft_device() {
    let (core, _radio) = with_radio().await;
    let companion = core.core.setup_companion().await.unwrap().unwrap();
    assert_eq!(
        companion.frequency_khz, 910_525,
        "the core's radio, as it reports"
    );
    let (link, driver) = administrative_whole_driver(soft_config(false));
    let setup = core
        .core
        .set_up_device(
            driver.clone(),
            MobileSetupGoal::Tracker,
            Some(companion),
            Some(PHONE_KEY.to_vec()),
            true,
            ZONE.to_owned(),
        )
        .await
        .unwrap();
    let snapshot = setup.snapshot();
    assert_eq!(snapshot.refusal, None);
    assert!(matches!(
        snapshot.profile,
        Some(MobileSetupProfile::Copied { .. })
    ));
    let mut draft = setup.draft().unwrap();
    draft.name.text = "Pika".to_owned();
    let outcome = setup.apply(draft).await.unwrap();
    assert_eq!(
        outcome.result,
        MobileSetupResult::Configured {
            clock_failed: false
        }
    );
    {
        let mut device = link.device.lock().unwrap();
        let session = device.session();
        assert_eq!(session.device_name(), "Pika");
        assert_eq!(session.ident_role(), Some(3));
        assert!(session.ident_mobile());
        assert!(session.settings().enabled);
        assert_eq!(
            device.platform_mut().wall_clock(),
            Some(u32::try_from(NOW_MS / 1000).unwrap())
        );
    }
    let snapshot = setup.snapshot();
    assert_eq!(snapshot.advertised_role, Some(3));
    let reported = snapshot.reported.unwrap();
    assert_eq!(reported.tz_rule.as_deref(), Some(ZONE));
    assert!(reported.advert.is_some());
    assert!(setup.review(setup.draft().unwrap()).unwrap().applied);
    setup.release();
    driver.stop();
}

#[tokio::test]
async fn a_repeater_is_set_up_on_a_soft_device() {
    let core = Core::new();
    let (link, driver) = administrative_whole_driver(soft_config(true));
    let setup = core
        .core
        .set_up_device(
            driver.clone(),
            MobileSetupGoal::Repeater,
            None,
            Some(PHONE_KEY.to_vec()),
            true,
            ZONE.to_owned(),
        )
        .await
        .unwrap();
    let draft = setup.draft().unwrap();
    assert!(
        !setup.review(draft.clone()).unwrap().can_apply,
        "a profile to choose"
    );
    // Keeping the frequency the device holds is a choice too.
    let frequency = draft.radio.frequency_khz.value;
    let draft = setup_set_radio_parameter(draft, MobileSetupRadioParameter::Frequency, frequency);
    let outcome = setup.apply(draft).await.unwrap();
    assert_eq!(
        outcome.result,
        MobileSetupResult::Configured {
            clock_failed: false
        }
    );
    {
        let device = link.device.lock().unwrap();
        let session = device.session();
        assert_eq!(session.repeater_mode(), 1);
        assert_eq!(session.ident_role(), None, "derived from forwarding");
        assert!(!session.ident_mobile());
        assert!(session.dev_admins().any(|admin| admin == PHONE_KEY));
    }
    assert_eq!(setup.snapshot().advertised_role, Some(1));
    assert!(
        outcome
            .draft
            .administrators
            .value
            .contains(&PHONE_KEY.to_vec())
    );
    driver.stop();
}

#[tokio::test]
async fn a_setup_and_management_share_one_engine_and_its_key() {
    let core = Core::new();
    let (_link, driver) = administrative_whole_driver(soft_config(false));
    let device = core
        .core
        .manage_administered(driver.clone(), Some(PHONE_KEY.to_vec()), true)
        .await
        .unwrap();
    let setup = core
        .core
        .set_up_device(
            driver.clone(),
            MobileSetupGoal::Tracker,
            None,
            Some(vec![0x11; 32]),
            true,
            ZONE.to_owned(),
        )
        .await
        .unwrap();
    // The first caller's key stands on the shared engine.
    assert_eq!(setup.snapshot().phone_node_key, Some(PHONE_KEY.to_vec()));
    let draft = setup.set_phone_administers(setup.draft().unwrap(), true);
    let review = setup.review(draft).unwrap();
    assert!(review.phone_administers);
    assert!(
        review
            .administrators
            .iter()
            .any(|entry| entry.is_this_phone && entry.key == PHONE_KEY)
    );
    let registered = core
        .core
        .on_worker(|worker| async move { Ok(worker.managed.borrow().len()) })
        .await
        .unwrap();
    assert_eq!(registered, 1, "one engine");
    device.release();
    setup.release();
    driver.stop();
}

#[tokio::test]
async fn a_lazily_attached_driver_cannot_be_set_up() {
    let core = Core::new();
    let (_link, driver) = administrative_linked_driver();
    assert_eq!(
        core.core
            .set_up_device(
                driver.clone(),
                MobileSetupGoal::Tracker,
                None,
                None,
                true,
                ZONE.to_owned(),
            )
            .await
            .err(),
        Some(MobileAppError::InvalidRequest)
    );
    driver.stop();
}

#[tokio::test]
async fn the_companion_is_none_without_a_radio() {
    let core = Core::new();
    assert_eq!(core.core.setup_companion().await, Ok(None));
}

/// The staged devices beside the phone, as the simulator offers them: the
/// one that forwards takes either goal; the one that does not reports no
/// forwarding policy, so the repeater goal refuses it.
#[tokio::test]
async fn the_staged_devices_take_the_goals_they_can() {
    let core = Core::new();
    let dir = tempfile::tempdir().unwrap();
    let air = crate::MobileStagingAir::start(dir.path().display().to_string(), false).unwrap();
    let cases = [
        (false, MobileSetupGoal::Tracker, None),
        (
            false,
            MobileSetupGoal::Repeater,
            Some(MobileSetupRefusal::CannotForward),
        ),
        (true, MobileSetupGoal::Tracker, None),
        (true, MobileSetupGoal::Repeater, None),
    ];
    for (forwards, goal, refusal) in cases {
        // Listed with the device that forwards first.
        let staged = &air.administered_devices()[usize::from(!forwards)];
        let driver = air
            .administered_device(staged.link_id.clone(), None, false)
            .unwrap();
        driver.attached().await.unwrap();
        let setup = core
            .core
            .set_up_device(
                driver.clone(),
                goal,
                None,
                Some(PHONE_KEY.to_vec()),
                true,
                ZONE.to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(
            setup.snapshot().refusal,
            refusal,
            "{goal:?} on the device that forwards: {forwards}"
        );
        if refusal.is_none() {
            let draft = setup_set_radio_parameter(
                setup.draft().unwrap(),
                MobileSetupRadioParameter::Frequency,
                setup.draft().unwrap().radio.frequency_khz.value,
            );
            let outcome = setup.apply(draft).await.unwrap();
            assert_eq!(
                outcome.result,
                MobileSetupResult::Configured {
                    clock_failed: false
                },
                "{goal:?} on the device that forwards: {forwards}"
            );
        }
        setup.release();
        driver.stop();
    }
}
