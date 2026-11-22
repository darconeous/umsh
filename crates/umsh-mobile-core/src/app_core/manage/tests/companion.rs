//! The companion link against a soft device behind a real radio driver.

use std::sync::Arc;

use umsh_ulcp::ids::prop;

use super::{OWNER_SEED, reading, until};
use crate::app_core::MobileAppError;
use crate::app_core::manage::records::{
    MobileApplyOutcome, MobileApplyResult, MobileManagementLink, MobileManagementOutcome,
    MobileManagementProblem as Problem,
};
use crate::app_core::test_support::Core;
use crate::radio_driver::{MobileRadioDriver, MobileRadioPhase};
use crate::test_support::{DeviceLink, attached_driver, linked_driver};
use crate::ulcp::{UlcpDevicePropertiesRecord, UlcpDfuMode, UlcpManageCategory};

/// The radio's own address, from the key it reports.
fn radio_address(driver: &MobileRadioDriver) -> String {
    crate::inspect_public_identity_bytes(driver.state().device_key.expect("a device identity"))
        .unwrap()
        .canonical_address
}

/// A running core carrying the soft device as this phone's radio.
async fn attached() -> (Core, Arc<DeviceLink>, Arc<MobileRadioDriver>) {
    let core = Core::new();
    let (link, driver) = linked_driver();
    core.core.use_radio(Some(driver.clone())).await.unwrap();
    core.start(OWNER_SEED).await;
    core.until("the core saw the attach", |core| {
        core.status()
            .unwrap()
            .radio
            .is_some_and(|radio| radio.phase == MobileRadioPhase::Attached)
    })
    .await;
    (core, link, driver)
}

#[tokio::test]
async fn the_attached_radio_is_managed_over_its_own_link() {
    let (core, link, driver) = attached().await;
    let address = radio_address(&driver);
    // The radio is a peer of the owner's, so its cache is kept.
    core.store
        .upsert_peer(
            super::address_of(OWNER_SEED),
            address.clone(),
            crate::store::MobilePeerUpsertRecord {
                is_saved: true,
                ..crate::store::MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
    let device = core.core.manage_radio(false).await.unwrap();
    // The radio's address manages the same device.
    let same = core
        .core
        .manage_device(address.clone(), false)
        .await
        .unwrap();
    assert_eq!(same.id(), device.id());
    assert_eq!(same.snapshot().link, MobileManagementLink::Companion);

    assert_eq!(device.load_card().await, Ok(MobileManagementOutcome::Done));
    let snapshot = device.snapshot();
    assert_eq!(snapshot.address.as_deref(), Some(address.as_str()));
    assert!(snapshot.card_is_fresh);
    assert!(snapshot.phone_node_key.is_some());
    assert_eq!(
        device.load_category(UlcpManageCategory::Identity).await,
        Ok(MobileManagementOutcome::Done)
    );
    assert!(
        reading(&device.snapshot(), UlcpManageCategory::Identity)
            .is_some_and(|reading| reading.is_fresh && reading.properties.device_name.is_some())
    );

    let applied = device
        .apply_properties(
            UlcpManageCategory::Identity,
            UlcpDevicePropertiesRecord {
                device_name: Some("Ridge Camp".to_owned()),
                ..UlcpDevicePropertiesRecord::default()
            },
            vec![prop::DEV_NAME],
            true,
        )
        .await;
    assert_eq!(
        applied,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Applied
        })
    );
    assert_eq!(
        reading(&device.snapshot(), UlcpManageCategory::Identity)
            .and_then(|reading| reading.properties.device_name.clone())
            .as_deref(),
        Some("Ridge Camp")
    );
    let owner = super::address_of(OWNER_SEED);
    assert!(
        core.store
            .management_card(owner.clone(), address.clone())
            .unwrap()
            .is_some()
    );
    assert!(
        core.store
            .cached_properties(owner, address, vec![prop::DEV_NAME])
            .unwrap()
            .contains_key(&prop::DEV_NAME)
    );

    // A push from the radio reaches the reading that holds it.
    device
        .load_category(UlcpManageCategory::Bluetooth)
        .await
        .unwrap();
    let enabled = || {
        reading(&device.snapshot(), UlcpManageCategory::Bluetooth)
            .and_then(|reading| reading.properties.ble_enabled)
    };
    let before = enabled();
    assert!(before.is_some());
    link.device.lock().unwrap().toggle_ble();
    link.deliver();
    until("the pushed value arrived", || enabled() != before).await;

    // The soft device has no bootloader to enter.
    assert_eq!(
        device.enter_dfu(UlcpDfuMode::Default).await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::DfuUnsupported
        })
    );
    assert!(!device.snapshot().entered_dfu);
}

#[tokio::test]
async fn a_radio_switch_never_sends_one_radios_edits_to_another() {
    let (core, _link, _driver) = attached().await;
    let device = core.core.manage_radio(false).await.unwrap();
    device.load_card().await.unwrap();
    let (_other_link, other) = linked_driver();
    core.core.use_radio(Some(other)).await.unwrap();
    assert_eq!(
        device.refresh_card().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoRadio
        })
    );
}

#[tokio::test]
async fn the_radios_own_address_needs_no_owner() {
    let core = Core::new();
    let (_link, driver) = attached_driver(&[9; 32]);
    core.core.use_radio(Some(driver.clone())).await.unwrap();
    let address = radio_address(&driver);
    let device = core.core.manage_device(address, true).await.unwrap();
    let snapshot = device.snapshot();
    assert_eq!(snapshot.link, MobileManagementLink::Companion);
    assert!(snapshot.uses_bluetooth);
    assert_eq!(device.load_card().await, Ok(MobileManagementOutcome::Done));
    assert_eq!(
        device.snapshot().address,
        None,
        "storeless without an owner"
    );
    assert_eq!(
        core.core
            .manage_device(super::address_of(0x22), false)
            .await
            .err(),
        Some(MobileAppError::NoOwner)
    );
    assert_eq!(
        core.core
            .manage_device("not an address".to_owned(), false)
            .await
            .err()
            .map(|error| matches!(error, MobileAppError::InvalidInput { .. })),
        Some(true)
    );
}

#[tokio::test]
async fn an_owner_set_later_is_this_phone() {
    let core = Core::new();
    let (_link, driver) = linked_driver();
    core.core.use_radio(Some(driver)).await.unwrap();
    let device = core.core.manage_radio(false).await.unwrap();
    let _ = device.load_card().await;
    assert_eq!(device.snapshot().phone_node_key, None, "no owner yet");
    core.start(OWNER_SEED).await;
    // The storeless device serves the new owner too, and learns its key.
    let same = core.core.manage_radio(false).await.unwrap();
    assert_eq!(same.id(), device.id());
    let _ = device.load_card().await;
    assert_eq!(
        device.snapshot().phone_node_key,
        Some(crate::public_identity_bytes(super::address_of(OWNER_SEED)).unwrap())
    );
}

#[tokio::test]
async fn a_retired_device_keeps_nothing_the_radio_pushes() {
    let (core, link, driver) = attached().await;
    let address = radio_address(&driver);
    let owner = super::address_of(OWNER_SEED);
    core.store
        .upsert_peer(
            owner.clone(),
            address.clone(),
            crate::store::MobilePeerUpsertRecord {
                is_saved: true,
                ..crate::store::MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
    let device = core.core.manage_radio(false).await.unwrap();
    device.load_card().await.unwrap();
    device
        .load_category(UlcpManageCategory::Bluetooth)
        .await
        .unwrap();
    // The content stays, so a value the retired device kept would land.
    core.core.erase(false).await.unwrap();
    let cached = || {
        core.store
            .cached_properties(owner.clone(), address.clone(), vec![prop::BLE_ENABLED])
            .unwrap()
    };
    let kept = cached();
    let held = || {
        reading(&device.snapshot(), UlcpManageCategory::Bluetooth)
            .and_then(|reading| reading.properties.ble_enabled)
    };
    let held_before = held();
    // A device opened after the erase sees the push, so the retired one,
    // still held open, was handed it too.
    let after = core.core.manage_radio(false).await.unwrap();
    assert_ne!(after.id(), device.id());
    after.load_card().await.unwrap();
    after
        .load_category(UlcpManageCategory::Bluetooth)
        .await
        .unwrap();
    let enabled = || {
        reading(&after.snapshot(), UlcpManageCategory::Bluetooth)
            .and_then(|reading| reading.properties.ble_enabled)
    };
    let before = enabled();
    assert!(before.is_some());
    link.device.lock().unwrap().toggle_ble();
    link.deliver();
    until("the pushed value arrived", || enabled() != before).await;
    assert_eq!(cached(), kept, "nothing cached under the erased owner");
    assert_eq!(held(), held_before, "the retired device took nothing");
}

#[tokio::test]
async fn with_no_radio_there_is_nothing_to_manage() {
    let core = Core::new();
    assert_eq!(
        core.core.manage_radio(false).await.err(),
        Some(MobileAppError::NoRadio)
    );
}
