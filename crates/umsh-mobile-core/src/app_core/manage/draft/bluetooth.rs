//! Whether the device can be reached over Bluetooth, and its pairing
//! window. The bond count is cleared by its own action, not a draft.

use umsh_ulcp::ids::prop;

use super::{Fold, Source, rebased, toggle};
use crate::app_core::manage::records::{
    MobileApplyWarning, MobileBluetoothDraft, MobileDraftDetails, MobileManagedDeviceRecord,
};

pub(super) fn build(source: &Source<'_>) -> MobileBluetoothDraft {
    let held = source.held();
    MobileBluetoothDraft {
        reading_revision: source.revision(),
        enabled: toggle(prop::BLE_ENABLED, held.ble_enabled),
        pairing: toggle(prop::BLE_PAIRING, held.ble_pairing),
    }
}

pub(super) fn rebase(
    fresh: MobileBluetoothDraft,
    old: &MobileBluetoothDraft,
) -> MobileBluetoothDraft {
    MobileBluetoothDraft {
        reading_revision: fresh.reading_revision,
        enabled: rebased(fresh.enabled, &old.enabled),
        pairing: rebased(fresh.pairing, &old.pairing),
    }
}

pub(super) fn fold(draft: &MobileBluetoothDraft, fold: &mut Fold) {
    fold.toggle(&draft.enabled, |desired, value| {
        desired.ble_enabled = Some(value);
    });
    fold.toggle(&draft.pairing, |desired, value| {
        desired.ble_pairing = Some(value);
    });
}

/// One confirmation at most. Stranding the link outranks the pairing
/// window: a change that does both is confirmed for the harm it can do.
pub(super) fn assess(
    device: &MobileManagedDeviceRecord,
    fold: &Fold,
) -> (Option<MobileApplyWarning>, MobileDraftDetails) {
    let disables = fold.is_dirty(prop::BLE_ENABLED) && fold.desired.ble_enabled == Some(false);
    let opens = fold.is_dirty(prop::BLE_PAIRING) && fold.desired.ble_pairing == Some(true);
    let warning = if device.uses_bluetooth && disables {
        Some(MobileApplyWarning::DisablesBluetooth)
    } else if opens {
        Some(MobileApplyWarning::OpensPairing)
    } else {
        None
    };
    (
        warning,
        MobileDraftDetails::Bluetooth {
            disables_this_link: device.uses_bluetooth,
        },
    )
}
