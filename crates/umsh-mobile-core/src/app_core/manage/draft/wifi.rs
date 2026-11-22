//! The Wi-Fi station switch. The network table is edited an item at a
//! time and scanning is a button, so neither is part of a draft.

use umsh_ulcp::ids::prop;

use super::{Fold, Source, rebased, toggle};
use crate::app_core::manage::records::{
    MobileApplyWarning, MobileManagedDeviceRecord, MobileManagementLink, MobileWifiDraft,
};

pub(super) fn build(source: &Source<'_>) -> MobileWifiDraft {
    MobileWifiDraft {
        reading_revision: source.revision(),
        enabled: toggle(prop::WIFI_ENABLED, source.held().wifi_enabled),
    }
}

pub(super) fn rebase(fresh: MobileWifiDraft, old: &MobileWifiDraft) -> MobileWifiDraft {
    MobileWifiDraft {
        reading_revision: fresh.reading_revision,
        enabled: rebased(fresh.enabled, &old.enabled),
    }
}

pub(super) fn fold(draft: &MobileWifiDraft, fold: &mut Fold) {
    fold.toggle(&draft.enabled, |desired, value| {
        desired.wifi_enabled = Some(value);
    });
}

/// Across the mesh, a station switched off may be how the device reaches
/// the mesh at all.
pub(super) fn warning(
    device: &MobileManagedDeviceRecord,
    fold: &Fold,
) -> Option<MobileApplyWarning> {
    (device.link == MobileManagementLink::Mesh
        && fold.is_dirty(prop::WIFI_ENABLED)
        && fold.desired.wifi_enabled == Some(false))
    .then_some(MobileApplyWarning::DisablesWifi)
}
