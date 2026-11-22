//! MeshCore forwarding, which the device keeps under its repeater
//! category with properties of its own.

use umsh_ulcp::ids::prop;

use super::{Fold, Source, choice, list, rebased, toggle, trim_horizontal};
use crate::app_core::manage::records::{
    MobileCategoryReadingRecord, MobileDraftDetails, MobileMeshCoreDraft, MobileRegionEntryProblem,
};
use crate::ulcp::{ulcp_meshcore_identity_allowed, ulcp_meshcore_region_name};

pub(super) fn build(source: &Source<'_>) -> MobileMeshCoreDraft {
    let held = source.held();
    MobileMeshCoreDraft {
        reading_revision: source.revision(),
        enabled: toggle(
            prop::MESHCORE_FORWARDING_ENABLED,
            held.meshcore_forwarding_enabled,
        ),
        policy: choice(prop::MESHCORE_REGION_POLICY, held.meshcore_region_policy),
        regions: list(prop::MESHCORE_REGIONS, held.meshcore_regions.clone()),
    }
}

pub(super) fn rebase(fresh: MobileMeshCoreDraft, old: &MobileMeshCoreDraft) -> MobileMeshCoreDraft {
    MobileMeshCoreDraft {
        reading_revision: fresh.reading_revision,
        enabled: rebased(fresh.enabled, &old.enabled),
        policy: rebased(fresh.policy, &old.policy),
        regions: rebased(fresh.regions, &old.regions),
    }
}

pub(super) fn fold(draft: &MobileMeshCoreDraft, fold: &mut Fold) {
    fold.toggle(&draft.enabled, |desired, value| {
        desired.meshcore_forwarding_enabled = Some(value);
    });
    fold.choice(&draft.policy, |desired, value: u8| {
        desired.meshcore_region_policy = Some(value);
    });
    fold.list(&draft.regions, |desired, regions| {
        desired.meshcore_regions = Some(regions);
    });
}

pub(super) fn details(
    draft: &MobileMeshCoreDraft,
    reading: Option<&MobileCategoryReadingRecord>,
) -> MobileDraftDetails {
    // A key not yet read is no reason to say no: the device decides.
    let identity_allowed = reading
        .and_then(|reading| reading.properties.dev_key.clone())
        .is_none_or(ulcp_meshcore_identity_allowed);
    // Turning forwarding off stays possible whatever the key.
    let on = draft.enabled.known && draft.enabled.reported;
    MobileDraftDetails::MeshCore {
        identity_allowed,
        toggle_locked: !identity_allowed && !on,
    }
}

/// Add a MeshCore region name, kept as typed (case included) less any
/// leading `#`. `Invalid` for a name the device would refuse,
/// `AlreadyListed` for one listed exactly; empty text changes nothing.
#[uniffi::export]
pub fn draft_add_meshcore_region(
    draft: MobileMeshCoreDraft,
    text: String,
) -> Result<MobileMeshCoreDraft, MobileRegionEntryProblem> {
    let text = trim_horizontal(&text);
    if text.is_empty() {
        return Ok(draft);
    }
    let name =
        ulcp_meshcore_region_name(text.to_owned()).ok_or(MobileRegionEntryProblem::Invalid)?;
    if draft.regions.value.contains(&name) {
        return Err(MobileRegionEntryProblem::AlreadyListed);
    }
    let mut draft = draft;
    draft.regions.value.push(name);
    Ok(draft)
}
