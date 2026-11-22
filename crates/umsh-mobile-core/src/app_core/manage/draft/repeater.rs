//! The forwarding policy: the mode, the regions it forwards for, the
//! region it tags untagged floods with, and the thresholds it forwards
//! above.

use umsh_ulcp::ids::prop;

use super::{
    Field, Fold, Source, choice, list, optional_integer, rebased, text_known, trim_horizontal,
};
use crate::app_core::manage::records::{
    MobileDraftDetails, MobileFieldProblem, MobileRegionEntryProblem, MobileRepeaterDraft,
};
use crate::ulcp::{region_code_description, region_code_from_string};

pub(super) fn build(source: &Source<'_>) -> MobileRepeaterDraft {
    let held = source.held();
    // Empty is "never tag" and "no threshold": values in their own right,
    // known by whether the device answered for the property at all.
    let default_region = spelled(
        held.repeater_default_region.clone(),
        held.repeater_regions.as_deref().unwrap_or_default(),
    );
    MobileRepeaterDraft {
        reading_revision: source.revision(),
        mode: choice(prop::MAC_REPEATER_MODE, held.repeater_mode),
        regions: list(prop::MAC_REPEATER_REGIONS, held.repeater_regions.clone()),
        default_region: text_known(
            prop::MAC_REPEATER_DEFAULT_REGION,
            source.answered(prop::MAC_REPEATER_DEFAULT_REGION),
            default_region,
        ),
        min_rssi: optional_integer(
            prop::MAC_REPEATER_MIN_RSSI,
            source.answered(prop::MAC_REPEATER_MIN_RSSI),
            held.repeater_min_rssi_dbm,
        ),
        min_snr: optional_integer(
            prop::MAC_REPEATER_MIN_SNR,
            source.answered(prop::MAC_REPEATER_MIN_SNR),
            held.repeater_min_snr_db,
        ),
    }
}

pub(super) fn rebase(fresh: MobileRepeaterDraft, old: &MobileRepeaterDraft) -> MobileRepeaterDraft {
    MobileRepeaterDraft {
        reading_revision: fresh.reading_revision,
        mode: rebased(fresh.mode, &old.mode),
        regions: rebased(fresh.regions, &old.regions),
        default_region: rebased(fresh.default_region, &old.default_region),
        min_rssi: rebased(fresh.min_rssi, &old.min_rssi),
        min_snr: rebased(fresh.min_snr, &old.min_snr),
    }
}

/// A default-region code as text: spelled as the region list spells it
/// where it lists that region, else in the code's own form; empty for
/// "never tag".
pub(in crate::app_core::manage) fn spelled(code: Option<Vec<u8>>, listed: &[String]) -> String {
    let Some(code) = code.filter(|code| !code.is_empty()) else {
        return String::new();
    };
    listed
        .iter()
        .find(|region| region_code_from_string((*region).clone()).ok().as_ref() == Some(&code))
        .cloned()
        .or_else(|| region_code_description(code).ok())
        .unwrap_or_default()
}

/// The code a default-region string tags with; empty text never tags.
pub(in crate::app_core::manage) fn region_code(text: &str) -> Option<Vec<u8>> {
    let text = trim_horizontal(text);
    if text.is_empty() {
        return Some(Vec::new());
    }
    region_code_from_string(text.to_owned()).ok()
}

pub(super) fn fold(draft: &MobileRepeaterDraft, fold: &mut Fold) {
    fold.choice(&draft.mode, |desired, value: u8| {
        desired.repeater_mode = Some(value);
    });
    fold.list(&draft.regions, |desired, regions| {
        desired.repeater_regions = Some(regions);
    });
    let default = &draft.default_region;
    if default.dirty() {
        match region_code(&default.text) {
            None => fold.problem(default.property_id, MobileFieldProblem::OutOfRange),
            // The same region spelled another way is not an edit.
            Some(code) if Some(&code) == region_code(&default.reported).as_ref() => {}
            Some(code) => fold.edit(default.property_id, |desired| {
                desired.repeater_default_region = Some(code);
            }),
        }
    }
    fold.optional_integer(
        &draft.min_rssi,
        MobileFieldProblem::OutOfRange,
        |_: i16| true,
        |desired, value| desired.repeater_min_rssi_dbm = value,
    );
    fold.optional_integer(
        &draft.min_snr,
        MobileFieldProblem::OutOfRange,
        |_: i8| true,
        |desired, value| desired.repeater_min_snr_db = value,
    );
}

pub(super) fn details(draft: &MobileRepeaterDraft) -> MobileDraftDetails {
    MobileDraftDetails::Repeater {
        taggable_regions: taggable_regions(draft),
    }
}

/// The regions the default-region picker offers: those listed that tag
/// with a code, and the one the device tags with, whether or not it is
/// still listed, so the picker always has a row for what the device holds.
/// A region is offered once, however it is spelled.
pub(in crate::app_core::manage) fn taggable_regions(draft: &MobileRepeaterDraft) -> Vec<String> {
    let mut listed: Vec<(Vec<u8>, String)> = if draft.regions.known {
        draft
            .regions
            .value
            .iter()
            .filter_map(|region| {
                Some((
                    region_code_from_string(region.clone()).ok()?,
                    region.clone(),
                ))
            })
            .collect()
    } else {
        Vec::new()
    };
    let default = &draft.default_region;
    if default.known
        && let Some(code) = region_code(&default.text).filter(|code| !code.is_empty())
        && !listed.iter().any(|(listed, _)| *listed == code)
    {
        listed.push((code, default.text.clone()));
    }
    listed.into_iter().map(|(_, region)| region).collect()
}

/// Two spellings of one region, compared as the code derivation compares
/// them: ASCII letters fold to lowercase, nothing else does.
fn folded(region: &str) -> String {
    region.to_ascii_lowercase()
}

/// Add a typed region, or respell the one the list already holds under
/// another capitalization: the device keeps one entry per region however
/// it is spelled. `Invalid` for text that is not a region; empty text
/// changes nothing.
#[uniffi::export]
pub fn draft_add_repeater_region(
    draft: MobileRepeaterDraft,
    text: String,
) -> Result<MobileRepeaterDraft, MobileRegionEntryProblem> {
    let text = trim_horizontal(&text);
    if text.is_empty() {
        return Ok(draft);
    }
    if region_code_from_string(text.to_owned()).is_err() {
        return Err(MobileRegionEntryProblem::Invalid);
    }
    let mut draft = draft;
    let target = folded(text);
    let regions = &mut draft.regions.value;
    match regions.iter().position(|region| folded(region) == target) {
        Some(index) => regions[index] = text.to_owned(),
        None => regions.push(text.to_owned()),
    }
    // The default region, where it is this one, takes the list's spelling.
    let default = &mut draft.default_region;
    if default.known && region_code(&default.text) == region_code(text) {
        default.text = text.to_owned();
    }
    Ok(draft)
}

/// Take a region suggestion: its regions always, and its default region
/// (a code, `None` for never tag) where the device answered for one.
#[uniffi::export]
pub fn draft_adopt_regions(
    draft: MobileRepeaterDraft,
    regions: Vec<String>,
    default_region: Option<Vec<u8>>,
) -> MobileRepeaterDraft {
    let mut draft = draft;
    draft.regions.value = regions;
    if draft.default_region.known {
        draft.default_region.text = spelled(default_region, &draft.regions.value);
    }
    draft
}
