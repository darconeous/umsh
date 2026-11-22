//! The radio: whether it runs, where, how hard, and under which modem
//! profile.

use umsh_ulcp::ids::prop;

use super::{Field, Fold, Source, choice, integer, rebased, toggle};
use crate::app_core::manage::records::{
    MobileApplyWarning, MobileChoiceField, MobileDraftDetails, MobileFieldProblem,
    MobileManagedDeviceRecord, MobileManagementLink, MobileRadioDraft,
};
use crate::ulcp::{RadioPresetRecord, ulcp_radio_presets};

pub(super) fn build(source: &Source<'_>) -> MobileRadioDraft {
    let held = source.held();
    MobileRadioDraft {
        reading_revision: source.revision(),
        enabled: toggle(prop::PHY_ENABLED, held.phy_enabled),
        frequency_khz: integer(prop::PHY_FREQ, held.frequency_khz),
        transmit_power_dbm: integer(prop::PHY_TX_POWER, held.transmit_power_dbm),
        bandwidth: choice(prop::PHY_LORA_BW, held.bandwidth_hz),
        spreading_factor: choice(prop::PHY_LORA_SF, held.spreading_factor),
        coding_rate: choice(prop::PHY_LORA_CR, held.coding_rate_denom),
        duty_limit: choice(prop::PHY_DUTY_LIMIT, held.duty_cycle_limit),
    }
}

pub(super) fn rebase(fresh: MobileRadioDraft, old: &MobileRadioDraft) -> MobileRadioDraft {
    MobileRadioDraft {
        reading_revision: fresh.reading_revision,
        enabled: rebased(fresh.enabled, &old.enabled),
        frequency_khz: rebased(fresh.frequency_khz, &old.frequency_khz),
        transmit_power_dbm: rebased(fresh.transmit_power_dbm, &old.transmit_power_dbm),
        bandwidth: rebased(fresh.bandwidth, &old.bandwidth),
        spreading_factor: rebased(fresh.spreading_factor, &old.spreading_factor),
        coding_rate: rebased(fresh.coding_rate, &old.coding_rate),
        duty_limit: rebased(fresh.duty_limit, &old.duty_limit),
    }
}

pub(super) fn fold(draft: &MobileRadioDraft, fold: &mut Fold) {
    fold.toggle(&draft.enabled, |desired, value| {
        desired.phy_enabled = Some(value);
    });
    fold.integer(
        &draft.frequency_khz,
        MobileFieldProblem::OutOfRange,
        |_: u32| true,
        |desired, value| desired.frequency_khz = Some(value),
    );
    fold.integer(
        &draft.transmit_power_dbm,
        MobileFieldProblem::OutOfRange,
        |_: i8| true,
        |desired, value| desired.transmit_power_dbm = Some(value),
    );
    fold.choice(&draft.bandwidth, |desired, value: u32| {
        desired.bandwidth_hz = Some(value);
    });
    fold.choice(&draft.spreading_factor, |desired, value: u8| {
        desired.spreading_factor = Some(value);
    });
    fold.choice(&draft.coding_rate, |desired, value: u8| {
        desired.coding_rate_denom = Some(value);
    });
    fold.choice(&draft.duty_limit, |desired, value: u16| {
        desired.duty_cycle_limit = Some(value);
    });
}

pub(super) fn assess(
    draft: &MobileRadioDraft,
    device: &MobileManagedDeviceRecord,
    fold: &Fold,
) -> (Option<MobileApplyWarning>, MobileDraftDetails) {
    // Frequency and the modem profile decide who can hear whom, and a radio
    // switched off hears nothing. Power and the transmit limit only change
    // how far the device reaches, so they apply unwarned.
    let strands = [
        prop::PHY_FREQ,
        prop::PHY_LORA_BW,
        prop::PHY_LORA_SF,
        prop::PHY_LORA_CR,
    ]
    .into_iter()
    .any(|property| fold.is_dirty(property))
        || (fold.is_dirty(prop::PHY_ENABLED) && !draft.enabled.value);
    let warning = (device.link == MobileManagementLink::Mesh && strands)
        .then_some(MobileApplyWarning::StrandsRadio);
    let card = device.card.as_ref();
    let shows_presets = draft.frequency_khz.known
        && draft.transmit_power_dbm.known
        && (!card.is_some_and(|card| card.supports_lora) || draft.bandwidth.known)
        && (!card.is_some_and(|card| card.supports_duty_cycle_limit) || draft.duty_limit.known);
    let preset_id = ulcp_radio_presets()
        .into_iter()
        .find(|preset| matches(draft, preset))
        .map(|preset| preset.id);
    (
        warning,
        MobileDraftDetails::Radio {
            preset_id,
            shows_presets,
        },
    )
}

/// Whether the fields spell out `preset`. Only what decides who can hear
/// whom is compared: power and the transmit limit are this one device's
/// business, and a radio reports power clamped to what it can reach. A
/// parameter the device never answered for is left out.
pub(in crate::app_core::manage) fn matches(
    draft: &MobileRadioDraft,
    preset: &RadioPresetRecord,
) -> bool {
    let same = |field: &MobileChoiceField, value: i64| !field.known() || field.value == Some(value);
    draft.frequency_khz.known
        && draft.frequency_khz.value == i64::from(preset.frequency_khz)
        && same(&draft.bandwidth, preset.bandwidth_hz.into())
        && same(&draft.spreading_factor, preset.spreading_factor.into())
        && same(&draft.coding_rate, preset.coding_rate_denom.into())
}

/// Every radio parameter `preset_id` names, written into the fields the
/// device answered for; power only where the preset has one. Unchanged
/// for an id that is not a vetted preset.
#[uniffi::export]
pub fn draft_adopt_preset(draft: MobileRadioDraft, preset_id: String) -> MobileRadioDraft {
    let Some(preset) = ulcp_radio_presets()
        .into_iter()
        .find(|preset| preset.id == preset_id)
    else {
        return draft;
    };
    let mut draft = draft;
    if draft.enabled.known {
        draft.enabled.value = true;
    }
    if draft.frequency_khz.known {
        draft.frequency_khz.value = preset.frequency_khz.into();
    }
    if let Some(power) = preset.transmit_power_dbm
        && draft.transmit_power_dbm.known
    {
        draft.transmit_power_dbm.value = power.into();
    }
    if draft.bandwidth.known {
        draft.bandwidth.value = Some(preset.bandwidth_hz.into());
    }
    if draft.spreading_factor.known {
        draft.spreading_factor.value = Some(preset.spreading_factor.into());
    }
    if draft.coding_rate.known {
        draft.coding_rate.value = Some(preset.coding_rate_denom.into());
    }
    if draft.duty_limit.known {
        draft.duty_limit.value = Some(preset.duty_cycle_limit.into());
    }
    draft
}
