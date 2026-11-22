//! What Apply would do with a setup draft: the record it writes, the
//! values the device cannot take, the pickers' lists, the administrator
//! details, and whether the device already holds it.

use std::collections::BTreeSet;

use umsh_node::location::MAX_PRECISION;
use umsh_ulcp::ids::{MAX_AUTO_ANNOUNCE_INTERVAL_S, MIN_AUTO_ANNOUNCE_INTERVAL_S, prop};

use super::draft::Setup;
use super::records::{
    MobileDeviceSetupRecord, MobileSetupChoicesRecord, MobileSetupDraft, MobileSetupResult,
    MobileSetupReviewRecord, MobileSetupSetting,
};
use super::verify::advertised_role;
use super::{plan, records::MobileSetupGoal, records::MobileSetupRefusal};
use crate::app_core::manage::draft::{
    choice_list, matches_preset, optional_choice_list, region_code, taggable_regions,
};
use crate::app_core::manage::records::{
    MobileChoiceField, MobileFieldProblem, MobileFieldProblemRecord, MobileKeyEntryRecord,
    MobileToggleField,
};
use crate::app_core::mobile_limits;
use crate::ulcp::{
    DEVICE_NAME_MAX_LEN, UlcpAdvertSettingsRecord, UlcpDeviceConfigRecord, UlcpGnssSettingsRecord,
    UlcpRadioSettingsRecord, UlcpRepeaterSettingsRecord, UlcpSyncRecord, device_config_writes,
    encode_region_list, region_code_from_string, ulcp_max_dev_admins, ulcp_radio_choices,
    ulcp_radio_presets,
};

/// The repeater thresholds offered, besides "Off".
const MIN_RSSI_CHOICES_DBM: std::ops::RangeInclusive<i64> = -130..=-60;
const MIN_RSSI_STEP_DBM: usize = 5;
const MIN_SNR_CHOICES_DB: std::ops::RangeInclusive<i64> = -20..=10;
const MIN_SNR_STEP_DB: usize = 2;

/// Where a setup stands, besides its draft.
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::app_core::manage) struct Standing<'a> {
    pub(in crate::app_core::manage) applying: bool,
    pub(in crate::app_core::manage) released: bool,
    /// The record the device confirmed, after an apply that did.
    pub(in crate::app_core::manage) applied: Option<&'a UlcpDeviceConfigRecord>,
}

// A field's value where the device reported it, else the placeholder: an
// unknown field is never written, so what it holds is never judged and
// never reaches the record.

fn toggle_value(field: &MobileToggleField, placeholder: bool) -> bool {
    if field.known {
        field.value
    } else {
        placeholder
    }
}

fn choice_value(field: &MobileChoiceField, placeholder: i64) -> Option<i64> {
    if field.known {
        field.value
    } else {
        Some(placeholder)
    }
}

impl Setup {
    /// The name as the record carries it.
    fn trimmed_name(draft: &MobileSetupDraft) -> &str {
        draft.name.text.trim()
    }

    /// The whole configuration Apply writes for `draft`, each optional
    /// present exactly when the device has its capability; `None` when a
    /// value the device reported is edited outside its type, which
    /// `problems` names.
    pub(in crate::app_core::manage) fn record(
        &self,
        draft: &MobileSetupDraft,
    ) -> Option<UlcpDeviceConfigRecord> {
        let sync = &self.sync;
        let defaults = &self.defaults;
        let radio = &draft.radio;
        let modem = if sync.supports_lora {
            Some((
                u32::try_from(choice_value(&radio.bandwidth, defaults.bandwidth_hz)?).ok()?,
                u8::try_from(choice_value(
                    &radio.spreading_factor,
                    defaults.spreading_factor,
                )?)
                .ok()?,
                u8::try_from(choice_value(&radio.coding_rate, defaults.coding_rate)?).ok()?,
            ))
        } else {
            None
        };
        let duty_limit = if sync.supports_duty_cycle_limit {
            Some(u16::try_from(choice_value(&radio.duty_limit, defaults.duty_limit)?).ok()?)
        } else {
            None
        };
        let repeater = if sync.supports_repeater {
            let fields = &draft.repeater;
            let known = fields.mode.known;
            let regions = if known {
                fields.regions.value.clone()
            } else {
                Vec::new()
            };
            let default_region = if known {
                region_code(&fields.default_region.text)?
            } else {
                Vec::new()
            };
            let threshold = |value: Option<i64>| if known { value } else { None };
            Some(UlcpRepeaterSettingsRecord {
                mode: u8::try_from(choice_value(&fields.mode, defaults.repeater_mode)?).ok()?,
                regions,
                default_region: (!default_region.is_empty()).then_some(default_region),
                min_rssi_dbm: threshold(fields.min_rssi.value)
                    .map(i16::try_from)
                    .transpose()
                    .ok()?,
                min_snr_db: threshold(fields.min_snr.value)
                    .map(i8::try_from)
                    .transpose()
                    .ok()?,
            })
        } else {
            None
        };
        let gnss = if sync.supports_gnss {
            Some(UlcpGnssSettingsRecord {
                enabled: toggle_value(&draft.gnss_enabled, defaults.gnss_enabled),
                ident_update: toggle_value(&draft.share_position, defaults.share_position),
                ident_precision: u8::try_from(choice_value(&draft.precision, defaults.precision)?)
                    .ok()?,
                time_trust: toggle_value(&draft.time_trust, defaults.time_trust),
            })
        } else {
            None
        };
        let advert = if sync.supports_advert {
            Some(UlcpAdvertSettingsRecord {
                advert_interval_seconds: u32::try_from(choice_value(
                    &draft.advert_interval,
                    defaults.advert_interval_s,
                )?)
                .ok()?,
                beacon_interval_seconds: u32::try_from(choice_value(
                    &draft.beacon_interval,
                    defaults.beacon_interval_s,
                )?)
                .ok()?,
                startup_beacon: toggle_value(&draft.startup_beacon, defaults.startup_beacon),
            })
        } else {
            None
        };
        Some(UlcpDeviceConfigRecord {
            radio: UlcpRadioSettingsRecord {
                device_name: sync
                    .supports_device_name
                    .then(|| Self::trimmed_name(draft).to_owned()),
                phy_enabled: radio.enabled.value,
                frequency_khz: u32::try_from(radio.frequency_khz.value).ok()?,
                transmit_power_dbm: i8::try_from(radio.transmit_power_dbm.value).ok()?,
                bandwidth_hz: modem.map(|(bandwidth, _, _)| bandwidth),
                spreading_factor: modem.map(|(_, sf, _)| sf),
                coding_rate_denom: modem.map(|(_, _, cr)| cr),
                duty_cycle_limit: duty_limit,
            },
            ident_role: self.hidden.role.filter(|_| sync.supports_ident),
            ident_mobile: sync.supports_ident.then_some(self.hidden.mobile),
            dev_discoverable: sync
                .supports_device_identity
                .then(|| toggle_value(&draft.discoverable, defaults.discoverable)),
            repeater,
            meshcore: sync
                .supports_meshcore_forwarder
                .then(|| self.hidden.meshcore.clone()),
            tz_rule: sync.supports_time.then(|| self.hidden.tz_rule.clone()),
            time_24h: sync.supports_time.then_some(self.hidden.time_24h),
            gnss,
            advert,
        })
    }

    /// Every value `draft` would write that the device cannot take, by
    /// property, ascending. Only known fields are judged: setup writes
    /// every one of them, and an unknown one is never written.
    pub(in crate::app_core::manage) fn problems(
        &self,
        draft: &MobileSetupDraft,
    ) -> Vec<MobileFieldProblemRecord> {
        let sync = &self.sync;
        let mut problems = BTreeSet::new();
        let mut problem = |property: u32, bad: bool| {
            if bad {
                problems.insert(property);
            }
        };
        if draft.name.known {
            let name = Self::trimmed_name(draft);
            problem(
                prop::DEV_NAME,
                name.is_empty() || name.len() > DEVICE_NAME_MAX_LEN || name.contains('\0'),
            );
        }
        let radio = &draft.radio;
        problem(
            prop::PHY_FREQ,
            !u32::try_from(radio.frequency_khz.value).is_ok_and(|frequency| frequency > 0),
        );
        problem(
            prop::PHY_TX_POWER,
            i8::try_from(radio.transmit_power_dbm.value).is_err(),
        );
        if sync.supports_lora {
            let bad = |field: &MobileChoiceField, valid: &dyn Fn(i64) -> bool| {
                field.known && !field.value.is_some_and(valid)
            };
            problem(
                prop::PHY_LORA_BW,
                bad(&radio.bandwidth, &|bandwidth| {
                    u32::try_from(bandwidth).is_ok_and(|bandwidth| bandwidth > 0)
                }),
            );
            problem(
                prop::PHY_LORA_SF,
                bad(&radio.spreading_factor, &|sf| (5..=12).contains(&sf)),
            );
            problem(
                prop::PHY_LORA_CR,
                bad(&radio.coding_rate, &|cr| (5..=8).contains(&cr)),
            );
        }
        if sync.supports_duty_cycle_limit {
            problem(prop::PHY_DUTY_LIMIT, !fits::<u16>(&radio.duty_limit));
        }
        let repeater = &draft.repeater;
        if sync.supports_repeater && repeater.mode.known {
            problem(prop::MAC_REPEATER_MODE, !fits::<u8>(&repeater.mode));
            problem(
                prop::MAC_REPEATER_REGIONS,
                encode_region_list(&repeater.regions.value).is_err(),
            );
            problem(
                prop::MAC_REPEATER_DEFAULT_REGION,
                region_code(&repeater.default_region.text).is_none(),
            );
            problem(
                prop::MAC_REPEATER_MIN_RSSI,
                repeater
                    .min_rssi
                    .value
                    .is_some_and(|rssi| i16::try_from(rssi).is_err()),
            );
            problem(
                prop::MAC_REPEATER_MIN_SNR,
                repeater
                    .min_snr
                    .value
                    .is_some_and(|snr| i8::try_from(snr).is_err()),
            );
        }
        if sync.supports_gnss && draft.precision.known {
            problem(
                prop::GNSS_IDENT_PRECISION,
                !draft
                    .precision
                    .value
                    .is_some_and(|precision| (1..=i64::from(MAX_PRECISION)).contains(&precision)),
            );
        }
        if sync.supports_advert {
            for field in [&draft.advert_interval, &draft.beacon_interval] {
                problem(
                    field.property_id,
                    field.known && !field.value.is_some_and(announce_interval),
                );
            }
        }
        problems
            .into_iter()
            .map(|property_id| MobileFieldProblemRecord {
                property_id,
                problem: MobileFieldProblem::OutOfRange,
            })
            .collect()
    }

    /// No profile choice is pending: none was asked for, one was made, or
    /// a radio value was moved off the one the goal built.
    pub(in crate::app_core::manage) fn profile_chosen(&self, draft: &MobileSetupDraft) -> bool {
        let values = |draft: &MobileSetupDraft| {
            let radio = &draft.radio;
            (
                radio.frequency_khz.value,
                radio.transmit_power_dbm.value,
                radio.bandwidth.value,
                radio.spreading_factor.value,
                radio.coding_rate.value,
                radio.duty_limit.value,
            )
        };
        !matches!(
            self.profile,
            super::records::MobileSetupProfile::MustChoose { .. }
        ) || draft.profile_settled
            || values(draft) != values(&self.built)
    }

    /// The vetted preset the radio fields spell out. None on a LoRa
    /// device that would not report its modem: its fields are not its
    /// own.
    pub(in crate::app_core::manage) fn preset_id(
        &self,
        draft: &MobileSetupDraft,
    ) -> Option<String> {
        if self.sync.supports_lora && !self.gates.shows_modem {
            return None;
        }
        ulcp_radio_presets()
            .into_iter()
            .find(|preset| matches_preset(&draft.radio, preset))
            .map(|preset| preset.id)
    }

    /// The writes Apply would make of `record`: the backstop, and the set
    /// a read-back is checked against.
    pub(in crate::app_core::manage) fn writes(
        &self,
        record: UlcpDeviceConfigRecord,
    ) -> Option<Vec<(u32, Vec<u8>)>> {
        device_config_writes(record, &self.sync).ok()
    }

    /// What Apply would do with `draft` now.
    pub(in crate::app_core::manage) fn review(
        &self,
        draft: &MobileSetupDraft,
        standing: Standing<'_>,
    ) -> MobileSetupReviewRecord {
        let problems = self.problems(draft);
        let record = self.record(draft);
        // Each problem above restates what the encoder refuses, so a draft
        // with none always encodes; one that does not is a bug here.
        let encodes = problems.is_empty()
            && record
                .clone()
                .is_some_and(|record| self.writes(record).is_some());
        debug_assert!(
            encodes || !problems.is_empty(),
            "a setup draft with no problem the encoder refuses"
        );
        let profile_chosen = self.profile_chosen(draft);
        let administrators = &draft.administrators;
        let phone = self.phone_node_key.as_deref();
        let listed = |key: &[u8]| administrators.value.iter().any(|admin| admin == key);
        let full = administrators.value.len() >= usize::from(ulcp_max_dev_admins());
        let phone_administers = phone.is_some_and(listed);
        MobileSetupReviewRecord {
            unshown_problems: unshown_problems(&problems),
            can_apply: encodes && profile_chosen && !standing.applying && !standing.released,
            problems,
            profile_chosen,
            applied: standing
                .applied
                .is_some_and(|applied| record.as_ref() == Some(applied))
                && administrators.value.iter().collect::<BTreeSet<_>>()
                    == administrators.reported.iter().collect::<BTreeSet<_>>(),
            preset_id: self.preset_id(draft),
            choices: choices(draft),
            taggable_regions: taggable_regions(&draft.repeater),
            default_region_unlisted: default_region_unlisted(draft),
            administrators: administrators
                .value
                .iter()
                .map(|key| MobileKeyEntryRecord {
                    key: key.clone(),
                    is_this_phone: phone == Some(key.as_slice()),
                    removable: true,
                })
                .collect(),
            phone_administers,
            phone_switch_enabled: phone.is_some() && (phone_administers || !full),
            administrators_full: full,
        }
    }
}

/// A known picker's value fits `T`.
fn fits<T: TryFrom<i64>>(field: &MobileChoiceField) -> bool {
    !field.known || field.value.is_some_and(|value| T::try_from(value).is_ok())
}

/// 0 (off), or within the bounds a device enforces.
fn announce_interval(seconds: i64) -> bool {
    seconds == 0
        || (i64::from(MIN_AUTO_ANNOUNCE_INTERVAL_S)..=i64::from(MAX_AUTO_ANNOUNCE_INTERVAL_S))
            .contains(&seconds)
}

/// The setting the operator knows `property` as, for a problem with no
/// box of its own; `None` for the name, frequency and power, which show
/// their own.
pub(in crate::app_core::manage) fn unshown_setting(property: u32) -> Option<MobileSetupSetting> {
    match property {
        prop::PHY_LORA_BW => Some(MobileSetupSetting::Bandwidth),
        prop::PHY_LORA_SF => Some(MobileSetupSetting::SpreadingFactor),
        prop::PHY_LORA_CR => Some(MobileSetupSetting::CodingRate),
        prop::PHY_DUTY_LIMIT => Some(MobileSetupSetting::TransmitLimit),
        prop::MAC_REPEATER_MODE
        | prop::MAC_REPEATER_REGIONS
        | prop::MAC_REPEATER_DEFAULT_REGION
        | prop::MAC_REPEATER_MIN_RSSI
        | prop::MAC_REPEATER_MIN_SNR => Some(MobileSetupSetting::ForwardingPolicy),
        prop::GNSS_ENABLED
        | prop::GNSS_IDENT_UPDATE
        | prop::GNSS_IDENT_PRECISION
        | prop::GNSS_TIME_TRUST => Some(MobileSetupSetting::Positioning),
        prop::ADVERT_INTERVAL | prop::BEACON_INTERVAL | prop::STARTUP_BEACON => {
            Some(MobileSetupSetting::Announcements)
        }
        _ => None,
    }
}

/// The settings of `problems` that have no box of their own, once each,
/// in `MobileSetupSetting` order.
pub(in crate::app_core::manage) fn unshown_problems(
    problems: &[MobileFieldProblemRecord],
) -> Vec<MobileSetupSetting> {
    problems
        .iter()
        .filter_map(|problem| unshown_setting(problem.property_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Every picker's list.
pub(in crate::app_core::manage) fn choices(draft: &MobileSetupDraft) -> MobileSetupChoicesRecord {
    let radio = ulcp_radio_choices();
    let limits = mobile_limits();
    let wide = |values: Vec<u32>| values.into_iter().map(i64::from).collect::<Vec<_>>();
    let narrow = |values: Vec<u8>| values.into_iter().map(i64::from).collect::<Vec<_>>();
    let rssi: Vec<i64> = MIN_RSSI_CHOICES_DBM.step_by(MIN_RSSI_STEP_DBM).collect();
    let snr: Vec<i64> = MIN_SNR_CHOICES_DB.step_by(MIN_SNR_STEP_DB).collect();
    MobileSetupChoicesRecord {
        bandwidths_hz: choice_list(&wide(radio.bandwidths_hz), &draft.radio.bandwidth),
        spreading_factors: choice_list(
            &narrow(radio.spreading_factors),
            &draft.radio.spreading_factor,
        ),
        coding_rates: choice_list(&narrow(radio.coding_rates), &draft.radio.coding_rate),
        duty_limits: choice_list(
            &radio
                .duty_cycle_limits
                .into_iter()
                .map(i64::from)
                .collect::<Vec<_>>(),
            &draft.radio.duty_limit,
        ),
        precisions: choice_list(
            &(limits.min_location_precision..=limits.max_location_precision)
                .map(i64::from)
                .collect::<Vec<_>>(),
            &draft.precision,
        ),
        advert_intervals_s: choice_list(
            &wide(limits.advert_interval_choices_s),
            &draft.advert_interval,
        ),
        beacon_intervals_s: choice_list(
            &wide(limits.beacon_interval_choices_s),
            &draft.beacon_interval,
        ),
        min_rssi_dbm: optional_choice_list(&rssi, &draft.repeater.min_rssi),
        min_snr_db: optional_choice_list(&snr, &draft.repeater.min_snr),
    }
}

/// The device would tag untagged floods with a region it does not relay.
pub(in crate::app_core::manage) fn default_region_unlisted(draft: &MobileSetupDraft) -> bool {
    let repeater = &draft.repeater;
    if !repeater.default_region.known {
        return false;
    }
    let Some(code) = region_code(&repeater.default_region.text).filter(|code| !code.is_empty())
    else {
        return false;
    };
    !repeater
        .regions
        .value
        .iter()
        .any(|region| region_code_from_string(region.clone()).ok().as_ref() == Some(&code))
}

/// The setup record for a device `goal` can use, or the one it refused.
/// `reported` is what the device reports now, the attach's record until
/// an apply reads it back.
pub(in crate::app_core::manage) fn snapshot(
    goal: MobileSetupGoal,
    setup: Result<&Setup, MobileSetupRefusal>,
    phone_node_key: Option<Vec<u8>>,
    reported: Option<UlcpSyncRecord>,
    applying: bool,
    last_result: Option<MobileSetupResult>,
) -> MobileDeviceSetupRecord {
    let advertised_role = reported.as_ref().and_then(advertised_role);
    let mut record = MobileDeviceSetupRecord {
        goal,
        refusal: None,
        sections: Vec::new(),
        notes: Vec::new(),
        unreadable: Vec::new(),
        profile: None,
        shows_presets: false,
        shows_modem: false,
        shows_duty_limit: false,
        suggests_regions_from_phone: plan::suggests_regions_from_phone(goal),
        phone_node_key,
        reported,
        advertised_role,
        applying,
        last_result,
    };
    match setup {
        Err(refusal) => record.refusal = Some(refusal),
        Ok(setup) => {
            let sync = &setup.sync;
            record.sections = plan::sections(goal, sync, &setup.gates);
            record.notes = plan::notes(sync);
            record.unreadable = super::draft::unreadable(sync);
            record.profile = Some(setup.profile.clone());
            record.shows_presets = setup.gates.shows_presets;
            record.shows_modem = setup.gates.shows_modem;
            record.shows_duty_limit = setup.gates.shows_duty_limit;
        }
    }
    record
}
