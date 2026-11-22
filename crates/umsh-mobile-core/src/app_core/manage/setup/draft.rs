//! The setup draft: what the device reported and would not report, the
//! placeholders a setting it would not report holds, the radio profile it
//! is put on, and the draft a goal builds from all of that.

use umsh_node::NodeRole;
use umsh_ulcp::ids::{
    DEFAULT_ADVERT_INTERVAL_S, DEFAULT_BEACON_INTERVAL_S, DUTY_LIMIT_DISABLED,
    meshcore_region_policy, prop,
};

use super::plan::{self, Assumption};
use super::records::{
    MobileKeyListField, MobileSetupCompanionRecord, MobileSetupDraft, MobileSetupGoal,
    MobileSetupProfile, MobileSetupProfileGap, MobileSetupRadioParameter, MobileSetupRefusal,
    MobileSetupUnreadable,
};
use crate::app_core::DEFAULT_LOCATION_PRECISION;
use crate::app_core::manage::draft::{draft_adopt_preset, spelled};
use crate::app_core::manage::records::{
    MobileChoiceField, MobileIntegerField, MobileOptionalIntegerField, MobileRadioDraft,
    MobileRepeaterDraft, MobileTextField, MobileTextListField, MobileToggleField,
};
use crate::ulcp::{
    UlcpMeshCoreSettingsRecord, UlcpSyncRecord, ulcp_max_dev_admins, ulcp_radio_presets,
};

/// What a device that reported `sync` lets the sheet show and write. Fixed
/// for a setup's life: capabilities do not change mid-session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app_core::manage) struct Gates {
    /// The modem profile is three properties; part of it is none of it.
    pub(in crate::app_core::manage) shows_modem: bool,
    pub(in crate::app_core::manage) shows_duty_limit: bool,
    pub(in crate::app_core::manage) shows_discoverable: bool,
    pub(in crate::app_core::manage) shows_forwarding: bool,
    pub(in crate::app_core::manage) shows_positioning: bool,
    pub(in crate::app_core::manage) shows_announcements: bool,
    pub(in crate::app_core::manage) shows_administrators: bool,
    /// Every parameter a preset sets was reported.
    pub(in crate::app_core::manage) shows_presets: bool,
    /// Mobility stands for the whole advertised identity: an empty role
    /// is also a device deriving its own.
    pub(in crate::app_core::manage) shows_identity: bool,
    pub(in crate::app_core::manage) shows_time_zone: bool,
    /// No modem, or all of it reported.
    pub(in crate::app_core::manage) modem_readable: bool,
}

impl Gates {
    pub(in crate::app_core::manage) fn of(sync: &UlcpSyncRecord) -> Self {
        let triple = sync.bandwidth_hz.is_some()
            && sync.spreading_factor.is_some()
            && sync.coding_rate_denom.is_some();
        let modem_readable = !sync.supports_lora || triple;
        let duty_readable = !sync.supports_duty_cycle_limit || sync.duty_cycle_limit.is_some();
        Self {
            shows_modem: sync.supports_lora && triple,
            shows_duty_limit: sync.supports_duty_cycle_limit && sync.duty_cycle_limit.is_some(),
            shows_discoverable: sync.supports_device_identity && sync.dev_discoverable.is_some(),
            shows_forwarding: sync.supports_repeater && sync.repeater.is_some(),
            shows_positioning: sync.supports_gnss && sync.gnss.is_some(),
            shows_announcements: sync.supports_advert && sync.advert.is_some(),
            shows_administrators: sync.supports_admin && sync.dev_admin_keys.is_some(),
            shows_presets: modem_readable && duty_readable,
            shows_identity: sync.supports_ident && sync.ident_mobile.is_some(),
            shows_time_zone: sync.supports_time && sync.tz_rule.is_some(),
            modem_readable,
        }
    }
}

/// The settings a device that reported `sync` would not report, in the
/// order the sheet names them. The name, frequency and power are never
/// among them: a device always reports those.
pub(in crate::app_core::manage) fn unreadable(sync: &UlcpSyncRecord) -> Vec<MobileSetupUnreadable> {
    let gates = Gates::of(sync);
    [
        (sync.supports_lora && !gates.shows_modem).then_some(MobileSetupUnreadable::ModemProfile),
        (sync.supports_duty_cycle_limit && sync.duty_cycle_limit.is_none())
            .then_some(MobileSetupUnreadable::TransmitLimit),
        (sync.supports_ident && !gates.shows_identity)
            .then_some(MobileSetupUnreadable::AdvertisedIdentity),
        (sync.supports_device_identity && !gates.shows_discoverable)
            .then_some(MobileSetupUnreadable::Discoverability),
        (sync.supports_repeater && sync.repeater.is_none())
            .then_some(MobileSetupUnreadable::ForwardingPolicy),
        (sync.supports_meshcore_forwarder && sync.meshcore.is_none())
            .then_some(MobileSetupUnreadable::MeshCoreForwarding),
        (sync.supports_gnss && !gates.shows_positioning)
            .then_some(MobileSetupUnreadable::Positioning),
        (sync.supports_advert && !gates.shows_announcements)
            .then_some(MobileSetupUnreadable::Announcements),
        (sync.supports_time && !gates.shows_time_zone).then_some(MobileSetupUnreadable::TimeZone),
        (sync.supports_admin && !gates.shows_administrators)
            .then_some(MobileSetupUnreadable::Administrators),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// What a setting the device would not report holds: a placeholder that
/// satisfies the record, never a value that reaches the device, because
/// the write leaves out every property the device would not report and
/// every group with one in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::app_core::manage) struct Defaults {
    pub(in crate::app_core::manage) bandwidth_hz: i64,
    pub(in crate::app_core::manage) spreading_factor: i64,
    pub(in crate::app_core::manage) coding_rate: i64,
    pub(in crate::app_core::manage) duty_limit: i64,
    pub(in crate::app_core::manage) discoverable: bool,
    pub(in crate::app_core::manage) repeater_mode: i64,
    pub(in crate::app_core::manage) gnss_enabled: bool,
    pub(in crate::app_core::manage) share_position: bool,
    pub(in crate::app_core::manage) precision: i64,
    pub(in crate::app_core::manage) time_trust: bool,
    pub(in crate::app_core::manage) advert_interval_s: i64,
    pub(in crate::app_core::manage) beacon_interval_s: i64,
    pub(in crate::app_core::manage) startup_beacon: bool,
    pub(in crate::app_core::manage) mobile: bool,
    pub(in crate::app_core::manage) time_24h: bool,
    pub(in crate::app_core::manage) meshcore: UlcpMeshCoreSettingsRecord,
}

/// The placeholders a setup uses.
pub(in crate::app_core::manage) const DEFAULTS: Defaults = Defaults {
    bandwidth_hz: 125_000,
    spreading_factor: 9,
    coding_rate: 5,
    duty_limit: DUTY_LIMIT_DISABLED as i64,
    discoverable: true,
    repeater_mode: 0,
    gnss_enabled: false,
    share_position: false,
    precision: DEFAULT_LOCATION_PRECISION as i64,
    time_trust: true,
    advert_interval_s: DEFAULT_ADVERT_INTERVAL_S as i64,
    beacon_interval_s: DEFAULT_BEACON_INTERVAL_S as i64,
    startup_beacon: true,
    mobile: false,
    time_24h: true,
    meshcore: UlcpMeshCoreSettingsRecord {
        enabled: false,
        region_policy: meshcore_region_policy::OPEN,
        regions: Vec::new(),
    },
};

/// The values a goal decides that the sheet never shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::app_core::manage) struct Hidden {
    /// `None` lets the device derive its role.
    pub(in crate::app_core::manage) role: Option<u8>,
    pub(in crate::app_core::manage) mobile: bool,
    /// Carried as the device reported it.
    pub(in crate::app_core::manage) meshcore: UlcpMeshCoreSettingsRecord,
    pub(in crate::app_core::manage) tz_rule: String,
    /// Carried as the device reported it.
    pub(in crate::app_core::manage) time_24h: bool,
}

/// One device a goal can use, and the draft it built for it.
#[derive(Clone, Debug, PartialEq)]
pub(in crate::app_core::manage) struct Setup {
    pub(in crate::app_core::manage) goal: MobileSetupGoal,
    /// What the device reported when it attached: the authority on what
    /// it can be told.
    pub(in crate::app_core::manage) sync: UlcpSyncRecord,
    pub(in crate::app_core::manage) gates: Gates,
    pub(in crate::app_core::manage) profile: MobileSetupProfile,
    pub(in crate::app_core::manage) hidden: Hidden,
    /// The draft as the goal built it; a radio value that differs from it
    /// settles a pending profile choice.
    pub(in crate::app_core::manage) built: MobileSetupDraft,
    pub(in crate::app_core::manage) defaults: Defaults,
    pub(in crate::app_core::manage) phone_node_key: Option<Vec<u8>>,
}

/// The companion record of a radio named `name` that reported `sync`.
pub(in crate::app_core::manage) fn companion_record(
    name: Option<String>,
    sync: &UlcpSyncRecord,
) -> MobileSetupCompanionRecord {
    MobileSetupCompanionRecord {
        name: name.filter(|name| !name.is_empty()),
        frequency_khz: sync.frequency_khz.into(),
        transmit_power_dbm: sync.transmit_power_dbm.into(),
        bandwidth_hz: sync.bandwidth_hz.map(Into::into),
        spreading_factor: sync.spreading_factor.map(Into::into),
        coding_rate: sync.coding_rate_denom.map(Into::into),
        duty_limit: sync.duty_cycle_limit.map(Into::into),
    }
}

/// The radio values copied from a companion, reduced to what the device
/// takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app_core::manage) struct CopiedProfile {
    pub(in crate::app_core::manage) frequency_khz: i64,
    pub(in crate::app_core::manage) transmit_power_dbm: i64,
    /// Bandwidth, spreading factor and coding rate, on a LoRa device.
    pub(in crate::app_core::manage) modem: Option<(i64, i64, i64)>,
    pub(in crate::app_core::manage) duty_limit: Option<i64>,
}

/// Where the profile of a device that reported `sync` comes from, and
/// what is copied.
pub(in crate::app_core::manage) fn resolve_profile(
    companion: Option<&MobileSetupCompanionRecord>,
    sync: &UlcpSyncRecord,
) -> (MobileSetupProfile, Option<CopiedProfile>) {
    let gates = Gates::of(sync);
    // A profile sets every radio parameter, so one is only chosen for a
    // device that reported every one it sets.
    let gap = |gap| {
        if gates.shows_presets {
            MobileSetupProfile::MustChoose { gap }
        } else {
            MobileSetupProfile::LeftAsFound { gap }
        }
    };
    let Some(companion) = companion else {
        return (gap(MobileSetupProfileGap::NoCompanion), None);
    };
    // The triple travels only to a device with a modem, and only whole.
    let modem = match (
        companion.bandwidth_hz,
        companion.spreading_factor,
        companion.coding_rate,
    ) {
        (Some(bandwidth), Some(sf), Some(cr)) => Some((bandwidth, sf, cr)),
        _ if sync.supports_lora => {
            return (gap(MobileSetupProfileGap::CompanionHasNoModemProfile), None);
        }
        _ => None,
    };
    // A copy would move the device onto the mesh's frequency under a modem
    // profile nobody read, so a device that would not report it keeps its
    // own radio.
    if !gates.modem_readable {
        return (
            MobileSetupProfile::LeftAsFound {
                gap: MobileSetupProfileGap::DeviceModemUnreported,
            },
            None,
        );
    }
    let copied = CopiedProfile {
        frequency_khz: companion.frequency_khz,
        transmit_power_dbm: companion.transmit_power_dbm,
        modem: modem.filter(|_| sync.supports_lora),
        // A local regulatory setting, not an interop one: a companion
        // without one falls back to what the device holds.
        duty_limit: sync.supports_duty_cycle_limit.then(|| {
            companion
                .duty_limit
                .or(sync.duty_cycle_limit.map(Into::into))
                .unwrap_or(DUTY_LIMIT_DISABLED.into())
        }),
    };
    (
        MobileSetupProfile::Copied {
            companion_name: companion.name.clone(),
        },
        Some(copied),
    )
}

/// The setup `goal` makes of a device that reported `sync`, or why it
/// refuses it. `name` is the device's name as its link knows it;
/// `phone_zone_rule` is the phone's own.
pub(in crate::app_core::manage) fn build(
    goal: MobileSetupGoal,
    sync: Option<&UlcpSyncRecord>,
    name: Option<String>,
    companion: Option<&MobileSetupCompanionRecord>,
    phone_node_key: Option<Vec<u8>>,
    phone_zone_rule: &str,
) -> Result<Setup, MobileSetupRefusal> {
    build_with(
        goal,
        sync,
        name,
        companion,
        phone_node_key,
        phone_zone_rule,
        &DEFAULTS,
    )
}

/// `build` with the placeholders given.
pub(in crate::app_core::manage) fn build_with(
    goal: MobileSetupGoal,
    sync: Option<&UlcpSyncRecord>,
    name: Option<String>,
    companion: Option<&MobileSetupCompanionRecord>,
    phone_node_key: Option<Vec<u8>>,
    phone_zone_rule: &str,
    defaults: &Defaults,
) -> Result<Setup, MobileSetupRefusal> {
    if let Some(refusal) = plan::refusal(goal, sync) {
        return Err(refusal);
    }
    let sync = sync.expect("a refusal answers a missing record");
    let gates = Gates::of(sync);
    let mut draft = reported_draft(sync, name, &gates, defaults);
    let mut hidden = Hidden {
        role: sync.ident_role,
        mobile: sync.ident_mobile.unwrap_or(defaults.mobile),
        meshcore: sync
            .meshcore
            .clone()
            .unwrap_or_else(|| defaults.meshcore.clone()),
        // The phone doing the setup stands next to the device.
        tz_rule: sync
            .tz_rule
            .clone()
            .unwrap_or_else(|| phone_zone_rule.to_owned()),
        time_24h: sync.time_24h.unwrap_or(defaults.time_24h),
    };
    let (profile, copied) = resolve_profile(companion, sync);
    if let Some(copied) = copied {
        adopt_copied(&mut draft.radio, copied);
    }
    for assumption in plan::assumptions(goal) {
        if assumption.applies(sync) {
            force(
                *assumption,
                &mut draft,
                &mut hidden,
                phone_node_key.as_deref(),
                phone_zone_rule,
            );
        }
    }
    Ok(Setup {
        goal,
        sync: sync.clone(),
        gates,
        profile,
        hidden,
        built: draft,
        defaults: defaults.clone(),
        phone_node_key,
    })
}

/// The draft of what `sync` reported, before the goal decides anything.
fn reported_draft(
    sync: &UlcpSyncRecord,
    name: Option<String>,
    gates: &Gates,
    defaults: &Defaults,
) -> MobileSetupDraft {
    let choice = |property_id, known, reported: Option<i64>, default: i64| MobileChoiceField {
        property_id,
        known,
        reported,
        value: Some(reported.unwrap_or(default)),
    };
    let toggle = |property_id, known, reported: Option<bool>, default: bool| {
        let value = reported.unwrap_or(default);
        MobileToggleField {
            property_id,
            known,
            reported: value,
            value,
        }
    };
    let repeater = sync.repeater.as_ref();
    let forwarding = gates.shows_forwarding;
    let gnss = sync.gnss.as_ref();
    let positioning = gates.shows_positioning;
    let advert = sync.advert.as_ref();
    let announcements = gates.shows_announcements;
    let regions = repeater.map(|repeater| repeater.regions.clone());
    let default_region = repeater
        .map(|repeater| {
            spelled(
                repeater.default_region.clone(),
                regions.as_deref().unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let threshold = |property_id, reported: Option<i64>| MobileOptionalIntegerField {
        property_id,
        known: forwarding,
        reported,
        value: reported,
    };
    let admins = sync.dev_admin_keys.clone().unwrap_or_default();
    MobileSetupDraft {
        name: MobileTextField {
            property_id: prop::DEV_NAME,
            known: sync.supports_device_name,
            reported: sync.device_name.clone().unwrap_or_default(),
            text: name.unwrap_or_default(),
        },
        radio: MobileRadioDraft {
            reading_revision: 0,
            enabled: toggle(prop::PHY_ENABLED, true, Some(sync.phy_enabled), true),
            frequency_khz: integer(prop::PHY_FREQ, sync.frequency_khz.into()),
            transmit_power_dbm: integer(prop::PHY_TX_POWER, sync.transmit_power_dbm.into()),
            bandwidth: choice(
                prop::PHY_LORA_BW,
                gates.shows_modem,
                sync.bandwidth_hz.map(Into::into),
                defaults.bandwidth_hz,
            ),
            spreading_factor: choice(
                prop::PHY_LORA_SF,
                gates.shows_modem,
                sync.spreading_factor.map(Into::into),
                defaults.spreading_factor,
            ),
            coding_rate: choice(
                prop::PHY_LORA_CR,
                gates.shows_modem,
                sync.coding_rate_denom.map(Into::into),
                defaults.coding_rate,
            ),
            duty_limit: choice(
                prop::PHY_DUTY_LIMIT,
                gates.shows_duty_limit,
                sync.duty_cycle_limit.map(Into::into),
                defaults.duty_limit,
            ),
        },
        discoverable: toggle(
            prop::DEV_DISCOVERABLE,
            gates.shows_discoverable,
            sync.dev_discoverable,
            defaults.discoverable,
        ),
        repeater: MobileRepeaterDraft {
            reading_revision: 0,
            mode: choice(
                prop::MAC_REPEATER_MODE,
                forwarding,
                repeater.map(|repeater| repeater.mode.into()),
                defaults.repeater_mode,
            ),
            regions: MobileTextListField {
                property_id: prop::MAC_REPEATER_REGIONS,
                known: forwarding,
                reported: regions.clone().unwrap_or_default(),
                value: regions.unwrap_or_default(),
            },
            default_region: MobileTextField {
                property_id: prop::MAC_REPEATER_DEFAULT_REGION,
                known: forwarding,
                reported: default_region.clone(),
                text: default_region,
            },
            min_rssi: threshold(
                prop::MAC_REPEATER_MIN_RSSI,
                repeater.and_then(|repeater| repeater.min_rssi_dbm.map(Into::into)),
            ),
            min_snr: threshold(
                prop::MAC_REPEATER_MIN_SNR,
                repeater.and_then(|repeater| repeater.min_snr_db.map(Into::into)),
            ),
        },
        gnss_enabled: toggle(
            prop::GNSS_ENABLED,
            positioning,
            gnss.map(|gnss| gnss.enabled),
            defaults.gnss_enabled,
        ),
        share_position: toggle(
            prop::GNSS_IDENT_UPDATE,
            positioning,
            gnss.map(|gnss| gnss.ident_update),
            defaults.share_position,
        ),
        precision: choice(
            prop::GNSS_IDENT_PRECISION,
            positioning,
            gnss.map(|gnss| gnss.ident_precision.into()),
            defaults.precision,
        ),
        time_trust: toggle(
            prop::GNSS_TIME_TRUST,
            positioning,
            gnss.map(|gnss| gnss.time_trust),
            defaults.time_trust,
        ),
        advert_interval: choice(
            prop::ADVERT_INTERVAL,
            announcements,
            advert.map(|advert| advert.advert_interval_seconds.into()),
            defaults.advert_interval_s,
        ),
        beacon_interval: choice(
            prop::BEACON_INTERVAL,
            announcements,
            advert.map(|advert| advert.beacon_interval_seconds.into()),
            defaults.beacon_interval_s,
        ),
        startup_beacon: toggle(
            prop::STARTUP_BEACON,
            announcements,
            advert.map(|advert| advert.startup_beacon),
            defaults.startup_beacon,
        ),
        administrators: MobileKeyListField {
            property_id: prop::DEV_ADMINS,
            known: gates.shows_administrators,
            reported: admins.clone(),
            value: admins,
        },
        profile_settled: false,
    }
}

/// A number the device always reports.
fn integer(property_id: u32, reported: i64) -> MobileIntegerField {
    MobileIntegerField {
        property_id,
        known: true,
        reported,
        value: reported,
    }
}

/// Put the radio fields on a copied profile, whatever their `known`: an
/// unknown one is never written.
fn adopt_copied(radio: &mut MobileRadioDraft, copied: CopiedProfile) {
    radio.enabled.value = true;
    radio.frequency_khz.value = copied.frequency_khz;
    radio.transmit_power_dbm.value = copied.transmit_power_dbm;
    if let Some((bandwidth, sf, cr)) = copied.modem {
        radio.bandwidth.value = Some(bandwidth);
        radio.spreading_factor.value = Some(sf);
        radio.coding_rate.value = Some(cr);
    }
    if let Some(limit) = copied.duty_limit {
        radio.duty_limit.value = Some(limit);
    }
}

/// Force what `assumption` decides. Role, mobility and the zone are forced
/// whether or not the device reported them: one it would not report is
/// left out of the write.
fn force(
    assumption: Assumption,
    draft: &mut MobileSetupDraft,
    hidden: &mut Hidden,
    phone_node_key: Option<&[u8]>,
    phone_zone_rule: &str,
) {
    match assumption {
        Assumption::ForwardingOff => draft.repeater.mode.value = Some(0),
        Assumption::ForwardingOn => draft.repeater.mode.value = Some(1),
        Assumption::RadioEnabled => draft.radio.enabled.value = true,
        Assumption::AdvertisesTracker => hidden.role = Some(NodeRole::Tracker.as_byte()),
        // Derived, so the advertised role cannot drift from what it does.
        Assumption::RoleDerivedFromForwarding => hidden.role = None,
        Assumption::Mobile => hidden.mobile = true,
        Assumption::Stationary => hidden.mobile = false,
        Assumption::PhoneAdministers => {
            *draft = set_phone_administers(draft.clone(), phone_node_key, true);
        }
        Assumption::PhoneTimeZone => hidden.tz_rule = phone_zone_rule.to_owned(),
        Assumption::ClockFromPhone => {}
    }
}

// MARK: Edits

/// A vetted preset's parameters on the radio fields the device reported,
/// as `draft_adopt_preset`; settles a pending profile choice. Unchanged for
/// an id that is not a vetted preset.
#[uniffi::export]
pub fn setup_adopt_preset(draft: MobileSetupDraft, preset_id: String) -> MobileSetupDraft {
    if !ulcp_radio_presets()
        .iter()
        .any(|preset| preset.id == preset_id)
    {
        return draft;
    }
    let mut draft = draft;
    draft.radio = draft_adopt_preset(draft.radio, preset_id);
    draft.profile_settled = true;
    draft
}

/// One radio parameter, and a pending profile choice settled: any edit of
/// a parameter is a choice, even of the value it already had.
#[uniffi::export]
pub fn setup_set_radio_parameter(
    draft: MobileSetupDraft,
    parameter: MobileSetupRadioParameter,
    value: i64,
) -> MobileSetupDraft {
    let mut draft = draft;
    let radio = &mut draft.radio;
    match parameter {
        MobileSetupRadioParameter::Frequency => radio.frequency_khz.value = value,
        MobileSetupRadioParameter::TransmitPower => radio.transmit_power_dbm.value = value,
        MobileSetupRadioParameter::Bandwidth => radio.bandwidth.value = Some(value),
        MobileSetupRadioParameter::SpreadingFactor => radio.spreading_factor.value = Some(value),
        MobileSetupRadioParameter::CodingRate => radio.coding_rate.value = Some(value),
        MobileSetupRadioParameter::DutyLimit => radio.duty_limit.value = Some(value),
    }
    draft.profile_settled = true;
    draft
}

/// Let `key` manage the device. Idempotent; unchanged on a full list.
pub(in crate::app_core::manage) fn add_administrator(
    draft: MobileSetupDraft,
    key: &[u8],
) -> MobileSetupDraft {
    let mut draft = draft;
    let admins = &mut draft.administrators.value;
    if !admins.iter().any(|admin| admin == key) && admins.len() < usize::from(ulcp_max_dev_admins())
    {
        admins.push(key.to_vec());
    }
    draft
}

/// Stop `key` managing the device: this phone's key and the last entry
/// included.
pub(in crate::app_core::manage) fn remove_administrator(
    draft: MobileSetupDraft,
    key: &[u8],
) -> MobileSetupDraft {
    let mut draft = draft;
    draft.administrators.value.retain(|admin| admin != key);
    draft
}

/// Put this phone on the list or take it off. Unchanged without the
/// phone's key, and on a full list the phone is not on.
pub(in crate::app_core::manage) fn set_phone_administers(
    draft: MobileSetupDraft,
    phone_node_key: Option<&[u8]>,
    administers: bool,
) -> MobileSetupDraft {
    match phone_node_key {
        None => draft,
        Some(key) if administers => add_administrator(draft, key),
        Some(key) => remove_administrator(draft, key),
    }
}
