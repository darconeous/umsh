//! The setup rules, pure: refusals, assumptions, readability, defaults,
//! the radio profile, presets, validation, choices, administrators, the
//! read-back check and the role. The rules live in `manage/setup/`; each
//! test states the rule it checks.

use std::collections::BTreeMap;

use umsh_ulcp::Cmd;
use umsh_ulcp::ids::{
    DUTY_LIMIT_DISABLED, INTERFACE_TYPE, MAX_AUTO_ANNOUNCE_INTERVAL_S,
    MIN_AUTO_ANNOUNCE_INTERVAL_S, cap, prop, saved,
};

use super::{capabilities, items, key};
use crate::app_core::manage::draft::draft_adopt_preset;
use crate::app_core::manage::records::{MobileFieldProblem, MobileKeyEntryRecord};
use crate::app_core::manage::setup::{
    Assumption, DEFAULTS, Defaults, MobileSetupCompanionRecord, MobileSetupDraft, MobileSetupGoal,
    MobileSetupNote, MobileSetupProfile, MobileSetupProfileGap, MobileSetupRadioParameter,
    MobileSetupRefusal, MobileSetupResult, MobileSetupSection, MobileSetupSetting,
    MobileSetupUnreadable, Standing, add_administrator, advertised_role, assumptions, build,
    build_with, choices, companion_record, default_region_unlisted, first_mismatch, notes, refusal,
    remove_administrator, resolve_profile, sections, set_phone_administers, sets_clock,
    setup_adopt_preset, setup_set_radio_parameter, snapshot, unreadable, unshown_setting,
};
use crate::app_core::manage::setup::{Gates, Setup};
use crate::ulcp::{
    UlcpDeviceConfigRecord, UlcpPropertyFrameRecord, UlcpSyncRecord, device_config_writes,
    inspect_ulcp_sync, region_code_description, region_code_from_string, ulcp_max_dev_admins,
};

use MobileSetupGoal::{Repeater, Tracker};

const PHONE: u8 = 0x77;
pub(super) const ZONE: &str = "PST8PDT,M3.2.0,M11.1.0";
const NAME: &str = "Kestrel";

fn phone() -> Vec<u8> {
    key(PHONE)
}

fn code(region: &str) -> Vec<u8> {
    region_code_from_string(region.to_owned()).unwrap()
}

/// Every capability setup reads.
const CAPABILITIES: [u32; 12] = [
    cap::DEV_NAME,
    cap::PHY_LORA,
    cap::PHY_DUTY_LIMIT,
    cap::DEV_IDENTITY,
    cap::IDENT,
    cap::REPEATER,
    cap::MESHCORE_FORWARDER,
    cap::ADMIN,
    cap::TIME,
    cap::GNSS,
    cap::ADVERT,
    cap::SAVE,
];

/// A device as an attach reads it: capabilities and property answers,
/// reduced by `inspect_ulcp_sync` exactly as a session reduces them.
#[derive(Clone)]
pub(super) struct Device {
    capabilities: Vec<u32>,
    values: BTreeMap<u32, Vec<u8>>,
}

impl Device {
    /// A device with every setup capability, on `umsh-us-ca`, its radio
    /// off, forwarding for two regions and tagging with the first.
    pub(super) fn full() -> Self {
        let values = BTreeMap::from([
            (prop::INTERFACE_TYPE, vec![INTERFACE_TYPE as u8]),
            (prop::PHY_ENABLED, vec![0]),
            (prop::PHY_FREQ, 917_500u32.to_le_bytes().to_vec()),
            (prop::PHY_TX_POWER, vec![20]),
            (prop::PHY_LORA_BW, 500_000u32.to_le_bytes().to_vec()),
            (prop::PHY_LORA_SF, vec![10]),
            (prop::PHY_LORA_CR, vec![5]),
            (prop::PHY_DUTY_NOW, 0u16.to_le_bytes().to_vec()),
            (prop::PHY_DUTY_LIMIT, 6_553u16.to_le_bytes().to_vec()),
            (prop::SAVED, vec![saved::CURRENT]),
            (prop::DEV_NAME, b"Tallac Ridge".to_vec()),
            (prop::DEV_PEERS, Vec::new()),
            (prop::DEV_CHANNEL_KEYS, Vec::new()),
            (prop::DEV_DISCOVERABLE, vec![0]),
            (prop::DEV_ADMINS, key(0xa1)),
            (prop::MAC_REPEATER_MODE, vec![0]),
            (
                prop::MAC_REPEATER_REGIONS,
                items(&[b"SJC".to_vec(), b"WA".to_vec()]),
            ),
            (prop::MAC_REPEATER_DEFAULT_REGION, code("sjc")),
            (prop::MAC_REPEATER_MIN_RSSI, Vec::new()),
            (prop::MAC_REPEATER_MIN_SNR, Vec::new()),
            (prop::MESHCORE_FORWARDING_ENABLED, vec![1]),
            (prop::MESHCORE_REGION_POLICY, vec![1]),
            (prop::MESHCORE_REGIONS, items(&[b"bay".to_vec()])),
            (prop::IDENT_ROLE, vec![2]),
            (prop::IDENT_MOBILE, vec![0]),
            (prop::IDENT_LOCATION, Vec::new()),
            (prop::IDENT_ALTITUDE, Vec::new()),
            (prop::TZ_RULE, b"UTC0".to_vec()),
            (prop::TIME_24H, vec![0]),
            (prop::GNSS_ENABLED, vec![1]),
            (prop::GNSS_IDENT_UPDATE, vec![1]),
            (prop::GNSS_IDENT_PRECISION, vec![4]),
            (prop::GNSS_TIME_TRUST, vec![0]),
            (prop::ADVERT_INTERVAL, (12 * 3600u32).to_le_bytes().to_vec()),
            (prop::BEACON_INTERVAL, 1800u32.to_le_bytes().to_vec()),
            (prop::STARTUP_BEACON, vec![0]),
        ]);
        Self {
            capabilities: CAPABILITIES.to_vec(),
            values,
        }
    }

    pub(super) fn without(mut self, capability: u32) -> Self {
        self.capabilities.retain(|held| *held != capability);
        self
    }

    /// The device refuses each of `properties`: absent from its answer,
    /// so the attach records it unreadable.
    fn refusing(mut self, properties: &[u32]) -> Self {
        for property in properties {
            self.values.remove(property);
        }
        self
    }

    pub(super) fn with(mut self, property: u32, value: Vec<u8>) -> Self {
        self.values.insert(property, value);
        self
    }

    /// Its answers as a scripted device holds them, `PROP_CAPS` among
    /// them.
    pub(super) fn values(&self) -> BTreeMap<u32, Vec<u8>> {
        let mut values = self.values.clone();
        values.insert(prop::CAPS, capabilities(&self.capabilities));
        values
    }

    fn sync(&self) -> UlcpSyncRecord {
        let frame = |property_id, value: &[u8]| UlcpPropertyFrameRecord {
            transaction_id: 1,
            command: Cmd::PropIs as u8,
            property_id,
            value: value.to_vec(),
        };
        let mut frames = vec![frame(prop::CAPS, &capabilities(&self.capabilities))];
        frames.extend(
            self.values
                .iter()
                .map(|(property, value)| frame(*property, value)),
        );
        inspect_ulcp_sync(frames).unwrap()
    }
}

fn setup_of(goal: MobileSetupGoal, device: &Device) -> Setup {
    setup_with(goal, device, None)
}

fn setup_with(
    goal: MobileSetupGoal,
    device: &Device,
    companion: Option<&MobileSetupCompanionRecord>,
) -> Setup {
    build(
        goal,
        Some(&device.sync()),
        Some(NAME.to_owned()),
        companion,
        Some(phone()),
        ZONE,
    )
    .unwrap()
}

/// The phone's radio on `meshcore-us-ca`, at 21 dBm, with no limit.
pub(super) fn companion() -> MobileSetupCompanionRecord {
    MobileSetupCompanionRecord {
        name: Some("Pocket".to_owned()),
        frequency_khz: 910_525,
        transmit_power_dbm: 21,
        bandwidth_hz: Some(62_500),
        spreading_factor: Some(7),
        coding_rate: Some(5),
        duty_limit: None,
    }
}

fn problems(setup: &Setup, draft: &MobileSetupDraft) -> Vec<u32> {
    setup
        .problems(draft)
        .into_iter()
        .map(|problem| {
            assert_eq!(problem.problem, MobileFieldProblem::OutOfRange);
            problem.property_id
        })
        .collect()
}

fn writes(setup: &Setup, draft: &MobileSetupDraft) -> Vec<(u32, Vec<u8>)> {
    setup.writes(setup.record(draft).unwrap()).unwrap()
}

fn written(writes: &[(u32, Vec<u8>)]) -> Vec<u32> {
    writes.iter().map(|(property, _)| *property).collect()
}

// MARK: Refusals

/// Each goal refuses a device that cannot report what it needs, naming
/// the first gap in a fixed order.
#[test]
fn each_goal_refuses_what_it_cannot_use_in_order() {
    assert_eq!(
        refusal(Tracker, None),
        Some(MobileSetupRefusal::NotReported)
    );
    assert_eq!(
        refusal(Repeater, None),
        Some(MobileSetupRefusal::NotReported)
    );
    let full = Device::full();
    assert_eq!(refusal(Tracker, Some(&full.sync())), None);
    assert_eq!(refusal(Repeater, Some(&full.sync())), None);

    let tracker = |device: Device| refusal(Tracker, Some(&device.sync()));
    assert_eq!(
        tracker(Device::full().without(cap::DEV_IDENTITY)),
        Some(MobileSetupRefusal::NoDeviceIdentity)
    );
    // The identity is checked first.
    assert_eq!(
        tracker(
            Device::full()
                .without(cap::DEV_IDENTITY)
                .without(cap::ADVERT)
        ),
        Some(MobileSetupRefusal::NoDeviceIdentity)
    );
    assert_eq!(
        tracker(Device::full().without(cap::ADVERT)),
        Some(MobileSetupRefusal::NoAdvertSchedule)
    );
    // A tracker does not care whether the device forwards.
    assert_eq!(tracker(Device::full().without(cap::REPEATER)), None);

    let repeater = |device: Device| refusal(Repeater, Some(&device.sync()));
    assert_eq!(
        repeater(Device::full().without(cap::REPEATER)),
        Some(MobileSetupRefusal::CannotForward)
    );
    assert_eq!(
        repeater(
            Device::full()
                .without(cap::REPEATER)
                .refusing(&[prop::MAC_REPEATER_MODE])
        ),
        Some(MobileSetupRefusal::CannotForward)
    );
    assert_eq!(
        repeater(Device::full().refusing(&[prop::MAC_REPEATER_MIN_SNR])),
        Some(MobileSetupRefusal::ForwardingUnreported)
    );
    // A repeater is not gated on announcing.
    assert_eq!(repeater(Device::full().without(cap::ADVERT)), None);

    // `build` answers the same refusal and no draft.
    assert_eq!(
        build(
            Repeater,
            Some(&Device::full().without(cap::REPEATER).sync()),
            None,
            None,
            None,
            ZONE
        ),
        Err(MobileSetupRefusal::CannotForward)
    );
}

// MARK: The plan

/// Each goal assumes its own forwarding mode, role, mobility and
/// administrators; the rest is carried as reported.
#[test]
fn each_goal_assumes_its_own_values() {
    let device = Device::full().with(prop::MAC_REPEATER_MODE, vec![1]);
    let tracker = setup_of(Tracker, &device);
    assert_eq!(tracker.built.repeater.mode.value, Some(0));
    assert!(tracker.built.radio.enabled.value);
    assert_eq!(tracker.hidden.role, Some(3));
    assert!(tracker.hidden.mobile);
    assert_eq!(tracker.hidden.tz_rule, ZONE);
    // A tracker does not put the phone on the list.
    assert_eq!(tracker.built.administrators.value, vec![key(0xa1)]);

    let device = Device::full().with(prop::IDENT_MOBILE, vec![1]);
    let repeater = setup_of(Repeater, &device);
    assert_eq!(repeater.built.repeater.mode.value, Some(1));
    assert!(repeater.built.radio.enabled.value);
    assert_eq!(repeater.hidden.role, None);
    assert!(!repeater.hidden.mobile);
    assert_eq!(repeater.hidden.tz_rule, ZONE);
    assert_eq!(
        repeater.built.administrators.value,
        vec![key(0xa1), phone()]
    );
    // What no goal decides is carried as reported.
    assert!(!repeater.hidden.time_24h);
    assert!(repeater.hidden.meshcore.enabled);
    assert_eq!(repeater.hidden.meshcore.regions, vec!["bay".to_owned()]);

    assert_eq!(
        assumptions(Tracker),
        [
            Assumption::ForwardingOff,
            Assumption::RadioEnabled,
            Assumption::AdvertisesTracker,
            Assumption::Mobile,
            Assumption::PhoneTimeZone,
            Assumption::ClockFromPhone,
        ]
    );
    assert_eq!(
        assumptions(Repeater),
        [
            Assumption::ForwardingOn,
            Assumption::RadioEnabled,
            Assumption::RoleDerivedFromForwarding,
            Assumption::Stationary,
            Assumption::PhoneAdministers,
            Assumption::PhoneTimeZone,
            Assumption::ClockFromPhone,
        ]
    );
}

/// An assumption the device cannot be told is skipped.
#[test]
fn an_assumption_applies_only_where_the_device_can_take_it() {
    let full = Device::full().sync();
    let gated = [
        (
            Assumption::ForwardingOff,
            Device::full().without(cap::REPEATER),
        ),
        (
            Assumption::ForwardingOn,
            Device::full().refusing(&[prop::MAC_REPEATER_REGIONS]),
        ),
        (
            Assumption::AdvertisesTracker,
            Device::full().without(cap::IDENT),
        ),
        (
            Assumption::RoleDerivedFromForwarding,
            Device::full().without(cap::IDENT),
        ),
        (Assumption::Mobile, Device::full().without(cap::IDENT)),
        (Assumption::Stationary, Device::full().without(cap::IDENT)),
        (
            Assumption::PhoneAdministers,
            Device::full().without(cap::ADMIN),
        ),
        (
            Assumption::PhoneAdministers,
            Device::full().refusing(&[prop::DEV_ADMINS]),
        ),
        (Assumption::PhoneTimeZone, Device::full().without(cap::TIME)),
        (
            Assumption::ClockFromPhone,
            Device::full().without(cap::TIME),
        ),
    ];
    for (assumption, device) in gated {
        assert!(assumption.applies(&full), "{assumption:?}");
        assert!(!assumption.applies(&device.sync()), "{assumption:?}");
    }
    // Every device has a radio.
    let bare = Device::full()
        .without(cap::PHY_LORA)
        .without(cap::REPEATER)
        .without(cap::IDENT)
        .without(cap::TIME)
        .without(cap::ADMIN);
    assert!(Assumption::RadioEnabled.applies(&bare.sync()));

    // Unapplied, the values stay as reported.
    let device = Device::full()
        .without(cap::IDENT)
        .without(cap::TIME)
        .with(prop::MAC_REPEATER_MODE, vec![1]);
    let tracker = setup_of(Tracker, &device.clone().without(cap::REPEATER));
    assert_eq!(tracker.hidden.role, None);
    assert!(!tracker.hidden.mobile);
    assert!(!sets_clock(Tracker, &device.sync()));
    assert!(sets_clock(Tracker, &Device::full().sync()));
    assert!(sets_clock(Repeater, &Device::full().sync()));
    let unlisted = setup_of(Repeater, &Device::full().refusing(&[prop::DEV_ADMINS]));
    assert!(unlisted.built.administrators.value.is_empty());
}

/// On a full list, or with no key for this phone, the repeater's phone assumption does nothing.
#[test]
fn the_phone_assumption_does_nothing_on_a_full_list_or_without_a_key() {
    let admins: Vec<Vec<u8>> = (0..ulcp_max_dev_admins()).map(|n| key(0xc0 + n)).collect();
    let full = Device::full().with(prop::DEV_ADMINS, admins.concat());
    let setup = setup_of(Repeater, &full);
    assert_eq!(setup.built.administrators.value, admins);

    let keyless = build(
        Repeater,
        Some(&Device::full().sync()),
        None,
        None,
        None,
        ZONE,
    )
    .unwrap();
    assert_eq!(keyless.built.administrators.value, vec![key(0xa1)]);
}

/// Each goal shows its sections only where the device reported them.
#[test]
fn each_goal_shows_its_sections_where_the_device_reported_them() {
    use MobileSetupSection::{
        Administrators, Announcements, Discoverability, Forwarding, Name, Positioning, RadioProfile,
    };
    let shown = |goal, device: &Device| {
        let sync = device.sync();
        sections(goal, &sync, &Gates::of(&sync))
    };
    let full = Device::full();
    assert_eq!(
        shown(Tracker, &full),
        [
            Name,
            Discoverability,
            Positioning,
            Announcements,
            RadioProfile
        ]
    );
    assert_eq!(
        shown(Repeater, &full),
        [
            Name,
            Forwarding,
            Discoverability,
            Positioning,
            Announcements,
            RadioProfile,
            Administrators,
        ]
    );
    let dropped = [
        (Name, Device::full().without(cap::DEV_NAME)),
        (
            Forwarding,
            Device::full().refusing(&[prop::MAC_REPEATER_MODE]),
        ),
        (
            Discoverability,
            Device::full().refusing(&[prop::DEV_DISCOVERABLE]),
        ),
        (
            Positioning,
            Device::full().refusing(&[prop::GNSS_TIME_TRUST]),
        ),
        (
            Announcements,
            Device::full().refusing(&[prop::STARTUP_BEACON]),
        ),
        (Administrators, Device::full().refusing(&[prop::DEV_ADMINS])),
    ];
    for (section, device) in dropped {
        let sections = shown(Repeater, &device);
        assert!(!sections.contains(&section), "{section:?}");
        assert_eq!(sections.len(), 6, "{section:?}");
    }
    // The radio profile always stays.
    let bare = Device::full()
        .without(cap::DEV_NAME)
        .without(cap::DEV_IDENTITY)
        .without(cap::GNSS)
        .without(cap::ADVERT);
    assert_eq!(shown(Tracker, &bare), [RadioProfile]);
}

/// The notes name what the goal cannot do, one note each, in order.
#[test]
fn notes_name_what_the_goal_cannot_do_in_order() {
    assert!(notes(&Device::full().sync()).is_empty());
    let bare = Device::full()
        .without(cap::GNSS)
        .without(cap::IDENT)
        .without(cap::TIME);
    assert_eq!(
        notes(&bare.sync()),
        [
            MobileSetupNote::NoPositioning,
            MobileSetupNote::NoRole,
            MobileSetupNote::NoClock,
        ]
    );
    assert_eq!(
        notes(&Device::full().without(cap::IDENT).sync()),
        [MobileSetupNote::NoRole]
    );
}

/// The record a setup publishes carries its plan, or its refusal.
#[test]
fn the_record_carries_the_plan_or_the_refusal() {
    let device = Device::full();
    let tracker = setup_of(Tracker, &device);
    let record = snapshot(
        Tracker,
        Ok(&tracker),
        Some(phone()),
        Some(device.sync()),
        false,
        None,
    );
    assert_eq!(record.refusal, None);
    assert_eq!(record.sections.len(), 5);
    assert!(record.notes.is_empty() && record.unreadable.is_empty());
    assert_eq!(
        record.profile,
        Some(MobileSetupProfile::MustChoose {
            gap: MobileSetupProfileGap::NoCompanion
        })
    );
    assert!(record.shows_presets && record.shows_modem && record.shows_duty_limit);
    assert!(!record.suggests_regions_from_phone);
    // Chat, as the device reports it.
    assert_eq!(record.advertised_role, Some(2));

    let refused = snapshot(
        Repeater,
        Err(MobileSetupRefusal::CannotForward),
        None,
        Some(device.sync()),
        false,
        Some(MobileSetupResult::Invalid),
    );
    assert_eq!(refused.refusal, Some(MobileSetupRefusal::CannotForward));
    assert!(refused.sections.is_empty() && refused.profile.is_none());
    assert!(!refused.shows_presets && !refused.shows_modem);
    assert!(refused.suggests_regions_from_phone);
    assert_eq!(refused.last_result, Some(MobileSetupResult::Invalid));
}

// MARK: Readability

/// Each gate reads only its own settings.
#[test]
fn each_gate_reads_its_own_settings() {
    let gates = |device: Device| Gates::of(&device.sync());
    let full = gates(Device::full());
    assert!(
        full.shows_modem
            && full.shows_duty_limit
            && full.shows_discoverable
            && full.shows_forwarding
            && full.shows_positioning
            && full.shows_announcements
            && full.shows_administrators
            && full.shows_presets
            && full.shows_identity
            && full.shows_time_zone
    );
    // Part of the modem profile is none of it.
    for property in [prop::PHY_LORA_BW, prop::PHY_LORA_SF, prop::PHY_LORA_CR] {
        let partial = gates(Device::full().refusing(&[property]));
        assert!(!partial.shows_modem && !partial.shows_presets, "{property}");
        let draft = setup_of(Tracker, &Device::full().refusing(&[property])).built;
        assert!(
            !draft.radio.bandwidth.known
                && !draft.radio.spreading_factor.known
                && !draft.radio.coding_rate.known
        );
    }
    type Shows = fn(&Gates) -> bool;
    let cases: [(Device, Shows); 9] = [
        (Device::full().refusing(&[prop::PHY_DUTY_LIMIT]), |g| {
            g.shows_duty_limit || g.shows_presets
        }),
        (Device::full().refusing(&[prop::DEV_DISCOVERABLE]), |g| {
            g.shows_discoverable
        }),
        (
            Device::full().refusing(&[prop::MAC_REPEATER_REGIONS]),
            |g| g.shows_forwarding,
        ),
        (Device::full().refusing(&[prop::GNSS_ENABLED]), |g| {
            g.shows_positioning
        }),
        (Device::full().refusing(&[prop::BEACON_INTERVAL]), |g| {
            g.shows_announcements
        }),
        (Device::full().refusing(&[prop::DEV_ADMINS]), |g| {
            g.shows_administrators
        }),
        (Device::full().refusing(&[prop::IDENT_MOBILE]), |g| {
            g.shows_identity
        }),
        (Device::full().refusing(&[prop::TZ_RULE]), |g| {
            g.shows_time_zone
        }),
        (Device::full().without(cap::DEV_IDENTITY), |g| {
            g.shows_discoverable
        }),
    ];
    for (device, shows) in cases {
        assert!(!shows(&gates(device)));
    }
    // A device with no modem and no limit offers presets on its frequency.
    let plain = gates(
        Device::full()
            .without(cap::PHY_LORA)
            .without(cap::PHY_DUTY_LIMIT),
    );
    assert!(plain.shows_presets && !plain.shows_modem && !plain.shows_duty_limit);
}

/// Unreadable settings are named in a fixed order.
#[test]
fn unreadable_settings_are_named_in_order() {
    assert!(unreadable(&Device::full().sync()).is_empty());
    let everything = Device::full().refusing(&[
        prop::PHY_LORA_SF,
        prop::PHY_DUTY_LIMIT,
        prop::IDENT_MOBILE,
        prop::DEV_DISCOVERABLE,
        prop::MAC_REPEATER_MODE,
        prop::MESHCORE_REGIONS,
        prop::GNSS_ENABLED,
        prop::ADVERT_INTERVAL,
        prop::TZ_RULE,
        prop::DEV_ADMINS,
    ]);
    assert_eq!(
        unreadable(&everything.sync()),
        [
            MobileSetupUnreadable::ModemProfile,
            MobileSetupUnreadable::TransmitLimit,
            MobileSetupUnreadable::AdvertisedIdentity,
            MobileSetupUnreadable::Discoverability,
            MobileSetupUnreadable::ForwardingPolicy,
            MobileSetupUnreadable::MeshCoreForwarding,
            MobileSetupUnreadable::Positioning,
            MobileSetupUnreadable::Announcements,
            MobileSetupUnreadable::TimeZone,
            MobileSetupUnreadable::Administrators,
        ]
    );
    // A missing capability is not an unreadable setting.
    let bare = Device::full()
        .without(cap::PHY_LORA)
        .without(cap::GNSS)
        .without(cap::ADMIN);
    assert!(unreadable(&bare.sync()).is_empty());
}

// MARK: Defaults

/// Every gated group a device can refuse, one property from each.
const REFUSABLE: [u32; 9] = [
    prop::PHY_LORA_CR,
    prop::PHY_DUTY_LIMIT,
    prop::IDENT_MOBILE,
    prop::DEV_DISCOVERABLE,
    prop::MAC_REPEATER_MIN_RSSI,
    prop::MESHCORE_REGION_POLICY,
    prop::GNSS_IDENT_PRECISION,
    prop::ADVERT_INTERVAL,
    prop::TZ_RULE,
];

/// A setting the device did not report is unknown and holds its default.
#[test]
fn an_unreported_setting_is_unknown_and_holds_its_default() {
    let device = Device::full().refusing(&REFUSABLE).refusing(&[
        prop::DEV_ADMINS,
        prop::TIME_24H,
        prop::IDENT_ROLE,
    ]);
    let setup = setup_of(Tracker, &device);
    let draft = &setup.built;
    let radio = &draft.radio;
    // The rest of the triple is still the device's own, but unknown.
    assert!(!radio.bandwidth.known && !radio.spreading_factor.known);
    assert_eq!(radio.coding_rate.value, Some(DEFAULTS.coding_rate));
    assert!(!radio.duty_limit.known);
    assert_eq!(radio.duty_limit.value, Some(i64::from(DUTY_LIMIT_DISABLED)));
    assert!(!draft.discoverable.known && draft.discoverable.value);
    let repeater = &draft.repeater;
    assert!(
        !repeater.mode.known
            && !repeater.regions.known
            && !repeater.default_region.known
            && !repeater.min_rssi.known
            && !repeater.min_snr.known
    );
    assert!(repeater.regions.value.is_empty() && repeater.default_region.text.is_empty());
    assert_eq!(repeater.min_rssi.value, None);
    assert!(!draft.precision.known);
    assert_eq!(draft.precision.value, Some(5));
    assert!(!draft.gnss_enabled.value && !draft.share_position.value && draft.time_trust.value);
    assert!(!draft.advert_interval.known);
    assert_eq!(
        (draft.advert_interval.value, draft.beacon_interval.value),
        (Some(14_400), Some(3_600))
    );
    assert!(draft.startup_beacon.value);
    assert!(!draft.administrators.known && draft.administrators.value.is_empty());
    assert!(setup.hidden.time_24h);
    assert_eq!(setup.hidden.meshcore, DEFAULTS.meshcore);
    assert_eq!(setup.hidden.tz_rule, ZONE);
    // The name is the link's, not the record's.
    assert_eq!(draft.name.text, NAME);
    assert_eq!(draft.name.reported, "Tallac Ridge");
    assert!(draft.name.known);
    // Known fields are the device's.
    let full = setup_of(Tracker, &Device::full());
    assert_eq!(full.built.precision.value, Some(4));
    assert_eq!(full.built.radio.duty_limit.value, Some(6_553));
    assert!(!full.built.discoverable.value);
}

/// A placeholder never reaches the wire.
#[test]
fn defaults_never_reach_the_wire() {
    let device = Device::full().refusing(&REFUSABLE);
    let sync = device.sync();
    let other = Defaults {
        bandwidth_hz: 250_000,
        spreading_factor: 12,
        coding_rate: 8,
        duty_limit: 655,
        discoverable: false,
        repeater_mode: 2,
        gnss_enabled: true,
        share_position: true,
        precision: 7,
        time_trust: false,
        advert_interval_s: 3_600,
        beacon_interval_s: 1_200,
        startup_beacon: false,
        mobile: true,
        time_24h: false,
        meshcore: crate::ulcp::UlcpMeshCoreSettingsRecord {
            enabled: true,
            region_policy: 2,
            regions: vec!["sea".to_owned()],
        },
    };
    {
        let ours = setup_of(Tracker, &device);
        let theirs = build_with(
            Tracker,
            Some(&sync),
            Some(NAME.to_owned()),
            None,
            Some(phone()),
            ZONE,
            &other,
        )
        .unwrap();
        assert_ne!(ours.record(&ours.built), theirs.record(&theirs.built));
        let ours = writes(&ours, &ours.built);
        assert_eq!(ours, writes(&theirs, &theirs.built));
        let properties = written(&ours);
        for group in [
            &[prop::PHY_LORA_BW, prop::PHY_LORA_SF, prop::PHY_LORA_CR][..],
            &[prop::PHY_DUTY_LIMIT],
            &[prop::IDENT_MOBILE],
            &[prop::DEV_DISCOVERABLE],
            &[
                prop::MAC_REPEATER_MODE,
                prop::MAC_REPEATER_REGIONS,
                prop::MAC_REPEATER_DEFAULT_REGION,
                prop::MAC_REPEATER_MIN_RSSI,
                prop::MAC_REPEATER_MIN_SNR,
            ],
            &[
                prop::MESHCORE_FORWARDING_ENABLED,
                prop::MESHCORE_REGION_POLICY,
                prop::MESHCORE_REGIONS,
            ],
            &[
                prop::GNSS_ENABLED,
                prop::GNSS_IDENT_UPDATE,
                prop::GNSS_IDENT_PRECISION,
                prop::GNSS_TIME_TRUST,
            ],
            &[
                prop::ADVERT_INTERVAL,
                prop::BEACON_INTERVAL,
                prop::STARTUP_BEACON,
            ],
            &[prop::TZ_RULE],
        ] {
            for property in group {
                assert!(!properties.contains(property), "{property}");
            }
        }
        // What the device reported is still written.
        for property in [
            prop::DEV_NAME,
            prop::PHY_FREQ,
            prop::PHY_TX_POWER,
            prop::IDENT_ROLE,
            prop::TIME_24H,
        ] {
            assert!(properties.contains(&property), "{property}");
        }
    }
}

/// For every combination of refused groups, with and without a copied
/// profile, the built draft has no problem and encodes.
#[test]
fn defaults_and_copies_never_trip_the_backstop() {
    let companion = companion();
    for mask in 0u32..(1 << REFUSABLE.len()) {
        let refused: Vec<u32> = REFUSABLE
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, property)| *property)
            .collect();
        let device = Device::full().refusing(&refused);
        for goal in [Tracker, Repeater] {
            for companion in [None, Some(&companion)] {
                let sync = device.sync();
                let Ok(setup) = build(
                    goal,
                    Some(&sync),
                    Some(NAME.to_owned()),
                    companion,
                    Some(phone()),
                    ZONE,
                ) else {
                    continue;
                };
                assert!(setup.problems(&setup.built).is_empty(), "{refused:?}");
                assert!(
                    setup.writes(setup.record(&setup.built).unwrap()).is_some(),
                    "{refused:?}"
                );
            }
        }
    }
    // A MeshCore name the device reports but would refuse on write leaves
    // the list unreadable, so it is never written back.
    let device = Device::full().with(prop::MESHCORE_REGIONS, items(&[b"#bay".to_vec()]));
    for goal in [Tracker, Repeater] {
        let setup = setup_of(goal, &device);
        assert!(setup.problems(&setup.built).is_empty());
        assert!(!written(&writes(&setup, &setup.built)).contains(&prop::MESHCORE_REGIONS));
    }

    // An unknown field set out of range by hand is not a problem: it is
    // never written.
    let setup = setup_of(Tracker, &Device::full().refusing(&REFUSABLE));
    let mut draft = setup.built.clone();
    draft.radio.spreading_factor.value = Some(99);
    draft.radio.duty_limit.value = Some(-1);
    draft.precision.value = Some(0);
    draft.advert_interval.value = Some(1);
    draft.discoverable.value = false;
    assert!(setup.problems(&draft).is_empty());
    assert_eq!(writes(&setup, &draft), writes(&setup, &setup.built));
    // The modem would not read, so nothing is pending and Apply is open.
    assert!(setup.review(&draft, Standing::default()).can_apply);
}

// MARK: The radio profile

/// The radio profile is copied from the companion where it can be, left
/// as found where the device would not report the rest, and otherwise
/// must be chosen; a device whose modem is unreported keeps its radio.
#[test]
fn the_profile_resolves_from_the_companion_and_the_device() {
    let resolve = |companion: Option<&MobileSetupCompanionRecord>, device: Device| {
        resolve_profile(companion, &device.sync()).0
    };
    let must = |gap| MobileSetupProfile::MustChoose { gap };
    let left = |gap| MobileSetupProfile::LeftAsFound { gap };
    assert_eq!(
        resolve(None, Device::full()),
        must(MobileSetupProfileGap::NoCompanion)
    );
    assert_eq!(
        resolve(None, Device::full().refusing(&[prop::PHY_LORA_SF])),
        left(MobileSetupProfileGap::NoCompanion)
    );
    assert_eq!(
        resolve(None, Device::full().refusing(&[prop::PHY_DUTY_LIMIT])),
        left(MobileSetupProfileGap::NoCompanion)
    );
    let modemless = MobileSetupCompanionRecord {
        spreading_factor: None,
        ..companion()
    };
    assert_eq!(
        resolve(Some(&modemless), Device::full()),
        must(MobileSetupProfileGap::CompanionHasNoModemProfile)
    );
    assert_eq!(
        resolve(
            Some(&modemless),
            Device::full().refusing(&[prop::PHY_DUTY_LIMIT])
        ),
        left(MobileSetupProfileGap::CompanionHasNoModemProfile)
    );
    // A device with no modem takes the frequency and power alone.
    assert_eq!(
        resolve(Some(&modemless), Device::full().without(cap::PHY_LORA)),
        MobileSetupProfile::Copied {
            companion_name: Some("Pocket".to_owned())
        }
    );
    // A device that would not report its modem keeps its own radio.
    let unread = Device::full().refusing(&[prop::PHY_LORA_BW]);
    assert_eq!(
        resolve(Some(&companion()), unread.clone()),
        left(MobileSetupProfileGap::DeviceModemUnreported)
    );
    let kept = setup_with(Tracker, &unread, Some(&companion()));
    assert_eq!(kept.built.radio.frequency_khz.value, 917_500);
    assert_eq!(kept.built.radio.transmit_power_dbm.value, 20);
    assert!(kept.profile_chosen(&kept.built));
}

/// A copied profile lands on the radio fields.
#[test]
fn a_copied_profile_lands_on_the_radio_fields() {
    let setup = setup_with(Tracker, &Device::full(), Some(&companion()));
    assert_eq!(
        setup.profile,
        MobileSetupProfile::Copied {
            companion_name: Some("Pocket".to_owned())
        }
    );
    let radio = &setup.built.radio;
    assert!(radio.enabled.value);
    assert_eq!(radio.frequency_khz.value, 910_525);
    assert_eq!(radio.transmit_power_dbm.value, 21);
    assert_eq!(
        (
            radio.bandwidth.value,
            radio.spreading_factor.value,
            radio.coding_rate.value
        ),
        (Some(62_500), Some(7), Some(5))
    );
    // No limit on the companion: the device's own stands.
    assert_eq!(radio.duty_limit.value, Some(6_553));
    let limited = MobileSetupCompanionRecord {
        duty_limit: Some(655),
        ..companion()
    };
    let setup = setup_with(Tracker, &Device::full(), Some(&limited));
    assert_eq!(setup.built.radio.duty_limit.value, Some(655));
    // Neither has one: disabled.
    let (_, copied) = resolve_profile(
        Some(&companion()),
        &Device::full().refusing(&[prop::PHY_DUTY_LIMIT]).sync(),
    );
    assert_eq!(
        copied.unwrap().duty_limit,
        Some(i64::from(DUTY_LIMIT_DISABLED))
    );
    // A device without a limit or a modem is given neither.
    let (_, copied) = resolve_profile(
        Some(&companion()),
        &Device::full()
            .without(cap::PHY_DUTY_LIMIT)
            .without(cap::PHY_LORA)
            .sync(),
    );
    let copied = copied.unwrap();
    assert_eq!((copied.modem, copied.duty_limit), (None, None));
    assert_eq!(copied.frequency_khz, 910_525);
    // The preset follows the copy.
    let setup = setup_with(Tracker, &Device::full(), Some(&companion()));
    assert_eq!(
        setup.preset_id(&setup.built).as_deref(),
        Some("meshcore-us-ca")
    );
}

/// A profile is chosen by any edit of a parameter: a setter, a preset, or
/// a direct write that moves a value.
#[test]
fn a_profile_is_chosen_by_any_edit_of_a_parameter() {
    let setup = setup_of(Tracker, &Device::full());
    assert!(!setup.profile_chosen(&setup.built));
    // Re-picking the value shown settles through the function.
    let same = setup_set_radio_parameter(
        setup.built.clone(),
        MobileSetupRadioParameter::Frequency,
        917_500,
    );
    assert_eq!(same.radio, setup.built.radio);
    assert!(same.profile_settled && setup.profile_chosen(&same));
    // A direct write that moves a value settles; one that does not, not.
    let mut moved = setup.built.clone();
    moved.radio.duty_limit.value = Some(655);
    assert!(!moved.profile_settled && setup.profile_chosen(&moved));
    let mut unmoved = setup.built.clone();
    unmoved.radio.frequency_khz.value = 917_500;
    unmoved.radio.enabled.value = false;
    assert!(!setup.profile_chosen(&unmoved));
    // A preset settles.
    let preset = setup_adopt_preset(setup.built.clone(), "umsh-us-ca".to_owned());
    assert!(preset.profile_settled && setup.profile_chosen(&preset));
    // Nothing is pending on a copied or left profile.
    let copied = setup_with(Tracker, &Device::full(), Some(&companion()));
    assert!(copied.profile_chosen(&copied.built));
    // Every parameter's setter writes its own field.
    let draft = setup.built.clone();
    for (parameter, value) in [
        (MobileSetupRadioParameter::TransmitPower, 7),
        (MobileSetupRadioParameter::Bandwidth, 250_000),
        (MobileSetupRadioParameter::SpreadingFactor, 12),
        (MobileSetupRadioParameter::CodingRate, 8),
        (MobileSetupRadioParameter::DutyLimit, 65),
    ] {
        let radio = setup_set_radio_parameter(draft.clone(), parameter, value).radio;
        let held = match parameter {
            MobileSetupRadioParameter::TransmitPower => Some(radio.transmit_power_dbm.value),
            MobileSetupRadioParameter::Bandwidth => radio.bandwidth.value,
            MobileSetupRadioParameter::SpreadingFactor => radio.spreading_factor.value,
            MobileSetupRadioParameter::CodingRate => radio.coding_rate.value,
            MobileSetupRadioParameter::DutyLimit => radio.duty_limit.value,
            MobileSetupRadioParameter::Frequency => unreachable!(),
        };
        assert_eq!(held, Some(value), "{parameter:?}");
    }
}

/// The companion record is what the radio reports: an empty name is no
/// name, and a setting it lacks is absent.
#[test]
fn the_companion_record_is_the_radio_s_report() {
    let sync = Device::full().sync();
    assert_eq!(
        companion_record(Some("Pocket".to_owned()), &sync),
        MobileSetupCompanionRecord {
            name: Some("Pocket".to_owned()),
            frequency_khz: 917_500,
            transmit_power_dbm: 20,
            bandwidth_hz: Some(500_000),
            spreading_factor: Some(10),
            coding_rate: Some(5),
            duty_limit: Some(6_553),
        }
    );
    let plain = Device::full()
        .without(cap::PHY_LORA)
        .without(cap::PHY_DUTY_LIMIT)
        .sync();
    let record = companion_record(Some(String::new()), &plain);
    assert_eq!(record.name, None);
    assert_eq!(
        (
            record.bandwidth_hz,
            record.spreading_factor,
            record.duty_limit
        ),
        (None, None, None)
    );
}

// MARK: The forwarding policy

/// The forwarding-policy draft is built from the attach's record.
#[test]
fn the_forwarding_policy_is_built_from_the_record() {
    let setup = setup_of(Repeater, &Device::full());
    let repeater = &setup.built.repeater;
    assert!(repeater.mode.known && repeater.regions.known && repeater.min_snr.known);
    assert_eq!(repeater.reading_revision, 0);
    assert_eq!(repeater.regions.value, ["SJC", "WA"]);
    // Spelled as the list spells it.
    assert_eq!(repeater.default_region.text, "SJC");
    assert_eq!(repeater.default_region.reported, "SJC");
    let record = setup.record(&setup.built).unwrap().repeater.unwrap();
    assert_eq!(record.default_region, Some(code("sjc")));
    assert_eq!((record.min_rssi_dbm, record.min_snr_db), (None, None));
    let review = setup.review(&setup.built, Standing::default());
    assert_eq!(review.taggable_regions, ["SJC", "WA"]);
    assert!(!review.default_region_unlisted);

    // A tag the list does not hold is spelled as a code, still offered,
    // and flagged.
    let unlisted = Device::full().with(prop::MAC_REPEATER_DEFAULT_REGION, code("PDX"));
    let setup = setup_of(Repeater, &unlisted);
    let spelled = region_code_description(code("PDX")).unwrap();
    assert_eq!(setup.built.repeater.default_region.text, spelled);
    let review = setup.review(&setup.built, Standing::default());
    assert_eq!(
        review.taggable_regions,
        ["SJC".to_owned(), "WA".to_owned(), spelled]
    );
    assert!(review.default_region_unlisted);
    assert_eq!(
        setup
            .record(&setup.built)
            .unwrap()
            .repeater
            .unwrap()
            .default_region,
        Some(code("PDX"))
    );
    // Deleting the tagged region keeps the tag.
    let mut draft = setup_of(Repeater, &Device::full()).built;
    draft
        .repeater
        .regions
        .value
        .retain(|region| region != "SJC");
    assert_eq!(draft.repeater.default_region.text, "SJC");
    assert!(default_region_unlisted(&draft));

    // None tags nothing.
    let untagged = Device::full().with(prop::MAC_REPEATER_DEFAULT_REGION, Vec::new());
    let setup = setup_of(Repeater, &untagged);
    assert_eq!(setup.built.repeater.default_region.text, "");
    let review = setup.review(&setup.built, Standing::default());
    assert_eq!(review.taggable_regions, ["SJC", "WA"]);
    assert!(!review.default_region_unlisted);
    assert_eq!(
        setup
            .record(&setup.built)
            .unwrap()
            .repeater
            .unwrap()
            .default_region,
        None
    );
}

// MARK: Problems

/// The settings a problem with no box of its own names.
#[test]
fn a_problem_without_a_box_names_its_setting() {
    for property in [prop::DEV_NAME, prop::PHY_FREQ, prop::PHY_TX_POWER] {
        assert_eq!(unshown_setting(property), None);
    }
    for (property, setting) in [
        (prop::PHY_LORA_BW, MobileSetupSetting::Bandwidth),
        (prop::PHY_LORA_SF, MobileSetupSetting::SpreadingFactor),
        (prop::PHY_LORA_CR, MobileSetupSetting::CodingRate),
        (prop::PHY_DUTY_LIMIT, MobileSetupSetting::TransmitLimit),
        (
            prop::MAC_REPEATER_MODE,
            MobileSetupSetting::ForwardingPolicy,
        ),
        (
            prop::MAC_REPEATER_REGIONS,
            MobileSetupSetting::ForwardingPolicy,
        ),
        (
            prop::MAC_REPEATER_DEFAULT_REGION,
            MobileSetupSetting::ForwardingPolicy,
        ),
        (
            prop::MAC_REPEATER_MIN_RSSI,
            MobileSetupSetting::ForwardingPolicy,
        ),
        (
            prop::MAC_REPEATER_MIN_SNR,
            MobileSetupSetting::ForwardingPolicy,
        ),
        (prop::GNSS_IDENT_PRECISION, MobileSetupSetting::Positioning),
        (prop::ADVERT_INTERVAL, MobileSetupSetting::Announcements),
        (prop::BEACON_INTERVAL, MobileSetupSetting::Announcements),
    ] {
        assert_eq!(unshown_setting(property), Some(setting), "{property}");
    }
    // Once each, in the enum's order, the boxed ones left out.
    let setup = setup_of(Repeater, &Device::full());
    let mut draft = setup.built.clone();
    draft.name.text = String::new();
    draft.precision.value = Some(0);
    draft.repeater.min_snr.value = Some(200);
    draft.repeater.mode.value = Some(300);
    draft.radio.spreading_factor.value = Some(4);
    draft.beacon_interval.value = Some(1);
    draft.advert_interval.value = Some(1);
    let review = setup.review(&draft, Standing::default());
    assert_eq!(
        review.unshown_problems,
        [
            MobileSetupSetting::SpreadingFactor,
            MobileSetupSetting::ForwardingPolicy,
            MobileSetupSetting::Positioning,
            MobileSetupSetting::Announcements,
        ]
    );
    assert!(!review.can_apply);
}

// MARK: Presets

/// Presets are adopted and named from the fields; power and the duty
/// limit do not unname one.
#[test]
fn presets_are_adopted_and_named_from_the_fields() {
    let setup = setup_of(Tracker, &Device::full());
    assert_eq!(setup.preset_id(&setup.built).as_deref(), Some("umsh-us-ca"));
    let adopted = setup_adopt_preset(setup.built.clone(), "meshcore-us-ca".to_owned());
    assert!(adopted.profile_settled);
    assert_eq!(
        adopted.radio,
        draft_adopt_preset(setup.built.radio.clone(), "meshcore-us-ca".to_owned())
    );
    assert_eq!(adopted.radio.transmit_power_dbm.value, 21);
    assert_eq!(setup.preset_id(&adopted).as_deref(), Some("meshcore-us-ca"));
    // An unknown id changes nothing and settles nothing.
    let unchanged = setup_adopt_preset(setup.built.clone(), "custom".to_owned());
    assert_eq!(unchanged, setup.built);
    // Power and the limit do not unname a preset.
    let mut louder = setup.built.clone();
    louder.radio.transmit_power_dbm.value = 2;
    louder.radio.duty_limit.value = Some(65);
    assert_eq!(setup.preset_id(&louder).as_deref(), Some("umsh-us-ca"));
    let mut custom = setup.built.clone();
    custom.radio.spreading_factor.value = Some(11);
    assert_eq!(setup.preset_id(&custom), None);

    // A modem the device would not report names no preset, though the
    // frequency matches one.
    let unread = setup_of(Tracker, &Device::full().refusing(&[prop::PHY_LORA_CR]));
    assert_eq!(unread.built.radio.frequency_khz.value, 917_500);
    assert_eq!(unread.preset_id(&unread.built), None);
    // A device with no modem is named by its frequency.
    let plain = setup_of(Tracker, &Device::full().without(cap::PHY_LORA));
    assert_eq!(plain.preset_id(&plain.built).as_deref(), Some("umsh-us-ca"));
}

// MARK: Validation

/// At each boundary, against the encoder: a value review lets
/// through is one the encoder takes, and the first value past it is one
/// both refuse.
#[test]
fn review_refuses_exactly_what_the_encoder_refuses() {
    let setup = setup_of(Repeater, &Device::full());
    let base = setup.built.clone();
    assert!(problems(&setup, &base).is_empty());
    // Accepted by both.
    let fine = |edit: &dyn Fn(&mut MobileSetupDraft)| {
        let mut draft = base.clone();
        edit(&mut draft);
        assert!(problems(&setup, &draft).is_empty());
        let record = setup.record(&draft).unwrap();
        assert!(device_config_writes(record, &setup.sync).is_ok());
    };
    // Refused by both: by review on `property`, and by the encoder or
    // the record's own type.
    let refused = |property: u32, edit: &dyn Fn(&mut MobileSetupDraft)| {
        let mut draft = base.clone();
        edit(&mut draft);
        assert_eq!(problems(&setup, &draft), [property]);
        let review = setup.review(&draft, Standing::default());
        assert!(!review.can_apply);
        if let Some(record) = setup.record(&draft) {
            assert!(
                device_config_writes(record, &setup.sync).is_err(),
                "{property}"
            );
        }
    };
    let name = |text: &str| {
        let text = text.to_owned();
        move |draft: &mut MobileSetupDraft| draft.name.text.clone_from(&text)
    };
    fine(&name(&"n".repeat(64)));
    fine(&name("  Kestrel \n"));
    refused(prop::DEV_NAME, &name(""));
    refused(prop::DEV_NAME, &name("  \n\t"));
    refused(prop::DEV_NAME, &name(&"n".repeat(65)));
    refused(prop::DEV_NAME, &name("Kes\0trel"));
    // `é` is two bytes: 33 of them are 66.
    refused(prop::DEV_NAME, &name(&"é".repeat(33)));

    fine(&|draft| draft.radio.frequency_khz.value = 1);
    fine(&|draft| draft.radio.frequency_khz.value = i64::from(u32::MAX));
    refused(prop::PHY_FREQ, &|draft| draft.radio.frequency_khz.value = 0);
    refused(prop::PHY_FREQ, &|draft| {
        draft.radio.frequency_khz.value = i64::from(u32::MAX) + 1;
    });
    fine(&|draft| draft.radio.transmit_power_dbm.value = -128);
    fine(&|draft| draft.radio.transmit_power_dbm.value = 127);
    refused(prop::PHY_TX_POWER, &|draft| {
        draft.radio.transmit_power_dbm.value = 128;
    });
    refused(prop::PHY_TX_POWER, &|draft| {
        draft.radio.transmit_power_dbm.value = -129;
    });

    fine(&|draft| draft.radio.bandwidth.value = Some(1));
    refused(prop::PHY_LORA_BW, &|draft| {
        draft.radio.bandwidth.value = Some(0)
    });
    refused(prop::PHY_LORA_BW, &|draft| {
        draft.radio.bandwidth.value = None
    });
    for sf in [5, 12] {
        fine(&|draft| draft.radio.spreading_factor.value = Some(sf));
    }
    for sf in [4, 13] {
        refused(prop::PHY_LORA_SF, &|draft| {
            draft.radio.spreading_factor.value = Some(sf);
        });
    }
    for cr in [5, 8] {
        fine(&|draft| draft.radio.coding_rate.value = Some(cr));
    }
    for cr in [4, 9] {
        refused(prop::PHY_LORA_CR, &|draft| {
            draft.radio.coding_rate.value = Some(cr);
        });
    }
    fine(&|draft| draft.radio.duty_limit.value = Some(0));
    fine(&|draft| draft.radio.duty_limit.value = Some(65_535));
    refused(prop::PHY_DUTY_LIMIT, &|draft| {
        draft.radio.duty_limit.value = Some(65_536);
    });

    fine(&|draft| draft.repeater.mode.value = Some(255));
    refused(prop::MAC_REPEATER_MODE, &|draft| {
        draft.repeater.mode.value = Some(256);
    });
    fine(&|draft| draft.repeater.regions.value.push("r".repeat(24)));
    refused(prop::MAC_REPEATER_REGIONS, &|draft| {
        draft.repeater.regions.value.push("r".repeat(25));
    });
    refused(prop::MAC_REPEATER_REGIONS, &|draft| {
        draft.repeater.regions.value.push(String::new());
    });
    fine(&|draft| draft.repeater.default_region.text = "WA".to_owned());
    fine(&|draft| draft.repeater.default_region.text = String::new());
    refused(prop::MAC_REPEATER_DEFAULT_REGION, &|draft| {
        draft.repeater.default_region.text = "r".repeat(40);
    });
    fine(&|draft| draft.repeater.min_rssi.value = Some(-32_768));
    refused(prop::MAC_REPEATER_MIN_RSSI, &|draft| {
        draft.repeater.min_rssi.value = Some(-32_769);
    });
    fine(&|draft| draft.repeater.min_snr.value = Some(-128));
    refused(prop::MAC_REPEATER_MIN_SNR, &|draft| {
        draft.repeater.min_snr.value = Some(128);
    });

    for precision in [1, 7] {
        fine(&|draft| draft.precision.value = Some(precision));
    }
    for precision in [0, 8] {
        refused(prop::GNSS_IDENT_PRECISION, &|draft| {
            draft.precision.value = Some(precision);
        });
    }
    let min = i64::from(MIN_AUTO_ANNOUNCE_INTERVAL_S);
    let max = i64::from(MAX_AUTO_ANNOUNCE_INTERVAL_S);
    for seconds in [0, min, max] {
        fine(&|draft| draft.advert_interval.value = Some(seconds));
        fine(&|draft| draft.beacon_interval.value = Some(seconds));
    }
    for seconds in [min - 1, max + 1, -1] {
        refused(prop::ADVERT_INTERVAL, &|draft| {
            draft.advert_interval.value = Some(seconds);
        });
        refused(prop::BEACON_INTERVAL, &|draft| {
            draft.beacon_interval.value = Some(seconds);
        });
    }
    // The trimmed name is what the record carries.
    let mut draft = base.clone();
    draft.name.text = "  Kestrel \n".to_owned();
    assert_eq!(
        setup.record(&draft).unwrap().radio.device_name.as_deref(),
        Some("Kestrel")
    );
    // A device without a name takes none, whatever the box holds.
    let nameless = setup_of(Tracker, &Device::full().without(cap::DEV_NAME));
    let mut draft = nameless.built.clone();
    draft.name.text = String::new();
    assert!(problems(&nameless, &draft).is_empty());
    assert_eq!(nameless.record(&draft).unwrap().radio.device_name, None);
}

/// Every known value is judged, not only edits, so a value the device
/// reported and its encoder refuses holds Apply back on its own row.
#[test]
fn a_reported_value_the_encoder_refuses_is_a_problem() {
    let device = Device::full()
        .with(prop::PHY_LORA_SF, vec![4])
        .with(prop::ADVERT_INTERVAL, 1u32.to_le_bytes().to_vec());
    let setup = setup_with(Tracker, &device, Some(&modemless_companion()));
    assert_eq!(
        problems(&setup, &setup.built),
        [prop::PHY_LORA_SF, prop::ADVERT_INTERVAL]
    );
    let review = setup.review(&setup.built, Standing::default());
    assert!(!review.can_apply);
    assert_eq!(
        review.unshown_problems,
        [
            MobileSetupSetting::SpreadingFactor,
            MobileSetupSetting::Announcements
        ]
    );
    // Fixing it is what opens Apply.
    let mut draft = setup_set_radio_parameter(
        setup.built.clone(),
        MobileSetupRadioParameter::SpreadingFactor,
        7,
    );
    draft.advert_interval.value = Some(0);
    assert!(setup.review(&draft, Standing::default()).can_apply);
}

/// A companion with no modem profile: the device's own modem stands.
fn modemless_companion() -> MobileSetupCompanionRecord {
    MobileSetupCompanionRecord {
        bandwidth_hz: None,
        ..companion()
    }
}

/// Apply waits for a clean draft, a chosen profile and its turn; the link
/// is native code's to add.
#[test]
fn apply_waits_for_a_clean_draft_a_chosen_profile_and_its_turn() {
    let setup = setup_with(Tracker, &Device::full(), Some(&companion()));
    let draft = setup.built.clone();
    assert!(setup.review(&draft, Standing::default()).can_apply);
    let mut bad = draft.clone();
    bad.radio.frequency_khz.value = 0;
    assert!(!setup.review(&bad, Standing::default()).can_apply);
    let applying = Standing {
        applying: true,
        ..Standing::default()
    };
    assert!(!setup.review(&draft, applying).can_apply);
    let released = Standing {
        released: true,
        ..Standing::default()
    };
    assert!(!setup.review(&draft, released).can_apply);
    let unchosen = setup_of(Tracker, &Device::full());
    let review = unchosen.review(&unchosen.built, Standing::default());
    assert!(!review.profile_chosen && !review.can_apply && review.problems.is_empty());
}

/// Applied holds while the draft is what the device confirmed.
#[test]
fn applied_holds_until_the_next_edit() {
    let setup = setup_with(Repeater, &Device::full(), Some(&companion()));
    let draft = setup.built.clone();
    let record = setup.record(&draft).unwrap();
    let kept = Standing {
        applied: Some(&record),
        ..Standing::default()
    };
    assert!(!setup.review(&draft, Standing::default()).applied);
    // The phone was added and not yet written.
    assert!(!setup.review(&draft, kept).applied);
    let mut confirmed = draft.clone();
    confirmed.administrators.reported = confirmed.administrators.value.clone();
    assert!(setup.review(&confirmed, kept).applied);
    // Order does not matter; membership does.
    confirmed.administrators.reported.reverse();
    assert!(setup.review(&confirmed, kept).applied);
    let mut edited = confirmed.clone();
    edited.radio.transmit_power_dbm.value = 2;
    assert!(!setup.review(&edited, kept).applied);
    let removed = remove_administrator(confirmed, &phone());
    assert!(!setup.review(&removed, kept).applied);
}

// MARK: Choices

/// Every picker keeps the value it holds, offered apart when it is off
/// the list.
#[test]
fn every_picker_keeps_the_value_it_holds() {
    let setup = setup_of(Repeater, &Device::full());
    let listed = choices(&setup.built);
    for list in [
        &listed.bandwidths_hz,
        &listed.spreading_factors,
        &listed.coding_rates,
        &listed.duty_limits,
        &listed.precisions,
        &listed.advert_intervals_s,
        &listed.beacon_intervals_s,
        &listed.min_rssi_dbm,
        &listed.min_snr_db,
    ] {
        assert_eq!(list.other, None);
        assert!(!list.offered.is_empty());
    }
    assert_eq!(listed.precisions.offered, [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        listed.spreading_factors.offered,
        (5..=12).collect::<Vec<_>>()
    );
    assert_eq!(
        listed.duty_limits.offered[0],
        i64::from(DUTY_LIMIT_DISABLED)
    );
    // The signal floors run in steps of 5 dBm and 2 dB.
    assert_eq!(
        listed.min_rssi_dbm.offered,
        (-130..=-60).step_by(5).collect::<Vec<_>>()
    );
    assert_eq!(
        listed.min_snr_db.offered,
        (-20..=10).step_by(2).collect::<Vec<_>>()
    );

    let off_list = Device::full()
        .with(prop::PHY_LORA_BW, 123_456u32.to_le_bytes().to_vec())
        .with(prop::PHY_DUTY_LIMIT, 1_000u16.to_le_bytes().to_vec())
        .with(prop::ADVERT_INTERVAL, 7_200u32.to_le_bytes().to_vec())
        .with(prop::BEACON_INTERVAL, 5_000u32.to_le_bytes().to_vec())
        .with(
            prop::MAC_REPEATER_MIN_RSSI,
            (-101i16).to_le_bytes().to_vec(),
        )
        .with(prop::MAC_REPEATER_MIN_SNR, vec![(-5i8) as u8]);
    let setup = setup_of(Repeater, &off_list);
    let listed = choices(&setup.built);
    assert_eq!(listed.bandwidths_hz.other, Some(123_456));
    assert_eq!(listed.duty_limits.other, Some(1_000));
    assert_eq!(listed.advert_intervals_s.other, Some(7_200));
    assert_eq!(listed.beacon_intervals_s.other, Some(5_000));
    assert_eq!(listed.min_rssi_dbm.other, Some(-101));
    assert_eq!(listed.min_snr_db.other, Some(-5));
    // A pick onto the list drops it: the draft's value, not the device's.
    let mut draft = setup.built.clone();
    draft.radio.duty_limit.value = Some(655);
    assert_eq!(choices(&draft).duty_limits.other, None);
    // "Off" is not off the list.
    draft.repeater.min_rssi.value = None;
    assert_eq!(choices(&draft).min_rssi_dbm.other, None);
    // An unknown field's value is never offered.
    let unread = setup_of(
        Tracker,
        &off_list.refusing(&[prop::PHY_LORA_SF, prop::STARTUP_BEACON]),
    );
    let listed = choices(&unread.built);
    assert_eq!(listed.bandwidths_hz.other, None);
    assert_eq!(listed.advert_intervals_s.other, None);
}

// MARK: Administrators

/// Administrators are edited within the device's capacity.
#[test]
fn administrators_are_edited_within_capacity() {
    let setup = setup_of(Tracker, &Device::full());
    let draft = setup.built.clone();
    let added = add_administrator(draft.clone(), &key(0xb2));
    assert_eq!(added.administrators.value, vec![key(0xa1), key(0xb2)]);
    assert_eq!(add_administrator(added.clone(), &key(0xb2)), added);
    let mut full = draft.clone();
    for n in 0..20 {
        full = add_administrator(full, &key(n));
    }
    assert_eq!(
        full.administrators.value.len(),
        usize::from(ulcp_max_dev_admins())
    );
    // Without the phone's key the switch does nothing.
    assert_eq!(set_phone_administers(draft.clone(), None, true), draft);
    let on = set_phone_administers(draft.clone(), Some(&phone()), true);
    assert_eq!(on.administrators.value, vec![key(0xa1), phone()]);
    assert_eq!(
        set_phone_administers(on.clone(), Some(&phone()), false),
        draft
    );
    // The phone and the last entry can both go.
    let empty = remove_administrator(remove_administrator(on.clone(), &phone()), &key(0xa1));
    assert!(empty.administrators.value.is_empty());

    let review = setup.review(&on, Standing::default());
    assert_eq!(
        review.administrators,
        [
            MobileKeyEntryRecord {
                key: key(0xa1),
                is_this_phone: false,
                removable: true,
            },
            MobileKeyEntryRecord {
                key: phone(),
                is_this_phone: true,
                removable: true,
            },
        ]
    );
    assert!(review.phone_administers && review.phone_switch_enabled);
    assert!(!review.administrators_full);
    // Listed and full: can still be taken off.
    let mut crowded = on.clone();
    for n in 0..20 {
        crowded = add_administrator(crowded, &key(n));
    }
    let review = setup.review(&crowded, Standing::default());
    assert!(review.administrators_full && review.phone_switch_enabled);
    // Not listed and full: cannot be put on.
    let crowded = remove_administrator(crowded, &phone());
    let crowded = add_administrator(crowded, &key(0x55));
    let review = setup.review(&crowded, Standing::default());
    assert!(review.administrators_full && !review.phone_administers);
    assert!(!review.phone_switch_enabled);
    // Not listed, room: can be put on.
    let review = setup.review(&draft, Standing::default());
    assert!(!review.phone_administers && review.phone_switch_enabled);
    // No key: never.
    let keyless = build(
        Tracker,
        Some(&Device::full().sync()),
        None,
        None,
        None,
        ZONE,
    )
    .unwrap();
    let review = keyless.review(&keyless.built, Standing::default());
    assert!(!review.phone_switch_enabled && !review.phone_administers);
    assert!(
        review
            .administrators
            .iter()
            .all(|entry| !entry.is_this_phone)
    );
}

// MARK: The read-back

fn requested(setup: &Setup) -> (UlcpDeviceConfigRecord, Vec<(u32, Vec<u8>)>) {
    let record = setup.record(&setup.built).unwrap();
    let writes = setup.writes(record.clone()).unwrap();
    (record, writes)
}

/// The record `requested` would read back as, had the device kept it all.
fn kept(record: &UlcpDeviceConfigRecord, sync: &UlcpSyncRecord) -> UlcpSyncRecord {
    let radio = &record.radio;
    UlcpSyncRecord {
        phy_enabled: radio.phy_enabled,
        frequency_khz: radio.frequency_khz,
        transmit_power_dbm: radio.transmit_power_dbm,
        bandwidth_hz: radio.bandwidth_hz,
        spreading_factor: radio.spreading_factor,
        coding_rate_denom: radio.coding_rate_denom,
        duty_cycle_limit: radio.duty_cycle_limit,
        ident_role: record.ident_role,
        ident_mobile: record.ident_mobile,
        dev_discoverable: record.dev_discoverable,
        repeater: record.repeater.clone(),
        meshcore: record.meshcore.clone(),
        tz_rule: record.tz_rule.clone(),
        time_24h: record.time_24h,
        gnss: record.gnss,
        advert: record.advert,
        ..sync.clone()
    }
}

/// The first setting reported differently from what was written is named,
/// in a fixed order.
#[test]
fn the_first_setting_reported_differently_is_named() {
    let setup = setup_with(Tracker, &Device::full(), Some(&companion()));
    let (record, writes) = requested(&setup);
    let read = kept(&record, &setup.sync);
    assert_eq!(first_mismatch(&record, &read, &writes), None);

    type Misreport = fn(&mut UlcpSyncRecord);
    let cases: [(MobileSetupSetting, Misreport); 15] = [
        (MobileSetupSetting::RadioSwitch, |read| {
            read.phy_enabled = false;
        }),
        (MobileSetupSetting::Frequency, |read| read.frequency_khz = 1),
        (MobileSetupSetting::Bandwidth, |read| {
            read.bandwidth_hz = Some(125_000);
        }),
        (MobileSetupSetting::SpreadingFactor, |read| {
            read.spreading_factor = Some(11);
        }),
        (MobileSetupSetting::CodingRate, |read| {
            read.coding_rate_denom = Some(8);
        }),
        (MobileSetupSetting::TransmitLimit, |read| {
            read.duty_cycle_limit = Some(1);
        }),
        (MobileSetupSetting::AdvertisedRole, |read| {
            read.ident_role = Some(1);
        }),
        (MobileSetupSetting::Mobility, |read| {
            read.ident_mobile = Some(false);
        }),
        (MobileSetupSetting::Discoverability, |read| {
            read.dev_discoverable = Some(true);
        }),
        (MobileSetupSetting::ForwardingPolicy, |read| {
            read.repeater.as_mut().unwrap().regions.pop();
        }),
        (MobileSetupSetting::MeshCoreForwarding, |read| {
            read.meshcore.as_mut().unwrap().enabled = false;
        }),
        (MobileSetupSetting::TimeZone, |read| {
            read.tz_rule = Some("UTC0".to_owned());
        }),
        (MobileSetupSetting::ClockFormat, |read| {
            read.time_24h = Some(true);
        }),
        (MobileSetupSetting::Positioning, |read| {
            read.gnss.as_mut().unwrap().ident_precision = 7;
        }),
        (MobileSetupSetting::Announcements, |read| {
            read.advert.as_mut().unwrap().startup_beacon = true;
        }),
    ];
    for (index, (setting, misreport)) in cases.iter().enumerate() {
        let mut wrong = read.clone();
        misreport(&mut wrong);
        assert_eq!(
            first_mismatch(&record, &wrong, &writes),
            Some(*setting),
            "{setting:?}"
        );
        // With every later one wrong too, the first still wins.
        for (_, later) in &cases[index..] {
            later(&mut wrong);
        }
        assert_eq!(first_mismatch(&record, &wrong, &writes), Some(*setting));
    }
    // A setting the device does not report back is not compared.
    let mut silent = read.clone();
    silent.gnss = None;
    silent.repeater = None;
    silent.bandwidth_hz = None;
    assert_eq!(first_mismatch(&record, &silent, &writes), None);
    // Neither power (clamped) nor the name is ever compared.
    let mut clamped = read.clone();
    clamped.transmit_power_dbm = 5;
    clamped.device_name = Some("Other".to_owned());
    clamped.dev_admin_keys = Some(Vec::new());
    assert_eq!(first_mismatch(&record, &clamped, &writes), None);
    // A role the device was told to derive and names anyway.
    let repeater = setup_with(Repeater, &Device::full(), Some(&companion()));
    let (record, writes) = requested(&repeater);
    assert_eq!(record.ident_role, None);
    let mut named = kept(&record, &repeater.sync);
    named.ident_role = Some(1);
    assert_eq!(
        first_mismatch(&record, &named, &writes),
        Some(MobileSetupSetting::AdvertisedRole)
    );
}

/// A setting the attach could not read was not written, so a
/// read-back that reports it is not held to the placeholder.
#[test]
fn a_setting_that_was_not_written_is_never_a_mismatch() {
    let device = Device::full().refusing(&[prop::GNSS_TIME_TRUST, prop::PHY_DUTY_LIMIT]);
    let setup = setup_with(Tracker, &device, Some(&companion()));
    let (record, writes) = requested(&setup);
    assert!(!written(&writes).contains(&prop::GNSS_ENABLED));
    let mut read = kept(&record, &setup.sync);
    // The device reports both in full this time, differently from the
    // placeholders.
    read.gnss = Device::full().sync().gnss;
    read.duty_cycle_limit = Some(13_107);
    assert_ne!(read.gnss, record.gnss);
    assert_eq!(first_mismatch(&record, &read, &writes), None);
}

/// The role filed under is the one the device names, 1 through 7; a
/// device that names none is a repeater only in forwarding mode 1.
#[test]
fn the_role_filed_under_is_the_one_the_device_names() {
    let with = |role: Option<u8>, mode: Option<u8>| {
        let mut sync = Device::full().sync();
        sync.ident_role = role;
        match mode {
            Some(mode) => sync.repeater.as_mut().unwrap().mode = mode,
            None => sync.repeater = None,
        }
        advertised_role(&sync)
    };
    for role in 1..=7 {
        assert_eq!(with(Some(role), Some(1)), Some(role));
    }
    assert_eq!(with(Some(0), Some(1)), None);
    assert_eq!(with(Some(9), Some(1)), None);
    assert_eq!(with(None, Some(1)), Some(1));
    assert_eq!(with(None, Some(2)), None);
    assert_eq!(with(None, Some(0)), None);
    assert_eq!(with(None, None), None);
}
