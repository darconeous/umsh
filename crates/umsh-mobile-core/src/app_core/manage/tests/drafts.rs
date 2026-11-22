//! Drafts: building, rebasing, folding and reviewing, as pure functions
//! over a published device, and applying them on a scripted device.

use std::collections::BTreeMap;

use umsh_ulcp::ids::{cap, prop};

use super::script::{Call, ScriptedCarrier};
use super::{Bench, address_of, capabilities, device_values, encoded, name, reading};
use crate::app_core::MobileAppError;
use crate::app_core::manage::draft::{self, cell_decimals, trim_horizontal};
use crate::app_core::manage::reading::Reading;
use crate::app_core::manage::records::{
    MobileApplyOutcome, MobileApplyResult, MobileApplyWarning, MobileBluetoothDraft,
    MobileBridgeDraft, MobileDraftDetails, MobileDraftKind, MobileDraftReviewRecord,
    MobileFieldProblem, MobileIdentityDraft, MobileManagedDeviceRecord, MobileManagementDraft,
    MobileManagementLink, MobileMeshCoreDraft, MobileNetworkDraft, MobileOfferedCategoryRecord,
    MobileRadioDraft, MobileRegionEntryProblem, MobileRepeaterDraft, MobileWifiDraft,
};
use crate::app_core::manage::{
    draft_add_meshcore_region, draft_add_repeater_region, draft_adopt_preset, draft_adopt_regions,
    draft_clear_position, draft_place, draft_place_from_phone, draft_set_precision,
};
use crate::ulcp::{
    UlcpAlertState, UlcpDevicePropertiesRecord, UlcpIpConfigRecord, UlcpManageCategory,
    UlcpPropertyPushKind, UlcpPropertyPushRecord, inspect_ulcp_device_card,
    inspect_ulcp_properties, region_code_description, region_code_from_string,
    ulcp_category_properties, ulcp_dirty_writes, ulcp_encode_location, ulcp_property_record,
    ulcp_radio_presets,
};

const MESH: MobileManagementLink = MobileManagementLink::Mesh;
const COMPANION: MobileManagementLink = MobileManagementLink::Companion;

const ALL_CATEGORIES: [UlcpManageCategory; 13] = [
    UlcpManageCategory::Power,
    UlcpManageCategory::Sensors,
    UlcpManageCategory::Radio,
    UlcpManageCategory::Statistics,
    UlcpManageCategory::Identity,
    UlcpManageCategory::Gnss,
    UlcpManageCategory::Time,
    UlcpManageCategory::Bluetooth,
    UlcpManageCategory::Wifi,
    UlcpManageCategory::Network,
    UlcpManageCategory::Bridge,
    UlcpManageCategory::Repeater,
    UlcpManageCategory::PeerNodes,
];

/// A device with everything a draft edits, as published.
struct Fixture {
    link: MobileManagementLink,
    uses_bluetooth: bool,
    capabilities: Vec<u32>,
    held: UlcpDevicePropertiesRecord,
    /// Properties the last read refused.
    refused: Vec<u32>,
    dev_key: Option<Vec<u8>>,
    revision: u64,
}

const LATITUDE: f64 = 47.123_45;
const LONGITUDE: f64 = -122.567_89;

fn location(latitude: f64, longitude: f64, precision: u8) -> Vec<u8> {
    ulcp_encode_location(latitude, longitude, precision).unwrap()
}

fn decoded_location(bytes: &[u8]) -> (f64, f64) {
    let properties = inspect_ulcp_properties(vec![ulcp_property_record(
        prop::IDENT_LOCATION,
        bytes.to_vec(),
    )]);
    (
        properties.ident_latitude_deg.unwrap(),
        properties.ident_longitude_deg.unwrap(),
    )
}

fn server_key(seed: u8) -> Vec<u8> {
    crate::public_identity_bytes(address_of(seed)).unwrap()
}

fn static_v4(address: [u8; 4], prefix: u8, gateway: [u8; 4]) -> UlcpIpConfigRecord {
    UlcpIpConfigRecord {
        method: 2,
        address: address.to_vec(),
        prefix,
        gateway: gateway.to_vec(),
    }
}

fn automatic() -> UlcpIpConfigRecord {
    UlcpIpConfigRecord {
        method: 1,
        address: Vec::new(),
        prefix: 0,
        gateway: Vec::new(),
    }
}

impl Fixture {
    fn new(link: MobileManagementLink) -> Self {
        let preset = &ulcp_radio_presets()[0];
        Self {
            link,
            uses_bluetooth: false,
            capabilities: vec![
                cap::PHY_LORA,
                cap::PHY_DUTY_LIMIT,
                cap::DEV_NAME,
                cap::IDENT,
                cap::DEV_IDENTITY,
                cap::GNSS,
                cap::ADVERT,
                cap::TIME,
                cap::REPEATER,
                cap::MESHCORE_FORWARDER,
                cap::IPV4,
                cap::IPV6,
                cap::LAN_BEARER,
                cap::BRIDGE_CLIENT,
                cap::BLE,
                cap::WIFI,
                cap::WIFI_SCAN,
            ],
            held: UlcpDevicePropertiesRecord {
                phy_enabled: Some(true),
                frequency_khz: Some(preset.frequency_khz),
                transmit_power_dbm: Some(14),
                bandwidth_hz: Some(preset.bandwidth_hz),
                spreading_factor: Some(preset.spreading_factor),
                coding_rate_denom: Some(preset.coding_rate_denom),
                duty_cycle_limit: Some(preset.duty_cycle_limit),
                device_name: Some("Tallac Ridge".to_owned()),
                ident_role: Some(1),
                ident_mobile: Some(false),
                ident_location: Some(location(LATITUDE, LONGITUDE, 5)),
                ident_altitude_m: Some(120),
                dev_discoverable: Some(true),
                gnss_ident_update: Some(false),
                gnss_ident_precision: Some(5),
                advert_interval_seconds: Some(3_600),
                beacon_interval_seconds: Some(900),
                startup_beacon: Some(true),
                gnss_enabled: Some(true),
                tz_rule: Some("PST8PDT,M3.2.0,M11.1.0".to_owned()),
                time_24h: Some(false),
                gnss_time_trust: Some(true),
                ble_enabled: Some(true),
                ble_pairing: Some(false),
                wifi_enabled: Some(true),
                ipv4_config: Some(static_v4([10, 0, 0, 2], 24, [10, 0, 0, 1])),
                ipv6_config: Some(automatic()),
                ip_dns: Some(vec![vec![1, 1, 1, 1]]),
                bridge_enabled: Some(true),
                bridge_host: Some("bridge.example.net".to_owned()),
                bridge_port: Some(4403),
                bridge_server_key: Some(server_key(9)),
                lan_bearer_enabled: Some(true),
                lan_bearer_group: Some("239.255.0.1:4403".to_owned()),
                lan_bearer_ingress_limit: Some(600),
                repeater_mode: Some(1),
                repeater_regions: Some(vec!["SJC".to_owned(), "Bay Area".to_owned()]),
                repeater_default_region: Some(region_code_from_string("SJC".to_owned()).unwrap()),
                repeater_min_rssi_dbm: Some(-110),
                repeater_min_snr_db: Some(-5),
                meshcore_forwarding_enabled: Some(false),
                meshcore_region_policy: Some(0),
                meshcore_regions: Some(vec!["sf".to_owned()]),
                ..UlcpDevicePropertiesRecord::default()
            },
            refused: Vec::new(),
            dev_key: None,
            revision: 1,
        }
    }

    /// A device whose medium is the LAN group: the group is Network's.
    fn lan_only(link: MobileManagementLink) -> Self {
        let mut fixture = Self::new(link);
        fixture
            .capabilities
            .retain(|capability| *capability != cap::REPEATER);
        fixture
    }

    /// The device as published, every offered category read.
    fn record(&self) -> MobileManagedDeviceRecord {
        let caps = capabilities(&self.capabilities);
        let card =
            inspect_ulcp_device_card(vec![ulcp_property_record(prop::CAPS, caps.clone())]).unwrap();
        let mut categories = Vec::new();
        let mut readings = Vec::new();
        for category in ALL_CATEGORIES {
            let property_ids = ulcp_category_properties(category, caps.clone()).unwrap();
            if property_ids.is_empty() {
                continue;
            }
            categories.push(MobileOfferedCategoryRecord {
                category,
                property_ids: property_ids.clone(),
            });
            let values: BTreeMap<u32, Vec<u8>> = property_ids
                .iter()
                .filter(|property| !self.refused.contains(property))
                .filter_map(|property| {
                    let writes = ulcp_dirty_writes(self.held.clone(), vec![*property]).ok()?;
                    let write = writes
                        .into_iter()
                        .find(|write| write.property_id == *property)?;
                    Some((*property, write.value))
                })
                .collect();
            let mut reading = Reading::new(category, property_ids, self.revision);
            reading.absorb(&values, 0, true, &BTreeMap::new(), self.revision);
            reading.refused = self
                .refused
                .iter()
                .copied()
                .filter(|property| reading.covers(*property))
                .collect();
            if let Some(key) = &self.dev_key {
                reading.properties.dev_key = Some(key.clone());
            }
            readings.push(reading.record(None));
        }
        MobileManagedDeviceRecord {
            revision: self.revision,
            link: self.link,
            uses_bluetooth: self.uses_bluetooth,
            address: None,
            card: Some(card),
            card_as_of_ms: None,
            card_is_fresh: true,
            categories,
            readings,
            alert: UlcpAlertState::None,
            busy: false,
            entered_dfu: false,
            problem: None,
            phone_node_key: None,
            heard_networks: Vec::new(),
            refreshes_stale_readings: false,
            offers_factory_reset: false,
            phone_stands_for_device: false,
            supports_wifi_station: false,
            supports_bluetooth_pairing: false,
            peers: None,
            administrators: None,
        }
    }

    /// The device's values move under a draft: a new reading.
    fn moved(&mut self, change: impl FnOnce(&mut UlcpDevicePropertiesRecord)) {
        change(&mut self.held);
        self.revision += 1;
    }
}

fn judged(
    device: &MobileManagedDeviceRecord,
    draft: MobileManagementDraft,
) -> MobileDraftReviewRecord {
    draft::review(device, draft).unwrap()
}

fn problems(review: &MobileDraftReviewRecord) -> Vec<(u32, MobileFieldProblem)> {
    review
        .problems
        .iter()
        .map(|problem| (problem.property_id, problem.problem))
        .collect()
}

macro_rules! typed {
    ($name:ident, $variant:ident, $record:ty, $kind:ident) => {
        fn $name(device: &MobileManagedDeviceRecord) -> $record {
            match draft::build(device, MobileDraftKind::$kind) {
                Some(MobileManagementDraft::$variant { draft }) => draft,
                other => panic!("not a {} draft: {other:?}", stringify!($kind)),
            }
        }
    };
}

typed!(radio, Radio, MobileRadioDraft, Radio);
typed!(identity_draft, Identity, MobileIdentityDraft, Identity);
typed!(repeater, Repeater, MobileRepeaterDraft, Repeater);
typed!(meshcore, MeshCore, MobileMeshCoreDraft, MeshCore);
typed!(wifi, Wifi, MobileWifiDraft, Wifi);
typed!(network, Network, MobileNetworkDraft, Network);
typed!(bridge, Bridge, MobileBridgeDraft, Bridge);
typed!(bluetooth, Bluetooth, MobileBluetoothDraft, Bluetooth);

fn wrap_radio(draft: MobileRadioDraft) -> MobileManagementDraft {
    MobileManagementDraft::Radio { draft }
}
fn wrap_identity(draft: MobileIdentityDraft) -> MobileManagementDraft {
    MobileManagementDraft::Identity { draft }
}
fn wrap_repeater(draft: MobileRepeaterDraft) -> MobileManagementDraft {
    MobileManagementDraft::Repeater { draft }
}
fn wrap_network(draft: MobileNetworkDraft) -> MobileManagementDraft {
    MobileManagementDraft::Network { draft }
}
fn wrap_bridge(draft: MobileBridgeDraft) -> MobileManagementDraft {
    MobileManagementDraft::Bridge { draft }
}

// MARK: Building

#[test]
fn a_draft_needs_a_reading_and_an_offered_category() {
    let fixture = Fixture::new(MESH);
    let mut device = fixture.record();
    let radio_reading = device
        .readings
        .iter()
        .position(|reading| reading.category == UlcpManageCategory::Radio)
        .unwrap();
    device.readings.remove(radio_reading);
    assert_eq!(draft::build(&device, MobileDraftKind::Radio), None);
    assert!(draft::build(&fixture.record(), MobileDraftKind::Radio).is_some());

    let mut without_bridge = Fixture::new(MESH);
    without_bridge
        .capabilities
        .retain(|capability| *capability != cap::BRIDGE_CLIENT && *capability != cap::LAN_BEARER);
    let device = without_bridge.record();
    assert_eq!(draft::build(&device, MobileDraftKind::Bridge), None);
    let bridge_draft = bridge(&fixture.record());
    assert_eq!(
        draft::rebase(&device, wrap_bridge(bridge_draft.clone())),
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        draft::review(&device, wrap_bridge(bridge_draft)),
        Err(MobileAppError::InvalidRequest)
    );
}

#[test]
fn a_fresh_draft_has_no_edits_and_carries_its_baseline() {
    let fixture = Fixture::new(MESH);
    let device = fixture.record();
    for kind in [
        MobileDraftKind::Radio,
        MobileDraftKind::Identity,
        MobileDraftKind::Repeater,
        MobileDraftKind::MeshCore,
        MobileDraftKind::Wifi,
        MobileDraftKind::Network,
        MobileDraftKind::Bridge,
        MobileDraftKind::Bluetooth,
        MobileDraftKind::Gnss,
        MobileDraftKind::Time,
    ] {
        let built = draft::build(&device, kind).unwrap();
        assert_eq!(draft::kind(&built), kind);
        let review = judged(&device, built);
        assert!(review.dirty.is_empty(), "{kind:?}: {review:?}");
        assert!(review.problems.is_empty(), "{kind:?}: {review:?}");
        assert!(!review.has_edits);
        assert_eq!(review.warning, None);
    }
    let radio = radio(&device);
    assert_eq!(radio.reading_revision, fixture.revision);
    assert!(radio.frequency_khz.known);
    assert_eq!(radio.frequency_khz.reported, radio.frequency_khz.value);
    let identity = identity_draft(&device);
    assert_eq!(identity.name.reported, "Tallac Ridge");
    assert_eq!(identity.role.reported, Some(1));
    assert_eq!(identity.altitude_m.reported, Some(120));
    let network = network(&device);
    assert_eq!(network.v4_address.reported, "10.0.0.2");
    assert_eq!(network.v4_prefix.reported, Some(24));
    assert_eq!(network.v4_gateway.reported, "10.0.0.1");
    // A family with no address shows its fields empty, the prefix too.
    assert_eq!(network.v6_address.reported, "");
    assert_eq!(network.v6_prefix.reported, None);
    assert_eq!(network.dns.reported, vec!["1.1.1.1".to_owned()]);
    let bridge = bridge(&device);
    assert_eq!(bridge.server_key.reported, address_of(9));
    assert_eq!(bridge.ingress_limit.reported, Some(600));
    assert_eq!(repeater(&device).default_region.reported, "SJC");
}

#[test]
fn an_unknown_field_takes_nothing() {
    let mut fixture = Fixture::new(MESH);
    fixture.refused = vec![prop::PHY_TX_POWER, prop::IDENT_ROLE];
    let device = fixture.record();
    let mut draft = radio(&device);
    assert!(!draft.transmit_power_dbm.known);
    assert_eq!(draft.transmit_power_dbm.value, 0);
    draft.transmit_power_dbm.value = 20;
    assert!(judged(&device, wrap_radio(draft)).dirty.is_empty());
    // Where empty is a value, known is whether the device answered.
    let mut identity = identity_draft(&device);
    assert!(!identity.role.known);
    assert!(identity.altitude_m.known);
    identity.role.value = Some(3);
    assert!(judged(&device, wrap_identity(identity)).dirty.is_empty());
}

// MARK: Folding typed values

#[test]
fn integer_fields_are_checked_against_their_wire_type() {
    let fixture = Fixture::new(MESH);
    let device = fixture.record();
    let radio_case = |power: i64, frequency: i64| {
        let mut draft = radio(&device);
        draft.transmit_power_dbm.value = power;
        draft.frequency_khz.value = frequency;
        judged(&device, wrap_radio(draft))
    };
    let base = radio(&device).frequency_khz.reported;
    let review = radio_case(127, base);
    assert_eq!(review.dirty, vec![prop::PHY_TX_POWER]);
    let review = radio_case(128, base);
    assert!(review.dirty.is_empty());
    assert_eq!(
        problems(&review),
        vec![(prop::PHY_TX_POWER, MobileFieldProblem::OutOfRange)]
    );
    assert_eq!(radio_case(-128, base).dirty, vec![prop::PHY_TX_POWER]);
    assert!(radio_case(-129, base).dirty.is_empty());
    assert_eq!(
        radio_case(14, i64::from(u32::MAX)).dirty,
        vec![prop::PHY_FREQ]
    );
    assert_eq!(
        problems(&radio_case(14, 1 << 32)),
        vec![(prop::PHY_FREQ, MobileFieldProblem::OutOfRange)]
    );
    assert_eq!(
        problems(&radio_case(14, -1)),
        vec![(prop::PHY_FREQ, MobileFieldProblem::OutOfRange)]
    );

    let repeater_case = |rssi: Option<i64>, snr: Option<i64>| {
        let mut draft = repeater(&device);
        draft.min_rssi.value = rssi;
        draft.min_snr.value = snr;
        judged(&device, wrap_repeater(draft))
    };
    assert_eq!(
        repeater_case(Some(-32_768), Some(-128)).dirty,
        vec![prop::MAC_REPEATER_MIN_RSSI, prop::MAC_REPEATER_MIN_SNR]
    );
    assert_eq!(
        problems(&repeater_case(Some(-32_769), Some(-129))),
        vec![
            (prop::MAC_REPEATER_MIN_RSSI, MobileFieldProblem::OutOfRange),
            (prop::MAC_REPEATER_MIN_SNR, MobileFieldProblem::OutOfRange),
        ]
    );
    assert_eq!(
        problems(&repeater_case(Some(32_768), Some(128))),
        vec![
            (prop::MAC_REPEATER_MIN_RSSI, MobileFieldProblem::OutOfRange),
            (prop::MAC_REPEATER_MIN_SNR, MobileFieldProblem::OutOfRange),
        ]
    );

    let altitude_case = |altitude: Option<i64>| {
        let mut draft = identity_draft(&device);
        draft.altitude_m.value = altitude;
        judged(&device, wrap_identity(draft))
    };
    assert_eq!(
        altitude_case(Some(i64::from(i32::MIN))).dirty,
        vec![prop::IDENT_ALTITUDE]
    );
    assert_eq!(
        altitude_case(Some(i64::from(i32::MAX))).dirty,
        vec![prop::IDENT_ALTITUDE]
    );
    assert_eq!(
        problems(&altitude_case(Some(i64::from(i32::MAX) + 1))),
        vec![(prop::IDENT_ALTITUDE, MobileFieldProblem::OutOfRange)]
    );
    assert_eq!(
        problems(&altitude_case(Some(i64::from(i32::MIN) - 1))),
        vec![(prop::IDENT_ALTITUDE, MobileFieldProblem::OutOfRange)]
    );
}

#[test]
fn an_optional_field_writes_none_as_its_empty_value() {
    let fixture = Fixture::new(MESH);
    let device = fixture.record();
    let mut draft = repeater(&device);
    draft.min_rssi.value = None;
    let prepared = draft::prepare(&device, wrap_repeater(draft)).unwrap();
    assert_eq!(prepared.dirty, vec![prop::MAC_REPEATER_MIN_RSSI]);
    assert_eq!(prepared.desired.repeater_min_rssi_dbm, None);
    let writes = ulcp_dirty_writes(prepared.desired, prepared.dirty).unwrap();
    assert_eq!(writes[0].value, Vec::<u8>::new(), "no threshold");

    let mut draft = identity_draft(&device);
    draft.altitude_m.value = None;
    let prepared = draft::prepare(&device, wrap_identity(draft)).unwrap();
    assert_eq!(prepared.dirty, vec![prop::IDENT_ALTITUDE]);
    assert_eq!(prepared.desired.ident_altitude_m, None);

    let mut draft = bridge(&device);
    draft.ingress_limit.value = None;
    let prepared = draft::prepare(&device, wrap_bridge(draft)).unwrap();
    assert_eq!(prepared.dirty, vec![prop::LAN_BEARER_INGRESS_LIMIT]);
    assert_eq!(
        prepared.desired.lan_bearer_ingress_limit, None,
        "device default"
    );

    // A required number cannot be empty at all: its type has no `None`.
    let mut draft = identity_draft(&device);
    draft.role.value = None;
    let prepared = draft::prepare(&device, wrap_identity(draft)).unwrap();
    assert_eq!(prepared.desired.ident_role, None, "derive the role");
}

#[test]
fn a_picker_without_an_empty_choice_refuses_none() {
    let device = Fixture::new(MESH).record();
    // A choice is checked against its wire type as a typed number is.
    let mut draft = radio(&device);
    draft.spreading_factor.value = Some(256);
    draft.duty_limit.value = Some(65_536);
    draft.bandwidth.value = Some(i64::from(u32::MAX) + 1);
    assert_eq!(
        problems(&judged(&device, wrap_radio(draft))),
        vec![
            (prop::PHY_LORA_BW, MobileFieldProblem::OutOfRange),
            (prop::PHY_LORA_SF, MobileFieldProblem::OutOfRange),
            (prop::PHY_DUTY_LIMIT, MobileFieldProblem::OutOfRange),
        ]
    );
    let mut draft = identity_draft(&device);
    draft.advert_interval.value = Some(1 << 32);
    draft.role.value = Some(256);
    assert_eq!(
        problems(&judged(&device, wrap_identity(draft))),
        vec![
            (prop::IDENT_ROLE, MobileFieldProblem::OutOfRange),
            (prop::ADVERT_INTERVAL, MobileFieldProblem::OutOfRange),
        ]
    );
    let mut draft = radio(&device);
    draft.spreading_factor.value = None;
    draft.bandwidth.value = Some(-1);
    let review = judged(&device, wrap_radio(draft));
    assert!(review.dirty.is_empty());
    assert_eq!(
        problems(&review),
        vec![
            (prop::PHY_LORA_BW, MobileFieldProblem::OutOfRange),
            (prop::PHY_LORA_SF, MobileFieldProblem::OutOfRange),
        ]
    );
}

#[test]
fn a_value_the_encoder_refuses_is_a_problem_not_a_failed_apply() {
    let device = Fixture::new(MESH).record();
    let mut draft = identity_draft(&device);
    draft.precision.value = Some(9);
    let review = judged(&device, wrap_identity(draft));
    assert!(review.dirty.is_empty());
    assert_eq!(
        problems(&review),
        vec![(prop::GNSS_IDENT_PRECISION, MobileFieldProblem::OutOfRange)]
    );
    let mut draft = repeater(&device);
    draft.regions.value.push("x".repeat(40));
    assert_eq!(
        problems(&review_of(&device, wrap_repeater(draft))),
        vec![(prop::MAC_REPEATER_REGIONS, MobileFieldProblem::OutOfRange)]
    );
}

fn review_of(
    device: &MobileManagedDeviceRecord,
    draft: MobileManagementDraft,
) -> MobileDraftReviewRecord {
    judged(device, draft)
}

// MARK: Rebasing

#[test]
fn rebase_keeps_edits_follows_clean_fields_and_cleans_on_landing() {
    let mut fixture = Fixture::new(MESH);
    let device = fixture.record();
    let mut draft = radio(&device);
    draft.transmit_power_dbm.value = 20;
    draft.duty_limit.value = Some(655);
    fixture.moved(|held| {
        // Power lands on the edit; the frequency moves under a clean field;
        // the duty limit moves under an edit.
        held.transmit_power_dbm = Some(20);
        held.frequency_khz = Some(915_000);
        held.duty_cycle_limit = Some(13_107);
    });
    let device = fixture.record();
    let MobileManagementDraft::Radio { draft: rebased } =
        draft::rebase(&device, wrap_radio(draft.clone())).unwrap()
    else {
        panic!("the variant it was given");
    };
    assert_eq!(rebased.reading_revision, fixture.revision);
    assert_eq!(rebased.frequency_khz.value, 915_000, "clean follows");
    assert_eq!(rebased.transmit_power_dbm.value, 20);
    assert_eq!(rebased.transmit_power_dbm.reported, 20, "landed: clean");
    assert_eq!(rebased.duty_limit.reported, Some(13_107));
    assert_eq!(rebased.duty_limit.value, Some(655), "the edit stands");
    assert_eq!(
        judged(&device, wrap_radio(rebased.clone())).dirty,
        vec![prop::PHY_DUTY_LIMIT]
    );
    // Built on the current reading, a draft comes back as it was.
    assert_eq!(
        draft::rebase(&device, wrap_radio(rebased.clone())).unwrap(),
        wrap_radio(rebased)
    );
}

#[test]
fn rebase_drops_an_edit_whose_field_is_no_longer_known() {
    let mut fixture = Fixture::new(MESH);
    let mut draft = radio(&fixture.record());
    draft.transmit_power_dbm.value = 20;
    fixture.refused = vec![prop::PHY_TX_POWER];
    fixture.revision += 1;
    let device = fixture.record();
    let MobileManagementDraft::Radio { draft } = draft::rebase(&device, wrap_radio(draft)).unwrap()
    else {
        panic!()
    };
    assert!(!draft.transmit_power_dbm.known);
    assert!(judged(&device, wrap_radio(draft)).dirty.is_empty());
}

/// Bug 2: a clean editor whose device value moved kept the stale text,
/// because the old text was compared to the new baseline's.
#[test]
fn bug2_a_clean_network_family_follows_the_device() {
    let mut fixture = Fixture::lan_only(MESH);
    let draft = network(&fixture.record());
    fixture.moved(|held| {
        held.ipv4_config = Some(static_v4([10, 0, 0, 3], 16, [10, 0, 0, 254]));
        held.ip_dns = Some(vec![vec![9, 9, 9, 9]]);
    });
    let device = fixture.record();
    let MobileManagementDraft::Network { draft } =
        draft::rebase(&device, wrap_network(draft)).unwrap()
    else {
        panic!()
    };
    assert_eq!(draft.v4_address.text, "10.0.0.3");
    assert_eq!(draft.v4_prefix.value, Some(16));
    assert_eq!(draft.v4_gateway.text, "10.0.0.254");
    assert_eq!(draft.dns.value, vec!["9.9.9.9".to_owned()]);
    assert!(judged(&device, wrap_network(draft)).dirty.is_empty());
}

#[test]
fn an_edited_network_family_travels_whole() {
    let mut fixture = Fixture::lan_only(MESH);
    let mut draft = network(&fixture.record());
    draft.v4_prefix.value = Some(25);
    fixture.moved(|held| {
        held.ipv4_config = Some(static_v4([10, 0, 0, 3], 24, [10, 0, 0, 254]));
    });
    let device = fixture.record();
    let MobileManagementDraft::Network { draft } =
        draft::rebase(&device, wrap_network(draft)).unwrap()
    else {
        panic!()
    };
    // The address and gateway were not touched, but ride with the prefix.
    assert_eq!(draft.v4_address.text, "10.0.0.2");
    assert_eq!(draft.v4_prefix.value, Some(25));
    assert_eq!(draft.v4_gateway.text, "10.0.0.1");
    assert_eq!(draft.v4_address.reported, "10.0.0.3");
}

// MARK: Position

fn moved_position(
    device: &MobileManagedDeviceRecord,
    latitude: Option<f64>,
    longitude: Option<f64>,
) -> MobileDraftReviewRecord {
    let mut draft = identity_draft(device);
    draft.position.latitude = latitude;
    draft.position.longitude = longitude;
    judged(device, wrap_identity(draft))
}

#[test]
fn a_position_is_written_whole_and_cleared_whole() {
    let device = Fixture::new(MESH).record();
    let review = moved_position(&device, Some(46.5), Some(-121.25));
    assert_eq!(review.dirty, vec![prop::IDENT_LOCATION]);
    let MobileDraftDetails::Identity {
        latitude_deg,
        longitude_deg,
        ..
    } = review.details
    else {
        panic!()
    };
    let (latitude, longitude) = decoded_location(&location(46.5, -121.25, 5));
    assert_eq!(
        (latitude_deg, longitude_deg),
        (Some(latitude), Some(longitude))
    );

    let review = moved_position(&device, None, None);
    assert_eq!(review.dirty, vec![prop::IDENT_LOCATION]);
    let prepared = draft::prepare(
        &device,
        wrap_identity({
            let mut draft = identity_draft(&device);
            draft.position.latitude = None;
            draft.position.longitude = None;
            draft
        }),
    )
    .unwrap();
    assert_eq!(prepared.desired.ident_location, Some(Vec::new()));

    // Half a pair is not an edit.
    assert!(moved_position(&device, Some(46.5), None).dirty.is_empty());
    assert!(
        moved_position(&device, None, Some(-121.25))
            .dirty
            .is_empty()
    );
    assert!(
        moved_position(&device, None, Some(-121.25))
            .problems
            .is_empty()
    );
}

#[test]
fn a_position_inside_the_reported_cell_is_clean() {
    let device = Fixture::new(MESH).record();
    let draft = identity_draft(&device);
    let (latitude, longitude) = (
        draft.position.reported_latitude.unwrap(),
        draft.position.reported_longitude.unwrap(),
    );
    // A precision-5 cell is about 38 m wide; a nudge of a meter stays in it.
    assert!(
        moved_position(&device, Some(latitude + 0.000_01), Some(longitude))
            .dirty
            .is_empty()
    );
}

/// A position nudged within the reported cell is clean, so it follows the
/// device when the location moves rather than writing the old cell back.
#[test]
fn a_position_inside_the_reported_cell_follows_the_device() {
    let mut fixture = Fixture::new(MESH);
    let mut draft = identity_draft(&fixture.record());
    let latitude = draft.position.reported_latitude.unwrap();
    draft.position.latitude = Some(latitude + 0.000_01);
    assert!(
        judged(&fixture.record(), wrap_identity(draft.clone()))
            .dirty
            .is_empty()
    );
    fixture.moved(|held| held.ident_location = Some(location(46.5, -121.25, 5)));
    let device = fixture.record();
    let MobileManagementDraft::Identity { draft } =
        draft::rebase(&device, wrap_identity(draft)).unwrap()
    else {
        panic!()
    };
    let (latitude, longitude) = decoded_location(&location(46.5, -121.25, 5));
    assert_eq!(draft.position.latitude, Some(latitude));
    assert_eq!(draft.position.longitude, Some(longitude));
    assert!(judged(&device, wrap_identity(draft)).dirty.is_empty());
}

/// Decoding then encoding is the identity through precision 6. At 7 the
/// decoded pair is single precision and lands in a neighboring cell, so an
/// edit is compared against the reported octets, never a re-encoding.
#[test]
fn decoding_then_encoding_a_location_is_the_identity_at_every_precision() {
    for precision in 1..=7 {
        let bytes = location(LATITUDE, LONGITUDE, precision);
        let (latitude, longitude) = decoded_location(&bytes);
        if precision < 7 {
            assert_eq!(
                location(latitude, longitude, precision),
                bytes,
                "precision {precision}"
            );
        }
        let mut fixture = Fixture::new(MESH);
        fixture.held.ident_location = Some(bytes.clone());
        fixture.held.gnss_ident_precision = Some(precision);
        let device = fixture.record();
        let draft = identity_draft(&device);
        assert_eq!(draft.position.reported_location, bytes);
        assert!(judged(&device, wrap_identity(draft)).dirty.is_empty());
    }
}

/// Bug 6: one coordinate typed after a rebase wrote the earlier edit,
/// which the rebuilt editor still held.
#[test]
fn bug6_half_a_position_after_a_rebase_writes_nothing() {
    let mut fixture = Fixture::new(MESH);
    let mut draft = identity_draft(&fixture.record());
    draft.position.latitude = Some(46.5);
    draft.position.longitude = Some(-121.25);
    // The operator clears one coordinate, then the reading moves.
    draft.position.longitude = None;
    fixture.moved(|held| held.ident_mobile = Some(true));
    let device = fixture.record();
    let MobileManagementDraft::Identity { draft } =
        draft::rebase(&device, wrap_identity(draft)).unwrap()
    else {
        panic!()
    };
    assert_eq!(draft.position.latitude, Some(46.5), "kept whole");
    assert_eq!(draft.position.longitude, None, "kept whole");
    let review = judged(&device, wrap_identity(draft));
    assert!(!review.dirty.contains(&prop::IDENT_LOCATION), "{review:?}");
    assert!(review.problems.is_empty());
}

/// Bug 7: a coordinate out of range quietly reverted, with Apply gone and
/// no word why.
#[test]
fn bug7_an_out_of_range_coordinate_is_a_problem() {
    let device = Fixture::new(MESH).record();
    for (latitude, longitude) in [
        (90.000_001, 0.0),
        (-90.000_001, 0.0),
        (0.0, 180.000_001),
        (0.0, -180.000_001),
        (f64::NAN, 0.0),
    ] {
        let review = moved_position(&device, Some(latitude), Some(longitude));
        assert!(review.dirty.is_empty());
        assert_eq!(
            problems(&review),
            vec![(prop::IDENT_LOCATION, MobileFieldProblem::OutOfRange)],
            "{latitude}, {longitude}"
        );
    }
    assert_eq!(
        moved_position(&device, Some(90.0), Some(-180.0)).dirty,
        vec![prop::IDENT_LOCATION]
    );
}

#[test]
fn a_self_positioning_device_writes_no_position() {
    let mut fixture = Fixture::new(MESH);
    let device = fixture.record();
    // Turned on in the draft.
    let mut draft = identity_draft(&device);
    draft.self_positions.value = true;
    draft.position.latitude = Some(1.0);
    draft.position.longitude = Some(2.0);
    draft.altitude_m.value = Some(5);
    let review = judged(&device, wrap_identity(draft));
    assert_eq!(review.dirty, vec![prop::GNSS_IDENT_UPDATE]);
    let MobileDraftDetails::Identity {
        self_positioning,
        latitude_deg,
        ..
    } = review.details
    else {
        panic!()
    };
    assert!(self_positioning);
    // The summary shows the position the device keeps.
    assert_eq!(
        latitude_deg,
        identity_draft(&device).position.reported_latitude
    );

    // On on the device, turned off in the draft: still refused this time.
    fixture.held.gnss_ident_update = Some(true);
    let device = fixture.record();
    let mut draft = identity_draft(&device);
    draft.self_positions.value = false;
    draft.position.latitude = Some(1.0);
    draft.position.longitude = Some(2.0);
    assert_eq!(
        review_of(&device, wrap_identity(draft)).dirty,
        vec![prop::GNSS_IDENT_UPDATE]
    );
}

#[test]
fn placing_rounds_to_what_the_field_shows() {
    let device = Fixture::new(MESH).record();
    for precision in 1..=7u8 {
        let mut draft = draft_set_precision(identity_draft(&device), precision);
        draft = draft_place(draft, 47.123_456_789_1, -122.987_654_321_9);
        let decimals = cell_decimals(precision).max(5);
        let scale = 10f64.powi(decimals.into());
        let latitude = draft.position.latitude.unwrap();
        assert_eq!((latitude * scale).round() / scale, latitude);
        assert!((latitude - 47.123_456_789_1).abs() <= 0.5 / scale + 1e-12);
        let review = judged(&device, wrap_identity(draft));
        let MobileDraftDetails::Identity {
            encoding_precision,
            coordinate_decimals: shown,
            ..
        } = review.details
        else {
            panic!()
        };
        assert_eq!(encoding_precision, precision);
        assert_eq!(shown, decimals);
    }
    // 2,500 km cells show none; 15 cm cells show six.
    assert_eq!(cell_decimals(1), 0);
    assert_eq!(cell_decimals(6), 5);
    assert_eq!(cell_decimals(7), 6);
    assert_eq!(cell_decimals(0), 5);
}

#[test]
fn the_phone_gives_its_height_only_where_the_device_takes_one() {
    let mut fixture = Fixture::new(COMPANION);
    let device = fixture.record();
    let draft = draft_place_from_phone(identity_draft(&device), 46.5, -121.25, Some(301.6));
    assert_eq!(draft.altitude_m.value, Some(302));
    let draft = draft_place_from_phone(identity_draft(&device), 46.5, -121.25, None);
    assert_eq!(draft.altitude_m.value, Some(120), "left alone");
    fixture.refused = vec![prop::IDENT_ALTITUDE];
    let device = fixture.record();
    let draft = draft_place_from_phone(identity_draft(&device), 46.5, -121.25, Some(301.6));
    assert_eq!(draft.altitude_m.value, None, "not known: untouched");

    let cleared = draft_clear_position(identity_draft(&Fixture::new(COMPANION).record()));
    assert_eq!(
        (cleared.position.latitude, cleared.position.longitude),
        (None, None)
    );
    assert_eq!(cleared.altitude_m.value, None);
}

#[test]
fn the_manual_precision_comes_from_the_device_then_the_location_then_five() {
    let mut fixture = Fixture::new(MESH);
    fixture.held.gnss_ident_precision = Some(6);
    assert_eq!(identity_draft(&fixture.record()).manual_precision, 6);
    fixture.held.gnss_ident_precision = None;
    fixture.held.ident_location = Some(location(LATITUDE, LONGITUDE, 3));
    let draft = identity_draft(&fixture.record());
    assert_eq!(draft.manual_precision, 3);
    assert!(!draft.precision.known);
    // Choosing a precision without the property sets the local grid, and
    // the same place on it is a new location.
    let draft = draft_set_precision(draft, 4);
    assert_eq!(draft.manual_precision, 4);
    assert_eq!(
        judged(&fixture.record(), wrap_identity(draft)).dirty,
        vec![prop::IDENT_LOCATION]
    );
    fixture.held.ident_location = None;
    assert_eq!(identity_draft(&fixture.record()).manual_precision, 5);
    // The manual choice survives a rebase.
    let draft = draft_set_precision(identity_draft(&fixture.record()), 7);
    fixture.moved(|held| held.ident_mobile = Some(true));
    let MobileManagementDraft::Identity { draft } =
        draft::rebase(&fixture.record(), wrap_identity(draft)).unwrap()
    else {
        panic!()
    };
    assert_eq!(draft.manual_precision, 7);
}

// MARK: Radio

#[test]
fn a_preset_matches_on_what_decides_who_hears_whom() {
    let preset = ulcp_radio_presets()[0].clone();
    let mut fixture = Fixture::new(COMPANION);
    fixture.held.transmit_power_dbm = Some(2);
    fixture.held.duty_cycle_limit = Some(65);
    let device = fixture.record();
    let details = judged(&device, wrap_radio(radio(&device))).details;
    assert_eq!(
        details,
        MobileDraftDetails::Radio {
            preset_id: Some(preset.id.clone()),
            shows_presets: true
        }
    );
    // Unknown modem fields are left out of the comparison, and hide the
    // presets on a LoRa device.
    fixture.refused = vec![prop::PHY_LORA_BW, prop::PHY_LORA_SF];
    fixture.held.coding_rate_denom = Some(8);
    let device = fixture.record();
    let MobileDraftDetails::Radio {
        preset_id,
        shows_presets,
    } = judged(&device, wrap_radio(radio(&device))).details
    else {
        panic!()
    };
    assert_eq!(preset_id, None, "the known coding rate differs");
    assert!(!shows_presets);
    fixture.held.coding_rate_denom = Some(preset.coding_rate_denom);
    let device = fixture.record();
    let MobileDraftDetails::Radio { preset_id, .. } =
        judged(&device, wrap_radio(radio(&device))).details
    else {
        panic!()
    };
    assert_eq!(preset_id, Some(preset.id));
}

#[test]
fn adopting_a_preset_writes_only_known_fields() {
    let presets = ulcp_radio_presets();
    let target = presets
        .iter()
        .find(|preset| preset.frequency_khz != presets[0].frequency_khz)
        .unwrap_or(&presets[0])
        .clone();
    let mut fixture = Fixture::new(COMPANION);
    fixture.held.phy_enabled = Some(false);
    fixture.refused = vec![prop::PHY_LORA_SF];
    let device = fixture.record();
    let draft = draft_adopt_preset(radio(&device), target.id.clone());
    assert!(draft.enabled.value);
    assert_eq!(draft.frequency_khz.value, i64::from(target.frequency_khz));
    assert_eq!(draft.bandwidth.value, Some(target.bandwidth_hz.into()));
    assert_eq!(draft.spreading_factor.value, None, "unknown: untouched");
    assert_eq!(
        draft.coding_rate.value,
        Some(target.coding_rate_denom.into())
    );
    assert_eq!(draft.duty_limit.value, Some(target.duty_cycle_limit.into()));
    match target.transmit_power_dbm {
        Some(power) => assert_eq!(draft.transmit_power_dbm.value, i64::from(power)),
        None => assert_eq!(draft.transmit_power_dbm.value, 14),
    }
    assert_eq!(
        draft_adopt_preset(radio(&device), "nope".to_owned()),
        radio(&device)
    );
}

#[test]
fn a_radio_change_that_can_strand_warns_across_the_mesh_only() {
    for (link, expected) in [
        (MESH, Some(MobileApplyWarning::StrandsRadio)),
        (COMPANION, None),
    ] {
        let device = Fixture::new(link).record();
        let mut draft = radio(&device);
        draft.frequency_khz.value += 25;
        assert_eq!(judged(&device, wrap_radio(draft)).warning, expected);
        let mut draft = radio(&device);
        draft.enabled.value = false;
        assert_eq!(judged(&device, wrap_radio(draft)).warning, expected);
    }
    // Power and the transmit limit apply unwarned.
    let device = Fixture::new(MESH).record();
    let mut draft = radio(&device);
    draft.transmit_power_dbm.value = 20;
    draft.duty_limit.value = Some(655);
    assert_eq!(judged(&device, wrap_radio(draft)).warning, None);
}

// MARK: Network

fn network_with(
    device: &MobileManagedDeviceRecord,
    edit: impl FnOnce(&mut MobileNetworkDraft),
) -> MobileDraftReviewRecord {
    let mut draft = network(device);
    edit(&mut draft);
    judged(device, wrap_network(draft))
}

#[test]
fn a_network_family_is_built_for_every_method() {
    let device = Fixture::lan_only(MESH).record();
    // Off and automatic carry no address, whatever the fields hold.
    for method in [0, 1] {
        let prepared = draft::prepare(
            &device,
            wrap_network({
                let mut draft = network(&device);
                draft.v4_method.value = Some(method);
                draft.v4_address.text = "junk".to_owned();
                draft
            }),
        )
        .unwrap();
        assert!(prepared.problems.is_empty());
        assert_eq!(prepared.dirty, vec![prop::IPV4_CONFIG]);
        assert_eq!(
            prepared.desired.ipv4_config,
            Some(UlcpIpConfigRecord {
                method: method as u8,
                address: Vec::new(),
                prefix: 0,
                gateway: Vec::new()
            })
        );
    }
    // Static, valid, with an empty gateway: no default route.
    let prepared = draft::prepare(
        &device,
        wrap_network({
            let mut draft = network(&device);
            draft.v4_address.text = " 192.168.1.20\t".to_owned();
            draft.v4_gateway.text = String::new();
            draft
        }),
    )
    .unwrap();
    assert_eq!(
        prepared.desired.ipv4_config,
        Some(static_v4([192, 168, 1, 20], 24, [0, 0, 0, 0]))
    );
    // Static, invalid in each part.
    let review = network_with(&device, |draft| draft.v4_address.text = "10.0.0".to_owned());
    assert!(review.dirty.is_empty());
    assert_eq!(
        problems(&review),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::AddressInvalid)]
    );
    let review = network_with(&device, |draft| draft.v4_gateway.text = "router".to_owned());
    assert_eq!(
        problems(&review),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::GatewayInvalid)]
    );
    // An IPv6 address is not an IPv4 one.
    let review = network_with(&device, |draft| {
        draft.v4_address.text = "fd00::2".to_owned()
    });
    assert_eq!(
        problems(&review),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::AddressInvalid)]
    );
    // IPv6 static.
    let review = network_with(&device, |draft| {
        draft.v6_method.value = Some(2);
        draft.v6_address.text = "fd00::2".to_owned();
        draft.v6_prefix.value = Some(64);
    });
    assert_eq!(review.dirty, vec![prop::IPV6_CONFIG]);
}

#[test]
fn a_static_prefix_is_typed_and_fits_its_family() {
    let device = Fixture::lan_only(MESH).record();
    let v4 = |prefix| network_with(&device, |draft| draft.v4_prefix.value = prefix);
    assert_eq!(v4(Some(0)).dirty, vec![prop::IPV4_CONFIG]);
    assert_eq!(v4(Some(32)).dirty, vec![prop::IPV4_CONFIG]);
    assert_eq!(
        problems(&v4(Some(33))),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::PrefixInvalid)]
    );
    assert_eq!(
        problems(&v4(Some(-1))),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::PrefixInvalid)]
    );
    // Never written as /0.
    assert_eq!(
        problems(&v4(None)),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::PrefixInvalid)]
    );
    let v6 = |prefix| {
        network_with(&device, |draft| {
            draft.v6_method.value = Some(2);
            draft.v6_address.text = "fd00::2".to_owned();
            draft.v6_prefix.value = prefix;
        })
    };
    assert_eq!(v6(Some(128)).dirty, vec![prop::IPV6_CONFIG]);
    assert_eq!(
        problems(&v6(Some(129))),
        vec![(prop::IPV6_CONFIG, MobileFieldProblem::PrefixInvalid)]
    );
    // A family moved to static with an address and no prefix yet.
    assert_eq!(
        problems(&v6(None)),
        vec![(prop::IPV6_CONFIG, MobileFieldProblem::PrefixInvalid)]
    );
}

/// Bug 1: the static-address warning tested a field nothing ever edited.
#[test]
fn bug1_moving_onto_a_static_address_warns_across_the_mesh() {
    let device = Fixture::lan_only(MESH).record();
    let review = network_with(&device, |draft| {
        draft.v6_method.value = Some(2);
        draft.v6_address.text = "fd00::2".to_owned();
        draft.v6_prefix.value = Some(64);
    });
    assert_eq!(
        review.warning,
        Some(MobileApplyWarning::ChangesStaticAddressing)
    );
    // A new static address on a family already static is a change too.
    let review = network_with(&device, |draft| {
        draft.v4_address.text = "10.0.0.9".to_owned()
    });
    assert_eq!(
        review.warning,
        Some(MobileApplyWarning::ChangesStaticAddressing)
    );
    // Off static, or off the mesh: no warning.
    let review = network_with(&device, |draft| draft.v4_method.value = Some(1));
    assert_eq!(review.warning, None);
    let device = Fixture::lan_only(COMPANION).record();
    let review = network_with(&device, |draft| {
        draft.v4_address.text = "10.0.0.9".to_owned()
    });
    assert_eq!(review.warning, None);
}

#[test]
fn resolver_rows_drop_blanks_and_refuse_junk() {
    let device = Fixture::lan_only(MESH).record();
    // A blank row being filled in is no edit.
    let review = network_with(&device, |draft| draft.dns.value.push("  ".to_owned()));
    assert!(review.dirty.is_empty());
    let prepared = draft::prepare(
        &device,
        wrap_network({
            let mut draft = network(&device);
            draft.dns.value = vec![
                " 9.9.9.9".to_owned(),
                String::new(),
                "2620:fe::fe".to_owned(),
            ];
            draft
        }),
    )
    .unwrap();
    assert_eq!(prepared.dirty, vec![prop::IP_DNS]);
    assert_eq!(
        prepared.desired.ip_dns,
        Some(vec![
            vec![9, 9, 9, 9],
            "2620:fe::fe"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
        ])
    );
    let review = network_with(&device, |draft| {
        draft.dns.value.push("dns.example".to_owned())
    });
    assert_eq!(
        problems(&review),
        vec![(prop::IP_DNS, MobileFieldProblem::ResolverInvalid)]
    );
}

#[test]
fn the_lan_group_returns_to_its_default_when_emptied() {
    let device = Fixture::lan_only(MESH).record();
    let prepared = draft::prepare(
        &device,
        wrap_network({
            let mut draft = network(&device);
            draft.group.text = " ".to_owned();
            draft
        }),
    )
    .unwrap();
    assert_eq!(prepared.dirty, vec![prop::LAN_BEARER_GROUP]);
    assert_eq!(prepared.desired.lan_bearer_group, None);
    // The same group another way is no edit; a bad one is a problem.
    let review = network_with(&device, |draft| {
        draft.group.text = "\t239.255.0.1:4403 ".to_owned();
    });
    assert!(review.dirty.is_empty());
    assert!(review.problems.is_empty());
    let review = network_with(&device, |draft| {
        draft.group.text = "239.255.0.1:0".to_owned()
    });
    assert_eq!(
        problems(&review),
        vec![(prop::LAN_BEARER_GROUP, MobileFieldProblem::GroupInvalid)]
    );
}

#[test]
fn trimming_takes_horizontal_space_and_never_a_line_break() {
    assert_eq!(trim_horizontal(" \t10.0.0.1\u{00A0}\u{3000}"), "10.0.0.1");
    assert_eq!(trim_horizontal("10.0.0.1\n"), "10.0.0.1\n");
    assert_eq!(trim_horizontal("\u{2003}a b\u{202F}"), "a b");
    let device = Fixture::lan_only(MESH).record();
    let review = network_with(&device, |draft| {
        draft.v4_address.text = "10.0.0.9\n".to_owned()
    });
    assert_eq!(
        problems(&review),
        vec![(prop::IPV4_CONFIG, MobileFieldProblem::AddressInvalid)]
    );
}

// MARK: Bridge

/// Bug 8: Bridge offered Apply for an invalid port, key, group or limit,
/// then refused inside Apply.
#[test]
fn bug8_invalid_bridge_fields_are_problems_and_not_edits() {
    let device = Fixture::new(MESH).record();
    let case = |edit: &dyn Fn(&mut MobileBridgeDraft)| {
        let mut draft = bridge(&device);
        edit(&mut draft);
        judged(&device, wrap_bridge(draft))
    };
    for (port, valid) in [
        (0, false),
        (1, true),
        (65_535, true),
        (65_536, false),
        (-1, false),
    ] {
        let review = case(&|draft| draft.port.value = port);
        if valid {
            assert_eq!(review.dirty, vec![prop::BRIDGE_PORT], "port {port}");
        } else {
            assert!(review.dirty.is_empty(), "port {port}");
            assert!(!review.has_edits);
            assert_eq!(
                problems(&review),
                vec![(prop::BRIDGE_PORT, MobileFieldProblem::PortInvalid)]
            );
        }
    }
    for (limit, valid) in [
        (None, true),
        (Some(1), true),
        (Some(0), false),
        (Some(65_536), false),
    ] {
        let review = case(&|draft| draft.ingress_limit.value = limit);
        if valid {
            assert_eq!(
                review.dirty,
                vec![prop::LAN_BEARER_INGRESS_LIMIT],
                "{limit:?}"
            );
        } else {
            assert_eq!(
                problems(&review),
                vec![(
                    prop::LAN_BEARER_INGRESS_LIMIT,
                    MobileFieldProblem::LimitInvalid
                )],
                "{limit:?}"
            );
        }
    }
    let review = case(&|draft| draft.host.text = "bad host!".to_owned());
    assert_eq!(
        problems(&review),
        vec![(prop::BRIDGE_HOST, MobileFieldProblem::HostInvalid)]
    );
    let review = case(&|draft| draft.server_key.text = "not an address".to_owned());
    assert_eq!(
        problems(&review),
        vec![(
            prop::BRIDGE_SERVER_KEY,
            MobileFieldProblem::ServerKeyInvalid
        )]
    );
    let review = case(&|draft| draft.group.text = "nowhere".to_owned());
    assert_eq!(
        problems(&review),
        vec![(prop::LAN_BEARER_GROUP, MobileFieldProblem::GroupInvalid)]
    );
    // The good edits beside a bad one stay dirty.
    let review = case(&|draft| {
        draft.port.value = 0;
        draft.enabled.value = false;
        draft.server_key.text = String::new();
    });
    assert_eq!(
        review.dirty,
        vec![prop::BRIDGE_ENABLED, prop::BRIDGE_SERVER_KEY]
    );
    assert_eq!(review.problems.len(), 1);
    // The same key, written another way, is no edit.
    let review = case(&|draft| draft.server_key.text = address_of(9));
    assert!(review.dirty.is_empty());
}

#[test]
fn a_clean_field_is_never_a_problem() {
    let mut fixture = Fixture::new(MESH);
    // A device reporting what an edit could not be.
    fixture.held.bridge_port = Some(0);
    let device = fixture.record();
    let draft = bridge(&device);
    assert_eq!(draft.port.reported, 0);
    let review = judged(&device, wrap_bridge(draft));
    assert!(review.problems.is_empty());
    assert!(review.dirty.is_empty());
}

// MARK: Repeater and MeshCore

#[test]
fn a_repeater_region_is_added_respelled_or_refused() {
    let device = Fixture::new(MESH).record();
    let draft = repeater(&device);
    let draft = draft_add_repeater_region(draft, " sjc\t".to_owned()).unwrap();
    assert_eq!(
        draft.regions.value,
        vec!["sjc".to_owned(), "Bay Area".to_owned()]
    );
    let draft = draft_add_repeater_region(draft, "WA".to_owned()).unwrap();
    assert_eq!(draft.regions.value.last().unwrap(), "WA");
    assert_eq!(
        draft_add_repeater_region(draft.clone(), "x".repeat(25)),
        Err(MobileRegionEntryProblem::Invalid)
    );
    assert_eq!(
        draft_add_repeater_region(draft.clone(), "  ".to_owned()),
        Ok(draft.clone())
    );
    assert_eq!(
        judged(&device, wrap_repeater(draft)).dirty,
        vec![prop::MAC_REPEATER_REGIONS]
    );
}

#[test]
fn adopting_regions_leaves_an_unread_default_alone() {
    let mut fixture = Fixture::new(MESH);
    let device = fixture.record();
    let wa = region_code_from_string("WA".to_owned()).unwrap();
    let draft = draft_adopt_regions(repeater(&device), vec!["WA".to_owned()], Some(wa.clone()));
    assert_eq!(draft.default_region.text, "WA");
    assert_eq!(
        judged(&device, wrap_repeater(draft)).dirty,
        vec![
            prop::MAC_REPEATER_REGIONS,
            prop::MAC_REPEATER_DEFAULT_REGION
        ]
    );
    let draft = draft_adopt_regions(repeater(&device), vec!["SJC".to_owned()], None);
    assert_eq!(draft.default_region.text, "", "never tag");
    fixture.refused = vec![prop::MAC_REPEATER_DEFAULT_REGION];
    let device = fixture.record();
    let draft = draft_adopt_regions(repeater(&device), vec!["WA".to_owned()], Some(wa));
    assert_eq!(draft.default_region.text, "");
    assert_eq!(
        judged(&device, wrap_repeater(draft)).dirty,
        vec![prop::MAC_REPEATER_REGIONS]
    );
}

#[test]
fn the_default_region_text_reads_back_as_its_code_for_every_code() {
    for value in 0..=u16::MAX {
        let code = value.to_be_bytes().to_vec();
        let text = region_code_description(code.clone()).unwrap();
        assert_eq!(
            region_code_from_string(text.clone()).unwrap(),
            code,
            "{text}"
        );
    }
}

#[test]
fn the_default_region_picker_offers_the_list_and_the_device_tag() {
    let mut fixture = Fixture::new(MESH);
    fixture.held.repeater_default_region = Some(region_code_from_string("WA".to_owned()).unwrap());
    let device = fixture.record();
    let MobileDraftDetails::Repeater { taggable_regions } =
        judged(&device, wrap_repeater(repeater(&device))).details
    else {
        panic!()
    };
    assert_eq!(taggable_regions, vec!["SJC", "Bay Area", "WA"]);
    // A default spelled another way is the same tag; a cleared one never
    // tags.
    let mut draft = repeater(&device);
    draft.default_region.text = "wa".to_owned();
    assert!(
        judged(&device, wrap_repeater(draft.clone()))
            .dirty
            .is_empty()
    );
    draft.default_region.text = String::new();
    let prepared = draft::prepare(&device, wrap_repeater(draft)).unwrap();
    assert_eq!(prepared.dirty, vec![prop::MAC_REPEATER_DEFAULT_REGION]);
    assert_eq!(prepared.desired.repeater_default_region, Some(Vec::new()));
}

#[test]
fn a_listed_long_region_as_the_default_is_offered_once_by_name() {
    let mut fixture = Fixture::new(MESH);
    let bay_area = region_code_from_string("Bay Area".to_owned()).unwrap();
    fixture.held.repeater_default_region = Some(bay_area.clone());
    let device = fixture.record();
    let draft = repeater(&device);
    assert_eq!(draft.default_region.text, "Bay Area");
    let MobileDraftDetails::Repeater { taggable_regions } =
        judged(&device, wrap_repeater(draft.clone())).details
    else {
        panic!()
    };
    assert_eq!(taggable_regions, vec!["SJC", "Bay Area"]);
    // Its code form is the same tag, offered once.
    let mut respelled = draft.clone();
    respelled.default_region.text = region_code_description(bay_area.clone()).unwrap();
    let judged_respelled = judged(&device, wrap_repeater(respelled));
    assert!(judged_respelled.dirty.is_empty());
    let MobileDraftDetails::Repeater { taggable_regions } = judged_respelled.details else {
        panic!()
    };
    assert_eq!(taggable_regions, vec!["SJC", "Bay Area"]);
    // A suggestion that lists it spells the default as listed.
    let adopted = draft_adopt_regions(draft, vec!["Bay Area".to_owned()], Some(bay_area));
    assert_eq!(adopted.default_region.text, "Bay Area");
}

#[test]
fn a_region_added_later_gives_the_default_its_spelling() {
    let mut fixture = Fixture::new(MESH);
    let north_bay = region_code_from_string("North Bay".to_owned()).unwrap();
    fixture.held.repeater_default_region = Some(north_bay.clone());
    let device = fixture.record();
    let draft = repeater(&device);
    let code_form = region_code_description(north_bay).unwrap();
    assert_eq!(draft.default_region.text, code_form, "not listed");
    let draft = draft_add_repeater_region(draft, "North Bay".to_owned()).unwrap();
    assert_eq!(draft.default_region.text, "North Bay");
    let MobileDraftDetails::Repeater { taggable_regions } =
        judged(&device, wrap_repeater(draft)).details
    else {
        panic!()
    };
    assert_eq!(taggable_regions, vec!["SJC", "Bay Area", "North Bay"]);
}

#[test]
fn a_reading_with_nothing_heard_leaves_empty_able_fields_unknown() {
    // A category opened with an empty cache: covered, refused nothing,
    // and holds no value. An empty value would be a value; no value is
    // nothing heard yet.
    let mut device = Fixture::new(MESH).record();
    for reading in &mut device.readings {
        reading.values.clear();
        reading.properties = UlcpDevicePropertiesRecord::default();
    }
    let draft = repeater(&device);
    assert!(!draft.default_region.known);
    assert!(!draft.min_rssi.known);
    assert!(!draft.min_snr.known);
    let draft = identity_draft(&device);
    assert!(!draft.role.known);
    assert!(!draft.altitude_m.known);
}

#[test]
fn the_default_region_picker_leaves_out_a_listed_region_with_no_code() {
    let device = Fixture::new(MESH).record();
    let mut draft = repeater(&device);
    draft.regions.value = vec![" ".to_owned(), "SJC".to_owned(), "x".repeat(200)];
    let MobileDraftDetails::Repeater { taggable_regions } =
        judged(&device, wrap_repeater(draft)).details
    else {
        panic!()
    };
    assert_eq!(taggable_regions, vec!["SJC"]);
}

#[test]
fn meshcore_regions_dedupe_exactly_and_a_reserved_key_locks_the_switch() {
    let mut fixture = Fixture::new(MESH);
    let device = fixture.record();
    let draft = meshcore(&device);
    assert_eq!(
        draft_add_meshcore_region(draft.clone(), "sf".to_owned()),
        Err(MobileRegionEntryProblem::AlreadyListed)
    );
    let draft = draft_add_meshcore_region(draft, " #SF ".to_owned()).unwrap();
    assert_eq!(draft.regions.value, vec!["sf".to_owned(), "SF".to_owned()]);
    assert_eq!(
        draft_add_meshcore_region(draft, "$private".to_owned()),
        Err(MobileRegionEntryProblem::Invalid)
    );
    let details = |device: &MobileManagedDeviceRecord| {
        judged(
            device,
            MobileManagementDraft::MeshCore {
                draft: meshcore(device),
            },
        )
        .details
    };
    assert_eq!(
        details(&device),
        MobileDraftDetails::MeshCore {
            identity_allowed: true,
            toggle_locked: false
        }
    );
    fixture.dev_key = Some(vec![0; 32]);
    assert_eq!(
        details(&fixture.record()),
        MobileDraftDetails::MeshCore {
            identity_allowed: false,
            toggle_locked: true
        }
    );
    // Turning forwarding off stays possible.
    fixture.held.meshcore_forwarding_enabled = Some(true);
    assert_eq!(
        details(&fixture.record()),
        MobileDraftDetails::MeshCore {
            identity_allowed: false,
            toggle_locked: false
        }
    );
}

#[test]
fn repeater_and_meshcore_drafts_write_disjoint_properties() {
    let device = Fixture::new(MESH).record();
    let mut repeater_draft = repeater(&device);
    repeater_draft.mode.value = Some(2);
    repeater_draft.regions.value.clear();
    repeater_draft.default_region.text = String::new();
    repeater_draft.min_rssi.value = None;
    repeater_draft.min_snr.value = None;
    let mut meshcore_draft = meshcore(&device);
    meshcore_draft.enabled.value = true;
    meshcore_draft.policy.value = Some(1);
    meshcore_draft.regions.value.clear();
    let repeater_dirty = judged(&device, wrap_repeater(repeater_draft)).dirty;
    let meshcore_dirty = judged(
        &device,
        MobileManagementDraft::MeshCore {
            draft: meshcore_draft,
        },
    )
    .dirty;
    assert_eq!(repeater_dirty.len(), 5);
    assert_eq!(meshcore_dirty.len(), 3);
    assert!(
        repeater_dirty
            .iter()
            .all(|property| !meshcore_dirty.contains(property))
    );
}

// MARK: Wi-Fi and Bluetooth

#[test]
fn switching_the_station_off_warns_across_the_mesh_only() {
    for (link, expected) in [
        (MESH, Some(MobileApplyWarning::DisablesWifi)),
        (COMPANION, None),
    ] {
        let device = Fixture::new(link).record();
        let mut draft = wifi(&device);
        draft.enabled.value = false;
        let review = judged(&device, MobileManagementDraft::Wifi { draft });
        assert_eq!(review.dirty, vec![prop::WIFI_ENABLED]);
        assert_eq!(review.warning, expected);
    }
}

#[test]
fn stranding_the_bluetooth_link_outranks_the_pairing_window() {
    let assess = |uses_bluetooth: bool, enabled: bool, pairing: bool| {
        let mut fixture = Fixture::new(COMPANION);
        fixture.uses_bluetooth = uses_bluetooth;
        let device = fixture.record();
        let mut draft = bluetooth(&device);
        draft.enabled.value = enabled;
        draft.pairing.value = pairing;
        let review = judged(&device, MobileManagementDraft::Bluetooth { draft });
        (review.warning, review.details)
    };
    let link = |disables_this_link| MobileDraftDetails::Bluetooth { disables_this_link };
    assert_eq!(
        assess(true, false, true),
        (Some(MobileApplyWarning::DisablesBluetooth), link(true))
    );
    assert_eq!(
        assess(false, false, true),
        (Some(MobileApplyWarning::OpensPairing), link(false))
    );
    assert_eq!(
        assess(true, true, true),
        (Some(MobileApplyWarning::OpensPairing), link(true))
    );
    assert_eq!(assess(false, false, false), (None, link(false)));
}

// MARK: Applying

fn is(property_id: u32, value: Vec<u8>) -> UlcpPropertyPushRecord {
    UlcpPropertyPushRecord {
        property_id,
        value,
        kind: UlcpPropertyPushKind::Is,
    }
}

fn identity_of(bench: &Bench) -> MobileIdentityDraft {
    match bench.device.draft(MobileDraftKind::Identity) {
        Some(MobileManagementDraft::Identity { draft }) => draft,
        other => panic!("{other:?}"),
    }
}

/// The case rebasing first guards: a value moves under a field the draft
/// never touched, and Apply is tapped before native code rebased.
#[tokio::test(flavor = "current_thread")]
async fn apply_stale_draft_does_not_write_untouched_field() {
    let bench = Bench::new(MESH).await;
    bench.script.set(prop::IDENT_MOBILE, vec![0]);
    bench.device.load_card().await.unwrap();
    assert_eq!(
        bench.device.draft(MobileDraftKind::Identity),
        None,
        "no reading yet"
    );
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    let mut draft = identity_of(&bench);
    assert!(draft.mobile.known);
    draft.name.text = "Ridge".to_owned();
    let before = draft.reading_revision;
    bench
        .device
        .receive_pushes(vec![is(prop::IDENT_MOBILE, vec![1])], 0);
    bench
        .until("the push folds", |record| {
            reading(record, UlcpManageCategory::Identity)
                .is_some_and(|reading| reading.revision != before)
        })
        .await;
    bench.script.clear_asked();
    let outcome = bench
        .device
        .apply(MobileManagementDraft::Identity { draft })
        .await;
    assert_eq!(
        outcome,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Applied
        })
    );
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::Write(vec![(prop::DEV_NAME, name("Ridge"))]),
            Call::Save
        ]
    );
    let identity = reading(&bench.snapshot(), UlcpManageCategory::Identity)
        .unwrap()
        .properties
        .clone();
    assert_eq!(identity.ident_mobile, Some(true), "the device's own");
    // Rebuilt after the answer, the draft is clean.
    let review = bench
        .device
        .review(MobileManagementDraft::Identity {
            draft: identity_of(&bench),
        })
        .unwrap();
    assert!(!review.has_edits);
}

/// The case only rebasing first catches: the device moves onto the edit
/// before Apply, so the stale draft has nothing left to write.
#[tokio::test(flavor = "current_thread")]
async fn apply_stale_draft_whose_edit_landed_writes_nothing() {
    let bench = Bench::new(MESH).await;
    bench.script.set(prop::IDENT_MOBILE, vec![0]);
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    let mut draft = identity_of(&bench);
    draft.mobile.value = true;
    let before = draft.reading_revision;
    bench
        .device
        .receive_pushes(vec![is(prop::IDENT_MOBILE, vec![1])], 0);
    bench
        .until("the push folds", |record| {
            reading(record, UlcpManageCategory::Identity)
                .is_some_and(|reading| reading.revision != before)
        })
        .await;
    bench.script.clear_asked();
    let stale = MobileManagementDraft::Identity { draft };
    assert!(!bench.device.review(stale.clone()).unwrap().has_edits);
    assert_eq!(
        bench.device.apply(stale).await,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::NothingToApply
        })
    );
    assert_eq!(bench.script.asked(), Vec::new(), "nothing sent");
}

#[tokio::test(flavor = "current_thread")]
async fn applying_a_draft_judges_it_first() {
    let bench = Bench::new(MESH).await;
    // No stated height: an altitude the device answered for.
    bench.script.set(prop::IDENT_ALTITUDE, Vec::new());
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench.script.clear_asked();
    let draft = identity_of(&bench);
    assert_eq!(
        bench
            .device
            .apply(MobileManagementDraft::Identity {
                draft: draft.clone()
            })
            .await,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::NothingToApply
        })
    );
    let mut invalid = draft.clone();
    invalid.name.text = "Ridge".to_owned();
    invalid.altitude_m.value = Some(1 << 40);
    assert_eq!(
        bench
            .device
            .apply(MobileManagementDraft::Identity { draft: invalid })
            .await,
        Ok(MobileApplyOutcome {
            answered: false,
            result: MobileApplyResult::Invalid
        })
    );
    assert_eq!(bench.script.asked(), Vec::new(), "nothing sent");
    // A category the device does not offer.
    let other = Fixture::new(MESH).record();
    assert_eq!(
        bench.device.apply(wrap_bridge(bridge(&other))).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        bench.device.review(wrap_bridge(bridge(&other))),
        Err(MobileAppError::InvalidRequest)
    );
    // A released handle answers nothing more.
    bench.device.release();
    assert_eq!(bench.device.draft(MobileDraftKind::Identity), None);
    assert_eq!(
        bench.device.rebase(MobileManagementDraft::Identity {
            draft: draft.clone()
        }),
        Err(MobileAppError::Stopped)
    );
    assert_eq!(
        bench
            .device
            .review(MobileManagementDraft::Identity { draft }),
        Err(MobileAppError::Stopped)
    );
}

/// The repeater category on a scripted device: its own and MeshCore's.
fn repeater_values() -> BTreeMap<u32, Vec<u8>> {
    let mut values = device_values("1.0");
    values.insert(
        prop::CAPS,
        capabilities(&[
            cap::REPEATER,
            cap::MESHCORE_FORWARDER,
            cap::SAVE,
            cap::CMD_MULTI,
        ]),
    );
    let held = Fixture::new(MESH).held;
    for property in [
        prop::MAC_REPEATER_MODE,
        prop::MAC_REPEATER_REGIONS,
        prop::MAC_REPEATER_DEFAULT_REGION,
        prop::MAC_REPEATER_MIN_RSSI,
        prop::MAC_REPEATER_MIN_SNR,
        prop::MESHCORE_FORWARDING_ENABLED,
        prop::MESHCORE_REGION_POLICY,
        prop::MESHCORE_REGIONS,
    ] {
        values.insert(property, encoded(property, &held));
    }
    values
}

#[tokio::test(flavor = "current_thread")]
async fn applying_meshcore_never_writes_the_repeater_s_properties() {
    let script = ScriptedCarrier::new(Some(address_of(super::DEVICE_SEED)), repeater_values());
    let bench = Bench::scripted(MESH, script).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Repeater)
        .await
        .unwrap();
    let Some(MobileManagementDraft::MeshCore {
        draft: mut meshcore,
    }) = bench.device.draft(MobileDraftKind::MeshCore)
    else {
        panic!()
    };
    let Some(MobileManagementDraft::Repeater {
        draft: mut repeater,
    }) = bench.device.draft(MobileDraftKind::Repeater)
    else {
        panic!()
    };
    meshcore.enabled.value = true;
    repeater.mode.value = Some(2);
    bench.script.clear_asked();
    let outcome = bench
        .device
        .apply(MobileManagementDraft::MeshCore { draft: meshcore })
        .await
        .unwrap();
    assert_eq!(outcome.result, MobileApplyResult::Applied);
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::Write(vec![(prop::MESHCORE_FORWARDING_ENABLED, vec![1])]),
            Call::Save
        ]
    );
    // The repeater draft, stale now, still writes only its own edit.
    bench.script.clear_asked();
    let outcome = bench
        .device
        .apply(MobileManagementDraft::Repeater { draft: repeater })
        .await
        .unwrap();
    assert_eq!(outcome.result, MobileApplyResult::Applied);
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::Write(vec![(prop::MAC_REPEATER_MODE, vec![2])]),
            Call::Save
        ]
    );
}
