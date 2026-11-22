//! What is known of one category: the octets as the device reported them,
//! each with its own sample instant, and everything derived from them.
//!
//! The octets are the truth and the decoded record is derived, so an echo
//! or a push folds in as a merge and no field needs its own rule for what
//! a partial update means.

use std::collections::{BTreeMap, BTreeSet};

use umsh_ulcp::ids::prop;

use super::records::{
    MobileCategoryReadingRecord, MobileManagementProblem, MobilePropertyRefusalRecord,
    MobilePropertyState, MobilePropertyStateRecord, MobilePropertyValueRecord, MobileRefusal,
    MobileTemperatureNames, MobileTemperatureRowRecord, MobileTemperatureSummaryRecord,
    MobileTemperatureValue,
};
use super::refusal::classify;
use crate::ulcp::{
    UlcpDevicePropertiesRecord, UlcpManageCategory, inspect_ulcp_properties, ulcp_property_record,
};

/// Why a property asked for has no value, besides a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    /// The device answered the request without it.
    NoResponse,
    /// The request failed.
    Failed(MobileManagementProblem),
}

#[derive(Clone, Debug)]
pub(super) struct Reading {
    pub(super) category: UlcpManageCategory,
    /// What the category covers on this device, in ask order.
    pub(super) property_ids: Vec<u32>,
    pub(super) values: BTreeMap<u32, Vec<u8>>,
    pub(super) received_at_ms: BTreeMap<u32, i64>,
    pub(super) properties: UlcpDevicePropertiesRecord,
    /// What the last read refused, with the status when there was one.
    pub(super) refused: BTreeSet<u32>,
    pub(super) statuses: BTreeMap<u32, u32>,
    pub(super) failures: BTreeMap<u32, Failure>,
    /// A names reply was rejected; the names known before are kept.
    pub(super) invalid_temperature_names: bool,
    /// Battery pushes update the summary on their own, so they must not
    /// make the diagnostics look fresh.
    pub(super) battery_diagnostics_as_of_ms: Option<i64>,
    pub(super) as_of_ms: Option<i64>,
    pub(super) is_fresh: bool,
    pub(super) revision: u64,
}

impl Reading {
    pub(super) fn new(category: UlcpManageCategory, property_ids: Vec<u32>, revision: u64) -> Self {
        Self {
            category,
            property_ids,
            values: BTreeMap::new(),
            received_at_ms: BTreeMap::new(),
            properties: UlcpDevicePropertiesRecord::default(),
            refused: BTreeSet::new(),
            statuses: BTreeMap::new(),
            failures: BTreeMap::new(),
            invalid_temperature_names: false,
            battery_diagnostics_as_of_ms: None,
            as_of_ms: None,
            is_fresh: false,
            revision,
        }
    }

    pub(super) fn covers(&self, property: u32) -> bool {
        self.property_ids.contains(&property)
    }

    /// Whether the device answered for `property`: covered and not
    /// refused.
    pub(super) fn answered(&self, property: u32) -> bool {
        self.covers(property) && !self.refused.contains(&property)
    }

    /// The counters Reset Counters zeroes: the ones this reading answered.
    pub(super) fn resettable_counters(&self) -> Vec<u32> {
        STATISTICS_COUNTERS
            .into_iter()
            .filter(|counter| self.answered(*counter))
            .collect()
    }

    /// Take in values the device reported, from a read, an echo or a
    /// push, at `instant`; `sampled_at_ms` dates any of them otherwise
    /// (the cache's own instants).
    pub(super) fn absorb(
        &mut self,
        reported: &BTreeMap<u32, Vec<u8>>,
        instant: i64,
        from_air: bool,
        sampled_at_ms: &BTreeMap<u32, i64>,
        revision: u64,
    ) {
        if reported
            .keys()
            .any(|property| BATTERY_DIAGNOSTICS.contains(property))
        {
            self.battery_diagnostics_as_of_ms = Some(instant);
        }
        for (property, value) in reported {
            self.received_at_ms.insert(
                *property,
                sampled_at_ms.get(property).copied().unwrap_or(instant),
            );
            self.values.insert(*property, value.clone());
        }
        self.properties = decode(&self.values);
        self.as_of_ms = Some(instant);
        self.is_fresh |= from_air;
        self.revision = revision;
    }

    /// A fresh sensors reading that keeps the names already known, with
    /// their own instant.
    pub(super) fn sensor_refresh(
        previous: Option<&Self>,
        property_ids: Vec<u32>,
        revision: u64,
    ) -> Self {
        let mut reading = Self::new(UlcpManageCategory::Sensors, property_ids, revision);
        let names = prop::TEMPERATURE_NAMES;
        if reading.covers(names)
            && let Some(previous) = previous
            && previous.properties.temperature_names.is_some()
            && let (Some(bytes), Some(at)) = (
                previous.values.get(&names),
                previous.received_at_ms.get(&names),
            )
        {
            reading.absorb(
                &BTreeMap::from([(names, bytes.clone())]),
                *at,
                false,
                &BTreeMap::new(),
                revision,
            );
        }
        reading
    }

    /// Every measurement in one request, with the names until they are
    /// known; once they are, the names alone after the measurements.
    pub(super) fn sensor_requests(&self) -> Vec<Vec<u32>> {
        let names = prop::TEMPERATURE_NAMES;
        if !self.covers(names) || self.properties.temperature_names.is_none() {
            return vec![self.property_ids.clone()];
        }
        vec![
            self.property_ids
                .iter()
                .copied()
                .filter(|property| *property != names)
                .collect(),
            vec![names],
        ]
    }

    /// Whether the measurements name more sensors than the names do.
    pub(super) fn needs_temperature_names(&self) -> bool {
        self.properties.temperatures.as_ref().map_or(0, Vec::len)
            > self
                .properties
                .temperature_names
                .as_ref()
                .map_or(0, Vec::len)
    }

    /// Take a names reply when it names at least as many sensors as the
    /// names known; otherwise keep those and say the reply was rejected.
    pub(super) fn absorb_temperature_names(&mut self, bytes: Vec<u8>, instant: i64, revision: u64) {
        let names = prop::TEMPERATURE_NAMES;
        let decoded = inspect_ulcp_properties(vec![ulcp_property_record(names, bytes.clone())])
            .temperature_names;
        let known = self
            .properties
            .temperature_names
            .as_ref()
            .map_or(0, Vec::len);
        match decoded {
            Some(decoded) if decoded.len() >= known => {
                self.invalid_temperature_names = false;
                self.absorb(
                    &BTreeMap::from([(names, bytes)]),
                    instant,
                    true,
                    &BTreeMap::new(),
                    revision,
                );
            }
            _ => {
                self.invalid_temperature_names = true;
                self.revision = revision;
            }
        }
    }

    /// One property's read state: refused, then failed, then by its
    /// octets.
    pub(super) fn state(&self, property: u32) -> MobilePropertyState {
        if self.refused.contains(&property) {
            return MobilePropertyState::Refused {
                refusal: classify(self.statuses.get(&property).copied()),
            };
        }
        match self.failures.get(&property) {
            Some(Failure::NoResponse) => return MobilePropertyState::NoResponse,
            Some(Failure::Failed(problem)) => {
                return MobilePropertyState::Failed {
                    problem: problem.clone(),
                };
            }
            None => {}
        }
        match self.values.get(&property) {
            None => MobilePropertyState::NotRead,
            Some(value) if value.is_empty() => MobilePropertyState::Empty,
            Some(_) => match decoder_row(property) {
                Some(Some(decoded)) if !decoded(&self.properties) => MobilePropertyState::Invalid,
                _ => MobilePropertyState::Present,
            },
        }
    }

    /// The reading as published, with the refusals the last write met.
    pub(super) fn record(
        &self,
        refusals: Option<&BTreeMap<u32, MobileRefusal>>,
    ) -> MobileCategoryReadingRecord {
        MobileCategoryReadingRecord {
            category: self.category,
            property_ids: self.property_ids.clone(),
            answered: self
                .property_ids
                .iter()
                .copied()
                .filter(|property| !self.refused.contains(property))
                .collect(),
            values: self
                .values
                .iter()
                .map(|(property, value)| MobilePropertyValueRecord {
                    property_id: *property,
                    value: value.clone(),
                    received_at_ms: self
                        .received_at_ms
                        .get(property)
                        .copied()
                        .unwrap_or_default(),
                })
                .collect(),
            properties: self.properties.clone(),
            states: self
                .property_ids
                .iter()
                .map(|property| MobilePropertyStateRecord {
                    property_id: *property,
                    state: self.state(*property),
                })
                .collect(),
            refusals: refusals
                .into_iter()
                .flatten()
                .map(|(property, refusal)| MobilePropertyRefusalRecord {
                    property_id: *property,
                    refusal: refusal.clone(),
                })
                .collect(),
            temperatures: self
                .covers(prop::TEMPERATURES)
                .then(|| self.temperature_summary()),
            can_reset_counters: !self.resettable_counters().is_empty(),
            battery_diagnostics_as_of_ms: self.battery_diagnostics_as_of_ms,
            as_of_ms: self.as_of_ms,
            is_fresh: self.is_fresh,
            revision: self.revision,
        }
    }

    /// The temperatures, classified: whether the names can be shown, why
    /// the readings cannot, and one row per sensor either names.
    fn temperature_summary(&self) -> MobileTemperatureSummaryRecord {
        let names_id = prop::TEMPERATURE_NAMES;
        let readings = self.properties.temperatures.as_ref();
        let names = self.properties.temperature_names.as_ref();
        let names_failed =
            self.failures.contains_key(&names_id) || self.refused.contains(&names_id);
        let names_malformed = self.invalid_temperature_names
            || (self.values.contains_key(&names_id) && names.is_none());
        let names_short =
            readings.is_some_and(|readings| names.is_none_or(|names| names.len() < readings.len()));
        let names_state = if names_failed {
            MobileTemperatureNames::Unreadable
        } else if names_malformed || names_short {
            MobileTemperatureNames::Incomplete
        } else {
            MobileTemperatureNames::Known
        };
        let failure = match self.state(prop::TEMPERATURES) {
            state @ (MobilePropertyState::Refused { .. }
            | MobilePropertyState::Failed { .. }
            | MobilePropertyState::NoResponse
            | MobilePropertyState::Invalid) => Some(state),
            _ => None,
        };
        let count = readings.map_or(0, Vec::len).max(names.map_or(0, Vec::len));
        let rows = (0..count)
            .map(|index| MobileTemperatureRowRecord {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                name: names.and_then(|names| names.get(index).cloned()),
                value: match readings.and_then(|readings| readings.get(index)) {
                    None => MobileTemperatureValue::NotRead,
                    Some(None | Some(u16::MAX)) => MobileTemperatureValue::Unavailable,
                    Some(Some(tenths_kelvin)) => MobileTemperatureValue::Reading {
                        tenths_kelvin: *tenths_kelvin,
                    },
                },
            })
            .collect();
        MobileTemperatureSummaryRecord {
            rows,
            failure,
            names: names_state,
            sampled_at_ms: self.received_at_ms.get(&prop::TEMPERATURES).copied(),
        }
    }
}

/// Decode a reading's octets whole.
pub(super) fn decode(values: &BTreeMap<u32, Vec<u8>>) -> UlcpDevicePropertiesRecord {
    inspect_ulcp_properties(
        values
            .iter()
            .map(|(property, value)| ulcp_property_record(*property, value.clone()))
            .collect(),
    )
}

/// The battery's diagnostic properties, which date the diagnostics apart
/// from the summary.
const BATTERY_DIAGNOSTICS: std::ops::RangeInclusive<u32> =
    prop::BATTERY_CURRENT..=prop::BATTERY_GAUGE_OPERATION_STATUS;

/// Whether `property` is kept in the cache. Sensor inventories belong to
/// one connection, and measurements, the scan table and the live scan
/// state are always read fresh.
pub(super) fn persistent(property: u32) -> bool {
    ![
        prop::ILLUMINANCE,
        prop::TEMPERATURES,
        prop::TEMPERATURE_NAMES,
        prop::WIFI_SCAN_RESULTS,
        prop::WIFI_RSSI,
        prop::WIFI_SCANNING,
    ]
    .contains(&property)
}

/// The counters Reset Counters zeroes.
pub(super) const STATISTICS_COUNTERS: [u32; 14] = [
    prop::STAT_TX_PACKETS,
    prop::STAT_TX_CHANNEL_BUSY,
    prop::STAT_RX_PACKETS,
    prop::STAT_RX_BAD_CRC,
    prop::STAT_RX_NON_UMSH,
    prop::STAT_RX_ACCEPTED,
    prop::STAT_RADIO_RESETS,
    prop::STAT_FORWARDED,
    prop::STAT_FORWARD_DROPPED,
    prop::STAT_FORWARD_CANCELLED,
    prop::STAT_MESHCORE_SEEN,
    prop::STAT_MESHCORE_FORWARDED_ROUTED,
    prop::STAT_MESHCORE_FORWARDED_FLOOD,
    prop::STAT_MESHCORE_DECLINED,
];

type Decoded = fn(&UlcpDevicePropertiesRecord) -> bool;

/// Which field of the decoded record a managed property fills: `None`
/// for a property this table does not list, `Some(None)` for one the
/// record has no field for (the card's, the battery diagnostics, the
/// alert), whose octets are taken as they come.
pub(super) fn decoder_row(property: u32) -> Option<Option<Decoded>> {
    macro_rules! field {
        ($field:ident) => {
            Some(Some((|record| record.$field.is_some()) as Decoded))
        };
    }
    match property {
        prop::CAPS
        | prop::HOST_KEY
        | prop::DEV_VERSION
        | prop::DEV_MODEL
        | prop::ALERT
        | prop::TEST_MESSAGE_ALERTS => Some(None),
        property if BATTERY_DIAGNOSTICS.contains(&property) => Some(None),
        prop::DEV_NAME => field!(device_name),
        prop::BATTERY => field!(battery),
        prop::ILLUMINANCE => field!(illuminance_millilux),
        prop::TEMPERATURES => field!(temperatures),
        prop::TEMPERATURE_NAMES => field!(temperature_names),
        prop::PHY_ENABLED => field!(phy_enabled),
        prop::PHY_FREQ => field!(frequency_khz),
        prop::PHY_TX_POWER => field!(transmit_power_dbm),
        prop::PHY_LORA_BW => field!(bandwidth_hz),
        prop::PHY_LORA_SF => field!(spreading_factor),
        prop::PHY_LORA_CR => field!(coding_rate_denom),
        prop::PHY_DUTY_NOW => field!(duty_cycle_now),
        prop::PHY_RX_DUTY => field!(rx_duty_cycle),
        prop::PHY_DUTY_LIMIT => field!(duty_cycle_limit),
        prop::STAT_TX_PACKETS => field!(stat_tx_packets),
        prop::STAT_TX_CHANNEL_BUSY => field!(stat_tx_channel_busy),
        prop::STAT_RX_PACKETS => field!(stat_rx_packets),
        prop::STAT_RX_BAD_CRC => field!(stat_rx_bad_crc),
        prop::STAT_RX_NON_UMSH => field!(stat_rx_non_umsh),
        prop::STAT_RX_ACCEPTED => field!(stat_rx_accepted),
        prop::STAT_RADIO_RESETS => field!(stat_radio_resets),
        prop::STAT_FORWARDED => field!(stat_forwarded),
        prop::STAT_FORWARD_DROPPED => field!(stat_forward_dropped),
        prop::STAT_FORWARD_CANCELLED => field!(stat_forward_cancelled),
        prop::MAC_REPEATERS_HEARD => field!(repeaters_heard),
        prop::STAT_MESHCORE_SEEN => field!(stat_meshcore_seen),
        prop::STAT_MESHCORE_FORWARDED_ROUTED => field!(stat_meshcore_forwarded_routed),
        prop::STAT_MESHCORE_FORWARDED_FLOOD => field!(stat_meshcore_forwarded_flood),
        prop::STAT_MESHCORE_DECLINED => field!(stat_meshcore_declined),
        prop::IDENT_ROLE => field!(ident_role),
        prop::IDENT_MOBILE => field!(ident_mobile),
        prop::IDENT_LOCATION => field!(ident_location),
        prop::IDENT_ALTITUDE => field!(ident_altitude_m),
        prop::DEV_DISCOVERABLE => field!(dev_discoverable),
        prop::GNSS_IDENT_UPDATE => field!(gnss_ident_update),
        prop::GNSS_IDENT_PRECISION => field!(gnss_ident_precision),
        prop::UPTIME => field!(uptime_seconds),
        prop::ADVERT_INTERVAL => field!(advert_interval_seconds),
        prop::BEACON_INTERVAL => field!(beacon_interval_seconds),
        prop::STARTUP_BEACON => field!(startup_beacon),
        prop::GNSS_ENABLED => field!(gnss_enabled),
        prop::DISPLAY_MOTION_WAKE_ENABLED => field!(display_motion_wake_enabled),
        prop::GNSS_TIME_TRUST => field!(gnss_time_trust),
        prop::BLE_ENABLED => field!(ble_enabled),
        prop::BLE_BOND_COUNT => field!(ble_bond_count),
        prop::BLE_LINK => field!(ble_link),
        prop::BLE_PAIRING => field!(ble_pairing),
        prop::WIFI_ENABLED => field!(wifi_enabled),
        prop::BRIDGE_ENABLED => field!(bridge_enabled),
        prop::BRIDGE_HOST => field!(bridge_host),
        prop::BRIDGE_PORT => field!(bridge_port),
        prop::BRIDGE_SERVER_KEY => field!(bridge_server_key),
        prop::BRIDGE_LINK => field!(bridge_link),
        prop::LAN_BEARER_ENABLED => field!(lan_bearer_enabled),
        prop::LAN_BEARER_GROUP => field!(lan_bearer_group),
        prop::LAN_BEARER_INGRESS_LIMIT => field!(lan_bearer_ingress_limit),
        prop::LAN_BEARER_STATE => field!(lan_bearer_state),
        prop::DEV_KEY => field!(dev_key),
        prop::WIFI_NETWORKS => field!(wifi_networks),
        prop::WIFI_NETWORK => field!(wifi_network),
        prop::WIFI_SCANNING => field!(wifi_scanning),
        prop::WIFI_SCAN_RESULTS => field!(wifi_scan_results),
        prop::WIFI_LINK => field!(wifi_link),
        prop::WIFI_RSSI => field!(wifi_rssi_dbm),
        prop::WIFI_MAC => field!(wifi_mac),
        prop::IPV4_STATE => field!(ipv4_state),
        prop::IPV4_CONFIG => field!(ipv4_config),
        prop::IPV4_ADDRESS => field!(ipv4_address),
        prop::IPV6_STATE => field!(ipv6_state),
        prop::IPV6_CONFIG => field!(ipv6_config),
        prop::IPV6_ADDRESSES => field!(ipv6_addresses),
        prop::IP_DNS => field!(ip_dns),
        prop::IP_RESOLVERS => field!(ip_resolvers),
        prop::TIME => field!(time),
        prop::TZ_RULE => field!(tz_rule),
        prop::TIME_24H => field!(time_24h),
        prop::MAC_REPEATER_MODE => field!(repeater_mode),
        prop::MAC_REPEATER_STATE => field!(repeater_state),
        prop::MAC_REPEATER_REGIONS => field!(repeater_regions),
        prop::MAC_REPEATER_DEFAULT_REGION => field!(repeater_default_region),
        prop::MAC_REPEATER_MIN_RSSI => field!(repeater_min_rssi_dbm),
        prop::MAC_REPEATER_MIN_SNR => field!(repeater_min_snr_db),
        prop::MESHCORE_FORWARDING_ENABLED => field!(meshcore_forwarding_enabled),
        prop::MESHCORE_REGION_POLICY => field!(meshcore_region_policy),
        prop::MESHCORE_REGIONS => field!(meshcore_regions),
        prop::DEV_PEERS => field!(dev_peer_keys),
        prop::DEV_ADMINS => field!(dev_admin_keys),
        _ => None,
    }
}
