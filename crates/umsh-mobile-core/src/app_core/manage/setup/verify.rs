//! What a read-back says about an apply: the first setting the device
//! reports differently from what was written, and the role it is filed
//! under.

use umsh_node::NodeRole;
use umsh_ulcp::ids::prop;

use super::records::MobileSetupSetting;
use crate::ulcp::{UlcpDeviceConfigRecord, UlcpSyncRecord};

/// The first setting `read` reports differently from `requested`, among
/// those `written` carried. The radio switch and the frequency are always
/// written. Every other setting is compared only when the device reports
/// it and its properties were written: a placeholder for a setting the
/// attach could not read never reached the device, so there is nothing to
/// hold the read-back to. The name, transmit power (a device clamps it to
/// what its radio reaches) and the administrators are never compared.
pub(in crate::app_core::manage) fn first_mismatch(
    requested: &UlcpDeviceConfigRecord,
    read: &UlcpSyncRecord,
    written: &[(u32, Vec<u8>)],
) -> Option<MobileSetupSetting> {
    if requested.radio.phy_enabled != read.phy_enabled {
        return Some(MobileSetupSetting::RadioSwitch);
    }
    if requested.radio.frequency_khz != read.frequency_khz {
        return Some(MobileSetupSetting::Frequency);
    }
    let wrote = |properties: &[u32]| {
        written
            .iter()
            .any(|(property, _)| properties.contains(property))
    };
    // A requested `None` against a reported value is a mismatch: the
    // device names a role it was told to derive.
    fn differs<T: PartialEq>(asked: Option<&T>, read: Option<&T>) -> bool {
        read.is_some() && asked != read
    }
    let radio = &requested.radio;
    let checks: [(MobileSetupSetting, &[u32], bool); 13] = [
        (
            MobileSetupSetting::Bandwidth,
            &[prop::PHY_LORA_BW],
            differs(radio.bandwidth_hz.as_ref(), read.bandwidth_hz.as_ref()),
        ),
        (
            MobileSetupSetting::SpreadingFactor,
            &[prop::PHY_LORA_SF],
            differs(
                radio.spreading_factor.as_ref(),
                read.spreading_factor.as_ref(),
            ),
        ),
        (
            MobileSetupSetting::CodingRate,
            &[prop::PHY_LORA_CR],
            differs(
                radio.coding_rate_denom.as_ref(),
                read.coding_rate_denom.as_ref(),
            ),
        ),
        (
            MobileSetupSetting::TransmitLimit,
            &[prop::PHY_DUTY_LIMIT],
            differs(
                radio.duty_cycle_limit.as_ref(),
                read.duty_cycle_limit.as_ref(),
            ),
        ),
        (
            MobileSetupSetting::AdvertisedRole,
            &[prop::IDENT_ROLE],
            differs(requested.ident_role.as_ref(), read.ident_role.as_ref()),
        ),
        (
            MobileSetupSetting::Mobility,
            &[prop::IDENT_MOBILE],
            differs(requested.ident_mobile.as_ref(), read.ident_mobile.as_ref()),
        ),
        (
            MobileSetupSetting::Discoverability,
            &[prop::DEV_DISCOVERABLE],
            differs(
                requested.dev_discoverable.as_ref(),
                read.dev_discoverable.as_ref(),
            ),
        ),
        (
            MobileSetupSetting::ForwardingPolicy,
            &[
                prop::MAC_REPEATER_MODE,
                prop::MAC_REPEATER_REGIONS,
                prop::MAC_REPEATER_DEFAULT_REGION,
                prop::MAC_REPEATER_MIN_RSSI,
                prop::MAC_REPEATER_MIN_SNR,
            ],
            differs(requested.repeater.as_ref(), read.repeater.as_ref()),
        ),
        (
            MobileSetupSetting::MeshCoreForwarding,
            &[
                prop::MESHCORE_FORWARDING_ENABLED,
                prop::MESHCORE_REGION_POLICY,
                prop::MESHCORE_REGIONS,
            ],
            differs(requested.meshcore.as_ref(), read.meshcore.as_ref()),
        ),
        (
            MobileSetupSetting::TimeZone,
            &[prop::TZ_RULE],
            differs(requested.tz_rule.as_ref(), read.tz_rule.as_ref()),
        ),
        (
            MobileSetupSetting::ClockFormat,
            &[prop::TIME_24H],
            differs(requested.time_24h.as_ref(), read.time_24h.as_ref()),
        ),
        (
            MobileSetupSetting::Positioning,
            &[
                prop::GNSS_ENABLED,
                prop::GNSS_IDENT_UPDATE,
                prop::GNSS_IDENT_PRECISION,
                prop::GNSS_TIME_TRUST,
            ],
            differs(requested.gnss.as_ref(), read.gnss.as_ref()),
        ),
        (
            MobileSetupSetting::Announcements,
            &[
                prop::ADVERT_INTERVAL,
                prop::BEACON_INTERVAL,
                prop::STARTUP_BEACON,
            ],
            differs(requested.advert.as_ref(), read.advert.as_ref()),
        ),
    ];
    checks
        .into_iter()
        .find(|(_, properties, differs)| *differs && wrote(properties))
        .map(|(setting, _, _)| setting)
}

/// The role code to file a device that reported `reported` under in
/// Peers: the role it names, else repeater for one that forwards (an
/// adaptive forwarder does not present itself as one); `None` keeps the
/// kind it is already filed under.
pub(in crate::app_core::manage) fn advertised_role(reported: &UlcpSyncRecord) -> Option<u8> {
    match reported.ident_role {
        Some(role) => match NodeRole::from_byte(role) {
            NodeRole::Unspecified | NodeRole::Unknown(_) => None,
            _ => Some(role),
        },
        None => reported
            .repeater
            .as_ref()
            .is_some_and(|repeater| repeater.mode == 1)
            .then(|| NodeRole::Repeater.as_byte()),
    }
}
