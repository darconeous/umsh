//! Allocation-free human-readable descriptions of ULCP values.
//!
//! Keeping this layer next to the wire grammar gives native tools, firmware
//! diagnostics, and browser clients one shared vocabulary without requiring
//! any of them to allocate.

use core::fmt;

use crate::{
    Status,
    frame::{Cmd, Frame, MultiEntries, MultiGetKeys, PropPayload, StreamPayload},
    ids::{cap, prop},
    pui,
};

/// The spec mnemonic for a known property identifier.
pub const fn property_name(key: u32) -> Option<&'static str> {
    Some(match key {
        prop::LAST_STATUS => "PROP_LAST_STATUS",
        prop::PROTOCOL_VERSION => "PROP_PROTOCOL_VERSION",
        prop::DEV_VERSION => "PROP_DEV_VERSION",
        prop::DEV_MODEL => "PROP_DEV_MODEL",
        prop::INTERFACE_TYPE => "PROP_INTERFACE_TYPE",
        prop::CAPS => "PROP_CAPS",
        prop::UPTIME => "PROP_UPTIME",
        prop::PHY_ENABLED => "PROP_PHY_ENABLED",
        prop::PHY_FREQ => "PROP_PHY_FREQ",
        prop::PHY_TX_POWER => "PROP_PHY_TX_POWER",
        prop::PHY_RSSI => "PROP_PHY_RSSI",
        prop::PHY_LORA_BW => "PROP_PHY_LORA_BW",
        prop::PHY_LORA_SF => "PROP_PHY_LORA_SF",
        prop::PHY_LORA_CR => "PROP_PHY_LORA_CR",
        prop::PHY_MTU => "PROP_PHY_MTU",
        prop::PHY_LORA_SW => "PROP_PHY_LORA_SW",
        prop::MAC_PROMISCUOUS => "PROP_MAC_PROMISCUOUS",
        prop::MAC_BACKHAUL => "PROP_MAC_BACKHAUL",
        prop::SAVED => "PROP_SAVED",
        prop::DEV_KEY => "PROP_DEV_KEY",
        prop::DEV_PRIVATE_KEY => "PROP_DEV_PRIVATE_KEY",
        prop::DEV_CHANNEL_KEYS => "PROP_DEV_CHANNEL_KEYS",
        prop::DEV_PEERS => "PROP_DEV_PEERS",
        prop::DEV_NAME => "PROP_DEV_NAME",
        prop::BATTERY => "PROP_BATTERY",
        prop::MAC_REPEATER_ENABLED => "PROP_MAC_REPEATER_ENABLED",
        prop::IDENT => "PROP_IDENT",
        prop::IDENT_ROLE => "PROP_IDENT_ROLE",
        prop::IDENT_MOBILE => "PROP_IDENT_MOBILE",
        prop::MAC_REPEATER_REGIONS => "PROP_MAC_REPEATER_REGIONS",
        prop::MAC_REPEATER_DEFAULT_REGION => "PROP_MAC_REPEATER_DEFAULT_REGION",
        prop::MAC_REPEATER_MIN_RSSI => "PROP_MAC_REPEATER_MIN_RSSI",
        prop::MAC_REPEATER_MIN_SNR => "PROP_MAC_REPEATER_MIN_SNR",
        prop::DEV_DISCOVERABLE => "PROP_DEV_DISCOVERABLE",
        prop::ALERT => "PROP_ALERT",
        prop::ADVERT_INTERVAL => "PROP_ADVERT_INTERVAL",
        prop::BEACON_INTERVAL => "PROP_BEACON_INTERVAL",
        prop::STARTUP_BEACON => "PROP_STARTUP_BEACON",
        prop::IDENT_LOCATION => "PROP_IDENT_LOCATION",
        prop::IDENT_ALTITUDE => "PROP_IDENT_ALTITUDE",
        prop::GNSS_ENABLED => "PROP_GNSS_ENABLED",
        prop::GNSS_LOCATION => "PROP_GNSS_LOCATION",
        prop::GNSS_ALTITUDE => "PROP_GNSS_ALTITUDE",
        prop::GNSS_FIX => "PROP_GNSS_FIX",
        prop::GNSS_PRECISION => "PROP_GNSS_PRECISION",
        prop::GNSS_SATELLITES => "PROP_GNSS_SATELLITES",
        prop::ILLUMINANCE => "PROP_ILLUMINANCE",
        prop::HOST_KEY => "PROP_HOST_KEY",
        prop::HOST_CHANNEL_KEYS => "PROP_HOST_CHANNEL_KEYS",
        prop::HOST_PEER_KEYS => "PROP_HOST_PEER_KEYS",
        prop::HOST_RX_FILTERS => "PROP_HOST_RX_FILTERS",
        prop::HOST_AUTO_ACK => "PROP_HOST_AUTO_ACK",
        prop::HOST_RX_QUEUE_COUNT => "PROP_HOST_RX_QUEUE_COUNT",
        prop::HOST_RX_QUEUE_CAPACITY => "PROP_HOST_RX_QUEUE_CAPACITY",
        prop::HOST_RX_QUEUE_DROPPED => "PROP_HOST_RX_QUEUE_DROPPED",
        prop::PHY_DUTY_NOW => "PROP_PHY_DUTY_NOW",
        prop::PHY_DUTY_LIMIT => "PROP_PHY_DUTY_LIMIT",
        prop::BLE_PAIRING_PIN => "PROP_BLE_PAIRING_PIN",
        prop::DEV_ADMINS => "PROP_DEV_ADMINS",
        prop::TIME => "PROP_TIME",
        prop::TZ_OFFSET => "PROP_TZ_OFFSET",
        prop::GNSS_IDENT_UPDATE => "PROP_GNSS_IDENT_UPDATE",
        prop::GNSS_IDENT_PRECISION => "PROP_GNSS_IDENT_PRECISION",
        prop::GNSS_TIME_TRUST => "PROP_GNSS_TIME_TRUST",
        prop::BLE_ENABLED => "PROP_BLE_ENABLED",
        prop::BLE_BOND_COUNT => "PROP_BLE_BOND_COUNT",
        prop::BLE_LINK => "PROP_BLE_LINK",
        _ => return None,
    })
}

/// Every property this module can name.
///
/// A tool that resolves a mnemonic back to an identifier derives its
/// lookup from this list rather than keeping a second copy of the table:
/// one place to add a property, one place that can fall out of date.
pub const PROPERTIES: &[u32] = &[
    prop::LAST_STATUS,
    prop::PROTOCOL_VERSION,
    prop::DEV_VERSION,
    prop::DEV_MODEL,
    prop::INTERFACE_TYPE,
    prop::CAPS,
    prop::UPTIME,
    prop::PHY_ENABLED,
    prop::PHY_FREQ,
    prop::PHY_TX_POWER,
    prop::PHY_RSSI,
    prop::PHY_LORA_BW,
    prop::PHY_LORA_SF,
    prop::PHY_LORA_CR,
    prop::PHY_MTU,
    prop::PHY_LORA_SW,
    prop::MAC_PROMISCUOUS,
    prop::MAC_BACKHAUL,
    prop::SAVED,
    prop::DEV_KEY,
    prop::DEV_PRIVATE_KEY,
    prop::DEV_CHANNEL_KEYS,
    prop::DEV_PEERS,
    prop::DEV_NAME,
    prop::BATTERY,
    prop::MAC_REPEATER_ENABLED,
    prop::IDENT,
    prop::IDENT_ROLE,
    prop::IDENT_MOBILE,
    prop::MAC_REPEATER_REGIONS,
    prop::MAC_REPEATER_DEFAULT_REGION,
    prop::MAC_REPEATER_MIN_RSSI,
    prop::MAC_REPEATER_MIN_SNR,
    prop::DEV_DISCOVERABLE,
    prop::ALERT,
    prop::ADVERT_INTERVAL,
    prop::BEACON_INTERVAL,
    prop::STARTUP_BEACON,
    prop::IDENT_LOCATION,
    prop::IDENT_ALTITUDE,
    prop::GNSS_ENABLED,
    prop::GNSS_LOCATION,
    prop::GNSS_ALTITUDE,
    prop::GNSS_FIX,
    prop::GNSS_PRECISION,
    prop::GNSS_SATELLITES,
    prop::ILLUMINANCE,
    prop::HOST_KEY,
    prop::HOST_CHANNEL_KEYS,
    prop::HOST_PEER_KEYS,
    prop::HOST_RX_FILTERS,
    prop::HOST_AUTO_ACK,
    prop::HOST_RX_QUEUE_COUNT,
    prop::HOST_RX_QUEUE_CAPACITY,
    prop::HOST_RX_QUEUE_DROPPED,
    prop::PHY_DUTY_NOW,
    prop::PHY_DUTY_LIMIT,
    prop::BLE_PAIRING_PIN,
    prop::DEV_ADMINS,
    prop::TIME,
    prop::TZ_OFFSET,
    prop::GNSS_IDENT_UPDATE,
    prop::GNSS_IDENT_PRECISION,
    prop::GNSS_TIME_TRUST,
    prop::BLE_ENABLED,
    prop::BLE_BOND_COUNT,
    prop::BLE_LINK,
];

/// How a property's octets are meant to be read.
///
/// Enough to render a value a person can check and to accept one typed
/// by hand. Anything whose shape is a structure rather than a scalar —
/// a battery snapshot, an interleaved location, a table of keys — is
/// [`PropertyType::Bytes`], which is an honest answer: the octets are
/// the value, and whatever decodes them knows more than this table does.
///
/// Numerics are little-endian, as ULCP has them throughout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropertyType {
    /// One octet, 0 or 1.
    Bool,
    U8,
    U16,
    U32,
    I8,
    I16,
    I32,
    /// UTF-8, NUL-terminated on the wire.
    Text,
    /// A 32-octet Ed25519 public key or channel key.
    Key32,
    /// A status code in PUI form.
    Status,
    /// Octets whose meaning is structural, not scalar.
    Bytes,
}

/// How to read a known property's octets.
///
/// A property absent from the table has no scalar reading, which is the
/// same answer as [`PropertyType::Bytes`] but says so by omission: the
/// caller knows it is looking at something this module has never heard
/// of rather than something deliberately opaque.
pub const fn property_type(key: u32) -> Option<PropertyType> {
    use PropertyType::{Bool, Bytes, I8, I16, I32, Key32, Status, Text, U8, U16, U32};
    Some(match key {
        prop::LAST_STATUS => Status,
        // Major and minor, one octet each.
        prop::PROTOCOL_VERSION => Bytes,
        prop::DEV_VERSION | prop::DEV_MODEL | prop::DEV_NAME => Text,
        prop::INTERFACE_TYPE => U32,
        // A list of capability codes in PUI form.
        prop::CAPS => Bytes,
        prop::UPTIME => U32,
        prop::PHY_ENABLED => Bool,
        prop::PHY_FREQ => U32,
        prop::PHY_TX_POWER | prop::PHY_RSSI => I8,
        prop::PHY_LORA_BW => U32,
        prop::PHY_LORA_SF | prop::PHY_LORA_CR => U8,
        prop::PHY_MTU | prop::PHY_LORA_SW => U16,
        prop::MAC_PROMISCUOUS | prop::MAC_BACKHAUL => Bool,
        prop::SAVED => U8,
        prop::DEV_KEY | prop::DEV_PRIVATE_KEY | prop::HOST_KEY => Key32,
        // Multiple-value tables, reported as digests.
        prop::DEV_CHANNEL_KEYS
        | prop::DEV_PEERS
        | prop::DEV_ADMINS
        | prop::HOST_CHANNEL_KEYS
        | prop::HOST_PEER_KEYS
        | prop::HOST_RX_FILTERS => Bytes,
        // A flags octet followed by whichever components it claims.
        prop::BATTERY => Bytes,
        prop::MAC_REPEATER_ENABLED => Bool,
        // The signed node-identity blob.
        prop::IDENT => Bytes,
        prop::IDENT_ROLE => U8,
        prop::IDENT_MOBILE => Bool,
        // UTF-8 region names, one per item.
        prop::MAC_REPEATER_REGIONS => Text,
        // A 2-octet region code.
        prop::MAC_REPEATER_DEFAULT_REGION => Bytes,
        prop::MAC_REPEATER_MIN_RSSI => I16,
        prop::MAC_REPEATER_MIN_SNR => I8,
        prop::DEV_DISCOVERABLE => Bool,
        prop::ALERT => U8,
        prop::ADVERT_INTERVAL | prop::BEACON_INTERVAL => U32,
        prop::STARTUP_BEACON => Bool,
        // Variable-precision interleaved coordinates.
        prop::IDENT_LOCATION | prop::GNSS_LOCATION => Bytes,
        // A minimal-length signed integer, which is its own encoding.
        prop::IDENT_ALTITUDE => Bytes,
        prop::GNSS_ENABLED => Bool,
        prop::GNSS_ALTITUDE => I32,
        prop::GNSS_FIX => U8,
        prop::GNSS_PRECISION => U16,
        // Used in the solution, optionally followed by in view.
        prop::GNSS_SATELLITES => Bytes,
        prop::ILLUMINANCE => U32,
        prop::HOST_AUTO_ACK => Bool,
        prop::HOST_RX_QUEUE_COUNT | prop::HOST_RX_QUEUE_CAPACITY => U16,
        prop::HOST_RX_QUEUE_DROPPED => U32,
        prop::PHY_DUTY_NOW | prop::PHY_DUTY_LIMIT => U16,
        prop::BLE_PAIRING_PIN => U32,
        prop::TIME => U32,
        prop::TZ_OFFSET => I16,
        prop::GNSS_IDENT_UPDATE => Bool,
        prop::GNSS_IDENT_PRECISION => U8,
        prop::GNSS_TIME_TRUST | prop::BLE_ENABLED => Bool,
        prop::BLE_BOND_COUNT | prop::BLE_LINK => U8,
        _ => return None,
    })
}

/// The spec mnemonic for a known capability code.
pub const fn capability_name(code: u32) -> Option<&'static str> {
    Some(match code {
        cap::WRITABLE_RAW_STREAM => "WRITABLE_RAW_STREAM",
        cap::PHY_DUTY_LIMIT => "PHY_DUTY_LIMIT",
        cap::PHY_LORA => "PHY_LORA",
        cap::HOST_FILTER => "HOST_FILTER",
        cap::HOST_RX_QUEUE => "HOST_RX_QUEUE",
        cap::HOST_KEYS => "HOST_KEYS",
        cap::HOST_AUTO_ACK => "HOST_AUTO_ACK",
        cap::SAVE => "SAVE",
        cap::DEV_IDENTITY => "DEV_IDENTITY",
        cap::DEV_NAME => "DEV_NAME",
        cap::BATTERY => "BATTERY",
        cap::REPEATER => "REPEATER",
        cap::IDENT => "IDENT",
        cap::ALERT => "ALERT",
        cap::TIME => "TIME",
        cap::GNSS => "GNSS",
        cap::ADVERT => "ADVERT",
        cap::ILLUMINANCE => "ILLUMINANCE",
        cap::MAC_BACKHAUL => "MAC_BACKHAUL",
        cap::ADMIN => "ADMIN",
        cap::CMD_MULTI => "CMD_MULTI",
        cap::BLE => "BLE",
        cap::REBOOT => "REBOOT",
        _ => return None,
    })
}

/// A display adapter for one ULCP frame.
///
/// Values are summarized by length and never dumped, so callers can safely use
/// the result in logs even for secret-bearing property writes.
pub struct FrameDescription<'a>(pub &'a [u8]);

impl fmt::Display for FrameDescription<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        let Ok(frame) = Frame::parse(bytes) else {
            return write!(out, "malformed frame ({} bytes)", bytes.len());
        };
        let tid = frame.header.tid();
        let Some(command) = frame.command() else {
            return write!(out, "unknown command tid={tid} ({} bytes)", bytes.len());
        };
        match command {
            Cmd::Nop
            | Cmd::Reset
            | Cmd::QueueDrain
            | Cmd::Save
            | Cmd::Clear
            | Cmd::Restore
            | Cmd::FactoryReset
            | Cmd::Reboot
            | Cmd::BleClearBonds
            | Cmd::BleStartPairing => {
                write!(out, "{command:?} tid={tid}")
            }
            Cmd::PropGet
            | Cmd::PropSet
            | Cmd::PropIs
            | Cmd::PropInsert
            | Cmd::PropRemove
            | Cmd::PropInserted
            | Cmd::PropRemoved => {
                let Ok(payload) = PropPayload::parse(frame.payload) else {
                    return write!(out, "{command:?} tid={tid} (malformed payload)");
                };
                let name = property_name(payload.key);
                if payload.key == prop::LAST_STATUS && command == Cmd::PropIs {
                    let status = pui::decode(payload.value)
                        .map(|(code, _)| Status(code))
                        .unwrap_or(Status::FAILURE);
                    if let Some(name) = name {
                        write!(out, "{command:?} tid={tid} {name} = {status:?}")
                    } else {
                        write!(
                            out,
                            "{command:?} tid={tid} prop {} = {status:?}",
                            payload.key
                        )
                    }
                } else if let Some(name) = name {
                    write!(
                        out,
                        "{command:?} tid={tid} {name} ({} value bytes)",
                        payload.value.len()
                    )
                } else {
                    write!(
                        out,
                        "{command:?} tid={tid} prop {} ({} value bytes)",
                        payload.key,
                        payload.value.len()
                    )
                }
            }
            Cmd::PropMultiGet => {
                let mut count = 0usize;
                for key in MultiGetKeys::new(frame.payload) {
                    if key.is_err() {
                        return write!(out, "{command:?} tid={tid} (malformed payload)");
                    }
                    count += 1;
                }
                write!(out, "{command:?} tid={tid} ({count} properties)")
            }
            Cmd::PropMultiSet | Cmd::PropAre => {
                let mut count = 0usize;
                let mut value_bytes = 0usize;
                for entry in MultiEntries::new(frame.payload) {
                    let Ok(entry) = entry else {
                        return write!(out, "{command:?} tid={tid} (malformed payload)");
                    };
                    count += 1;
                    value_bytes += entry.value.len();
                }
                write!(
                    out,
                    "{command:?} tid={tid} ({count} entries, {value_bytes} value bytes)"
                )
            }
            Cmd::StrSend | Cmd::StrRecv => match StreamPayload::parse(frame.payload) {
                Ok(payload) => write!(
                    out,
                    "{command:?} tid={tid} stream={} ({} data bytes, {} meta bytes)",
                    payload.stream,
                    payload.data.len(),
                    payload.metadata.len()
                ),
                Err(_) => write!(out, "{command:?} tid={tid} (malformed payload)"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    #[test]
    fn describes_known_and_unknown_properties_without_values() {
        let mut buf = [0u8; 16];
        let len = frame::prop_set(&mut buf, 2, prop::PHY_FREQ, &[0x7e, 0x42]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropSet tid=2 PROP_PHY_FREQ (2 value bytes)"
        );

        let len = frame::prop_get(&mut buf, 3, 60_000).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropGet tid=3 prop 60000 (0 value bytes)"
        );
    }

    #[test]
    fn describes_status_and_malformed_frames() {
        let mut buf = [0u8; 8];
        let len = frame::last_status(&mut buf, 4, Status::OK).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropIs tid=4 PROP_LAST_STATUS = Status::OK"
        );
        assert_eq!(
            FrameDescription(&[0x80]).to_string(),
            "malformed frame (1 bytes)"
        );
    }

    #[test]
    fn describes_multi_property_frames() {
        let mut buf = [0u8; 64];
        let len = frame::prop_multi_get(&mut buf, 1, &[prop::CAPS, prop::DEV_ADMINS]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropMultiGet tid=1 (2 properties)"
        );

        let mut writer = frame::prop_are(&mut buf, 2).unwrap();
        writer.write_entry(prop::PHY_TX_POWER, &[14]).unwrap();
        writer.write_status_entry(Status::PROP_NOT_FOUND).unwrap();
        let len = writer.finish();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropAre tid=2 (2 entries, 2 value bytes)"
        );

        // A body length that runs past the end of the payload.
        let malformed = [0x82, 0x17, 0x09, 0x71, 0xAA];
        assert_eq!(
            FrameDescription(&malformed).to_string(),
            "PropAre tid=2 (malformed payload)"
        );
    }

    #[test]
    fn names_capabilities() {
        assert_eq!(capability_name(cap::HOST_RX_QUEUE), Some("HOST_RX_QUEUE"));
        assert_eq!(capability_name(cap::BATTERY), Some("BATTERY"));
        assert_eq!(capability_name(cap::REPEATER), Some("REPEATER"));
        assert_eq!(capability_name(cap::IDENT), Some("IDENT"));
        assert_eq!(capability_name(cap::TIME), Some("TIME"));
        assert_eq!(capability_name(cap::GNSS), Some("GNSS"));
        assert_eq!(capability_name(60_000), None);
    }

    #[test]
    fn names_time_and_positioning_properties() {
        assert_eq!(property_name(prop::TIME), Some("PROP_TIME"));
        assert_eq!(property_name(prop::TZ_OFFSET), Some("PROP_TZ_OFFSET"));
        assert_eq!(property_name(prop::GNSS_ENABLED), Some("PROP_GNSS_ENABLED"));
        assert_eq!(
            property_name(prop::GNSS_LOCATION),
            Some("PROP_GNSS_LOCATION")
        );
        assert_eq!(
            property_name(prop::GNSS_ALTITUDE),
            Some("PROP_GNSS_ALTITUDE")
        );
        assert_eq!(property_name(prop::GNSS_FIX), Some("PROP_GNSS_FIX"));
        assert_eq!(
            property_name(prop::GNSS_PRECISION),
            Some("PROP_GNSS_PRECISION")
        );
        assert_eq!(
            property_name(prop::GNSS_SATELLITES),
            Some("PROP_GNSS_SATELLITES")
        );
        assert_eq!(
            property_name(prop::GNSS_IDENT_UPDATE),
            Some("PROP_GNSS_IDENT_UPDATE")
        );
        assert_eq!(
            property_name(prop::GNSS_IDENT_PRECISION),
            Some("PROP_GNSS_IDENT_PRECISION")
        );
        assert_eq!(
            property_name(prop::GNSS_TIME_TRUST),
            Some("PROP_GNSS_TIME_TRUST")
        );
    }

    #[test]
    fn names_repeater_policy_properties() {
        assert_eq!(
            property_name(prop::MAC_REPEATER_REGIONS),
            Some("PROP_MAC_REPEATER_REGIONS")
        );
        assert_eq!(
            property_name(prop::MAC_REPEATER_DEFAULT_REGION),
            Some("PROP_MAC_REPEATER_DEFAULT_REGION")
        );
        assert_eq!(
            property_name(prop::MAC_REPEATER_MIN_RSSI),
            Some("PROP_MAC_REPEATER_MIN_RSSI")
        );
        assert_eq!(
            property_name(prop::MAC_REPEATER_MIN_SNR),
            Some("PROP_MAC_REPEATER_MIN_SNR")
        );
        assert_eq!(property_name(prop::IDENT_ROLE), Some("PROP_IDENT_ROLE"));
    }

    #[test]
    fn names_the_bluetooth_toggle() {
        assert_eq!(property_name(prop::BLE_ENABLED), Some("PROP_BLE_ENABLED"));
        assert_eq!(property_type(prop::BLE_ENABLED), Some(PropertyType::Bool));
    }

    /// Bluetooth has one capability and three properties. Everything past
    /// reachability is discovered by asking, so nothing here may grow a
    /// capability of its own without the tables saying so out loud.
    #[test]
    fn names_the_bond_count_and_the_link() {
        assert_eq!(
            property_name(prop::BLE_BOND_COUNT),
            Some("PROP_BLE_BOND_COUNT")
        );
        assert_eq!(property_type(prop::BLE_BOND_COUNT), Some(PropertyType::U8));
        assert_eq!(property_name(prop::BLE_LINK), Some("PROP_BLE_LINK"));
        assert_eq!(property_type(prop::BLE_LINK), Some(PropertyType::U8));
        assert_eq!(capability_name(cap::BLE), Some("BLE"));
        assert_eq!(capability_name(cap::BLE + 2), None);
    }

    /// The three tables answer for the same set of properties. A name
    /// with no entry in `PROPERTIES` cannot be looked up backwards, and
    /// one with no type reads back as hex forever — both are the kind of
    /// omission that happens when a property is added in a hurry.
    #[test]
    fn every_named_property_is_listed_and_typed() {
        for &key in PROPERTIES {
            assert!(
                property_name(key).is_some(),
                "prop {key} is listed but unnamed"
            );
            assert!(
                property_type(key).is_some(),
                "prop {key} is listed but untyped"
            );
        }
        // The listing is a set, not a sequence with repeats.
        for (index, &key) in PROPERTIES.iter().enumerate() {
            assert!(
                !PROPERTIES[..index].contains(&key),
                "prop {key} is listed twice"
            );
        }
    }

    #[test]
    fn property_types_follow_the_wire() {
        assert_eq!(property_type(prop::PHY_FREQ), Some(PropertyType::U32));
        assert_eq!(property_type(prop::PHY_TX_POWER), Some(PropertyType::I8));
        assert_eq!(property_type(prop::DEV_NAME), Some(PropertyType::Text));
        assert_eq!(property_type(prop::DEV_KEY), Some(PropertyType::Key32));
        assert_eq!(property_type(prop::TZ_OFFSET), Some(PropertyType::I16));
        assert_eq!(
            property_type(prop::HOST_RX_QUEUE_DROPPED),
            Some(PropertyType::U32)
        );
        // Structured values are honestly opaque rather than mis-typed.
        assert_eq!(property_type(prop::BATTERY), Some(PropertyType::Bytes));
        assert_eq!(property_type(60_000), None);
    }

    #[test]
    fn describes_battery_snapshots_and_the_empty_form() {
        let mut buf = [0u8; 16];
        let len = frame::prop_is(&mut buf, 5, prop::BATTERY, &[0b101, 0x74, 0x0E, 0]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropIs tid=5 PROP_BATTERY (4 value bytes)"
        );

        let len = frame::prop_is(&mut buf, 6, prop::BATTERY, &[]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropIs tid=6 PROP_BATTERY (0 value bytes)"
        );
    }
}
