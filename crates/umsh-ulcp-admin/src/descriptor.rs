//! The properties the model covers.
//!
//! A descriptor says how to read a property's octets (its codec, from
//! [`umsh_ulcp::describe`]), whether the device has it at all (the
//! capability that gates it), and what may be done to it (its access and
//! kind). The device is the authority on everything else: a value that
//! fails to decode is held as the octets the device reported, and a write
//! the device adjusts is reported as the device adjusted it.

use umsh_ulcp::PropertyType;
use umsh_ulcp::ids::{cap, prop};

/// What may be done to a property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Read once: it never changes while the device runs.
    Constant,
    /// Read, never written.
    ReadOnly,
    /// Read only when asked for, never by a refresh: the device makes a
    /// new value for every read, such as a signature.
    OnDemand,
    /// Read and written whole.
    ReadWrite,
    /// Written whole, never read: the clock, which moves on its own, so a
    /// copy read once is wrong a second later.
    WriteOnly,
    /// A set of items, read whole and changed an item at a time.
    Table,
}

/// The shape of a property's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One value.
    Scalar,
    /// A list of packed unsigned integers.
    Puis,
    /// Fixed-length items with no length prefix. An item is inserted and
    /// selected for removal in its item form, and reported—in the
    /// property's value and in `CMD_PROP_INSERTED` and
    /// `CMD_PROP_REMOVED`—in its reported form, which omits any key
    /// material.
    Items { item_len: u8, reported_len: u8 },
}

/// One covered property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub key: u32,
    /// How its octets read.
    pub codec: PropertyType,
    /// The capability a device advertises when it has this property, or
    /// `None` for one every device has.
    pub gate: Option<u32>,
    pub access: Access,
    pub kind: Kind,
    /// The longest value or item the model writes, in octets.
    pub max_len: usize,
}

impl Descriptor {
    pub const fn writable(&self) -> bool {
        matches!(self.access, Access::ReadWrite | Access::WriteOnly)
    }

    pub const fn is_table(&self) -> bool {
        matches!(self.access, Access::Table)
    }
}

const fn scalar(
    key: u32,
    codec: PropertyType,
    gate: Option<u32>,
    access: Access,
    max_len: usize,
) -> Descriptor {
    Descriptor {
        key,
        codec,
        gate,
        access,
        kind: Kind::Scalar,
        max_len,
    }
}

const fn table(key: u32, gate: u32, item_len: u8, reported_len: u8) -> Descriptor {
    Descriptor {
        key,
        codec: PropertyType::Bytes,
        gate: Some(gate),
        access: Access::Table,
        kind: Kind::Items {
            item_len,
            reported_len,
        },
        max_len: item_len as usize,
    }
}

/// Longest `PROP_DEV_NAME`, in octets of UTF-8.
pub const DEVICE_NAME_MAX: usize = 64;

/// Longest `PROP_TZ_RULE`, in octets.
pub const TZ_RULE_MAX: usize = 64;

/// Every property the model covers.
pub const COVERED: &[Descriptor] = &[
    // The device.
    Descriptor {
        key: prop::CAPS,
        codec: PropertyType::Bytes,
        gate: None,
        access: Access::Constant,
        kind: Kind::Puis,
        max_len: 0,
    },
    scalar(
        prop::SAVED,
        PropertyType::U8,
        Some(cap::SAVE),
        Access::ReadOnly,
        0,
    ),
    scalar(
        prop::DEV_KEY,
        PropertyType::Key32,
        Some(cap::DEV_IDENTITY),
        Access::ReadOnly,
        0,
    ),
    scalar(
        prop::DEV_NAME,
        PropertyType::Text,
        Some(cap::DEV_NAME),
        Access::ReadWrite,
        DEVICE_NAME_MAX,
    ),
    // The radio profile: what two nodes must agree on to hear each other.
    scalar(
        prop::PHY_FREQ,
        PropertyType::U32,
        None,
        Access::ReadWrite,
        4,
    ),
    scalar(
        prop::PHY_LORA_BW,
        PropertyType::U32,
        Some(cap::PHY_LORA),
        Access::ReadWrite,
        4,
    ),
    scalar(
        prop::PHY_LORA_SF,
        PropertyType::U8,
        Some(cap::PHY_LORA),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::PHY_LORA_CR,
        PropertyType::U8,
        Some(cap::PHY_LORA),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::PHY_T_FRAME,
        PropertyType::U32,
        None,
        Access::ReadOnly,
        0,
    ),
    scalar(
        prop::PHY_LORA_SW,
        PropertyType::U16,
        Some(cap::PHY_LORA),
        Access::ReadOnly,
        0,
    ),
    // The radio's local settings.
    scalar(
        prop::PHY_ENABLED,
        PropertyType::Bool,
        None,
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::PHY_TX_POWER,
        PropertyType::I8,
        None,
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::PHY_DUTY_NOW,
        PropertyType::U16,
        Some(cap::PHY_DUTY_LIMIT),
        Access::ReadOnly,
        0,
    ),
    scalar(
        prop::PHY_DUTY_LIMIT,
        PropertyType::U16,
        Some(cap::PHY_DUTY_LIMIT),
        Access::ReadWrite,
        2,
    ),
    // Behavior.
    scalar(
        prop::MAC_REPEATER_ENABLED,
        PropertyType::Bool,
        Some(cap::REPEATER),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::GNSS_IDENT_UPDATE,
        PropertyType::Bool,
        Some(cap::GNSS),
        Access::ReadWrite,
        1,
    ),
    // The links beside the radio.
    scalar(
        prop::GNSS_ENABLED,
        PropertyType::Bool,
        Some(cap::GNSS),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::BLE_ENABLED,
        PropertyType::Bool,
        Some(cap::BLE),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::BLE_PAIRING,
        PropertyType::Bool,
        Some(cap::BLE),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::BLE_BOND_COUNT,
        PropertyType::U8,
        Some(cap::BLE),
        Access::ReadWrite,
        1,
    ),
    // The clock.
    scalar(
        prop::TIME,
        PropertyType::U32,
        Some(cap::TIME),
        Access::WriteOnly,
        4,
    ),
    scalar(
        prop::TZ_RULE,
        PropertyType::Text,
        Some(cap::TIME),
        Access::ReadWrite,
        TZ_RULE_MAX,
    ),
    scalar(
        prop::TIME_24H,
        PropertyType::Bool,
        Some(cap::TIME),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::GNSS_TIME_TRUST,
        PropertyType::Bool,
        Some(cap::GNSS),
        Access::ReadWrite,
        1,
    ),
    // The screen and the keyboard.
    scalar(
        prop::DISPLAY_BRIGHTNESS,
        PropertyType::U8,
        Some(cap::DISPLAY),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::DISPLAY_TIMEOUT,
        PropertyType::U16,
        Some(cap::DISPLAY),
        Access::ReadWrite,
        2,
    ),
    scalar(
        prop::KEYBOARD_LIGHT,
        PropertyType::Bool,
        Some(cap::KEYBOARD),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::KEYBOARD_AIDS,
        PropertyType::U8,
        Some(cap::KEYBOARD),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::SOUND_ENABLED,
        PropertyType::Bool,
        Some(cap::SOUND),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::SOUND_VOLUME,
        PropertyType::U8,
        Some(cap::SOUND),
        Access::ReadWrite,
        1,
    ),
    scalar(
        prop::SETUP_COMPLETE,
        PropertyType::Bool,
        Some(cap::KEYBOARD),
        Access::ReadWrite,
        1,
    ),
    // The device identity as it advertises itself, signed.
    scalar(
        prop::IDENT,
        PropertyType::Bytes,
        Some(cap::IDENT),
        Access::OnDemand,
        0,
    ),
    // ...and as a contact keeps it.
    scalar(
        prop::IDENT_CONTACT,
        PropertyType::Bytes,
        Some(cap::IDENT),
        Access::OnDemand,
        0,
    ),
    // The device identity's tables.
    table(prop::DEV_PEERS, cap::DEV_IDENTITY, 32, 32),
    table(prop::DEV_CHANNEL_KEYS, cap::DEV_IDENTITY, 32, 16),
    // How long the device has run, and what it has counted since: read
    // while someone is looking, as they move on their own.
    scalar(prop::UPTIME, PropertyType::U32, None, Access::OnDemand, 0),
    stat(prop::STAT_TX_PACKETS),
    stat(prop::STAT_TX_CHANNEL_BUSY),
    stat(prop::STAT_RX_PACKETS),
    stat(prop::STAT_RX_BAD_CRC),
    stat(prop::STAT_RX_NON_UMSH),
    stat(prop::STAT_RX_ACCEPTED),
    stat(prop::STAT_FORWARDED),
    stat(prop::STAT_FORWARD_DROPPED),
    stat(prop::STAT_FORWARD_CANCELLED),
    stat(prop::STAT_MESHCORE_SEEN),
    stat(prop::STAT_MESHCORE_FORWARDED_ROUTED),
    stat(prop::STAT_MESHCORE_FORWARDED_FLOOD),
    stat(prop::STAT_MESHCORE_DECLINED),
];

/// One of the device's counters (`CAP_STATS`).
const fn stat(key: u32) -> Descriptor {
    scalar(
        key,
        PropertyType::U32,
        Some(cap::STATS),
        Access::OnDemand,
        0,
    )
}

/// The descriptor for `key`, if the model covers it.
pub fn descriptor(key: u32) -> Option<&'static Descriptor> {
    COVERED.iter().find(|descriptor| descriptor.key == key)
}

/// A value read through its codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    I8(i8),
    I16(i16),
    I32(i32),
    Text(&'a str),
    Key32(&'a [u8; 32]),
    Bytes(&'a [u8]),
}

/// Read `raw` as `codec` says. `None` when the octets are not that
/// codec's: a value of the wrong width, or text that is not UTF-8.
pub fn decode(codec: PropertyType, raw: &[u8]) -> Option<Value<'_>> {
    Some(match codec {
        PropertyType::Bool => match raw {
            [0] => Value::Bool(false),
            [1] => Value::Bool(true),
            _ => return None,
        },
        PropertyType::U8 => Value::U8(u8::from_le_bytes(raw.try_into().ok()?)),
        PropertyType::U16 => Value::U16(u16::from_le_bytes(raw.try_into().ok()?)),
        PropertyType::U32 => Value::U32(u32::from_le_bytes(raw.try_into().ok()?)),
        PropertyType::I8 => Value::I8(i8::from_le_bytes(raw.try_into().ok()?)),
        PropertyType::I16 => Value::I16(i16::from_le_bytes(raw.try_into().ok()?)),
        PropertyType::I32 => Value::I32(i32::from_le_bytes(raw.try_into().ok()?)),
        PropertyType::Text => Value::Text(core::str::from_utf8(raw).ok()?),
        PropertyType::Key32 => Value::Key32(raw.try_into().ok()?),
        PropertyType::Status | PropertyType::BatteryDiagnostic | PropertyType::Bytes => {
            Value::Bytes(raw)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codecs are umsh-ulcp's, not this crate's opinion of them.
    #[test]
    fn every_codec_is_the_one_umsh_ulcp_describes() {
        for descriptor in COVERED {
            assert_eq!(
                umsh_ulcp::property_type(descriptor.key),
                Some(descriptor.codec),
                "{:?}",
                umsh_ulcp::property_name(descriptor.key)
            );
        }
    }

    #[test]
    fn each_property_is_covered_once() {
        for (index, descriptor) in COVERED.iter().enumerate() {
            assert!(
                COVERED[index + 1..]
                    .iter()
                    .all(|other| other.key != descriptor.key)
            );
        }
    }

    /// The administrator's binding refuses some writes outright, and
    /// the device's own interface has the same surface; nothing the model
    /// writes may be one of them.
    #[test]
    fn everything_the_model_writes_is_the_device_interfaces_to_write() {
        for descriptor in COVERED {
            if descriptor.writable() || descriptor.is_table() {
                assert!(umsh_ulcp::ids::device_writable(descriptor.key));
            }
        }
    }

    #[test]
    fn values_decode_through_their_codec() {
        assert_eq!(
            decode(PropertyType::U32, &910_525u32.to_le_bytes()),
            Some(Value::U32(910_525))
        );
        assert_eq!(decode(PropertyType::I8, &[0xF7]), Some(Value::I8(-9)));
        assert_eq!(decode(PropertyType::Bool, &[2]), None);
        assert_eq!(decode(PropertyType::U16, &[1]), None);
        assert_eq!(
            decode(PropertyType::Text, b"Pocket"),
            Some(Value::Text("Pocket"))
        );
        assert_eq!(decode(PropertyType::Text, &[0xFF]), None);
    }
}
