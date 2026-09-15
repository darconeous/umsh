//! Optional battery properties, compact codecs, and one acquisition's results.
use crate::{Status, battery::BatteryStatus, ids::prop, pui, sint, uint};

pub const KEYS: [u32; 13] = [
    prop::BATTERY_CURRENT,
    prop::BATTERY_REMAINING_CAPACITY,
    prop::BATTERY_FULL_CAPACITY,
    prop::BATTERY_DESIGN_CAPACITY,
    prop::BATTERY_EXT_POWER_PRESENT,
    prop::BATTERY_PRESENT,
    prop::BATTERY_GAUGE_FULL,
    prop::BATTERY_GAUGE_INITIALIZED,
    prop::BATTERY_GAUGE_SMOOTHING,
    prop::BATTERY_CHARGE_VOLTAGE_REQUEST,
    prop::BATTERY_GAUGE_FORMAT,
    prop::BATTERY_GAUGE_STATUS,
    prop::BATTERY_GAUGE_OPERATION_STATUS,
];
pub const BQ27220: u32 = 1;

pub const fn unit(key: u32) -> Option<&'static str> {
    match key {
        prop::BATTERY_CURRENT => Some("mA"),
        prop::BATTERY_REMAINING_CAPACITY..=prop::BATTERY_DESIGN_CAPACITY => Some("mAh"),
        prop::BATTERY_CHARGE_VOLTAGE_REQUEST => Some("mV"),
        _ => None,
    }
}

impl core::fmt::Display for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Current(v) => write!(f, "{v}"),
            Self::Unsigned(v) | Self::Format(v) => write!(f, "{v}"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Voltage(VoltageRequest::Millivolts(v)) => write!(f, "{v}"),
            Self::Voltage(VoltageRequest::Maximum) => f.write_str("maximum"),
        }
    }
}

pub const fn index(key: u32) -> Option<usize> {
    if key >= prop::BATTERY_CURRENT && key <= prop::BATTERY_GAUGE_OPERATION_STATUS {
        Some((key - prop::BATTERY_CURRENT) as usize)
    } else {
        None
    }
}

/// Requested/supported fields. Bit zero is the existing battery snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fields(u16);
impl Fields {
    pub const NONE: Self = Self(0);
    pub const SNAPSHOT: Self = Self(1);
    pub const DIAGNOSTICS: Self = Self(0x3ffe);
    pub const ALL: Self = Self(0x3fff);
    pub const fn for_key(key: u32) -> Self {
        if key == prop::BATTERY {
            Self::SNAPSHOT
        } else if let Some(index) = index(key) {
            Self(1 << (index + 1))
        } else {
            Self::NONE
        }
    }
    pub const fn contains(self, key: u32) -> bool {
        self.0 & Self::for_key(key).0 != 0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoltageRequest {
    Millivolts(u32),
    Maximum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Current(i32),
    Unsigned(u32),
    Bool(bool),
    Voltage(VoltageRequest),
    Format(u32),
}

impl Value {
    /// Decode a property's nonempty value; empty means temporarily unavailable.
    pub fn decode(key: u32, bytes: &[u8]) -> Result<Option<Self>, Status> {
        if index(key).is_none() {
            return Err(Status::PROP_NOT_FOUND);
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        let bad = || Status::PARSE_ERROR;
        Ok(Some(match key {
            prop::BATTERY_CURRENT => Self::Current(sint::decode(bytes).map_err(|_| bad())?),
            prop::BATTERY_EXT_POWER_PRESENT..=prop::BATTERY_GAUGE_SMOOTHING => {
                Self::Bool(match bytes {
                    [0] => false,
                    [1] => true,
                    _ => return Err(bad()),
                })
            }
            prop::BATTERY_CHARGE_VOLTAGE_REQUEST => {
                let (tag, used) = pui::decode(bytes).map_err(|_| bad())?;
                Self::Voltage(match (tag, &bytes[used..]) {
                    (0, rest) => VoltageRequest::Millivolts(uint::decode(rest).map_err(|_| bad())?),
                    (1, []) => VoltageRequest::Maximum,
                    _ => return Err(bad()),
                })
            }
            prop::BATTERY_GAUGE_FORMAT => {
                let (format, used) = pui::decode(bytes).map_err(|_| bad())?;
                if format == 0 || used != bytes.len() {
                    return Err(bad());
                }
                Self::Format(format)
            }
            _ => Self::Unsigned(uint::decode(bytes).map_err(|_| bad())?),
        }))
    }

    pub fn encode(self, key: u32, out: &mut [u8]) -> Result<usize, Status> {
        let len = match self {
            Self::Current(value) => sint::encode(value, out).map_err(|_| Status::NOMEM)?,
            Self::Unsigned(value) => uint::encode(value, out).map_err(|_| Status::NOMEM)?,
            Self::Bool(value) => {
                *out.first_mut().ok_or(Status::NOMEM)? = u8::from(value);
                1
            }
            Self::Format(value) => pui::encode(value, out).map_err(|_| Status::NOMEM)?,
            Self::Voltage(value) => {
                *out.first_mut().ok_or(Status::NOMEM)? = match value {
                    VoltageRequest::Millivolts(_) => 0,
                    VoltageRequest::Maximum => 1,
                };
                match value {
                    VoltageRequest::Millivolts(mv) => {
                        1 + uint::encode(mv, &mut out[1..]).map_err(|_| Status::NOMEM)?
                    }
                    VoltageRequest::Maximum => 1,
                }
            }
        };
        if Self::decode(key, &out[..len]) != Ok(Some(self)) {
            return Err(Status::FAILURE);
        }
        Ok(len)
    }
}

/// Per-property failures stay independent. Defaults fail rather than fabricate data.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub snapshot: Result<BatteryStatus, ()>,
    values: [Result<Option<Value>, Status>; 13],
}
impl Default for Sample {
    fn default() -> Self {
        Self {
            snapshot: Err(()),
            values: [Err(Status::FAILURE); 13],
        }
    }
}
impl Sample {
    pub fn set(&mut self, key: u32, value: Result<Option<Value>, Status>) {
        if let Some(i) = index(key) {
            self.values[i] = value;
        }
    }
    pub fn get(&self, key: u32) -> Result<Option<Value>, Status> {
        self.values[index(key).ok_or(Status::PROP_NOT_FOUND)?]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_reply_matches_the_documented_compact_budget() {
        let values = [
            Value::Current(-100),
            Value::Unsigned(1500),
            Value::Unsigned(1500),
            Value::Unsigned(1500),
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            Value::Voltage(VoltageRequest::Millivolts(4200)),
            Value::Format(1),
            Value::Unsigned(0x4268),
            Value::Unsigned(0xa6),
        ];
        let mut bytes = [0; 100];
        let mut reply = crate::frame::prop_are(&mut bytes, 1).unwrap();
        reply
            .write_entry(prop::BATTERY, &[7, 0x68, 0x10, 100, 0])
            .unwrap();
        for (key, value) in KEYS.into_iter().zip(values) {
            let mut encoded = [0; 5];
            let len = value.encode(key, &mut encoded).unwrap();
            reply.write_entry(key, &encoded[..len]).unwrap();
        }
        assert_eq!(reply.finish(), 67);
    }
    #[test]
    fn signed_and_tagged_values_use_the_shortest_encoding() {
        for (value, expected) in [
            (-100, &[0x9c][..]),
            (-200, &[0x38, 0xff][..]),
            (-128, &[0x80][..]),
            (-129, &[0x7f, 0xff][..]),
            (127, &[0x7f][..]),
            (128, &[0x80, 0][..]),
        ] {
            let mut bytes = [0; 5];
            let len = Value::Current(value)
                .encode(prop::BATTERY_CURRENT, &mut bytes)
                .unwrap();
            assert_eq!(&bytes[..len], expected);
            assert_eq!(
                Value::decode(prop::BATTERY_CURRENT, expected),
                Ok(Some(Value::Current(value)))
            );
        }
        assert_eq!(
            Value::decode(prop::BATTERY_CURRENT, &[0x9c, 0xff, 0xff, 0xff]),
            Ok(Some(Value::Current(-100)))
        );
        let mut bytes = [0; 5];
        let len = Value::Voltage(VoltageRequest::Millivolts(4200))
            .encode(prop::BATTERY_CHARGE_VOLTAGE_REQUEST, &mut bytes)
            .unwrap();
        assert_eq!(&bytes[..len], &[0, 0x68, 0x10]);
        assert_eq!(
            Value::decode(prop::BATTERY_CHARGE_VOLTAGE_REQUEST, &[1]),
            Ok(Some(Value::Voltage(VoltageRequest::Maximum)))
        );
        for bytes in [&[0][..], &[1, 0][..], &[2][..], &[0, 0, 0, 0, 0, 0][..]] {
            assert!(Value::decode(prop::BATTERY_CHARGE_VOLTAGE_REQUEST, bytes).is_err());
        }
        assert_eq!(Value::decode(prop::BATTERY_CURRENT, &[]), Ok(None));
        assert_eq!(
            Value::decode(prop::BATTERY_PRESENT, &[0]),
            Ok(Some(Value::Bool(false)))
        );
        assert!(Value::decode(prop::BATTERY_PRESENT, &[0, 0]).is_err());
        assert!(Value::decode(prop::BATTERY_CURRENT, &[0; 5]).is_err());
        assert!(Value::decode(prop::BATTERY_GAUGE_FORMAT, &[0]).is_err());
        assert_eq!(
            Value::decode(prop::BATTERY_GAUGE_FORMAT, &[99]),
            Ok(Some(Value::Format(99)))
        );
    }
}
