//! Fast, read-only BQ27220 standard-command telemetry.
use crate::{Status, pui, sint, uint};

pub const FORMAT: u32 = 1;
pub const VERSION: u32 = 1;

pub struct Field {
    pub name: &'static str,
    pub register: u8,
    pub unit: &'static str,
    pub signed: bool,
}

macro_rules! fields {
    ($(($name:literal, $register:literal, $unit:literal, $signed:literal)),* $(,)?) => {
        pub const FIELDS: &[Field] = &[$(Field { name: $name, register: $register, unit: $unit, signed: $signed }),*];
    };
}

// TI SLUUBD4A standard commands. Ordering is part of version 1.
fields![
    ("raw_coulomb_count", 0x22, "mAh", true),
    ("temperature", 0x06, "0.1 K", false),
    ("internal_temperature", 0x28, "0.1 K", false),
    ("average_current", 0x14, "mA", true),
    ("average_power", 0x24, "mW", true),
    ("time_to_empty", 0x16, "min", false),
    ("time_to_full", 0x18, "min", false),
    ("standby_current", 0x1a, "mA", true),
    ("standby_time_to_empty", 0x1c, "min", false),
    ("max_load_current", 0x1e, "mA", true),
    ("max_load_time_to_empty", 0x20, "min", false),
    ("cycle_count", 0x2a, "cycles", false),
    ("state_of_health", 0x2e, "%", false),
    ("charging_current", 0x32, "mA", false),
];

pub const MAX_ENCODED: usize = 4 + FIELDS.len() * 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Telemetry {
    /// Original register bits, including documented sentinel values.
    pub raw: [u16; FIELDS.len()],
}

impl Telemetry {
    pub fn value(&self, index: usize) -> i32 {
        if FIELDS[index].signed {
            i32::from(self.raw[index] as i16)
        } else {
            i32::from(self.raw[index])
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Status> {
        let mut used = pui::encode(FORMAT, out).map_err(|_| Status::NOMEM)?;
        used += pui::encode(VERSION, &mut out[used..]).map_err(|_| Status::NOMEM)?;
        let width_offset = used;
        out.get_mut(used..used + 2).ok_or(Status::NOMEM)?.fill(0);
        used += 2;
        let mut widths = 0u16;
        for (i, field) in FIELDS.iter().enumerate() {
            let len = if field.signed {
                sint::encode(self.value(i), &mut out[used..]).map_err(|_| Status::NOMEM)?
            } else {
                uint::encode(self.raw[i].into(), &mut out[used..]).map_err(|_| Status::NOMEM)?
            };
            widths |= ((len - 1) as u16) << i;
            used += len;
        }
        out[width_offset..width_offset + 2].copy_from_slice(&widths.to_le_bytes());
        Ok(used)
    }

    pub fn decode(mut bytes: &[u8]) -> Result<Self, Status> {
        fn next(bytes: &mut &[u8]) -> Result<u32, Status> {
            let (v, n) = pui::decode(bytes).map_err(|_| Status::PARSE_ERROR)?;
            *bytes = &bytes[n..];
            Ok(v)
        }
        if next(&mut bytes)? != FORMAT || next(&mut bytes)? != VERSION {
            return Err(Status::UNIMPLEMENTED);
        }
        let widths = u16::from_le_bytes(
            bytes
                .get(..2)
                .ok_or(Status::PARSE_ERROR)?
                .try_into()
                .unwrap(),
        );
        bytes = &bytes[2..];
        if widths >> FIELDS.len() != 0 {
            return Err(Status::PARSE_ERROR);
        }
        let mut result = Self::default();
        for (i, field) in FIELDS.iter().enumerate() {
            let len = 1 + usize::from((widths >> i) & 1);
            let value = bytes.get(..len).ok_or(Status::PARSE_ERROR)?;
            result.raw[i] = if field.signed {
                sint::decode(value).map_err(|_| Status::PARSE_ERROR)? as u16
            } else {
                uint::decode(value).map_err(|_| Status::PARSE_ERROR)? as u16
            };
            bytes = &bytes[len..];
        }
        if !bytes.is_empty() {
            return Err(Status::PARSE_ERROR);
        }
        Ok(result)
    }
}

impl core::fmt::Display for Telemetry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "BQ27220 telemetry v1")?;
        for (i, field) in FIELDS.iter().enumerate() {
            write!(f, "    {}: ", field.name)?;
            if field.unit == "min" && self.raw[i] == u16::MAX {
                writeln!(f, "unavailable (raw 65535)")?;
            } else if field.register == 0x32 && self.raw[i] == u16::MAX {
                writeln!(f, "maximum requested")?;
            } else if field.unit == "0.1 K" {
                let celsius = f64::from(self.raw[i]) / 10.0 - 273.15;
                writeln!(f, "{celsius:.2} °C ({} {})", self.raw[i], field.unit)?;
            } else {
                writeln!(f, "{} {}", self.value(i), field.unit)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_widths_preserve_sign_sentinels_and_full_counter_range() {
        let sample = Telemetry {
            raw: [
                65535,
                2981,
                3012,
                (-100i16) as u16,
                (-200i16) as u16,
                65535,
                0,
                (-128i16) as u16,
                120,
                (-129i16) as u16,
                256,
                180,
                91,
                65535,
            ],
        };
        let mut bytes = [0; MAX_ENCODED];
        let len = sample.encode(&mut bytes).unwrap();
        assert_eq!(len, 25);
        assert_eq!(&bytes[..4], &[1, 1, 0x36, 0x26]);
        assert_eq!(&bytes[9..12], &[0x9c, 0x38, 0xff]);
        assert_eq!(Telemetry::decode(&bytes[..len]), Ok(sample));
        assert_eq!(sample.value(3), -100);
        assert_eq!(sample.value(0), -1);
        for end in 0..len {
            assert!(Telemetry::decode(&bytes[..end]).is_err());
            let mut short = [0; MAX_ENCODED];
            assert_eq!(sample.encode(&mut short[..end]), Err(Status::NOMEM));
        }
        assert!(Telemetry::decode(&bytes[..len + 1]).is_err());
        bytes[3] |= 0x80;
        assert_eq!(Telemetry::decode(&bytes[..len]), Err(Status::PARSE_ERROR));
        bytes[1] = 2;
        assert_eq!(Telemetry::decode(&bytes[..len]), Err(Status::UNIMPLEMENTED));
        let extremes = Telemetry {
            raw: [0x8000; FIELDS.len()],
        };
        assert_eq!(extremes.encode(&mut bytes), Ok(MAX_ENCODED));
        assert_eq!(Telemetry::decode(&bytes), Ok(extremes));
    }

    #[test]
    fn coulomb_counter_round_trips_every_signed_value_at_minimum_width() {
        for value in i16::MIN..=i16::MAX {
            let mut sample = Telemetry::default();
            sample.raw[0] = value as u16;
            let mut bytes = [0; MAX_ENCODED];
            let len = sample.encode(&mut bytes).unwrap();
            let two_bytes = !(-128..=127).contains(&value);
            assert_eq!(len, 18 + usize::from(two_bytes));
            assert_eq!(bytes[2] & 1, u8::from(two_bytes));
            assert_eq!(
                Telemetry::decode(&bytes[..len]).unwrap().value(0),
                i32::from(value)
            );
        }
    }
}
