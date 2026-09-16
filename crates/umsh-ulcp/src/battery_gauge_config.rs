//! On-demand BQ27220 configuration snapshot. Integer values are unsigned PUI;
//! calibration F4 bit patterns use four LE octets and remain uninterpreted.
use crate::{Status, pui};

pub const FORMAT: u32 = 1;
pub const VERSION: u32 = 1;

pub struct Field {
    pub name: &'static str,
    pub address: u16,
    pub width: usize,
    pub unit: &'static str,
}

macro_rules! fields {
    ($(($name:literal, $address:literal, $width:literal, $unit:literal)),* $(,)?) => {
        pub const FIELDS: &[Field] = &[$(Field { name: $name, address: $address, width: $width, unit: $unit }),*];
    };
}

// TI SLUUBD4A table 3-2: RAM locations only. Ordering is part of version 1.
fields![
    ("battery_id", 0x929a, 1, "bits"),
    ("operation_config_a", 0x9206, 2, "bits"),
    ("operation_config_b", 0x9208, 2, "bits"),
    ("cedv_config", 0x929b, 2, "bits"),
    ("full_capacity", 0x929d, 2, "mAh"),
    ("design_capacity", 0x929f, 2, "mAh"),
    ("design_voltage", 0x92a3, 2, "mV"),
    ("termination_voltage_margin", 0x92a5, 2, "mV"),
    ("charging_voltage", 0x91fd, 2, "mV"),
    ("taper_current", 0x9201, 2, "mA"),
    ("discharge_detection", 0x9228, 2, "mA"),
    ("charge_detection", 0x922a, 2, "mA"),
    ("quit_current", 0x922c, 2, "mA"),
    ("battery_low", 0x9251, 2, "0.01%"),
    ("learning_low_temp", 0x925b, 1, "raw"),
    ("overload_current", 0x9264, 2, "mA"),
    ("near_full", 0x926b, 2, "mAh"),
    ("reserve_capacity", 0x926d, 2, "mAh"),
    ("charge_efficiency", 0x926f, 1, "%"),
    ("discharge_efficiency", 0x9270, 1, "%"),
    ("fixed_edv0", 0x92b4, 2, "mV"),
    ("edv0_hold", 0x92b6, 1, "s"),
    ("fixed_edv1", 0x92b7, 2, "mV"),
    ("edv1_hold", 0x92b9, 1, "s"),
    ("fixed_edv2", 0x92ba, 2, "mV"),
    ("edv2_hold", 0x92bc, 1, "s"),
    ("emf", 0x92a7, 2, "raw"),
    ("c0", 0x92a9, 2, "raw"),
    ("r0", 0x92ab, 2, "raw"),
    ("t0", 0x92ad, 2, "raw"),
    ("r1", 0x92af, 2, "raw"),
    ("tc", 0x92b1, 1, "raw"),
    ("c1", 0x92b2, 1, "raw"),
    ("age_factor", 0x92b3, 1, "raw"),
    ("flag_config_a", 0x927f, 2, "bits"),
    ("flag_config_b", 0x9281, 1, "bits"),
    ("full_set_voltage", 0x9288, 2, "mV"),
    ("full_clear_voltage", 0x928a, 2, "mV"),
    ("full_set_soc", 0x928c, 1, "%"),
    ("full_clear_soc", 0x928d, 1, "%"),
    ("smoothing_config", 0x9271, 1, "bits"),
    ("cc_gain", 0x9184, 4, "F4 bits"),
    ("cc_delta", 0x9188, 4, "F4 bits"),
    ("current_deadband", 0x91de, 1, "mA"),
    ("cc_deadband", 0x91df, 1, "294 nV"),
    ("voltage_0_dod", 0x92bd, 2, "mV"),
    ("voltage_50_dod", 0x92c7, 2, "mV"),
    ("voltage_100_dod", 0x92d1, 2, "mV"),
];

pub const MAX_ENCODED: usize = 2 + FIELDS.len() * 3 + 2;

const fn offset(index: usize) -> usize {
    let mut result = 0;
    let mut i = 0;
    while i < index {
        result += FIELDS[i].width;
        i += 1;
    }
    result
}
pub const RAW_LEN: usize = offset(FIELDS.len());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    // Retain hardware-width bytes rather than widening every field in all the
    // embedded session/future copies of a battery sample.
    data: [u8; RAW_LEN],
}

impl Default for Config {
    fn default() -> Self {
        Self { data: [0; RAW_LEN] }
    }
}

impl Config {
    pub fn value(&self, index: usize) -> u32 {
        let start = offset(index);
        self.data[start..start + FIELDS[index].width]
            .iter()
            .fold(0u32, |v, b| (v << 8) | u32::from(*b))
    }

    pub fn values(&self) -> impl Iterator<Item = u32> + '_ {
        (0..FIELDS.len()).map(|i| self.value(i))
    }

    pub fn set(&mut self, index: usize, value: u32) -> Result<(), Status> {
        let field = FIELDS.get(index).ok_or(Status::INVALID_ARGUMENT)?;
        if field.width < 4 && value >= 1 << (8 * field.width) {
            return Err(Status::INVALID_ARGUMENT);
        }
        let start = offset(index);
        self.data[start..start + field.width]
            .copy_from_slice(&value.to_be_bytes()[4 - field.width..]);
        Ok(())
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Status> {
        let mut used = pui::encode(FORMAT, out).map_err(|_| Status::NOMEM)?;
        used += pui::encode(VERSION, &mut out[used..]).map_err(|_| Status::NOMEM)?;
        for (field, value) in FIELDS.iter().zip(self.values()) {
            if field.width == 4 {
                out.get_mut(used..used + 4)
                    .ok_or(Status::NOMEM)?
                    .copy_from_slice(&value.to_le_bytes());
                used += 4;
            } else {
                if value >= 1 << (8 * field.width) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                used += pui::encode(value, &mut out[used..]).map_err(|_| Status::NOMEM)?;
            }
        }
        Ok(used)
    }

    pub fn decode(mut bytes: &[u8]) -> Result<Self, Status> {
        fn next(bytes: &mut &[u8]) -> Result<u32, Status> {
            let (value, used) = pui::decode(bytes).map_err(|_| Status::PARSE_ERROR)?;
            *bytes = &bytes[used..];
            Ok(value)
        }
        if next(&mut bytes)? != FORMAT || next(&mut bytes)? != VERSION {
            return Err(Status::UNIMPLEMENTED);
        }
        let mut result = Self::default();
        for (index, field) in FIELDS.iter().enumerate() {
            let value = if field.width == 4 {
                let value = u32::from_le_bytes(
                    bytes
                        .get(..4)
                        .ok_or(Status::PARSE_ERROR)?
                        .try_into()
                        .unwrap(),
                );
                bytes = &bytes[4..];
                value
            } else {
                next(&mut bytes)?
            };
            result.set(index, value).map_err(|_| Status::PARSE_ERROR)?;
        }
        if !bytes.is_empty() {
            return Err(Status::PARSE_ERROR);
        }
        Ok(result)
    }

    pub fn cedv_config(&self) -> u32 {
        self.value(3)
    }
}

impl core::fmt::Display for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "BQ27220 configuration v1")?;
        for (field, value) in FIELDS.iter().zip(self.values()) {
            if field.unit.contains("bits") {
                writeln!(f, "    {}: {value:#x} ({})", field.name, field.unit)?;
            } else {
                writeln!(f, "    {}: {value} {}", field.name, field.unit)?;
            }
        }
        write!(
            f,
            "    fcc_limit: {}; independent_charger: {}; edv_compensation: {}",
            self.cedv_config() & 0x100 != 0,
            self.cedv_config() & 0x10 != 0,
            self.cedv_config() & 8 != 0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_snapshot_rejects_truncation_unknown_versions_and_trailing_data() {
        let mut value = Config::default();
        value.set(3, 0x102a).unwrap();
        value.set(4, 1372).unwrap();
        value.set(5, 1500).unwrap();
        value.set(41, 0x3f2c3d70).unwrap();
        let mut bytes = [0; MAX_ENCODED];
        let len = value.encode(&mut bytes).unwrap();
        assert_eq!(&bytes[..8], &[1, 1, 0, 0, 0, 0xaa, 0x20, 0xdc]);
        assert_eq!(Config::decode(&bytes[..len]), Ok(value));
        for end in 0..len {
            assert!(Config::decode(&bytes[..end]).is_err());
        }
        assert!(Config::decode(&bytes[..len + 1]).is_err());
        bytes[1] = 2;
        assert_eq!(Config::decode(&bytes[..len]), Err(Status::UNIMPLEMENTED));
    }
}
