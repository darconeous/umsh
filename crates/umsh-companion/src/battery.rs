//! Battery status snapshot codec (`PROP_BATTERY`).
//!
//! The property value is either **empty** — the implementation reports no
//! battery measurements at all — or one field-flags octet followed by the
//! present fields in fixed order: voltage (`UINT16_LE`, millivolts), level
//! (`UINT8`, percent), charge state (PUI). Reserved flag bits must be
//! zero, and the value length must match the flags exactly.

use crate::pui;

/// Field-flags bit for the voltage field.
pub const FLAG_VOLTAGE: u8 = 1 << 0;
/// Field-flags bit for the level field.
pub const FLAG_LEVEL: u8 = 1 << 1;
/// Field-flags bit for the charge-state field.
pub const FLAG_CHARGE_STATE: u8 = 1 << 2;

const FLAGS_RESERVED: u8 = !(FLAG_VOLTAGE | FLAG_LEVEL | FLAG_CHARGE_STATE);

/// Largest encoded size of a snapshot: flags + voltage + level + a
/// one-byte PUI charge state.
pub const MAX_ENCODED_LEN: usize = 5;

/// The battery charge-state enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatteryChargeState {
    /// `BATTERY_CHARGE_STATE_DISCHARGING`
    Discharging = 0,
    /// `BATTERY_CHARGE_STATE_CHARGING`
    Charging = 1,
    /// `BATTERY_CHARGE_STATE_CHARGED`
    Charged = 2,
}

impl BatteryChargeState {
    /// The wire code for this state.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Strict conversion from a decoded wire code.
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Discharging),
            1 => Some(Self::Charging),
            2 => Some(Self::Charged),
            _ => None,
        }
    }
}

/// Snapshot or decode error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatteryError {
    /// Reserved flag bits set, length inconsistent with the flags, an
    /// out-of-range level, or an unknown charge-state code.
    Malformed,
    /// The output buffer cannot hold the encoded snapshot.
    BufferTooSmall,
}

/// One battery status snapshot: the fields the platform reports.
///
/// `None` means the field is unsupported (its flag bit is clear). A
/// snapshot with every field `None` encodes as the empty value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatteryStatus {
    /// Measured voltage at the battery terminals, in millivolts.
    pub voltage_mv: Option<u16>,
    /// Estimated state of charge, 0–100 percent.
    pub level_percent: Option<u8>,
    /// Charge state reported by the charging system.
    pub charge_state: Option<BatteryChargeState>,
}

impl BatteryStatus {
    /// Whether no field is reported (the empty wire form).
    pub const fn is_empty(&self) -> bool {
        self.voltage_mv.is_none() && self.level_percent.is_none() && self.charge_state.is_none()
    }

    /// The field-flags octet for this snapshot.
    pub fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.voltage_mv.is_some() {
            flags |= FLAG_VOLTAGE;
        }
        if self.level_percent.is_some() {
            flags |= FLAG_LEVEL;
        }
        if self.charge_state.is_some() {
            flags |= FLAG_CHARGE_STATE;
        }
        flags
    }

    /// Encode the snapshot, returning the number of bytes written.
    ///
    /// An all-`None` snapshot encodes as zero bytes (the empty form). A
    /// level above 100 is rejected as [`BatteryError::Malformed`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BatteryError> {
        if self.is_empty() {
            return Ok(0);
        }
        let mut len = 0;
        let mut push = |byte: u8| -> Result<(), BatteryError> {
            *out.get_mut(len).ok_or(BatteryError::BufferTooSmall)? = byte;
            len += 1;
            Ok(())
        };
        push(self.flags())?;
        if let Some(mv) = self.voltage_mv {
            let [low, high] = mv.to_le_bytes();
            push(low)?;
            push(high)?;
        }
        if let Some(percent) = self.level_percent {
            if percent > 100 {
                return Err(BatteryError::Malformed);
            }
            push(percent)?;
        }
        if let Some(state) = self.charge_state {
            let mut pui_buf = [0u8; pui::MAX_LEN];
            let pui_len = pui::encode(state.code(), &mut pui_buf)
                .map_err(|_| BatteryError::BufferTooSmall)?;
            for &byte in &pui_buf[..pui_len] {
                push(byte)?;
            }
        }
        Ok(len)
    }

    /// Strictly decode a property value.
    ///
    /// The empty value decodes to an all-`None` snapshot. Any other value
    /// must consist of exactly the flags octet and the fields it declares;
    /// a zero flags octet, reserved bits, trailing bytes, a level above
    /// 100, and unknown charge-state codes are all malformed.
    pub fn decode(value: &[u8]) -> Result<Self, BatteryError> {
        let Some((&flags, mut rest)) = value.split_first() else {
            return Ok(Self::default());
        };
        if flags == 0 || flags & FLAGS_RESERVED != 0 {
            return Err(BatteryError::Malformed);
        }
        let mut take = |count: usize| -> Result<&[u8], BatteryError> {
            if rest.len() < count {
                return Err(BatteryError::Malformed);
            }
            let (field, remaining) = rest.split_at(count);
            rest = remaining;
            Ok(field)
        };
        let voltage_mv = if flags & FLAG_VOLTAGE != 0 {
            let field = take(2)?;
            Some(u16::from_le_bytes([field[0], field[1]]))
        } else {
            None
        };
        let level_percent = if flags & FLAG_LEVEL != 0 {
            let percent = take(1)?[0];
            if percent > 100 {
                return Err(BatteryError::Malformed);
            }
            Some(percent)
        } else {
            None
        };
        let charge_state = if flags & FLAG_CHARGE_STATE != 0 {
            let (code, consumed) = pui::decode(rest).map_err(|_| BatteryError::Malformed)?;
            rest = &rest[consumed..];
            Some(BatteryChargeState::from_code(code).ok_or(BatteryError::Malformed)?)
        } else {
            None
        };
        if !rest.is_empty() {
            return Err(BatteryError::Malformed);
        }
        Ok(Self {
            voltage_mv,
            level_percent,
            charge_state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn round_trip(status: BatteryStatus, expected: &[u8]) {
        let mut buf = [0u8; MAX_ENCODED_LEN];
        let len = status.encode(&mut buf).unwrap();
        assert_eq!(&buf[..len], expected, "encoding of {status:?}");
        assert_eq!(BatteryStatus::decode(expected).unwrap(), status);
    }

    #[test]
    fn every_field_combination_round_trips() {
        round_trip(BatteryStatus::default(), &[]);
        round_trip(
            BatteryStatus {
                voltage_mv: Some(3987),
                ..Default::default()
            },
            &[0b001, 0x93, 0x0F],
        );
        round_trip(
            BatteryStatus {
                level_percent: Some(100),
                ..Default::default()
            },
            &[0b010, 100],
        );
        round_trip(
            BatteryStatus {
                charge_state: Some(BatteryChargeState::Charged),
                ..Default::default()
            },
            &[0b100, 2],
        );
        round_trip(
            BatteryStatus {
                voltage_mv: Some(4200),
                level_percent: Some(87),
                ..Default::default()
            },
            &[0b011, 0x68, 0x10, 87],
        );
        round_trip(
            BatteryStatus {
                voltage_mv: Some(3700),
                charge_state: Some(BatteryChargeState::Discharging),
                ..Default::default()
            },
            &[0b101, 0x74, 0x0E, 0],
        );
        round_trip(
            BatteryStatus {
                level_percent: Some(0),
                charge_state: Some(BatteryChargeState::Charging),
                ..Default::default()
            },
            &[0b110, 0, 1],
        );
        round_trip(
            BatteryStatus {
                voltage_mv: Some(4180),
                level_percent: Some(99),
                charge_state: Some(BatteryChargeState::Charging),
            },
            &[0b111, 0x54, 0x10, 99, 1],
        );
    }

    #[test]
    fn rejects_malformed_values() {
        // A zero flags octet: the empty form is the only no-field encoding.
        assert_eq!(
            BatteryStatus::decode(&[0]),
            Err(BatteryError::Malformed)
        );
        // Reserved flag bits.
        assert_eq!(
            BatteryStatus::decode(&[0b1000, 1]),
            Err(BatteryError::Malformed)
        );
        // Length shorter than the flags declare.
        assert_eq!(
            BatteryStatus::decode(&[0b001, 0x93]),
            Err(BatteryError::Malformed)
        );
        // Trailing bytes beyond the declared fields.
        assert_eq!(
            BatteryStatus::decode(&[0b010, 50, 0]),
            Err(BatteryError::Malformed)
        );
        // Level above 100.
        assert_eq!(
            BatteryStatus::decode(&[0b010, 101]),
            Err(BatteryError::Malformed)
        );
        // Unknown charge-state code.
        assert_eq!(
            BatteryStatus::decode(&[0b100, 3]),
            Err(BatteryError::Malformed)
        );
        // Truncated charge-state PUI.
        assert_eq!(
            BatteryStatus::decode(&[0b100, 0x80]),
            Err(BatteryError::Malformed)
        );
    }

    #[test]
    fn encode_rejects_out_of_range_level() {
        let status = BatteryStatus {
            level_percent: Some(101),
            ..Default::default()
        };
        let mut buf = [0u8; MAX_ENCODED_LEN];
        assert_eq!(status.encode(&mut buf), Err(BatteryError::Malformed));
    }

    #[test]
    fn encode_reports_short_buffers() {
        let status = BatteryStatus {
            voltage_mv: Some(4000),
            ..Default::default()
        };
        let mut buf = [0u8; 2];
        assert_eq!(status.encode(&mut buf), Err(BatteryError::BufferTooSmall));
    }

    #[test]
    fn charge_state_codes_are_strict() {
        assert_eq!(
            BatteryChargeState::from_code(0),
            Some(BatteryChargeState::Discharging)
        );
        assert_eq!(
            BatteryChargeState::from_code(1),
            Some(BatteryChargeState::Charging)
        );
        assert_eq!(
            BatteryChargeState::from_code(2),
            Some(BatteryChargeState::Charged)
        );
        assert_eq!(BatteryChargeState::from_code(3), None);
    }
}
