//! Persistent user-facing tracker preferences.
//!
//! The representation is deliberately tiny so board support can keep it in a
//! retained register such as the nRF52840's `GPREGRET2` without flash wear.

const MAGIC: u8 = 0xA0;
const MAGIC_MASK: u8 = 0xF8;
const ASLEEP: u8 = 1 << 0;
const SILENT: u8 = 1 << 1;
const BATTERY_CRITICAL: u8 = 1 << 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserPreferences {
    pub asleep: bool,
    pub silent: bool,
    /// Protective shutdown reason, kept separate from user-requested Sleep.
    pub battery_critical: bool,
}

impl UserPreferences {
    pub const fn try_decode(value: u8) -> Option<Self> {
        if value & MAGIC_MASK != MAGIC {
            return None;
        }
        Some(Self {
            asleep: value & ASLEEP != 0,
            silent: value & SILENT != 0,
            battery_critical: value & BATTERY_CRITICAL != 0,
        })
    }

    pub const fn encode(self) -> u8 {
        MAGIC
            | (self.asleep as u8) * ASLEEP
            | (self.silent as u8) * SILENT
            | (self.battery_critical as u8) * BATTERY_CRITICAL
    }

    pub const fn decode(value: u8) -> Self {
        match Self::try_decode(value) {
            Some(preferences) => preferences,
            None => Self {
                asleep: false,
                silent: false,
                battery_critical: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preference_combination_round_trips() {
        for asleep in [false, true] {
            for silent in [false, true] {
                for battery_critical in [false, true] {
                    let expected = UserPreferences {
                        asleep,
                        silent,
                        battery_critical,
                    };
                    assert_eq!(UserPreferences::decode(expected.encode()), expected);
                }
            }
        }
    }

    #[test]
    fn erased_or_foreign_register_defaults_awake_and_noisy() {
        for value in [0x00, 0x57, 0xff] {
            assert_eq!(UserPreferences::decode(value), UserPreferences::default());
        }
    }
}
