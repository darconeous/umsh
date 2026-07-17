//! User-facing tracker battery-state classification.

/// Mutually exclusive battery modes presented by the tracker UX.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BatteryState {
    BatteryOnly = 0,
    BatteryLow = 1,
    BatteryCritical = 2,
    BatteryCharging = 3,
    BatteryCharged = 4,
}

impl BatteryState {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::BatteryLow,
            2 => Self::BatteryCritical,
            3 => Self::BatteryCharging,
            4 => Self::BatteryCharged,
            _ => Self::BatteryOnly,
        }
    }
}

/// Default state thresholds for a single-cell Li-ion tracker.
#[derive(Clone, Copy, Debug)]
pub struct BatteryThresholds {
    pub low_mv: u16,
    pub critical_mv: u16,
}

impl Default for BatteryThresholds {
    fn default() -> Self {
        Self {
            low_mv: 3_500,
            critical_mv: 3_100,
        }
    }
}

/// Classify external power first so battery-only warnings and lockouts can
/// never leak into Charging or Charged from the user's perspective.
pub const fn classify(
    battery_mv: u16,
    external_power: bool,
    charging: bool,
    thresholds: BatteryThresholds,
) -> BatteryState {
    if external_power {
        if charging {
            BatteryState::BatteryCharging
        } else {
            BatteryState::BatteryCharged
        }
    } else if battery_mv <= thresholds.critical_mv {
        BatteryState::BatteryCritical
    } else if battery_mv <= thresholds.low_mv {
        BatteryState::BatteryLow
    } else {
        BatteryState::BatteryOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: BatteryThresholds = BatteryThresholds {
        low_mv: 3_500,
        critical_mv: 3_100,
    };

    #[test]
    fn external_power_suppresses_battery_only_modes() {
        assert_eq!(
            classify(2_900, true, true, T),
            BatteryState::BatteryCharging
        );
        assert_eq!(
            classify(2_900, true, false, T),
            BatteryState::BatteryCharged
        );
    }

    #[test]
    fn battery_levels_are_mutually_exclusive() {
        assert_eq!(classify(3_900, false, false, T), BatteryState::BatteryOnly);
        assert_eq!(classify(3_400, false, false, T), BatteryState::BatteryLow);
        assert_eq!(
            classify(3_000, false, false, T),
            BatteryState::BatteryCritical
        );
    }
}
