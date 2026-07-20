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

/// Generic single-cell Li-ion open-circuit-voltage → state-of-charge
/// breakpoints, linearly interpolated. Approximate by design (no cell
/// model, no temperature term); refine from a bench discharge log when
/// one exists.
const OCV_TABLE: &[(u16, u8)] = &[
    (3_300, 0),
    (3_400, 2),
    (3_500, 5),
    (3_550, 8),
    (3_600, 12),
    (3_650, 18),
    (3_700, 28),
    (3_750, 40),
    (3_800, 52),
    (3_850, 60),
    (3_900, 67),
    (3_950, 74),
    (4_000, 81),
    (4_050, 87),
    (4_100, 92),
    (4_150, 96),
    (4_200, 100),
];

/// State of charge for a *resting* (open-circuit) terminal voltage.
pub fn soc_from_ocv(mv: u16) -> u8 {
    let (first, last) = (OCV_TABLE[0], OCV_TABLE[OCV_TABLE.len() - 1]);
    if mv <= first.0 {
        return first.1;
    }
    if mv >= last.0 {
        return last.1;
    }
    let mut below = first;
    for &point in OCV_TABLE {
        if point.0 >= mv {
            let span_mv = u32::from(point.0 - below.0);
            let span_pct = u32::from(point.1 - below.1);
            let offset = u32::from(mv - below.0);
            return below.1 + ((offset * span_pct + span_mv / 2) / span_mv) as u8;
        }
        below = point;
    }
    last.1
}

/// Number of consecutive quiet samples the anchor median runs over.
const LEVEL_WINDOW: usize = 5;
/// Quiet time required before a window median is trusted as OCV.
const LEVEL_REST_MS: u32 = 180_000;
/// Reported levels move in steps of this size; coarse output is the
/// honesty the estimate can actually back.
const LEVEL_QUANT: u8 = 5;
/// Rough charge-elevation guess used only to bootstrap a provisional
/// level when the very first sample arrives with the charger active.
const CHARGE_ELEVATION_MV: u16 = 180;

/// One estimator input: the monitor's measurement plus its context.
#[derive(Clone, Copy, Debug)]
pub struct LevelSample {
    /// Measured terminal voltage, millivolts.
    pub battery_mv: u16,
    /// The classification for the same instant (see [`classify`]).
    pub state: BatteryState,
    /// A significant load (e.g. a radio transmission) ran since the
    /// previous sample, so this voltage may be sagged.
    pub load_since_last: bool,
    /// Monotonic milliseconds; any epoch, wrapping arithmetic.
    pub now_ms: u32,
}

/// Approximate state-of-charge estimator for gauge-less boards:
/// a rest-gated OCV table with a median filter, a discharge-direction
/// clamp, and quantized output.
///
/// Feed it every monitor sample via [`Self::sample`]. Terminal voltage
/// only counts toward an anchor after [`LEVEL_REST_MS`] of quiet
/// (no external power, no reported load); anchored levels never rise
/// while discharging, so the output is stable and monotone between
/// charge sessions. While charging the level holds (charging voltage
/// is not comparable to the discharge table); the `Charged`
/// classification pins it to 100.
pub struct LevelEstimator {
    window: [u16; LEVEL_WINDOW],
    window_len: usize,
    level: Option<u8>,
    last_disturbance_ms: u32,
    charged_since_anchor: bool,
    started: bool,
}

impl LevelEstimator {
    pub const fn new() -> Self {
        Self {
            window: [0; LEVEL_WINDOW],
            window_len: 0,
            level: None,
            last_disturbance_ms: 0,
            charged_since_anchor: false,
            started: false,
        }
    }

    /// The current estimate; `Some` after the first sample.
    pub const fn level(&self) -> Option<u8> {
        self.level
    }

    pub fn sample(&mut self, s: LevelSample) {
        if !self.started {
            self.started = true;
            self.last_disturbance_ms = s.now_ms;
        }
        match s.state {
            BatteryState::BatteryCharged => {
                // The charger's completion signal is the one exact
                // calibration point available.
                self.level = Some(100);
                self.disturb(s.now_ms);
                self.charged_since_anchor = true;
            }
            BatteryState::BatteryCharging => {
                // Charging terminal voltage does not map through the
                // discharge table; hold, except to bootstrap a first
                // provisional value with a rough elevation correction.
                if self.level.is_none() {
                    self.level = Some(quantize(soc_from_ocv(
                        s.battery_mv.saturating_sub(CHARGE_ELEVATION_MV),
                    )));
                }
                self.disturb(s.now_ms);
                self.charged_since_anchor = true;
            }
            BatteryState::BatteryOnly
            | BatteryState::BatteryLow
            | BatteryState::BatteryCritical => {
                if s.load_since_last {
                    // Sagged sample: not OCV, restart the quiet window.
                    self.disturb(s.now_ms);
                    return;
                }
                if self.level.is_none() {
                    // Provisional bootstrap from the first quiet sample;
                    // anchors refine it once true rest is observed.
                    self.level = Some(quantize(soc_from_ocv(s.battery_mv)));
                }
                if self.window_len < LEVEL_WINDOW {
                    self.window[self.window_len] = s.battery_mv;
                    self.window_len += 1;
                } else {
                    self.window.rotate_left(1);
                    self.window[LEVEL_WINDOW - 1] = s.battery_mv;
                }
                let rested = s.now_ms.wrapping_sub(self.last_disturbance_ms) >= LEVEL_REST_MS;
                if rested && self.window_len == LEVEL_WINDOW {
                    let mut candidate = quantize(soc_from_ocv(median(&self.window)));
                    // Discharge never raises the level; a completed or
                    // partial charge since the last anchor releases the
                    // clamp exactly once.
                    if !self.charged_since_anchor
                        && let Some(current) = self.level
                    {
                        candidate = candidate.min(current);
                    }
                    self.level = Some(candidate);
                    self.charged_since_anchor = false;
                }
            }
        }
    }

    fn disturb(&mut self, now_ms: u32) {
        self.last_disturbance_ms = now_ms;
        self.window_len = 0;
    }
}

impl Default for LevelEstimator {
    fn default() -> Self {
        Self::new()
    }
}

fn quantize(pct: u8) -> u8 {
    ((pct + LEVEL_QUANT / 2) / LEVEL_QUANT * LEVEL_QUANT).min(100)
}

fn median(window: &[u16; LEVEL_WINDOW]) -> u16 {
    let mut sorted = *window;
    sorted.sort_unstable();
    sorted[LEVEL_WINDOW / 2]
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

    fn quiet(mv: u16, now_ms: u32) -> LevelSample {
        LevelSample {
            battery_mv: mv,
            state: BatteryState::BatteryOnly,
            load_since_last: false,
            now_ms,
        }
    }

    #[test]
    fn ocv_table_is_monotone_and_clamped() {
        assert_eq!(soc_from_ocv(3_000), 0);
        assert_eq!(soc_from_ocv(4_300), 100);
        let mut previous = 0;
        for mv in (3_300..=4_200).step_by(10) {
            let soc = soc_from_ocv(mv);
            assert!(soc >= previous, "SoC fell at {mv} mV");
            previous = soc;
        }
        // A midpoint interpolates rather than steps.
        assert_eq!(soc_from_ocv(3_775), 46);
    }

    #[test]
    fn bootstraps_from_the_first_quiet_sample() {
        let mut estimator = LevelEstimator::new();
        assert_eq!(estimator.level(), None);
        estimator.sample(quiet(3_850, 0));
        assert_eq!(estimator.level(), Some(60));
    }

    #[test]
    fn rest_anchor_uses_the_median_and_never_raises_while_discharging() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(quiet(3_850, 0));
        assert_eq!(estimator.level(), Some(60));
        // Five quiet samples past the rest window; one recovery spike is
        // absorbed by the median, and the anchor can only move down.
        for (index, mv) in [3_805, 3_990, 3_805, 3_800, 3_805].iter().enumerate() {
            estimator.sample(quiet(*mv, 190_000 + index as u32 * 30_000));
        }
        assert_eq!(estimator.level(), Some(55));
        // A later, higher-voltage anchor cannot raise the level.
        for index in 0..5 {
            estimator.sample(quiet(3_900, 400_000 + index * 30_000));
        }
        assert_eq!(estimator.level(), Some(55));
    }

    #[test]
    fn load_restarts_the_quiet_window() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(quiet(3_850, 0));
        for index in 0..3u32 {
            estimator.sample(quiet(3_700, 190_000 + index * 30_000));
        }
        // A transmission invalidates the window right before it fills.
        estimator.sample(LevelSample {
            battery_mv: 3_600,
            state: BatteryState::BatteryOnly,
            load_since_last: true,
            now_ms: 280_000,
        });
        estimator.sample(quiet(3_700, 310_000));
        // No anchor happened: the bootstrap value is still in force.
        assert_eq!(estimator.level(), Some(60));
    }

    #[test]
    fn charging_holds_and_charged_pins_full() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(quiet(3_700, 0));
        assert_eq!(estimator.level(), Some(30));
        estimator.sample(LevelSample {
            battery_mv: 4_050,
            state: BatteryState::BatteryCharging,
            load_since_last: false,
            now_ms: 30_000,
        });
        assert_eq!(estimator.level(), Some(30), "charging voltage must not map");
        estimator.sample(LevelSample {
            battery_mv: 4_200,
            state: BatteryState::BatteryCharged,
            load_since_last: false,
            now_ms: 60_000,
        });
        assert_eq!(estimator.level(), Some(100));
        // After unplugging, the first rested anchor may lower the level
        // (the charge released the discharge clamp exactly once).
        for index in 0..5u32 {
            estimator.sample(quiet(4_150, 250_000 + index * 30_000));
        }
        assert_eq!(estimator.level(), Some(95));
    }

    #[test]
    fn bootstrap_while_charging_corrects_for_elevation() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(LevelSample {
            battery_mv: 4_060,
            state: BatteryState::BatteryCharging,
            load_since_last: false,
            now_ms: 0,
        });
        // 4060 - 180 = 3880 mV -> 64% -> 65 quantized.
        assert_eq!(estimator.level(), Some(65));
    }
}
