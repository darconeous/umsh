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

/// The charge-state distinction reported to something outside the UX —
/// a protocol property, a companion app — as opposed to the five-way
/// presentation classification.
///
/// Low and Critical are presentation policy layered over one physical
/// condition: the cell is discharging. Consumers that report charge state
/// rather than warning about it collapse all three unpowered
/// classifications into [`ChargeClass::Discharging`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeClass {
    Discharging,
    Charging,
    Charged,
}

/// The [`ChargeClass`] behind a five-way [`BatteryState`].
///
/// One definition so every consumer of the same monitor — an on-demand
/// read and an asynchronous notification, in particular — reports the
/// same charge state for the same sample.
pub const fn charge_class(state: BatteryState) -> ChargeClass {
    match state {
        BatteryState::BatteryCharging => ChargeClass::Charging,
        BatteryState::BatteryCharged => ChargeClass::Charged,
        BatteryState::BatteryOnly | BatteryState::BatteryLow | BatteryState::BatteryCritical => {
            ChargeClass::Discharging
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

/// How long after a transient load a terminal-voltage reading is still
/// treated as possibly sagged rather than as resting OCV.
///
/// A property of the cell's recovery, not of the monitor's schedule.
/// Deciding sag by "was there a load since the previous sample" instead
/// couples it to the sampling cadence: at a multi-minute cadence an
/// ordinary duty cycle puts one transmission in nearly every interval,
/// every sample looks sagged, and the anchor window never fills — so the
/// level would silently stop tracking on exactly the busy nodes that
/// matter most.
pub const SAG_WINDOW_MS: u32 = 30_000;

/// One estimator input: the monitor's measurement plus its context.
#[derive(Clone, Copy, Debug)]
pub struct LevelSample {
    /// Measured terminal voltage, millivolts.
    pub battery_mv: u16,
    /// The classification for the same instant (see [`classify`]).
    pub state: BatteryState,
    /// A significant load (e.g. a radio transmission) ran within
    /// [`SAG_WINDOW_MS`] of this reading, so the voltage may be sagged
    /// rather than resting.
    pub load_recent: bool,
    /// Monotonic milliseconds; any epoch, wrapping arithmetic.
    pub now_ms: u32,
}

/// Whether a reading taken at `now_ms` falls inside the sag window of the
/// most recent reported load.
///
/// `last_load_ms` is `None` when no load has ever been reported. Shared
/// by every monitor so the sag rule is one definition rather than one per
/// board.
pub const fn load_recent(now_ms: u32, last_load_ms: Option<u32>) -> bool {
    match last_load_ms {
        Some(load_ms) => now_ms.wrapping_sub(load_ms) < SAG_WINDOW_MS,
        None => false,
    }
}

/// Approximate state-of-charge estimator for gauge-less boards:
/// a rest-gated OCV table with a median filter, a discharge-direction
/// clamp, and quantized output.
///
/// Feed it every monitor sample via [`Self::sample`]. It moves at two
/// speeds:
///
/// - **Every quiet sample** sets a ceiling. A terminal voltage that is
///   not sagging relaxes downward toward true OCV, so the table can only
///   overstate what is in the pack; the level is capped to that reading
///   immediately. This is what keeps a stale estimate — most visibly the
///   one bootstrapped from a charger's elevated rail — from surviving
///   long after the pack has been unplugged.
/// - **A rested window of [`LEVEL_WINDOW`] samples** anchors. Only after
///   [`LEVEL_REST_MS`] of quiet (no external power, no reported load)
///   does the median become the level outright, and only then is the
///   discharge clamp re-established.
///
/// Anchored levels never rise while discharging, so the output is stable
/// and monotone between charge sessions. A charge since the last anchor
/// invalidates the stored level in both directions, so until the next
/// anchor the ceiling replaces it rather than capping it — which is how
/// a partial charge shows up without waiting out a full window.
///
/// While charging there is no level at all: charging voltage is not
/// comparable to the discharge table, so the estimate is withdrawn rather
/// than frozen at its pre-charge value. It returns on the first quiet
/// reading after the charger goes away. The one exception is the
/// `Charged` classification, which is a charger's completion signal and
/// therefore an exact calibration point: it pins the level to 100. Boards
/// whose charger reports no completion never see that state and simply
/// report nothing for as long as they are plugged in.
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

    /// The current estimate, or `None` when no trustworthy one exists —
    /// before the first quiet sample, and for as long as the pack is
    /// charging.
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
                // discharge table, and on a charger that reports no
                // completion there is no later moment to correct against
                // either — so there is no level to report, and holding the
                // pre-charge one would state a number that only grows more
                // wrong the longer the pack is plugged in. Report nothing
                // until a quiet reading says otherwise.
                self.level = None;
                self.disturb(s.now_ms);
                self.charged_since_anchor = true;
            }
            BatteryState::BatteryOnly
            | BatteryState::BatteryLow
            | BatteryState::BatteryCritical => {
                if s.load_recent {
                    // Sagged sample: not OCV, restart the quiet window.
                    self.disturb(s.now_ms);
                    return;
                }
                if self.window_len < LEVEL_WINDOW {
                    self.window[self.window_len] = s.battery_mv;
                    self.window_len += 1;
                } else {
                    self.window.rotate_left(1);
                    self.window[LEVEL_WINDOW - 1] = s.battery_mv;
                }

                // A quiet reading bounds the charge from above straight
                // away. Terminal voltage relaxes *downward* toward true
                // OCV once a charge stops, so the table can only overstate
                // what is left in the pack — which makes it a ceiling
                // worth applying on the spot rather than holding a stale
                // number until an anchor lands twenty-odd minutes later.
                // The median runs over however much of the window has
                // filled, so the bound gains outlier rejection as it goes
                // without giving up the first-sample response.
                let bound = quantize(soc_from_ocv(median(&self.window[..self.window_len])));
                self.level = Some(match self.level {
                    // A charge since the last anchor invalidates the
                    // stored level in *both* directions, so the bound
                    // replaces it rather than capping it: the pack may
                    // genuinely hold more than it did before.
                    Some(_) if self.charged_since_anchor => bound,
                    Some(current) => current.min(bound),
                    None => bound,
                });

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

/// Median of a non-empty run of samples, at most [`LEVEL_WINDOW`] long.
///
/// An even-length run takes the upper of the two middle values, which
/// biases a partially filled window's bound very slightly high — the
/// forgiving direction for a ceiling.
fn median(samples: &[u16]) -> u16 {
    let mut sorted = [0u16; LEVEL_WINDOW];
    let len = samples.len().min(LEVEL_WINDOW);
    sorted[..len].copy_from_slice(&samples[..len]);
    sorted[..len].sort_unstable();
    sorted[len / 2]
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
            load_recent: false,
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
    fn a_sagged_sample_neither_lowers_the_level_nor_fills_the_window() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(quiet(3_850, 0));
        for index in 0..3u32 {
            estimator.sample(quiet(3_850, 190_000 + index * 30_000));
        }
        assert_eq!(estimator.level(), Some(60));
        // A transmission drags the terminal voltage down right before the
        // window fills. That reading is sag, not state of charge: it must
        // not touch the level, and it restarts the window so the anchor
        // waits for genuinely quiet samples.
        estimator.sample(LevelSample {
            battery_mv: 3_400,
            state: BatteryState::BatteryOnly,
            load_recent: true,
            now_ms: 280_000,
        });
        assert_eq!(estimator.level(), Some(60));
        estimator.sample(quiet(3_850, 310_000));
        assert_eq!(estimator.level(), Some(60));
    }

    /// The failure this fixes, from a T-Echo flashed over USB: the level
    /// bootstraps from the charger's elevated rail, reads full, and then
    /// sits there for twenty-odd minutes after unplugging while the pack
    /// is visibly at 3.6 V. The elevated rail now produces no level at
    /// all, and the first quiet reading produces a true one.
    #[test]
    fn a_quiet_reading_after_a_charge_replaces_a_stale_level_at_once() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(LevelSample {
            battery_mv: 4_360,
            state: BatteryState::BatteryCharging,
            load_recent: false,
            now_ms: 0,
        });
        assert_eq!(estimator.level(), None);
        // Unplugged. The pack is nowhere near full and the very next
        // quiet reading is enough to say so — no five-sample anchor, no
        // twenty-five minute wait.
        estimator.sample(quiet(3_600, 300_000));
        assert_eq!(estimator.level(), Some(10));
    }

    #[test]
    fn a_partial_charge_lets_the_level_rise_on_the_next_quiet_reading() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(quiet(3_600, 0));
        assert_eq!(estimator.level(), Some(10));
        estimator.sample(LevelSample {
            battery_mv: 4_000,
            state: BatteryState::BatteryCharging,
            load_recent: false,
            now_ms: 60_000,
        });
        assert_eq!(estimator.level(), None, "charging voltage must not map");
        // Unplugged with real charge in the pack. The ceiling now sits
        // above the stored level, and a charge since the last anchor is
        // precisely the case where it is allowed to raise it.
        estimator.sample(quiet(3_900, 360_000));
        assert_eq!(estimator.level(), Some(65));
    }

    /// Once an anchor has re-established the clamp, the ceiling can only
    /// ever lower the level — no amount of voltage recovery raises it
    /// without a charge in between.
    #[test]
    fn the_ceiling_never_raises_a_level_that_has_been_anchored() {
        let mut estimator = LevelEstimator::new();
        for index in 0..5u32 {
            estimator.sample(quiet(3_700, 190_000 + index * 30_000));
        }
        assert_eq!(estimator.level(), Some(30));
        for index in 0..5u32 {
            estimator.sample(quiet(4_100, 400_000 + index * 30_000));
        }
        assert_eq!(estimator.level(), Some(30));
    }

    #[test]
    fn sag_window_is_a_recovery_time_not_a_sample_gap() {
        // Never loaded.
        assert!(!load_recent(500_000, None));
        // Inside the window.
        assert!(load_recent(500_000, Some(500_000)));
        assert!(load_recent(500_000, Some(500_000 - SAG_WINDOW_MS + 1)));
        // At and past the boundary the cell is considered recovered —
        // this is what lets a multi-minute sampling cadence still find
        // quiet samples on a node that transmits regularly.
        assert!(!load_recent(500_000, Some(500_000 - SAG_WINDOW_MS)));
        assert!(!load_recent(500_000, Some(200_000)));
        // The millisecond counter wraps; a load just before the wrap is
        // still recent just after it.
        assert!(load_recent(10, Some(u32::MAX - 10)));
    }

    #[test]
    fn charging_withdraws_the_level_and_charged_pins_full() {
        let mut estimator = LevelEstimator::new();
        estimator.sample(quiet(3_700, 0));
        assert_eq!(estimator.level(), Some(30));
        estimator.sample(LevelSample {
            battery_mv: 4_050,
            state: BatteryState::BatteryCharging,
            load_recent: false,
            now_ms: 30_000,
        });
        assert_eq!(
            estimator.level(),
            None,
            "a pre-charge level must not survive the charge"
        );
        estimator.sample(LevelSample {
            battery_mv: 4_200,
            state: BatteryState::BatteryCharged,
            load_recent: false,
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

    /// A board whose charger reports no completion — the T-Echo, the Wio
    /// Tracker L1, the SenseCAP Solar Node — stays in `BatteryCharging`
    /// for the whole session and never reaches `BatteryCharged`. It must
    /// report no level for that entire time rather than inventing one
    /// from the charger's elevated rail.
    #[test]
    fn a_charger_without_completion_reports_no_level_until_unplugged() {
        let mut estimator = LevelEstimator::new();
        for index in 0..10u32 {
            estimator.sample(LevelSample {
                battery_mv: 4_060 + index as u16 * 20,
                state: BatteryState::BatteryCharging,
                load_recent: false,
                now_ms: index * 300_000,
            });
            assert_eq!(estimator.level(), None, "sample {index} invented a level");
        }
        // Unplugged, and now the terminal voltage means something again.
        estimator.sample(quiet(4_050, 3_300_000));
        assert_eq!(estimator.level(), Some(85));
    }
}
