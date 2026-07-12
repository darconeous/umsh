//! Transmit duty-cycle accounting for `PROP_PHY_DUTY_NOW`.
//!
//! Per the spec: fifteen 16-bit bins, one per 4-minute interval,
//! covering the past hour. Each bin counts 5 ms units of transmit
//! time. Usage is `sum(bins) * 65535 / 720000`, i.e. 0-65535 maps to
//! 0-100% of the hour.

/// Length of one accounting interval in milliseconds (4 minutes).
const INTERVAL_MS: u64 = 240_000;
/// Number of bins covering the past hour.
const BINS: usize = 15;
/// Milliseconds of airtime per bin increment.
const UNIT_MS: u32 = 5;
/// Usage denominator per spec (`sum * 65535 / 720000`): one hour
/// expressed in 5 ms units.
const HOUR_UNITS: u64 = 720_000;

#[derive(Debug)]
pub struct DutyTracker {
    bins: [u16; BINS],
    current: usize,
    /// Interval number (`now_ms / INTERVAL_MS`) that `current` maps to.
    interval: u64,
}

impl DutyTracker {
    pub const fn new() -> Self {
        Self {
            bins: [0; BINS],
            current: 0,
            interval: 0,
        }
    }

    /// Rotate bins forward to the interval containing `now_ms`.
    pub fn advance(&mut self, now_ms: u64) {
        let interval = now_ms / INTERVAL_MS;
        let elapsed = interval.saturating_sub(self.interval);
        if elapsed >= BINS as u64 {
            self.bins = [0; BINS];
        } else {
            for _ in 0..elapsed {
                self.current = (self.current + 1) % BINS;
                self.bins[self.current] = 0;
            }
        }
        self.interval = interval;
    }

    /// Record `airtime_ms` of transmission into the current bin,
    /// rounding up to whole 5 ms units.
    pub fn record(&mut self, now_ms: u64, airtime_ms: u32) {
        self.advance(now_ms);
        let units = airtime_ms.div_ceil(UNIT_MS);
        let bin = &mut self.bins[self.current];
        *bin = bin.saturating_add(units.min(u32::from(u16::MAX)) as u16);
    }

    /// Current usage on the `PROP_PHY_DUTY_NOW` scale (0-65535 for
    /// 0-100%).
    pub fn usage(&mut self, now_ms: u64) -> u16 {
        self.advance(now_ms);
        Self::scale(self.total())
    }

    /// Whether transmitting `airtime_ms` now would push usage past
    /// `limit`.
    pub fn would_exceed(&mut self, now_ms: u64, airtime_ms: u32, limit: u16) -> bool {
        self.advance(now_ms);
        let projected = self.total() + u64::from(airtime_ms.div_ceil(UNIT_MS));
        Self::scale(projected) > limit
    }

    /// Zero all accounting (used by protocol reset).
    pub fn reset(&mut self) {
        self.bins = [0; BINS];
    }

    fn total(&self) -> u64 {
        self.bins.iter().map(|&bin| u64::from(bin)).sum()
    }

    fn scale(units: u64) -> u16 {
        (units * 65_535 / HOUR_UNITS).min(65_535) as u16
    }
}

impl Default for DutyTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_scaling() {
        // 20 ms costs 4 units; 22 ms costs 5 (spec examples).
        let mut duty = DutyTracker::new();
        duty.record(0, 20);
        assert_eq!(duty.bins[duty.current], 4);
        duty.record(0, 22);
        assert_eq!(duty.bins[duty.current], 9);
    }

    #[test]
    fn one_percent_duty() {
        let mut duty = DutyTracker::new();
        // 1% of an hour = 36 s of airtime.
        for _ in 0..36 {
            duty.record(0, 1_000);
        }
        // Spec's table: 1% ≈ 655.
        assert_eq!(duty.usage(0), 655);
    }

    #[test]
    fn bins_age_out_after_an_hour() {
        let mut duty = DutyTracker::new();
        duty.record(0, 10_000);
        assert!(duty.usage(0) > 0);
        // 14 intervals later the bin is still in the window...
        assert!(duty.usage(14 * INTERVAL_MS) > 0);
        // ...15 intervals later it has rotated out.
        assert_eq!(duty.usage(15 * INTERVAL_MS), 0);
    }

    #[test]
    fn long_gap_clears_everything() {
        let mut duty = DutyTracker::new();
        duty.record(0, 60_000);
        assert_eq!(duty.usage(100 * INTERVAL_MS), 0);
    }

    #[test]
    fn limit_projection() {
        let mut duty = DutyTracker::new();
        // 655 ≈ 1%: 36 s of airtime per hour.
        let limit = 655;
        assert!(!duty.would_exceed(0, 1_000, limit));
        for _ in 0..36 {
            duty.record(0, 1_000);
        }
        assert!(duty.would_exceed(0, 1_000, limit));
        // NODUTY-style unlimited value never blocks.
        assert!(!duty.would_exceed(0, 1_000, u16::MAX));
    }
}
