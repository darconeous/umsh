//! How much of the recent past other transmitters occupied the channel.
//!
//! The MAC sees every frame its radio receives, whatever protocol it
//! carried and whoever it was for, and the radio prices each one
//! ([`umsh_hal::Radio::airtime_ms`]). Their sum over a short window is how
//! busy others have made the channel lately, which a node reports
//! (`PROP_PHY_RX_DUTY`).
//!
//! It counts decoded frames only. A frame lost to a collision is not
//! counted, so the figure reads low on a channel busy enough that
//! collisions are what fills it.

/// Length of one interval in milliseconds.
const INTERVAL_MS: u64 = 30_000;
/// Number of intervals kept: five minutes of them.
const BINS: usize = 10;

/// The window the occupancy is a share of, in milliseconds.
pub const RX_OCCUPANCY_WINDOW_MS: u64 = INTERVAL_MS * BINS as u64;

/// Airtime received in each of the last [`BINS`] intervals.
///
/// Each bin counts milliseconds, which a 30-second interval cannot
/// overflow.
#[derive(Clone, Debug)]
pub struct RxOccupancy {
    bins: [u16; BINS],
    /// The bin for `interval`.
    current: usize,
    /// The newest interval (`now_ms / INTERVAL_MS`) recorded into.
    interval: u64,
}

impl RxOccupancy {
    pub const fn new() -> Self {
        Self {
            bins: [0; BINS],
            current: 0,
            interval: 0,
        }
    }

    /// Record `airtime_ms` of reception at `now_ms`.
    pub fn record(&mut self, now_ms: u64, airtime_ms: u32) {
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
        // A backward step keeps the newest interval seen: rewinding it
        // would make the next fresh stamp rotate over, and zero, bins that
        // are still live.
        self.interval = self.interval.max(interval);
        let bin = &mut self.bins[self.current];
        *bin = bin.saturating_add(airtime_ms.min(u32::from(u16::MAX)) as u16);
    }

    /// The share of the window ending at `now_ms` that receptions
    /// occupied, as a fraction of 65535.
    pub fn share(&self, now_ms: u64) -> u16 {
        // Intervals that have passed since the last reception have aged
        // that many of the oldest bins out, without anything having
        // rotated them away.
        let aged = (now_ms / INTERVAL_MS).saturating_sub(self.interval);
        if aged >= BINS as u64 {
            return 0;
        }
        let live = BINS - aged as usize;
        // Newest first, from `current` backward.
        let total: u64 = (0..live)
            .map(|back| u64::from(self.bins[(self.current + BINS - back) % BINS]))
            .sum();
        (total * 65_535 / RX_OCCUPANCY_WINDOW_MS).min(65_535) as u16
    }
}

impl Default for RxOccupancy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupancy_is_a_share_of_five_minutes() {
        let mut rx = RxOccupancy::new();
        assert_eq!(rx.share(0), 0);
        // Thirty seconds of reception in five minutes is a tenth.
        for second in 0..30 {
            rx.record(second * 1000, 1000);
        }
        assert_eq!(rx.share(30_000), 6553);
    }

    #[test]
    fn occupancy_ages_out_without_another_reception() {
        let mut rx = RxOccupancy::new();
        rx.record(0, 20_000);
        rx.record(60_000, 10_000);
        assert_eq!(rx.share(60_000), 6553);
        // The first reception leaves the window five minutes after its
        // interval began; the second, two intervals later.
        assert_eq!(rx.share(4 * 60_000 + 59_999), 6553);
        assert_eq!(rx.share(5 * 60_000), 2184);
        assert_eq!(rx.share(6 * 60_000), 0);
    }

    #[test]
    fn a_long_silence_clears_everything_at_once() {
        let mut rx = RxOccupancy::new();
        rx.record(0, 20_000);
        rx.record(60 * 60_000, 3000);
        assert_eq!(rx.share(60 * 60_000), 655);
    }

    #[test]
    fn a_backward_clock_step_zeroes_nothing() {
        let mut rx = RxOccupancy::new();
        rx.record(90_000, 3000);
        rx.record(10_000, 3000);
        assert_eq!(rx.share(90_000), 1310);
    }
}
