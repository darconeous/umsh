//! Transmit duty-cycle accounting for `PROP_PHY_DUTY_NOW`.
//!
//! Per the spec: fifteen 16-bit bins, one per 4-minute interval,
//! covering the past hour. Each bin counts 5 ms units of transmit
//! time. Usage is `sum(bins) * 65535 / 720000`, i.e. 0-65535 maps to
//! 0-100% of the hour.
//!
//! [`DutyTracker`] is the accounting engine; [`DutyLedger`] wraps one
//! tracker in a shared, interior-mutable form so every radio client on
//! a device — the companion session and the device node — draws from
//! the same combined budget (`PROP_PHY_DUTY_LIMIT` bounds their *total*
//! airtime, and `PROP_PHY_DUTY_NOW` reports the combined figure).

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use umsh_companion::airtime::lora_airtime_ms;
use umsh_companion::ids::DUTY_LIMIT_DISABLED;

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

/// A transmit was refused because it would push combined usage past
/// `PROP_PHY_DUTY_LIMIT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DutyExceeded;

struct LedgerState {
    tracker: DutyTracker,
    /// Live `PROP_PHY_DUTY_LIMIT`. The session owns its lifecycle
    /// (defaults, property sets, snapshot restore); it lives here so
    /// every radio client enforces the same bound.
    limit: u16,
    /// Modulation parameters of the last applied radio configuration,
    /// for computing the airtime of frames whose sender has no view of
    /// the session's settings (the device node).
    sf: u8,
    bw_hz: u32,
    cr_denom: u8,
}

/// The shared duty ledger: one [`DutyTracker`] plus the active limit
/// and modulation parameters, behind a blocking mutex so it can sit in
/// a `static` and be consulted from every radio client's TX path.
///
/// All time comes in as caller-supplied `now_ms` (the same monotonic
/// clock the session uses), keeping the ledger free of any platform
/// timer dependency.
pub struct DutyLedger {
    state: Mutex<CriticalSectionRawMutex, RefCell<LedgerState>>,
}

impl core::fmt::Debug for DutyLedger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DutyLedger")
            .field("limit", &self.limit())
            .finish_non_exhaustive()
    }
}

impl DutyLedger {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(LedgerState {
                tracker: DutyTracker::new(),
                limit: DUTY_LIMIT_DISABLED,
                // Placeholder modulation until the first radio apply;
                // nothing can transmit before one happens.
                sf: 7,
                bw_hz: 125_000,
                cr_denom: 5,
            })),
        }
    }

    /// Current combined usage on the `PROP_PHY_DUTY_NOW` scale.
    pub fn usage(&self, now_ms: u64) -> u16 {
        self.state
            .lock(|state| state.borrow_mut().tracker.usage(now_ms))
    }

    /// Whether transmitting `airtime_ms` now would push combined usage
    /// past the active limit.
    pub fn would_exceed(&self, now_ms: u64, airtime_ms: u32) -> bool {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            let limit = state.limit;
            state.tracker.would_exceed(now_ms, airtime_ms, limit)
        })
    }

    /// Record `airtime_ms` of completed transmission.
    pub fn record(&self, now_ms: u64, airtime_ms: u32) {
        self.state
            .lock(|state| state.borrow_mut().tracker.record(now_ms, airtime_ms));
    }

    /// Zero the accounting bins (protocol reset). The limit and
    /// modulation parameters are configuration and stay.
    pub fn reset_accounting(&self) {
        self.state.lock(|state| state.borrow_mut().tracker.reset());
    }

    /// The active `PROP_PHY_DUTY_LIMIT`.
    pub fn limit(&self) -> u16 {
        self.state.lock(|state| state.borrow().limit)
    }

    pub fn set_limit(&self, limit: u16) {
        self.state.lock(|state| state.borrow_mut().limit = limit);
    }

    /// Update the modulation parameters used for [`Self::airtime_ms`].
    /// The session calls this wherever it (re)applies radio settings.
    pub fn set_phy(&self, sf: u8, bw_hz: u32, cr_denom: u8) {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            state.sf = sf;
            state.bw_hz = bw_hz;
            state.cr_denom = cr_denom;
        });
    }

    /// Airtime of a `frame_len`-byte frame at the active modulation.
    pub fn airtime_ms(&self, frame_len: usize) -> u32 {
        self.state.lock(|state| {
            let state = state.borrow();
            lora_airtime_ms(state.sf, state.bw_hz, state.cr_denom, frame_len)
        })
    }

    /// Admission check for a client that knows only its frame length
    /// (the device node's radio path): compute the airtime at the
    /// active modulation and test it against the combined budget.
    /// Returns the airtime to [`Self::record`] once the transmit
    /// completes. Does not itself record — refused frames and failed
    /// transmits must not consume budget.
    pub fn admit(&self, now_ms: u64, frame_len: usize) -> Result<u32, DutyExceeded> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            let airtime_ms = lora_airtime_ms(state.sf, state.bw_hz, state.cr_denom, frame_len);
            let limit = state.limit;
            if state.tracker.would_exceed(now_ms, airtime_ms, limit) {
                Err(DutyExceeded)
            } else {
                Ok(airtime_ms)
            }
        })
    }
}

impl Default for DutyLedger {
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
    fn ledger_combines_clients_and_admits_by_frame_length() {
        let ledger = DutyLedger::new();
        ledger.set_phy(9, 250_000, 5);
        ledger.set_limit(655); // ≈1%: 36 s of airtime per hour.

        // Two "clients" record into the same ledger; the combined
        // figure gates both.
        for _ in 0..18 {
            ledger.record(0, 1_000); // session
            ledger.record(0, 1_000); // node
        }
        assert!(ledger.usage(0) >= 655);
        assert!(ledger.would_exceed(0, 1_000));
        let refused = ledger.admit(0, 32);
        assert_eq!(refused, Err(DutyExceeded));

        // Refusals consume nothing: after the window ages out, a frame
        // is admitted with the modulation-derived airtime.
        let airtime = ledger.admit(20 * INTERVAL_MS, 32).unwrap();
        assert_eq!(airtime, lora_airtime_ms(9, 250_000, 5, 32));
        // Admission alone records nothing either.
        assert_eq!(ledger.usage(20 * INTERVAL_MS), 0);

        // The disabled sentinel never blocks.
        ledger.set_limit(DUTY_LIMIT_DISABLED);
        for _ in 0..1000 {
            ledger.record(0, 60_000);
        }
        assert!(ledger.admit(0, 255).is_ok());

        // Reset zeroes accounting but keeps configuration.
        ledger.set_limit(655);
        ledger.record(21 * INTERVAL_MS, 60_000);
        ledger.reset_accounting();
        assert_eq!(ledger.usage(21 * INTERVAL_MS), 0);
        assert_eq!(ledger.limit(), 655);
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
