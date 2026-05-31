//! LED sequence engine.
//!
//! Owns the heartbeat (always-on; never suppressed) and arbitrates
//! one-shot sequences layered on top: power-on, power-off, location
//! advert. See `docs/firmware-plan-t1000e.md` for the UX rules.
//!
//! Pure logic over a monotonic-millisecond clock. The engine reports the
//! LED state to apply *right now* and the absolute time at which the
//! caller should re-invoke [`LedEngine::tick`] for the next transition.
//! No async, no I/O — fully unit-testable with synthetic time.
//!
//! # Heartbeat semantics
//!
//! The heartbeat is anchored at the engine's start time. After every
//! `heartbeat_interval`, the LED pulses for `heartbeat_pulse` (defaults:
//! 2 s and 50 ms). When a one-shot sequence is active it preempts the
//! heartbeat for the sequence's duration; once the sequence completes
//! the heartbeat resumes on its original rhythm (i.e. it is *not*
//! re-anchored), so the user-perceived 2-second cadence stays consistent
//! across overlays.

use core::time::Duration;

/// A one-shot LED flash sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedSequence {
    /// 1 s on at boot.
    PowerOn,
    /// Three short flashes just before System OFF.
    PowerOff,
    /// Quick double-blink on outgoing location advert.
    LocationAdvert,
}

impl LedSequence {
    fn pattern(self) -> &'static Pattern {
        match self {
            Self::PowerOn => &patterns::POWER_ON,
            Self::PowerOff => &patterns::POWER_OFF,
            Self::LocationAdvert => &patterns::LOCATION_ADVERT,
        }
    }
}

/// Tunable heartbeat timings. Defaults per `docs/firmware-plan-t1000e.md`.
#[derive(Debug, Clone, Copy)]
pub struct LedTimings {
    pub heartbeat_interval: Duration,
    pub heartbeat_pulse: Duration,
}

impl Default for LedTimings {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_millis(4_000),
            heartbeat_pulse: Duration::from_millis(20),
        }
    }
}

/// The result of a [`LedEngine::tick`]: the LED state to apply now and
/// the absolute monotonic-millisecond deadline at which to tick again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedDecision {
    pub on: bool,
    pub next_deadline_ms: u64,
}

/// A pre-computed LED pattern. `steps` is an alternating list of
/// durations starting with the ON phase: `[on_0, off_0, on_1, off_1, ...]`.
#[derive(Debug)]
pub struct Pattern {
    steps: &'static [Duration],
}

mod patterns {
    use super::Pattern;
    use core::time::Duration;

    pub static POWER_ON: Pattern = Pattern {
        steps: &[Duration::from_millis(1_000)],
    };

    /// Three flashes: ON 100, OFF 100, ON 100, OFF 100, ON 100.
    pub static POWER_OFF: Pattern = Pattern {
        steps: &[
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
        ],
    };

    /// Quick double-blink: ON 50, OFF 50, ON 50.
    pub static LOCATION_ADVERT: Pattern = Pattern {
        steps: &[
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_millis(50),
        ],
    };
}

#[derive(Debug)]
struct ActiveSequence {
    pattern: &'static Pattern,
    started_at_ms: u64,
}

impl ActiveSequence {
    /// Resolve the current step. Returns `Some((on, end_of_step_ms))` if
    /// the sequence is still running, `None` if it has completed.
    fn resolve(&self, now_ms: u64) -> Option<(bool, u64)> {
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        let mut cumulative_ms: u64 = 0;
        let mut state = true; // patterns start with ON
        for step in self.pattern.steps {
            cumulative_ms = cumulative_ms.saturating_add(step.as_millis() as u64);
            if elapsed < cumulative_ms {
                return Some((state, self.started_at_ms + cumulative_ms));
            }
            state = !state;
        }
        None
    }
}

/// LED sequence engine.
#[derive(Debug)]
pub struct LedEngine {
    timings: LedTimings,
    heartbeat_anchor_ms: u64,
    active: Option<ActiveSequence>,
}

impl LedEngine {
    /// Create a new engine anchored at `start_ms`. The first heartbeat
    /// pulse begins at `start_ms`.
    pub fn new(timings: LedTimings, start_ms: u64) -> Self {
        Self {
            timings,
            heartbeat_anchor_ms: start_ms,
            active: None,
        }
    }

    /// Start a one-shot sequence, preempting any currently active
    /// sequence and any in-progress heartbeat pulse.
    pub fn play(&mut self, seq: LedSequence, now_ms: u64) {
        self.active = Some(ActiveSequence {
            pattern: seq.pattern(),
            started_at_ms: now_ms,
        });
    }

    /// Compute the LED state to apply at `now_ms` and the next deadline.
    pub fn tick(&mut self, now_ms: u64) -> LedDecision {
        if let Some(seq) = &self.active {
            if let Some((on, end_ms)) = seq.resolve(now_ms) {
                return LedDecision {
                    on,
                    next_deadline_ms: end_ms,
                };
            }
            self.active = None;
        }
        self.heartbeat_decision(now_ms)
    }

    fn heartbeat_decision(&self, now_ms: u64) -> LedDecision {
        let interval = self.timings.heartbeat_interval.as_millis() as u64;
        let pulse = self.timings.heartbeat_pulse.as_millis() as u64;
        debug_assert!(pulse < interval, "heartbeat pulse must fit inside interval");

        let elapsed = now_ms.saturating_sub(self.heartbeat_anchor_ms);
        let cycle_start = now_ms - (elapsed % interval);
        let phase = elapsed % interval;

        if phase < pulse {
            LedDecision {
                on: true,
                next_deadline_ms: cycle_start + pulse,
            }
        } else {
            LedDecision {
                on: false,
                next_deadline_ms: cycle_start + interval,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(start: u64) -> LedEngine {
        LedEngine::new(LedTimings::default(), start)
    }

    #[test]
    fn heartbeat_starts_on_at_anchor() {
        let mut e = engine(0);
        let d = e.tick(0);
        assert_eq!(
            d,
            LedDecision {
                on: true,
                next_deadline_ms: 50
            }
        );
    }

    #[test]
    fn heartbeat_turns_off_after_pulse() {
        let mut e = engine(0);
        let d = e.tick(50);
        assert_eq!(
            d,
            LedDecision {
                on: false,
                next_deadline_ms: 2_000
            }
        );
    }

    #[test]
    fn heartbeat_pulses_at_regular_interval() {
        let mut e = engine(0);
        // First pulse.
        assert_eq!(e.tick(0).on, true);
        assert_eq!(e.tick(49).on, true);
        // Off gap.
        assert_eq!(e.tick(50).on, false);
        assert_eq!(e.tick(1_999).on, false);
        // Second pulse.
        let d = e.tick(2_000);
        assert_eq!(
            d,
            LedDecision {
                on: true,
                next_deadline_ms: 2_050
            }
        );
        // Off.
        let d = e.tick(2_050);
        assert_eq!(
            d,
            LedDecision {
                on: false,
                next_deadline_ms: 4_000
            }
        );
    }

    #[test]
    fn heartbeat_handles_skipped_ticks() {
        // tick() should still return correct phase if called late.
        let mut e = engine(0);
        // Skip to mid-pulse of cycle 5: 5*2000 + 20 = 10_020.
        let d = e.tick(10_020);
        assert_eq!(
            d,
            LedDecision {
                on: true,
                next_deadline_ms: 10_050
            }
        );

        // Skip to mid-gap of cycle 7: 7*2000 + 500 = 14_500.
        let d = e.tick(14_500);
        assert_eq!(
            d,
            LedDecision {
                on: false,
                next_deadline_ms: 16_000
            }
        );
    }

    #[test]
    fn power_on_sequence_holds_for_one_second() {
        let mut e = engine(0);
        e.play(LedSequence::PowerOn, 100);
        // During the sequence: ON until 100 + 1000 = 1100.
        assert_eq!(
            e.tick(100),
            LedDecision {
                on: true,
                next_deadline_ms: 1_100
            }
        );
        assert_eq!(
            e.tick(500),
            LedDecision {
                on: true,
                next_deadline_ms: 1_100
            }
        );
        assert_eq!(
            e.tick(1_099),
            LedDecision {
                on: true,
                next_deadline_ms: 1_100
            }
        );
    }

    #[test]
    fn power_on_sequence_releases_to_heartbeat() {
        let mut e = engine(0);
        e.play(LedSequence::PowerOn, 100);
        // After the sequence: heartbeat. At t=1100, we're in cycle 0's
        // off-gap (since first pulse was 0..50). Next ON is 2000.
        let d = e.tick(1_100);
        assert_eq!(
            d,
            LedDecision {
                on: false,
                next_deadline_ms: 2_000
            }
        );
    }

    #[test]
    fn power_off_sequence_flashes_three_times() {
        // ON 100, OFF 100, ON 100, OFF 100, ON 100.
        let mut e = engine(0);
        e.play(LedSequence::PowerOff, 0);
        assert_eq!(e.tick(0).on, true); // start of 1st ON
        assert_eq!(e.tick(99).on, true);
        assert_eq!(e.tick(100).on, false); // 1st OFF
        assert_eq!(e.tick(199).on, false);
        assert_eq!(e.tick(200).on, true); // 2nd ON
        assert_eq!(e.tick(299).on, true);
        assert_eq!(e.tick(300).on, false); // 2nd OFF
        assert_eq!(e.tick(399).on, false);
        assert_eq!(e.tick(400).on, true); // 3rd ON
        assert_eq!(e.tick(499).on, true);
        // After 500ms, sequence done → heartbeat. At t=500 we're past
        // the heartbeat ON pulse (0..50), in the off-gap → false.
        assert_eq!(e.tick(500).on, false);
    }

    #[test]
    fn sequence_preempts_in_progress_heartbeat_pulse() {
        // Engine anchored at 0; heartbeat would be ON at t=2000..2050.
        // Request location advert at t=2010 (during a heartbeat pulse).
        // The sequence takes over immediately (ON for 50ms).
        let mut e = engine(0);
        // Confirm heartbeat is currently ON.
        assert_eq!(e.tick(2_010).on, true);
        e.play(LedSequence::LocationAdvert, 2_010);
        let d = e.tick(2_010);
        assert_eq!(
            d,
            LedDecision {
                on: true,
                next_deadline_ms: 2_060
            }
        );
    }

    #[test]
    fn heartbeat_rhythm_preserved_across_sequence() {
        // Heartbeat ON expected at t=2000, 4000, 6000, ...
        let mut e = engine(0);
        e.play(LedSequence::PowerOn, 100); // 1s sequence
        // Sequence runs 100..1100; we evaluate after it ends.
        let _ = e.tick(100);
        let _ = e.tick(1_100); // clears the sequence
        // Engine should still align with heartbeat anchor=0, i.e. next
        // pulse is t=2000, not 1100 + 2000.
        let d = e.tick(2_000);
        assert_eq!(
            d,
            LedDecision {
                on: true,
                next_deadline_ms: 2_050
            }
        );
    }

    #[test]
    fn sequence_overrides_active_sequence() {
        // Start PowerOff (3 flashes), then mid-flash request PowerOn.
        let mut e = engine(0);
        e.play(LedSequence::PowerOff, 0);
        assert_eq!(e.tick(50).on, true); // still in 1st PowerOff ON
        e.play(LedSequence::PowerOn, 50);
        // PowerOn is 1s ON starting at 50; ends at 1050.
        let d = e.tick(50);
        assert_eq!(
            d,
            LedDecision {
                on: true,
                next_deadline_ms: 1_050
            }
        );
    }

    #[test]
    fn location_advert_double_blink() {
        // ON 50, OFF 50, ON 50.
        let mut e = engine(0);
        e.play(LedSequence::LocationAdvert, 0);
        assert_eq!(e.tick(0).on, true);
        assert_eq!(e.tick(49).on, true);
        assert_eq!(e.tick(50).on, false);
        assert_eq!(e.tick(99).on, false);
        assert_eq!(e.tick(100).on, true);
        assert_eq!(e.tick(149).on, true);
        // After 150ms → back to heartbeat (off-gap since past pulse window).
        assert_eq!(e.tick(150).on, false);
    }
}
