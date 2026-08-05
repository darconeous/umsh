//! Buzzer melody engine.
//!
//! Pure-logic sequencer that plays short melodies on the T1000-E's
//! piezo buzzer (P0.25, enable P1.05 — see `docs/hardware/t1000e-hardware.md`).
//! Symmetric in shape to the [`led`](crate::led) module, but with
//! tones instead of on/off pulses and with silence semantics.
//!
//! UX rules:
//!
//! - **Power-on:** rising melody.
//! - **Power-off:** falling melody.
//! - **Silence mode** (toggled by double-press) suppresses the buzzer
//!   entirely. The LED is **not** affected by silence — that mapping
//!   belongs to the LED engine, not here.
//! - **Silence mid-melody** cuts the current melody short, so the
//!   user's silence request is honored immediately rather than
//!   waiting for the in-flight sequence to finish.
//!
//! Pure logic over `u64` milliseconds; no PWM, no GPIO. The real
//! driver lives in `umsh-bsp-t1000e` and consumes
//! [`BuzzerDecision`]s emitted by `tick`.

use core::time::Duration;

/// One note in a melody. `frequency_hz == 0` is a deliberate rest
/// (silent gap between tones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tone {
    pub frequency_hz: u16,
    pub duration: Duration,
}

/// A short fixed sequence of tones / rests.
#[derive(Debug)]
pub struct Melody {
    pub notes: &'static [Tone],
}

impl Melody {
    pub const fn new(notes: &'static [Tone]) -> Self {
        Self { notes }
    }
}

/// Pre-baked melodies for the standard firmware events.
pub mod melodies {
    use super::{Melody, Tone};
    use core::time::Duration;

    /// Rising chirp: 1000 → 1500 → 2000 Hz.
    pub static POWER_ON: Melody = Melody::new(&[
        Tone {
            frequency_hz: 1_000,
            duration: Duration::from_millis(80),
        },
        Tone {
            frequency_hz: 1_500,
            duration: Duration::from_millis(80),
        },
        Tone {
            frequency_hz: 2_000,
            duration: Duration::from_millis(120),
        },
    ]);

    /// Falling chirp: 2000 → 1500 → 1000 Hz.
    pub static POWER_OFF: Melody = Melody::new(&[
        Tone {
            frequency_hz: 2_000,
            duration: Duration::from_millis(80),
        },
        Tone {
            frequency_hz: 1_500,
            duration: Duration::from_millis(80),
        },
        Tone {
            frequency_hz: 1_000,
            duration: Duration::from_millis(120),
        },
    ]);

    /// Short confirmation blip after a beacon is transmitted.
    pub static BEACON_ACK: Melody = Melody::new(&[
        Tone {
            frequency_hz: 1_800,
            duration: Duration::from_millis(60),
        },
        Tone {
            frequency_hz: 2_200,
            duration: Duration::from_millis(60),
        },
    ]);

    /// Locate alert: a two-tone warble, deliberately unlike any
    /// notification the device makes in normal operation, so it reads as
    /// "come find me" rather than "you have mail". Played on repeat by
    /// [`BuzzerEngine::play_alert`](super::BuzzerEngine::play_alert),
    /// which supplies the gap between passes.
    pub static LOCATE: Melody = Melody::new(&[
        Tone {
            frequency_hz: 2_600,
            duration: Duration::from_millis(150),
        },
        Tone {
            frequency_hz: 1_900,
            duration: Duration::from_millis(150),
        },
        Tone {
            frequency_hz: 2_600,
            duration: Duration::from_millis(150),
        },
        Tone {
            frequency_hz: 1_900,
            duration: Duration::from_millis(150),
        },
    ]);

    /// Receiver switched on: two pips at one pitch, then a higher held
    /// note — "searching, and now looking".
    ///
    /// Deliberately not another rising ramp. `POWER_ON` and `POWER_OFF`
    /// already own that shape, and a fourth ramp would be a tone the
    /// operator has to stop and decode. The repeated pip is what marks
    /// this pair as being about the receiver.
    pub static GNSS_ON: Melody = Melody::new(&[
        Tone {
            frequency_hz: 1_900,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 0,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 1_900,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 0,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 2_600,
            duration: Duration::from_millis(170),
        },
    ]);

    /// Receiver switched off: the held note first, falling away into two
    /// low pips — [`GNSS_ON`] in reverse.
    pub static GNSS_OFF: Melody = Melody::new(&[
        Tone {
            frequency_hz: 2_600,
            duration: Duration::from_millis(170),
        },
        Tone {
            frequency_hz: 0,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 1_500,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 0,
            duration: Duration::from_millis(45),
        },
        Tone {
            frequency_hz: 1_500,
            duration: Duration::from_millis(45),
        },
    ]);

    /// Bright blip played when the buzzer is un-silenced.
    pub static UNSILENCE: Melody = Melody::new(&[Tone {
        frequency_hz: 2_000,
        duration: Duration::from_millis(60),
    }]);

    /// Short low blip played just before the buzzer goes silent.
    pub static DO_SILENCE: Melody = Melody::new(&[Tone {
        frequency_hz: 1_200 / 8,
        // The amplified T1000-E piezo needs at least ~60 ms to become
        // audible. Keep this at the hardware floor so it reads as a subtle
        // thump rather than a notification tone.
        duration: Duration::from_millis(60),
    }]);
}

/// State to apply to the buzzer driver right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuzzerDecision {
    /// No tone; driver should disable the buzzer.
    Silent,
    /// A rest *inside* a melody that is still playing: no tone, but the
    /// sequence continues at `next_deadline_ms`.
    ///
    /// Distinct from [`Silent`](Self::Silent) because a driver that
    /// powers its sounder down between notes pays a warm-up to bring it
    /// back, and a warm-up that rewinds the melody turns every rest into
    /// a loop. A driver with nothing to warm up may treat the two alike.
    Rest { next_deadline_ms: u64 },
    /// Drive a tone at `frequency_hz`. Re-invoke [`BuzzerEngine::tick`]
    /// at `next_deadline_ms` to advance to the next note.
    Tone {
        frequency_hz: u16,
        next_deadline_ms: u64,
    },
}

#[derive(Debug)]
struct ActiveMelody {
    melody: &'static Melody,
    started_at_ms: u64,
    /// Replay the melody on this period instead of ending after one
    /// pass. The gap between repeats is `period_ms` minus the melody's
    /// own length, so a period shorter than the melody plays it back to
    /// back.
    repeat_every_ms: Option<u64>,
    /// Play even while the buzzer is silenced. Reserved for the locate
    /// alert: silencing is for not being a nuisance, and a radio nobody
    /// can find is a different problem (spec §PROP_ALERT).
    overrides_silence: bool,
}

impl ActiveMelody {
    /// Resolve the current note. Returns `Some((tone, end_of_note_ms))`
    /// if the melody is still playing, `None` if it has completed.
    fn resolve(&self, now_ms: u64) -> Option<(Tone, u64)> {
        self.step(now_ms).map(|step| match step {
            Step::Note(tone, end_ms) => (tone, end_ms),
            Step::Gap(end_ms) => (
                Tone {
                    frequency_hz: 0,
                    duration: Duration::from_millis(0),
                },
                end_ms,
            ),
        })
    }

    /// Resolve the current position, distinguishing a rest written into
    /// the melody from the gap a repeating melody waits out between
    /// passes.
    ///
    /// The difference is invisible on the wire and decisive at the
    /// driver: a gap is dead time a board should power its sounder down
    /// for, while a rest is part of a phrase that is still playing.
    fn step(&self, now_ms: u64) -> Option<Step> {
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        // A repeating melody folds the clock into one period; the
        // remainder of the period past the last note is the rest before
        // the next pass.
        let (elapsed, cycle_start_ms) = match self.repeat_every_ms {
            Some(period) if period > 0 => {
                let cycle = elapsed / period;
                (
                    elapsed % period,
                    self.started_at_ms
                        .saturating_add(cycle.saturating_mul(period)),
                )
            }
            _ => (elapsed, self.started_at_ms),
        };
        let mut cumulative_ms: u64 = 0;
        for &tone in self.melody.notes {
            let dur_ms = tone.duration.as_millis() as u64;
            cumulative_ms = cumulative_ms.saturating_add(dur_ms);
            if elapsed < cumulative_ms {
                return Some(Step::Note(tone, cycle_start_ms + cumulative_ms));
            }
        }
        // Past the last note. A one-shot melody is done; a repeating one
        // rests until the next period boundary.
        let period = self.repeat_every_ms?;
        Some(Step::Gap(cycle_start_ms.saturating_add(period)))
    }
}

/// Where a playing melody currently stands.
enum Step {
    /// A note written into the melody — a tone, or a rest when its
    /// frequency is zero — ending at the given deadline.
    Note(Tone, u64),
    /// The dead time a repeating melody waits out before its next pass.
    Gap(u64),
}

/// Buzzer melody engine.
#[derive(Debug)]
pub struct BuzzerEngine {
    silenced: bool,
    active: Option<ActiveMelody>,
}

impl Default for BuzzerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BuzzerEngine {
    pub const fn new() -> Self {
        Self {
            silenced: false,
            active: None,
        }
    }

    /// Returns true if the buzzer is currently silenced.
    pub fn is_silenced(&self) -> bool {
        self.silenced
    }

    /// Toggle silence. Engaging silence stops any in-flight melody so
    /// the user's request is honored without waiting for the sequence
    /// to finish — except a locate alert, which outranks it.
    pub fn set_silenced(&mut self, silenced: bool) {
        self.silenced = silenced;
        if silenced && !self.alert_active() {
            self.active = None;
        }
    }

    /// Whether a silence-overriding locate alert is playing.
    pub fn alert_active(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| active.overrides_silence)
    }

    /// Toggle silence on/off and return the new state. Convenience for
    /// the double-press handler.
    pub fn toggle_silenced(&mut self) -> bool {
        self.set_silenced(!self.silenced);
        self.silenced
    }

    /// Rewind the active melody so its first note plays from `now_ms`.
    /// No-op if no melody is active.
    ///
    /// Buzzer drivers that need an inaudible warmup period (e.g. the
    /// T1000-E's piezo driver chip needs ~20 ms of PWM activity before
    /// it starts emitting) should run that warmup with the engine
    /// already loaded, then call this to drop the warmup interval out
    /// of the engine's perceived clock so the first note gets its full
    /// declared duration.
    pub fn restart_active(&mut self, now_ms: u64) {
        if let Some(active) = self.active.as_mut() {
            active.started_at_ms = now_ms;
        }
    }

    /// Start a melody. No-op if silenced, and no-op while a locate alert
    /// is running — an ordinary notification must not displace the alarm
    /// someone is currently homing in on.
    pub fn play(&mut self, melody: &'static Melody, now_ms: u64) {
        if self.silenced || self.alert_active() {
            return;
        }
        self.active = Some(ActiveMelody {
            melody,
            started_at_ms: now_ms,
            repeat_every_ms: None,
            overrides_silence: false,
        });
    }

    /// Start the locate alert: `melody` on repeat every `period_ms`,
    /// playing through silence, until [`Self::stop_alert`].
    ///
    /// Intermittent by construction rather than a continuous tone — a
    /// lost radio is usually a nearly-flat radio, and a periodic chirp is
    /// easier to home in on than a constant one.
    pub fn play_alert(&mut self, melody: &'static Melody, now_ms: u64, period_ms: u64) {
        self.active = Some(ActiveMelody {
            melody,
            started_at_ms: now_ms,
            repeat_every_ms: Some(period_ms),
            overrides_silence: true,
        });
    }

    /// Stop a locate alert. Leaves an ordinary melody alone, so this is
    /// safe to call unconditionally when the alert clears.
    pub fn stop_alert(&mut self) {
        if self.alert_active() {
            self.active = None;
        }
    }

    /// When the engine next changes state, if it will.
    ///
    /// [`BuzzerDecision::Silent`] carries no deadline, but a repeating
    /// alert is silent *between* passes and must be woken for the next
    /// one — a driver that only re-ticks on `Tone` deadlines would play
    /// the alert once and stop. Drivers arm a timer on this whenever the
    /// decision is `Silent`.
    pub fn next_deadline_ms(&self, now_ms: u64) -> Option<u64> {
        if self.silenced && !self.alert_active() {
            return None;
        }
        self.active
            .as_ref()
            .and_then(|active| active.resolve(now_ms))
            .map(|(_, end_ms)| end_ms)
    }

    /// Compute the buzzer state to apply at `now_ms`.
    pub fn tick(&mut self, now_ms: u64) -> BuzzerDecision {
        if self.silenced && !self.alert_active() {
            return BuzzerDecision::Silent;
        }
        let Some(active) = &self.active else {
            return BuzzerDecision::Silent;
        };
        match active.step(now_ms) {
            // The gap between passes of a repeating melody is dead time,
            // not a phrase in progress: a board is free to power its
            // sounder down for it, and `next_deadline_ms` brings it back.
            Some(Step::Gap(_)) => BuzzerDecision::Silent,
            Some(Step::Note(tone, end_ms)) => {
                if tone.frequency_hz == 0 {
                    BuzzerDecision::Rest {
                        next_deadline_ms: end_ms,
                    }
                } else {
                    BuzzerDecision::Tone {
                        frequency_hz: tone.frequency_hz,
                        next_deadline_ms: end_ms,
                    }
                }
            }
            None => {
                self.active = None;
                BuzzerDecision::Silent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_engine_is_silent() {
        let mut e = BuzzerEngine::new();
        assert_eq!(e.tick(0), BuzzerDecision::Silent);
    }

    #[test]
    fn power_on_melody_steps_through_notes() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::POWER_ON, 0);

        // Note 1: 1000 Hz, 80ms
        assert_eq!(
            e.tick(0),
            BuzzerDecision::Tone {
                frequency_hz: 1_000,
                next_deadline_ms: 80
            }
        );
        assert_eq!(
            e.tick(79),
            BuzzerDecision::Tone {
                frequency_hz: 1_000,
                next_deadline_ms: 80
            }
        );

        // Note 2: 1500 Hz, 80ms
        assert_eq!(
            e.tick(80),
            BuzzerDecision::Tone {
                frequency_hz: 1_500,
                next_deadline_ms: 160
            }
        );

        // Note 3: 2000 Hz, 120ms
        assert_eq!(
            e.tick(160),
            BuzzerDecision::Tone {
                frequency_hz: 2_000,
                next_deadline_ms: 280
            }
        );

        // Melody done.
        assert_eq!(e.tick(280), BuzzerDecision::Silent);
    }

    #[test]
    fn power_on_is_rising() {
        for w in melodies::POWER_ON.notes.windows(2) {
            assert!(
                w[0].frequency_hz < w[1].frequency_hz,
                "expected rising melody, got {} then {}",
                w[0].frequency_hz,
                w[1].frequency_hz
            );
        }
    }

    #[test]
    fn power_off_is_falling() {
        for w in melodies::POWER_OFF.notes.windows(2) {
            assert!(
                w[0].frequency_hz > w[1].frequency_hz,
                "expected falling melody, got {} then {}",
                w[0].frequency_hz,
                w[1].frequency_hz
            );
        }
    }

    /// A gap between notes has to be distinguishable from the end of
    /// the melody. A driver that powers its sounder down for the one
    /// pays a warm-up to bring it back, and the T1000-E's warm-up
    /// rewinds the engine — so reporting a rest as `Silent` made every
    /// melody containing one restart at each gap and play forever.
    #[test]
    fn a_rest_is_not_the_end_of_the_melody() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::GNSS_ON, 0);

        // Pip, gap, pip — the gap reports as a rest that still carries
        // the sequence forward.
        assert_eq!(
            e.tick(0),
            BuzzerDecision::Tone {
                frequency_hz: 1_900,
                next_deadline_ms: 45
            }
        );
        assert_eq!(
            e.tick(45),
            BuzzerDecision::Rest {
                next_deadline_ms: 90
            }
        );
        assert_eq!(
            e.tick(90),
            BuzzerDecision::Tone {
                frequency_hz: 1_900,
                next_deadline_ms: 135
            }
        );

        // And the melody does end, once: the held note runs to 350, and
        // nothing follows it.
        assert_eq!(
            e.tick(300),
            BuzzerDecision::Tone {
                frequency_hz: 2_600,
                next_deadline_ms: 350
            }
        );
        assert_eq!(e.tick(350), BuzzerDecision::Silent);
    }

    /// The two directions of the receiver switch must not be a
    /// transposition of each other: told apart by ear is the whole job.
    #[test]
    fn the_receiver_switch_sounds_different_each_way() {
        /// The first and last note a listener actually hears, rests
        /// skipped.
        fn voiced(melody: &Melody) -> (u16, u16) {
            let mut heard = melody
                .notes
                .iter()
                .map(|tone| tone.frequency_hz)
                .filter(|frequency| *frequency != 0);
            let first = heard.next().expect("a melody with no notes");
            (first, heard.last().unwrap_or(first))
        }

        assert!(
            melodies::GNSS_ON
                .notes
                .iter()
                .map(|tone| tone.frequency_hz)
                .ne(melodies::GNSS_OFF
                    .notes
                    .iter()
                    .map(|tone| tone.frequency_hz))
        );

        let (on_first, on_last) = voiced(&melodies::GNSS_ON);
        assert!(on_last > on_first, "switching on should resolve upward");
        let (off_first, off_last) = voiced(&melodies::GNSS_OFF);
        assert!(
            off_last < off_first,
            "switching off should resolve downward"
        );
    }

    #[test]
    fn restart_active_rewinds_start_time() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::POWER_ON, 0);
        // Pretend a board-side warmup ran for 80ms; now rewind.
        e.restart_active(80);
        // First note should still play in full from t=80 (deadline 160).
        assert_eq!(
            e.tick(80),
            BuzzerDecision::Tone {
                frequency_hz: 1_000,
                next_deadline_ms: 160
            }
        );
    }

    #[test]
    fn silence_suppresses_play() {
        let mut e = BuzzerEngine::new();
        e.set_silenced(true);
        e.play(&melodies::POWER_ON, 0);
        assert_eq!(e.tick(0), BuzzerDecision::Silent);
    }

    #[test]
    fn engaging_silence_stops_in_flight_melody() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::POWER_ON, 0);
        // Confirm a tone is playing.
        match e.tick(10) {
            BuzzerDecision::Tone { .. } => {}
            d => panic!("expected Tone, got {:?}", d),
        }
        // Silence mid-melody.
        e.set_silenced(true);
        assert_eq!(e.tick(10), BuzzerDecision::Silent);
    }

    #[test]
    fn unsilencing_does_not_resume_killed_melody() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::POWER_ON, 0);
        e.set_silenced(true);
        e.set_silenced(false);
        // Active melody was discarded when silence engaged.
        assert_eq!(e.tick(0), BuzzerDecision::Silent);
    }

    #[test]
    fn toggle_silenced_returns_new_state() {
        let mut e = BuzzerEngine::new();
        assert_eq!(e.toggle_silenced(), true);
        assert_eq!(e.is_silenced(), true);
        assert_eq!(e.toggle_silenced(), false);
        assert_eq!(e.is_silenced(), false);
    }

    /// Total playing time of one pass of a melody.
    fn melody_len_ms(melody: &Melody) -> u64 {
        melody
            .notes
            .iter()
            .map(|tone| tone.duration.as_millis() as u64)
            .sum()
    }

    #[test]
    fn alert_sounds_through_silence() {
        let mut e = BuzzerEngine::new();
        e.set_silenced(true);
        // An ordinary melody stays suppressed.
        e.play(&melodies::POWER_ON, 0);
        assert_eq!(e.tick(0), BuzzerDecision::Silent);

        e.play_alert(&melodies::LOCATE, 0, 3_000);
        assert!(e.alert_active());
        assert!(matches!(e.tick(0), BuzzerDecision::Tone { .. }));
    }

    #[test]
    fn silencing_does_not_stop_a_running_alert() {
        let mut e = BuzzerEngine::new();
        e.play_alert(&melodies::LOCATE, 0, 3_000);
        e.set_silenced(true);
        assert!(e.alert_active());
        assert!(matches!(e.tick(10), BuzzerDecision::Tone { .. }));
    }

    #[test]
    fn stopping_an_alert_restores_the_previous_silence() {
        let mut e = BuzzerEngine::new();
        e.set_silenced(true);
        e.play_alert(&melodies::LOCATE, 0, 3_000);
        e.stop_alert();
        assert!(!e.alert_active());
        // The silence preference was suspended, not cleared.
        assert!(e.is_silenced());
        assert_eq!(e.tick(0), BuzzerDecision::Silent);
    }

    #[test]
    fn alert_repeats_on_its_period_with_a_rest_between() {
        let mut e = BuzzerEngine::new();
        let period = 3_000;
        let length = melody_len_ms(&melodies::LOCATE);
        e.play_alert(&melodies::LOCATE, 0, period);

        // Sounding during the melody, resting after it.
        assert!(matches!(e.tick(0), BuzzerDecision::Tone { .. }));
        assert_eq!(
            e.tick(length + 1),
            BuzzerDecision::Silent,
            "the gap between passes is silent"
        );
        // And sounding again at the top of the next period, indefinitely.
        assert!(matches!(e.tick(period), BuzzerDecision::Tone { .. }));
        assert!(matches!(e.tick(period * 20), BuzzerDecision::Tone { .. }));
        assert!(e.alert_active());
    }

    #[test]
    fn the_gap_between_alert_passes_still_reports_a_deadline() {
        // Regression: BuzzerDecision::Silent carries no deadline, so a
        // driver that only re-ticks on Tone deadlines would sleep through
        // the rest and play the alert exactly once.
        let mut e = BuzzerEngine::new();
        let period = 3_000;
        let length = melody_len_ms(&melodies::LOCATE);
        e.play_alert(&melodies::LOCATE, 0, period);

        let resting = length + 1;
        assert_eq!(e.tick(resting), BuzzerDecision::Silent);
        assert_eq!(
            e.next_deadline_ms(resting),
            Some(period),
            "wakes for the next pass"
        );
    }

    #[test]
    fn an_idle_engine_has_no_deadline() {
        let mut e = BuzzerEngine::new();
        assert_eq!(e.next_deadline_ms(0), None);
        e.play(&melodies::POWER_ON, 0);
        assert!(e.next_deadline_ms(0).is_some());
        // A silenced ordinary melody is not going to make a sound, so
        // there is nothing to wake for.
        e.set_silenced(true);
        assert_eq!(e.next_deadline_ms(0), None);
    }

    #[test]
    fn an_alert_is_not_displaced_by_an_ordinary_melody() {
        let mut e = BuzzerEngine::new();
        e.play_alert(&melodies::LOCATE, 0, 3_000);
        e.play(&melodies::BEACON_ACK, 10);
        assert!(e.alert_active(), "the alarm outranks a notification");
    }

    #[test]
    fn stop_alert_leaves_an_ordinary_melody_alone() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::POWER_ON, 0);
        e.stop_alert();
        assert!(matches!(e.tick(0), BuzzerDecision::Tone { .. }));
    }

    #[test]
    fn second_play_replaces_first() {
        let mut e = BuzzerEngine::new();
        e.play(&melodies::POWER_ON, 0);
        e.play(&melodies::POWER_OFF, 50);
        // First note of POWER_OFF is 2000 Hz, ends at 50 + 80 = 130.
        assert_eq!(
            e.tick(50),
            BuzzerDecision::Tone {
                frequency_hz: 2_000,
                next_deadline_ms: 130
            }
        );
    }

    #[test]
    fn rest_note_makes_no_tone_within_melody() {
        // Custom melody with a rest in the middle.
        static REST_MELODY: Melody = Melody::new(&[
            Tone {
                frequency_hz: 1_000,
                duration: Duration::from_millis(50),
            },
            Tone {
                frequency_hz: 0,
                duration: Duration::from_millis(50),
            }, // rest
            Tone {
                frequency_hz: 2_000,
                duration: Duration::from_millis(50),
            },
        ]);

        let mut e = BuzzerEngine::new();
        e.play(&REST_MELODY, 0);
        // 0..50: tone 1000
        match e.tick(25) {
            BuzzerDecision::Tone {
                frequency_hz: 1_000,
                ..
            } => {}
            d => panic!("expected 1000 Hz tone, got {:?}", d),
        }
        // 50..100: a rest, carrying the sequence to the next note. Not
        // `Silent`, which is how a driver knows the melody has ended.
        assert_eq!(
            e.tick(75),
            BuzzerDecision::Rest {
                next_deadline_ms: 100
            }
        );
        // 100..150: tone 2000
        match e.tick(125) {
            BuzzerDecision::Tone {
                frequency_hz: 2_000,
                ..
            } => {}
            d => panic!("expected 2000 Hz tone, got {:?}", d),
        }
    }
}
