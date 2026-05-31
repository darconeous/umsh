//! Buzzer melody engine.
//!
//! Pure-logic sequencer that plays short melodies on the T1000-E's
//! piezo buzzer (P0.25, enable P1.05 — see `docs/t1000e-hardware.md`).
//! Symmetric in shape to the [`led`](crate::led) module, but with
//! tones instead of on/off pulses and with silence semantics.
//!
//! Per `docs/firmware-plan-t1000e.md`:
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

    /// Bright blip played when the buzzer is un-silenced.
    pub static UNSILENCE: Melody = Melody::new(&[Tone {
        frequency_hz: 2_000,
        duration: Duration::from_millis(60),
    }]);

    /// Short low blip played just before the buzzer goes silent.
    pub static DO_SILENCE: Melody = Melody::new(&[Tone {
        frequency_hz: 1_200 / 8,
        duration: Duration::from_millis(10),
    }]);
}

/// State to apply to the buzzer driver right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuzzerDecision {
    /// No tone; driver should disable the buzzer.
    Silent,
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
}

impl ActiveMelody {
    /// Resolve the current note. Returns `Some((tone, end_of_note_ms))`
    /// if the melody is still playing, `None` if it has completed.
    fn resolve(&self, now_ms: u64) -> Option<(Tone, u64)> {
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        let mut cumulative_ms: u64 = 0;
        for &tone in self.melody.notes {
            let dur_ms = tone.duration.as_millis() as u64;
            cumulative_ms = cumulative_ms.saturating_add(dur_ms);
            if elapsed < cumulative_ms {
                return Some((tone, self.started_at_ms + cumulative_ms));
            }
        }
        None
    }
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
    /// to finish.
    pub fn set_silenced(&mut self, silenced: bool) {
        self.silenced = silenced;
        if silenced {
            self.active = None;
        }
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

    /// Start a melody. No-op if silenced.
    pub fn play(&mut self, melody: &'static Melody, now_ms: u64) {
        if self.silenced {
            return;
        }
        self.active = Some(ActiveMelody {
            melody,
            started_at_ms: now_ms,
        });
    }

    /// Compute the buzzer state to apply at `now_ms`.
    pub fn tick(&mut self, now_ms: u64) -> BuzzerDecision {
        if self.silenced {
            return BuzzerDecision::Silent;
        }
        let Some(active) = &self.active else {
            return BuzzerDecision::Silent;
        };
        match active.resolve(now_ms) {
            Some((tone, end_ms)) => {
                if tone.frequency_hz == 0 {
                    BuzzerDecision::Silent
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
    fn rest_note_is_silent_within_melody() {
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
        // 50..100: rest → silent
        assert_eq!(e.tick(75), BuzzerDecision::Silent);
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
