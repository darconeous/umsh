//! Piezo buzzer driver for the T1000-E.
//!
//! The T1000-E buzzer is a piezo driven by a small chip that needs both
//! a PWM tone signal (P0.25) and a power-enable gate (P1.05). When idle
//! we drop the enable pin so the driver chip draws no current.
//!
//! Firmwares fire [`BUZZER_SIGNAL`] with a `&'static Melody` from
//! [`umsh_ux_tracker::buzzer::melodies`] to play a tune; the runner
//! [`run`] steps the [`BuzzerEngine`] state machine and re-arms PWM
//! between notes.

use embassy_futures::select::{Either4, select4};
use embassy_nrf::gpio::Output;
use embassy_nrf::pwm::{DutyCycle, SimplePwm};
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use umsh_ux_tracker::buzzer::{BuzzerDecision, BuzzerEngine, Melody, melodies};

/// Time to hold the driver-chip enable HIGH (with PWM idle) before
/// starting PWM on a cold start. The piezo driver's internal oscillator
/// needs this long after power-up before it can drive the transducer;
/// without the wait, the first ~20 ms of any tone is inaudible.
const COLD_START_WARMUP: Duration = Duration::from_millis(20);

/// Firmware-visible signal: send a `&'static Melody` to request a tune.
/// Latest signal wins — firing during playback replaces the current
/// melody immediately. Silenced when `BUZZER_SILENCE_TOGGLE` has been
/// toggled to the silenced state.
pub static BUZZER_SIGNAL: Signal<ThreadModeRawMutex, &'static Melody> = Signal::new();

/// Firmware-visible signal: apply a persisted Silence-state transition.
/// Setting `true` plays `DO_SILENCE` immediately before silencing; setting
/// `false` unsilences first and then plays `UNSILENCE`.
pub static BUZZER_SILENCE_SET: Signal<ThreadModeRawMutex, bool> = Signal::new();

/// Runs the buzzer state machine. Wrap in `#[embassy_executor::task]`
/// in the firmware binary so the linker sees a concrete monomorphisation.
///
/// PWM clock is expected to be 1 MHz (caller picks `Prescaler::Div16`),
/// so for the 1–2 kHz melody range max_duty is 500–1000 — plenty of
/// resolution for the 50% duty square wave we emit.
pub async fn run(
    mut pwm: SimplePwm<'static>,
    mut enable: Output<'static>,
    initially_silenced: bool,
) {
    let mut engine = BuzzerEngine::new();
    engine.set_silenced(initially_silenced);

    // When set, silence the engine the next time it returns Silent. Lets
    // us play the `DO_SILENCE` feedback blip through the normal Tone path
    // before flipping the silenced flag (which would otherwise cancel the
    // in-flight melody before it sounds).
    let mut silence_pending = false;

    // Idle state: silent, unpowered.
    pwm.disable();
    enable.set_low();
    let mut driving = false;

    loop {
        let decision = engine.tick(Instant::now().as_millis());

        if matches!(decision, BuzzerDecision::Silent) && silence_pending {
            engine.set_silenced(true);
            silence_pending = false;
            continue;
        }

        match decision {
            BuzzerDecision::Tone {
                frequency_hz,
                next_deadline_ms,
            } => {
                pwm.set_period(frequency_hz as u32);
                let half = pwm.max_duty() / 2;
                if !driving {
                    // Cold start: power up the driver chip, start PWM at
                    // the upcoming tone's frequency, and run it for
                    // COLD_START_WARMUP. The chip needs ~20 ms of PWM
                    // activity before it emits audibly, so anything that
                    // played during this window would be lost. Once the
                    // wait completes we rewind the engine so its first
                    // note gets its full declared duration — keeps the
                    // chip-warmup quirk invisible to melody authors.
                    enable.set_high();
                    pwm.enable();
                    pwm.set_duty(0, DutyCycle::normal(half));
                    Timer::after(COLD_START_WARMUP).await;
                    driving = true;
                    engine.restart_active(Instant::now().as_millis());
                    continue;
                }
                pwm.set_duty(0, DutyCycle::normal(half));
                match select4(
                    BUZZER_SIGNAL.wait(),
                    BUZZER_SILENCE_SET.wait(),
                    crate::indicator::BUZZER_ALERT_SET.wait(),
                    Timer::at(Instant::from_millis(next_deadline_ms)),
                )
                .await
                {
                    Either4::First(melody) => {
                        engine.play(melody, Instant::now().as_millis());
                    }
                    Either4::Second(silenced) => {
                        apply_silence_state(&mut engine, &mut silence_pending, silenced)
                    }
                    Either4::Third(active) => apply_alert_state(&mut engine, active),
                    Either4::Fourth(()) => {}
                }
            }
            BuzzerDecision::Rest { next_deadline_ms } => {
                // A gap between notes, not the end of the melody. The
                // driver chip stays powered and the tone is stopped by
                // dropping the duty to zero: powering it down would cost
                // the next note a cold start, and a cold start rewinds
                // the melody — which would make any melody containing a
                // rest repeat until something else displaced it.
                if driving {
                    pwm.set_duty(0, DutyCycle::normal(0));
                }
                match select4(
                    BUZZER_SIGNAL.wait(),
                    BUZZER_SILENCE_SET.wait(),
                    crate::indicator::BUZZER_ALERT_SET.wait(),
                    Timer::at(Instant::from_millis(next_deadline_ms)),
                )
                .await
                {
                    Either4::First(melody) => {
                        engine.play(melody, Instant::now().as_millis());
                    }
                    Either4::Second(silenced) => {
                        apply_silence_state(&mut engine, &mut silence_pending, silenced)
                    }
                    Either4::Third(active) => apply_alert_state(&mut engine, active),
                    Either4::Fourth(()) => {}
                }
            }
            BuzzerDecision::Silent => {
                if driving {
                    pwm.disable();
                    enable.set_low();
                    driving = false;
                }
                // A repeating alert is silent *between* passes, so the
                // engine still has a deadline to wake for; without it the
                // alert would chirp once and sleep forever. An idle
                // engine reports none and this parks on the signals.
                let next = engine.next_deadline_ms(Instant::now().as_millis());
                let resume = async {
                    match next {
                        Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                        None => core::future::pending().await,
                    }
                };
                match select4(
                    BUZZER_SIGNAL.wait(),
                    BUZZER_SILENCE_SET.wait(),
                    crate::indicator::BUZZER_ALERT_SET.wait(),
                    resume,
                )
                .await
                {
                    Either4::First(melody) => {
                        engine.play(melody, Instant::now().as_millis());
                    }
                    Either4::Second(silenced) => {
                        apply_silence_state(&mut engine, &mut silence_pending, silenced)
                    }
                    Either4::Third(active) => apply_alert_state(&mut engine, active),
                    Either4::Fourth(()) => {}
                }
            }
        }
    }
}

/// How often the locate melody repeats. Long enough that the chirps read
/// as distinct events a searcher can walk toward, short enough not to
/// lose them between sweeps of a room.
const ALERT_PERIOD: Duration = Duration::from_millis(3_000);

/// Start or stop the locate alert (`PROP_ALERT`).
///
/// The alert plays through silence, and stopping it leaves the persisted
/// silence preference exactly as it was — the engine suspends that
/// preference rather than clearing it.
fn apply_alert_state(engine: &mut BuzzerEngine, active: bool) {
    if active {
        engine.play_alert(
            &melodies::LOCATE,
            Instant::now().as_millis(),
            ALERT_PERIOD.as_millis(),
        );
    } else {
        engine.stop_alert();
    }
}

/// Flip silence state, scheduling the audible feedback melody through the
/// engine. Both directions go through the normal Tone path; the silencing
/// case defers the `set_silenced(true)` call to the main loop via
/// `silence_pending` so the `DO_SILENCE` blip finishes before the engine
/// is muted.
fn apply_silence_state(engine: &mut BuzzerEngine, silence_pending: &mut bool, silenced: bool) {
    if !silenced {
        *silence_pending = false;
        engine.set_silenced(false);
        engine.play(&melodies::UNSILENCE, Instant::now().as_millis());
    } else if !engine.is_silenced() {
        engine.play(&melodies::DO_SILENCE, Instant::now().as_millis());
        *silence_pending = true;
    }
}
