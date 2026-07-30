//! Piezo buzzer driver for the Wio Tracker L1 (D12 / P1.00).
//!
//! Simpler than the T1000-E's buzzer: this transducer is driven straight
//! from a PWM channel with no driver chip behind it, so there is no
//! power-enable gate to hold and no cold-start warmup to wait out — the
//! first note of a melody is audible immediately.
//!
//! Firmwares fire [`BUZZER_SIGNAL`] with a `&'static Melody` from
//! [`umsh_ux_tracker::buzzer::melodies`] to play a tune, and set
//! [`BUZZER_ALERT_SET`] to start or stop the repeating locate alert. The
//! runner [`run`] steps the [`BuzzerEngine`] state machine and re-arms
//! PWM between notes.
//!
//! There is no silence preference on this board (nothing persists one
//! yet), so the engine's silenced flag is never raised.

use embassy_futures::select::{Either3, select3};
use embassy_nrf::pwm::{DutyCycle, SimplePwm};
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use umsh_ux_tracker::buzzer::{BuzzerDecision, BuzzerEngine, Melody, melodies};

/// Firmware-visible signal: send a `&'static Melody` to request a tune.
/// Latest signal wins — firing during playback replaces the current
/// melody immediately.
pub static BUZZER_SIGNAL: Signal<ThreadModeRawMutex, &'static Melody> = Signal::new();

/// Firmware-visible signal: start (`true`) or stop (`false`) the
/// repeating locate alert (`PROP_ALERT`).
pub static BUZZER_ALERT_SET: Signal<ThreadModeRawMutex, bool> = Signal::new();

/// How often the locate melody repeats. Long enough that the chirps read
/// as distinct events a searcher can walk toward, short enough not to
/// lose them between sweeps of a room. Matches the T1000-E.
const ALERT_PERIOD: Duration = Duration::from_millis(3_000);

/// Runs the buzzer state machine. Wrap in `#[embassy_executor::task]`
/// in the firmware binary so the linker sees a concrete monomorphisation.
///
/// PWM clock is expected to be 1 MHz (caller picks `Prescaler::Div16`),
/// so for the 1–2 kHz melody range max_duty is 500–1000 — plenty of
/// resolution for the 50% duty square wave we emit.
pub async fn run(mut pwm: SimplePwm<'static>) {
    let mut engine = BuzzerEngine::new();

    // Idle state: silent.
    pwm.disable();
    let mut driving = false;

    loop {
        match engine.tick(Instant::now().as_millis()) {
            BuzzerDecision::Tone {
                frequency_hz,
                next_deadline_ms,
            } => {
                pwm.set_period(frequency_hz as u32);
                if !driving {
                    pwm.enable();
                    driving = true;
                }
                let half = pwm.max_duty() / 2;
                pwm.set_duty(0, DutyCycle::normal(half));
                match select3(
                    BUZZER_SIGNAL.wait(),
                    BUZZER_ALERT_SET.wait(),
                    Timer::at(Instant::from_millis(next_deadline_ms)),
                )
                .await
                {
                    Either3::First(melody) => engine.play(melody, Instant::now().as_millis()),
                    Either3::Second(active) => apply_alert_state(&mut engine, active),
                    Either3::Third(()) => {}
                }
            }
            BuzzerDecision::Silent => {
                if driving {
                    pwm.disable();
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
                match select3(BUZZER_SIGNAL.wait(), BUZZER_ALERT_SET.wait(), resume).await {
                    Either3::First(melody) => engine.play(melody, Instant::now().as_millis()),
                    Either3::Second(active) => apply_alert_state(&mut engine, active),
                    Either3::Third(()) => {}
                }
            }
        }
    }
}

/// Start or stop the locate alert (`PROP_ALERT`).
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
