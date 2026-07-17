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

use embassy_futures::select::{Either, Either3, select, select3};
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
                match select3(
                    BUZZER_SIGNAL.wait(),
                    BUZZER_SILENCE_SET.wait(),
                    Timer::at(Instant::from_millis(next_deadline_ms)),
                )
                .await
                {
                    Either3::First(melody) => {
                        engine.play(melody, Instant::now().as_millis());
                    }
                    Either3::Second(silenced) => {
                        apply_silence_state(&mut engine, &mut silence_pending, silenced)
                    }
                    Either3::Third(()) => {}
                }
            }
            BuzzerDecision::Silent => {
                if driving {
                    pwm.disable();
                    enable.set_low();
                    driving = false;
                }
                match select(BUZZER_SIGNAL.wait(), BUZZER_SILENCE_SET.wait()).await {
                    Either::First(melody) => {
                        engine.play(melody, Instant::now().as_millis());
                    }
                    Either::Second(silenced) => {
                        apply_silence_state(&mut engine, &mut silence_pending, silenced)
                    }
                }
            }
        }
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
