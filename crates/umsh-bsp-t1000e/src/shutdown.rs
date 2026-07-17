//! Controlled power-off sequence for the T1000-E.
//!
//! Waits for [`SHUTDOWN_SIGNAL`](crate::SHUTDOWN_SIGNAL), plays the
//! power-off chirp through [`BUZZER_SIGNAL`](crate::BUZZER_SIGNAL),
//! holds the LR1110 in reset, tristates every peripheral signal pin
//! (so embassy's leftover SENSE bits don't fire DETECT and instant-wake
//! the chip), then enters nRF System OFF with the user button as the
//! wake source.

use embassy_futures::select::{Either3, select3};
use embassy_nrf::gpio::Input;
use embassy_nrf::pwm::{DutyCycle, SimplePwm};
use embassy_time::{Duration, Instant, Timer};
use umsh_bsp_nrf52840::system_off::{
    Port, WakePin, WakeSense, drive_pin_low, power_off, read_pin, tristate_pin,
};
use umsh_ux_tracker::buzzer::melodies as buzzer_melodies;

use crate::buzzer::BUZZER_SIGNAL;
use crate::indicator::LED_SEQUENCE_SIGNAL;
use crate::power::SHUTDOWN_SIGNAL;

/// Runs the shutdown orchestrator. Wrap in `#[embassy_executor::task]`
/// in the firmware binary so the linker sees a concrete monomorphisation.
///
/// Diverges via `power_off` — never returns.
pub async fn run() -> ! {
    SHUTDOWN_SIGNAL.wait().await;

    // Play the power-off chirp before tearing anything down. POWER_OFF
    // is 80+80+120 = 280 ms; wait 320 ms to let the final note finish
    // and the buzzer task return to its silent state.
    BUZZER_SIGNAL.signal(&buzzer_melodies::POWER_OFF);
    LED_SEQUENCE_SIGNAL.signal(umsh_ux_tracker::led::LedSequence::PowerOff);
    Timer::after(Duration::from_millis(520)).await;

    enter_system_off().await
}

/// Re-enter persisted Sleep State during boot without emitting any sound.
pub async fn resume_persisted_sleep() -> ! {
    enter_system_off().await
}

/// Logical Asleep mode while external power is present. Radios and normal
/// application work have not been started. The LED breathes only while the
/// charger reports active charging; a full battery leaves it off. Button wake
/// clears Sleep State and resets into the normal firmware boot path. Removing
/// external power returns to nRF System OFF.
pub async fn run_charging_sleep(
    mut led_pwm: SimplePwm<'static>,
    mut button: Input<'static>,
    mut external_power: Input<'static>,
    charge_active: Input<'static>,
) -> ! {
    const CYCLE_MS: u64 = 3_000;
    const STEP: Duration = Duration::from_millis(20);

    led_pwm.set_period(1_000);
    led_pwm.enable();

    loop {
        if button.is_high() {
            led_pwm.disable();
            crate::preferences::set_asleep(false);
            cortex_m::peripheral::SCB::sys_reset();
        }
        if external_power.is_low() {
            led_pwm.disable();
            enter_system_off().await;
        }

        let duty = if charge_active.is_low() {
            let phase = Instant::now().as_millis() % CYCLE_MS;
            let half = CYCLE_MS / 2;
            let ramp = if phase < half {
                phase
            } else {
                CYCLE_MS - phase
            };
            ((u64::from(led_pwm.max_duty()) * ramp) / half) as u16
        } else {
            0
        };
        led_pwm.set_duty(0, DutyCycle::normal(duty));

        match select3(
            Timer::after(STEP),
            button.wait_for_high(),
            external_power.wait_for_low(),
        )
        .await
        {
            Either3::First(()) | Either3::Second(()) | Either3::Third(()) => {}
        }
    }
}

async fn enter_system_off() -> ! {
    // If the shutdown was triggered by a long-press, the button (P0.06,
    // active-high) may still be held. Arming WakeSense::High on an already-HIGH
    // pin fires DETECT immediately → the chip wakes right back up. Poll until
    // the button is released before entering System OFF.
    while read_pin(Port::P0, 6) {
        Timer::after(Duration::from_millis(50)).await;
    }

    Timer::after(Duration::from_millis(50)).await;

    // Hold LR1110 in reset (active-low). Stops chip clocks and collapses
    // current draw to the reset-state minimum.
    drive_pin_low(Port::P1, 10);
    cortex_m::asm::delay(640); // ~10 µs @ 64 MHz

    // Tristate all peripheral signal pins. Embassy's async GPIO
    // `wait_for_*` leaves PIN_CNF SENSE bits set on in-flight waits;
    // any such pin matching its SENSE level at System OFF entry fires
    // DETECT and the chip wakes immediately (observable as a reboot).
    //
    // Button P0.06 and external-power detect P0.05 are left alone —
    // power_off configures them for wake.
    // P1.10 (LR1110 RESET) is left driving LOW intentionally.
    tristate_pin(Port::P0, 24); // LED
    tristate_pin(Port::P0, 25); // Buzzer PWM
    tristate_pin(Port::P1, 5); // Buzzer enable
    tristate_pin(Port::P1, 6); // Sensor rail enable
    tristate_pin(Port::P0, 2); // Battery ADC (AIN0)
    tristate_pin(Port::P0, 11); // SPI SCK
    tristate_pin(Port::P0, 12); // SPI CS
    tristate_pin(Port::P0, 7); // LR1110 BUSY
    tristate_pin(Port::P1, 1); // LR1110 DIO1/IRQ
    tristate_pin(Port::P1, 8); // SPI MISO
    tristate_pin(Port::P1, 9); // SPI MOSI

    // Button is active-high with pull-down → wake on rising edge.
    power_off(&[
        WakePin {
            port: Port::P0,
            pin: 6,
            sense: WakeSense::High,
        },
        WakePin {
            port: Port::P0,
            pin: 5,
            sense: WakeSense::High,
        },
    ])
}
