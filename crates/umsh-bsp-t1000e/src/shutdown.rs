//! Controlled power-off sequence for the T1000-E.
//!
//! Waits for [`SHUTDOWN_SIGNAL`](crate::SHUTDOWN_SIGNAL), plays the
//! power-off chirp through [`BUZZER_SIGNAL`](crate::BUZZER_SIGNAL),
//! holds the LR1110 in reset, tristates every peripheral signal pin
//! (so embassy's leftover SENSE bits don't fire DETECT and instant-wake
//! the chip), then enters nRF System OFF with the user button as the
//! wake source.

use embassy_time::{Duration, Timer};
use umsh_bsp_nrf52840::system_off::{
    Port, WakePin, WakeSense, drive_pin_low, power_off, tristate_pin,
};
use umsh_ux_tracker::buzzer::melodies as buzzer_melodies;

use crate::buzzer::BUZZER_SIGNAL;
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
    Timer::after(Duration::from_millis(320)).await;

    // Hold LR1110 in reset (active-low). Stops chip clocks and collapses
    // current draw to the reset-state minimum.
    drive_pin_low(Port::P1, 10);
    cortex_m::asm::delay(640); // ~10 µs @ 64 MHz

    // Tristate all peripheral signal pins. Embassy's async GPIO
    // `wait_for_*` leaves PIN_CNF SENSE bits set on in-flight waits;
    // any such pin matching its SENSE level at System OFF entry fires
    // DETECT and the chip wakes immediately (observable as a reboot).
    //
    // Button P0.06 is left alone — power_off configures it for wake.
    // P1.10 (LR1110 RESET) is left driving LOW intentionally.
    tristate_pin(Port::P0, 24); // LED
    tristate_pin(Port::P0, 25); // Buzzer PWM
    tristate_pin(Port::P1,  5); // Buzzer enable
    tristate_pin(Port::P1,  6); // Sensor rail enable
    tristate_pin(Port::P0,  2); // Battery ADC (AIN0)
    tristate_pin(Port::P0, 11); // SPI SCK
    tristate_pin(Port::P0, 12); // SPI CS
    tristate_pin(Port::P0,  7); // LR1110 BUSY
    tristate_pin(Port::P1,  1); // LR1110 DIO1/IRQ
    tristate_pin(Port::P1,  8); // SPI MISO
    tristate_pin(Port::P1,  9); // SPI MOSI

    // Button is active-high with pull-down → wake on rising edge.
    power_off(&[WakePin { port: Port::P0, pin: 6, sense: WakeSense::High }])
}
