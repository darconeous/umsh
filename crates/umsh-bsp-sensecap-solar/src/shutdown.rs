//! Controlled power-off for the SenseCAP Solar Node.
//!
//! Unlike the single-button boards (which overload one button into a full
//! gesture FSM), this board has a **dedicated power button** (P1.01,
//! active-low — MeshCore's `PIN_USER_BTN`). The power *policy* — hold-to-off
//! with a blink acknowledgement — lives in the firmware's power-button task;
//! this module only performs the System OFF teardown once
//! [`SHUTDOWN_SIGNAL`](crate::power::SHUTDOWN_SIGNAL) fires:
//!
//! - hold the SX1262 in reset (P0.28 low) to collapse its draw,
//! - disconnect the battery divider (active-low gate P0.14 driven HIGH) so
//!   the 1 MΩ/512 kΩ bridge stops drawing in System OFF,
//! - keep GNSS powered down (P1.05 low),
//! - tri-state every remaining peripheral signal pin so embassy's leftover
//!   SENSE bits can't fire DETECT and reverse current can't leak into the
//!   unpowered radio,
//! - arm **both** buttons — the power button (P1.01) and the secondary user
//!   button (P1.07), both pull-up — as GPIO-DETECT wake sources (SENSE low).
//!
//! Powering *off* is P1.01-only (the firmware policy), but *either* button
//! wakes the node: a press resets the chip — observed as a normal cold boot
//! (`RESETREAS.OFF`) — which powers it back on.

use embassy_time::{Duration, Timer};
use umsh_bsp_nrf52840::system_off::{
    Port, WakePin, WakePull, WakeSense, configure_wake_input, connect_input, drive_pin_high,
    drive_pin_low, enter_system_off, read_pin, tristate_pin,
};

use crate::power::SHUTDOWN_SIGNAL;

/// Await [`SHUTDOWN_SIGNAL`], then power off. Never returns. Wrap in an
/// `#[embassy_executor::task]` in the firmware binary so the linker sees a
/// concrete monomorphisation.
pub async fn run() -> ! {
    SHUTDOWN_SIGNAL.wait().await;
    enter_off().await
}

async fn enter_off() -> ! {
    // Both buttons (P1.01 power, P1.07 user) are active-low with a pull-up
    // and both are wake sources. If either is still held (LOW) when we arm
    // WakeSense::Low, DETECT fires immediately and the chip wakes right back
    // up — the power-off hold leaves P1.01 down. Connect both input buffers
    // (they may still be at their reset configuration, where IN reads 0
    // regardless of the pad), then wait for both to be released (HIGH).
    connect_input(Port::P1, 1, WakePull::Up);
    connect_input(Port::P1, 7, WakePull::Up);
    while !read_pin(Port::P1, 1) || !read_pin(Port::P1, 7) {
        Timer::after(Duration::from_millis(50)).await;
    }
    Timer::after(Duration::from_millis(50)).await;

    // Hold the SX1262 in reset (active-low). Collapses radio current to its
    // reset-state minimum without a switchable rail.
    drive_pin_low(Port::P0, 28);
    cortex_m::asm::delay(640); // ~10 µs @ 64 MHz

    // Disconnect the battery divider: active-low gate P0.14 → HIGH. A driven
    // output retains its level through System OFF, so the bridge stays
    // disconnected and its quiescent draw is removed.
    drive_pin_high(Port::P0, 14);
    // Keep GNSS powered down (enable P1.05 low).
    drive_pin_low(Port::P1, 5);

    // Tri-state the remaining peripheral signal pins. Embassy's async GPIO
    // `wait_for_*` leaves PIN_CNF SENSE bits set on in-flight waits; any pin
    // matching its SENSE level at System OFF entry fires DETECT and the chip
    // wakes immediately. P0.28 (radio reset) and P0.14 (divider gate) are
    // left driving intentionally; P1.01 and P1.07 are the wake sources.
    tristate_pin(Port::P1, 13); // radio SPI SCK
    tristate_pin(Port::P1, 14); // radio SPI MISO
    tristate_pin(Port::P1, 15); // radio SPI MOSI
    tristate_pin(Port::P0, 4); // radio CS
    tristate_pin(Port::P0, 29); // radio BUSY
    tristate_pin(Port::P0, 3); // radio DIO1
    tristate_pin(Port::P0, 5); // radio RXEN
    tristate_pin(Port::P0, 15); // LED_A (white)
    tristate_pin(Port::P0, 19); // LED_B (blue)
    tristate_pin(Port::P0, 31); // battery ADC (AIN7)

    // Either button wakes the node: active-low with pull-up → wake on the
    // falling edge (SENSE low). Power-off is P1.01-only, but wake is either.
    for pin in [1u8, 7u8] {
        configure_wake_input(
            WakePin {
                port: Port::P1,
                pin,
                sense: WakeSense::Low,
            },
            WakePull::Up,
        );
    }
    enter_system_off()
}
