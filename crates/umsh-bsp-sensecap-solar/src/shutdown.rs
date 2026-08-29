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
//! - settle the battery divider's active-low gate (P0.14) one way or the
//!   other — see below,
//! - keep GNSS powered down (enable P1.05 low, standby P0.02 low),
//! - tri-state every remaining peripheral signal pin so embassy's leftover
//!   SENSE bits can't fire DETECT and reverse current can't leak into the
//!   unpowered radio,
//! - arm **both** buttons — the power button (P1.01) and the secondary user
//!   button (P1.07), both pull-up — as GPIO-DETECT wake sources (SENSE low).
//!
//! Powering *off* is P1.01-only (the firmware policy), but *either* button
//! wakes the node: a press resets the chip — observed as a normal cold boot
//! (`RESETREAS.OFF`) — which powers it back on.
//!
//! ## Two ways down, and the divider decides
//!
//! The [`ShutdownReason`] on the signal splits the teardown, exactly as
//! MeshCore splits its own (see the hardware doc's shutdown section):
//!
//! - **[`ShutdownReason::Requested`]** — somebody turned the node off.
//!   Drive P0.14 HIGH to disconnect the 1 MΩ/512 kΩ bridge, since a driven
//!   output retains its level through System OFF and there is no reason to
//!   keep paying its quiescent draw. Off means off until a button press.
//! - **[`ShutdownReason::BatteryCritical`]** — the cell ran down. Drive
//!   P0.14 LOW instead, keeping the bridge connected, and arm LPCOMP on
//!   AIN7 (`P0.31`, the tap) against 3/8 VDD with upward detection. The
//!   divider's draw is the price of the wake; without it the comparator
//!   has nothing to look at.
//!
//! On this board that second path is the whole point. A solar node that
//! shuts down in a week of overcast is not a node someone walks out to
//! press a button on — it has to come back when the panel refills the
//! cell, and this is how it does.
//!
//! Where the threshold lands: the bridge gives cell = tap × 1512/512 =
//! tap × 2.953, and 3/8 of a regulated 3.3 V VDD puts the tap threshold at
//! 1.2375 V, so the crossing is at **≈3.65 V of cell** with 50 mV of
//! hysteresis at the tap (≈148 mV at the cell). That is at or above the
//! firmware's Low threshold and well clear of Critical (≈3.1 V), so a
//! freshly woken node is nowhere near re-triggering the cutoff — which
//! needs ten consecutive critical samples, about five minutes, anyway. The
//! reference is relative to VDD, but the cell feeds VDDH and REG0 holds
//! VDD at 3.3 V: while the regulator is in dropout the tap sits below the
//! fraction and the comparator cannot trip, so there is one effective wake
//! point rather than a moving one.
//!
//! Both buttons stay armed on either path, so the LPCOMP wake is strictly
//! an addition — a critical-cutoff node is revived by sunlight *or* by a
//! press, whichever comes first.

use embassy_time::{Duration, Timer};
use umsh_bsp_nrf52840::system_off::{
    LpcompInput, LpcompReference, Port, ShutdownReason, WakePin, WakePull, WakeSense,
    arm_lpcomp_wake_up, configure_wake_input, connect_input, drive_pin_high, drive_pin_low,
    enter_system_off, read_pin, tristate_pin,
};

use crate::power::SHUTDOWN_SIGNAL;

/// Await [`SHUTDOWN_SIGNAL`], then power off. Never returns. Wrap in an
/// `#[embassy_executor::task]` in the firmware binary so the linker sees a
/// concrete monomorphisation.
pub async fn run() -> ! {
    let reason = SHUTDOWN_SIGNAL.wait().await;
    enter_off(reason).await
}

async fn enter_off(reason: ShutdownReason) -> ! {
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

    // The battery divider's active-low gate P0.14, driven either way — a
    // driven output retains its level through System OFF. On a requested
    // power-off, HIGH disconnects the bridge and removes its quiescent
    // draw. On the low-battery cutoff, LOW keeps it connected so LPCOMP
    // has a tap to watch (the monitor left the gate HIGH before it
    // returned, and dropping its `Output` disconnected the pin, so this is
    // a real re-assertion, not a restatement).
    let battery_recovery = reason == ShutdownReason::BatteryCritical;
    if battery_recovery {
        drive_pin_low(Port::P0, 14);
    } else {
        drive_pin_high(Port::P0, 14);
    }
    // Keep GNSS powered down (enable P1.05 low), and pin its standby line
    // (P0.02) low with it. Standby sits on the module's side of the load
    // switch, so a pin left driving into an unpowered module is current
    // through its protection diodes — the same argument as the divider
    // gate above, and the reason both are driven rather than released.
    drive_pin_low(Port::P1, 5);
    drive_pin_low(Port::P0, 2);

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

    if battery_recovery {
        // Let the tap settle. The gate was HIGH — bridge disconnected —
        // until a moment ago, so P0.31 has been floating; give it time to
        // reach the divided cell voltage before the comparator starts.
        Timer::after(Duration::from_millis(10)).await;

        // Wake when the cell recovers past ~3.65 V. See the module docs.
        arm_lpcomp_wake_up(LpcompInput::AnalogInput7, LpcompReference::Ref38vdd);
    }

    enter_system_off()
}
