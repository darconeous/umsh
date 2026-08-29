//! Controlled power-off for the XIAO nRF52840 + Wio-SX1262 Kit.
//!
//! **This board has no GPIO wake source.** A stock kit's only button is
//! the XIAO's RESET, which is `nRESET` rather than a readable GPIO, and
//! the radio carrier's K1 footprint ships bare. So unlike every other
//! board in this family, the teardown here arms no *pin*: what brings the
//! board back is a cable, the reset button, or the cell itself refilling.
//!
//! What can bring it back:
//!
//! | Wake source            | Available | Notes |
//! |------------------------|-----------|-------|
//! | RESET button           | yes       | the reliable one; a cold boot either way |
//! | USB attach (VBUS)      | yes       | plugging in wakes the board |
//! | LPCOMP on AIN7         | yes       | the one *autonomous* wake; see below |
//! | NFC field `P0.09/0.10` | untested  | would forfeit those pads for I²C |
//! | GPIO DETECT on a button| **no**    | needs K1 retrofitted — see [`crate`] |
//!
//! In the shipping device image the only thing that gets here is the
//! protective low-battery cutoff — never a gesture, because there is no
//! gesture to make, and never a remote command, because that firmware has
//! no power-off command. That pairing is deliberate: a board that cannot
//! be woken by touching it should not be turnable off by anything except
//! the one condition where staying on is worse.
//!
//! If a remote power-off is ever added, the host UI for it must say
//! plainly that undoing it needs the reset button or a cable.
//!
//! ## What the teardown does
//!
//! - holds the SX1262 in reset (`P0.28` low) to collapse its draw. The
//!   carrier's 10 kΩ pull-up means the radio releases itself if the pin
//!   is merely left floating, so this has to be actively driven — and a
//!   driven output retains its level through System OFF, which is what
//!   makes it work at all without a switchable rail.
//! - **keeps `P0.14` driven LOW.** This is the one place this board's
//!   teardown deliberately diverges from its relatives: the Solar P1 and
//!   the Wio Tracker L1 raise their divider gates here to recover
//!   the quiescent draw, and doing the same thing on this board would put
//!   `P0.31` at its `VDD + 0.3` absolute maximum. Tri-stating it, the
//!   other intuitive move, is worse still — the tap floats to the full
//!   cell voltage. The ~2.8 µA the divider costs in System OFF is the
//!   documented price of the design; see [`crate::power`].
//! - keeps `P0.13` (`HICHG`) driven LOW, so a pack that shut down flat
//!   still charges at 100 mA when someone plugs the board in. USB attach
//!   is one of the two ways back from System OFF here, so the charge path
//!   has to survive the teardown.
//! - tri-states every remaining peripheral signal pin, so embassy's
//!   leftover SENSE bits cannot fire DETECT and reverse current cannot
//!   leak into the unpowered radio. The RGB LED is common-anode, so
//!   tri-stating its three cathodes extinguishes it.
//!
//! ## LPCOMP battery-recovery wake
//!
//! On the protective-cutoff path the teardown arms LPCOMP on AIN7 —
//! `P0.31`, the divider tap — against 3/8 VDD with upward detection, the
//! same configuration MeshCore uses. The chip then resets by itself, with
//! `RESETREAS.LPCOMP` set, when the cell has recharged. On a headless
//! board that is the difference between a node that recovers from a solar
//! lull and one that needs a visit.
//!
//! Where the threshold lands:
//!
//! - the divider gives cell = tap × 1510/510 = tap × 2.9608 (which is what
//!   [`crate::power`]'s `DIVIDER_MICRO` says too)
//! - 3/8 of a regulated 3.3 V VDD puts the tap threshold at 1.2375 V, so
//!   the crossing is at **≈3.66 V of cell**, with 50 mV of hysteresis at
//!   the tap ≈ 148 mV at the cell
//! - that is at or above the firmware's Low threshold and well clear of
//!   Critical (≈3.1 V), so a freshly woken board is nowhere near
//!   re-triggering the cutoff — which in any case needs ten consecutive
//!   critical samples, about five minutes
//! - the neighboring references are both wrong here: 5/16 lands at
//!   ≈3.05 V, *below* critical, which is a wake-and-die loop; 7/16 lands
//!   at ≈4.27 V, essentially "only when full"
//!
//! The reference is relative to VDD, which sounds like it should smear the
//! threshold across the rail — but the cell feeds VDDH and REG0 holds VDD
//! at 3.3 V. While the regulator is in dropout VDD tracks the cell and the
//! tap sits at 0.338 × VDD, below the 0.375 × VDD it would have to cross,
//! so the comparator cannot trip until the rail is back in regulation.
//! One effective wake point, not a moving one.
//!
//! A deliberate power-off does not arm it. There is no such path in the
//! shipping image, but if one is ever added, "off" should mean off until
//! someone comes back to the board.

use umsh_bsp_nrf52840::system_off::{
    LpcompInput, LpcompReference, Port, ShutdownReason, arm_lpcomp_wake_up, drive_pin_low,
    enter_system_off, tristate_pin,
};

use crate::power::SHUTDOWN_SIGNAL;

/// Await [`SHUTDOWN_SIGNAL`], then power off. Never returns. Wrap in an
/// `#[embassy_executor::task]` in the firmware binary so the linker sees a
/// concrete monomorphisation.
pub async fn run() -> ! {
    let reason = SHUTDOWN_SIGNAL.wait().await;
    enter_off(reason)
}

fn enter_off(reason: ShutdownReason) -> ! {
    // Hold the SX1262 in reset (active-low). Collapses radio current to
    // its reset-state minimum without a switchable rail. Must be driven,
    // not released: R1 on the carrier pulls this line up.
    drive_pin_low(Port::P0, 28);
    cortex_m::asm::delay(640); // ~10 µs @ 64 MHz

    // The battery divider's low side stays driven LOW, and the charge
    // current select stays driven LOW (100 mA). Both are re-asserted here
    // rather than assumed: the battery monitor owns them while running,
    // but the protective-cutoff path reaches this code after that task
    // has returned and dropped its `Output`s, which would leave the pins
    // disconnected — for P0.14 the single worst state it can be in.
    drive_pin_low(Port::P0, 14); // divider low side — see module docs
    drive_pin_low(Port::P0, 13); // HICHG: keep 100 mA charging available

    // Tri-state the remaining peripheral signal pins. Embassy's async GPIO
    // `wait_for_*` leaves PIN_CNF SENSE bits set on in-flight waits; any
    // pin matching its SENSE level at System OFF entry fires DETECT and
    // the chip wakes immediately. P0.28, P0.14 and P0.13 are left driving
    // intentionally.
    tristate_pin(Port::P1, 13); // radio SPI SCK
    tristate_pin(Port::P1, 14); // radio SPI MISO
    tristate_pin(Port::P1, 15); // radio SPI MOSI
    tristate_pin(Port::P0, 4); // radio CS
    tristate_pin(Port::P0, 29); // radio BUSY
    tristate_pin(Port::P0, 3); // radio DIO1
    tristate_pin(Port::P0, 5); // radio RXEN (RF_SW1 — no pull on the carrier)
    tristate_pin(Port::P0, 26); // RGB red   — common anode, so this is "off"
    tristate_pin(Port::P0, 6); // RGB blue  — ditto
    tristate_pin(Port::P0, 30); // RGB green — ditto
    tristate_pin(Port::P0, 31); // battery ADC (AIN7)
    tristate_pin(Port::P0, 17); // BQ25100 ~CHG: drop the input buffer

    // No wake pin is armed: there is nothing on this board to arm. The
    // chip comes back on RESET, on USB attach, or — below — on the cell
    // recovering.
    if reason == ShutdownReason::BatteryCritical {
        // Let the tap settle first. This path runs after the battery
        // monitor returned and dropped its `Output`s, so P0.14 floated
        // briefly and the tap drifted up toward the cell; give it time to
        // decay back through the 510 kΩ leg. Strictly this is belt and
        // braces — upward-only detection ignores a tap that starts high —
        // but the teardown has nothing else to do.
        cortex_m::asm::delay(640_000); // ~10 ms @ 64 MHz

        // Wake when the cell recovers past ~3.66 V. See the module docs.
        arm_lpcomp_wake_up(LpcompInput::AnalogInput7, LpcompReference::Ref38vdd);
    }

    enter_system_off()
}
