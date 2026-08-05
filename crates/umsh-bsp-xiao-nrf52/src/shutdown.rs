//! Controlled power-off for the XIAO nRF52840 + Wio-SX1262 Kit.
//!
//! **This board has no GPIO wake source.** A stock kit's only button is
//! the XIAO's RESET, which is `nRESET` rather than a readable GPIO, and
//! the radio carrier's K1 footprint ships bare. So unlike every other
//! board in this family, the teardown here arms nothing: System OFF is
//! entered and the chip stays down until something physical happens.
//!
//! What can still bring it back:
//!
//! | Wake source            | Available | Notes |
//! |------------------------|-----------|-------|
//! | RESET button           | yes       | the reliable one; a cold boot either way |
//! | USB attach (VBUS)      | yes       | plugging in wakes the board |
//! | LPCOMP on AIN7         | not yet   | the one *autonomous* wake; see below |
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
//! ## Not implemented: LPCOMP battery-recovery wake
//!
//! MeshCore arms LPCOMP on AIN7 (`REFSEL` 2 = 3/8 VDD) before its
//! low-battery System OFF, so the node comes back on its own once the
//! cell recovers. That is the only autonomous wake this board can have,
//! and it is the one that matters for an unattended node — worth adding.
//! Two cautions for whoever does: the divider must stay live (which it
//! is, per above), and the threshold is a *relative* comparison against
//! VDD, so it moves with the rail — roughly 3.67 V of cell at VDD 3.3 V,
//! 3.33 V at VDD 3.0 V.

use umsh_bsp_nrf52840::system_off::{Port, drive_pin_low, enter_system_off, tristate_pin};

use crate::power::SHUTDOWN_SIGNAL;

/// Await [`SHUTDOWN_SIGNAL`], then power off. Never returns. Wrap in an
/// `#[embassy_executor::task]` in the firmware binary so the linker sees a
/// concrete monomorphisation.
pub async fn run() -> ! {
    SHUTDOWN_SIGNAL.wait().await;
    enter_off()
}

fn enter_off() -> ! {
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
    // chip comes back on RESET or on USB attach.
    enter_system_off()
}
