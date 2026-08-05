//! Power sequencing for the T-Echo's Quectel L76K GNSS receiver.
//!
//! Three pins and one shared rail:
//!
//! | Signal | Pin | Notes |
//! |---|---|---|
//! | Standby / wake | P1.02 | High wakes the receiver; low lets it sleep |
//! | Reset | P1.05 | Active low, held past 100 ms |
//! | Module TX → MCU RX | P1.09 | 9600 baud — note the direction |
//! | Module RX ← MCU TX | P1.08 | Unused today; the receiver needs no commands |
//!
//! The UART direction is the reverse of what the upstream variant files'
//! pin names suggest, and was established by sampling each candidate pin
//! against the internal pull-down rather than by reading them. See
//! `docs/hardware/lilygo-techo-hardware.md`.
//!
//! The receiver has no enable pin of its own. It sits on the board's
//! peripheral rail (P0.12), shared with the e-paper, the LoRa module and
//! the sensors, so "off" here means the receiver's own standby state
//! rather than an unpowered module — the rail cannot be dropped for the
//! GNSS alone without taking the radio with it.
//!
//! That has one useful consequence and one limitation. The useful one:
//! while the rail is up the receiver's internal clock and ephemeris keep
//! running, so re-enabling it gets a warm start rather than a cold one.
//! The limitation: none of that survives the rail being cut at shutdown,
//! so the T-Echo's clock across a power cycle comes from its PCF8563 and
//! not from here.
//!
//! Standby polarity is confirmed: driving P1.02 low stops the sentence
//! stream within a second, so the property really does switch the
//! receiver off rather than merely stop reporting it. What remains
//! unmeasured is how much current that saves.

use embassy_nrf::Peri;
use embassy_nrf::gpio::{Level, Output, OutputDrive, Pin};
use embassy_time::{Duration, Timer};

/// The receiver's UART speed.
pub const BAUD: u32 = 9600;

/// How long the reset line is held low.
///
/// The datasheet asks for more than 100 ms; 150 gives it margin without
/// being noticeable, and this runs once per power-on.
const RESET_HOLD: Duration = Duration::from_millis(150);

/// How long the receiver takes to start emitting sentences after reset.
///
/// Not waited on for correctness — the parser resynchronizes at the next
/// `$` whatever arrives first — but powering on and immediately reading
/// otherwise spends a wake-up on a UART with nothing behind it yet.
const STARTUP: Duration = Duration::from_millis(100);

/// The T-Echo's GNSS power control.
///
/// Implements [`umsh_gnss::pump::Power`], which is the whole of its
/// public surface: the pump owns when the receiver runs, and this owns
/// how.
pub struct Gnss<'d> {
    standby: Output<'d>,
    reset: Output<'d>,
    /// Whether the receiver has been reset since the rail came up. The
    /// first wake gets a reset so the receiver starts from a known state
    /// whatever the bootloader left it in; later ones do not, because a
    /// reset discards the ephemeris that makes a re-enable a warm start.
    reset_done: bool,
}

impl<'d> Gnss<'d> {
    /// Take the standby and reset pins, leaving the receiver asleep.
    ///
    /// Both are driven, not tri-stated: a floating standby line is what
    /// left the receiver drawing current in an earlier bringup, and a
    /// driven level is also what survives nRF52840 System OFF.
    pub fn new(standby: Peri<'d, impl Pin>, reset: Peri<'d, impl Pin>) -> Self {
        Self {
            // Reset is released (high) at rest; asserting it is a
            // deliberate act, and holding a module in reset is not the
            // same as letting it sleep.
            reset: Output::new(reset, Level::High, OutputDrive::Standard),
            standby: Output::new(standby, Level::Low, OutputDrive::Standard),
            reset_done: false,
        }
    }
}

impl umsh_gnss::pump::Power for Gnss<'_> {
    async fn power_on(&mut self) {
        self.standby.set_high();
        if !self.reset_done {
            self.reset.set_low();
            Timer::after(RESET_HOLD).await;
            self.reset.set_high();
            self.reset_done = true;
        }
        Timer::after(STARTUP).await;
    }

    async fn power_off(&mut self) {
        // Standby only. The rail belongs to the whole board, and the
        // receiver's own low-power state is as far down as this board can
        // take it without also taking the radio and the display.
        self.standby.set_low();
    }
}
