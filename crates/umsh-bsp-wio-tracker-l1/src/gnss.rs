//! Power sequencing for the Wio Tracker L1's Quectel L76K GNSS receiver.
//!
//! One pin and no rail:
//!
//! | Signal | Pin | Notes |
//! |---|---|---|
//! | Standby / wake | P1.09 (D0) | High wakes the receiver; low lets it sleep |
//! | Module TX → MCU RX | P0.26 (D7) | 9600 baud — note the direction |
//! | Module RX ← MCU TX | P0.27 (D6) | Unused today; the receiver needs no commands |
//!
//! The board brings out no reset line and no enable for the module's
//! rail: the L76K sits on the battery rail, and standby is the whole of
//! the control surface. That has one consequence worth naming.
//!
//! A receiver that keeps its supply keeps its clock, so this is the
//! board's real-time clock — the only one it has. Standby leaves the
//! L76K's backup domain running, so the time survives an nRF52840 System
//! OFF that a firmware-held clock would not, and the boot path reads it
//! back out (the firmware's `gnss-holds-the-clock`). Confirmed on
//! hardware with the receiver's own switch off, which is what makes the
//! read a clock operation rather than a positioning one.
//!
//! The boundary is the battery, not the power state: the enclosure's
//! mechanical switch disconnects that same rail, and there is no coin
//! cell behind it, so the clock does not survive being switched off at
//! the slider. Nothing here can change that.
//!
//! The other side of the same coin is that "off" here is the module's
//! own standby current and nothing lower. Before this driver existed the
//! pin was left floating from boot, so the module chose its own state and
//! the board's idle floor was whatever that turned out to be; driving it
//! low at construction is what makes the floor a decision rather than an
//! accident.
//!
//! Standby polarity is inferred from the T-Echo, whose identical module
//! was measured: high wakes, low sleeps. See
//! `docs/hardware/seeed-wio-tracker-l1-pro-hardware.md`.

use embassy_nrf::Peri;
use embassy_nrf::gpio::{Level, Output, OutputDrive, Pin};
use embassy_time::{Duration, Timer};

/// The receiver's UART speed.
pub const BAUD: u32 = 9600;

/// How long the receiver takes to start emitting sentences after waking.
///
/// Not waited on for correctness — the parser resynchronizes at the next
/// `$` whatever arrives first — but waking and immediately reading
/// otherwise spends a wake-up on a UART with nothing behind it yet.
const STARTUP: Duration = Duration::from_millis(100);

/// The Wio Tracker L1's GNSS power control.
///
/// Implements [`umsh_gnss::pump::Power`], which is the whole of its
/// public surface: the pump owns when the receiver runs, and this owns
/// how.
pub struct Gnss<'d> {
    standby: Output<'d>,
}

impl<'d> Gnss<'d> {
    /// Take the standby pin, leaving the receiver asleep.
    ///
    /// Driven, not tri-stated: a floating standby line is what left this
    /// module drawing an unmeasured current overnight, and a driven level
    /// is also what survives nRF52840 System OFF.
    pub fn new(standby: Peri<'d, impl Pin>) -> Self {
        Self {
            standby: Output::new(standby, Level::Low, OutputDrive::Standard),
        }
    }
}

impl umsh_gnss::pump::Power for Gnss<'_> {
    async fn power_on(&mut self) {
        self.standby.set_high();
        Timer::after(STARTUP).await;
    }

    async fn power_off(&mut self) {
        // Standby only, and deliberately so: the module has no rail this
        // board can cut, and its backup domain is where the board's clock
        // lives. Cutting power — if it were possible — would trade the
        // time for the last few microamps.
        self.standby.set_low();
    }
}
