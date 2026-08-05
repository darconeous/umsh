//! Power sequencing for the Solar P1's Quectel L76K GNSS receiver.
//!
//! Two pins and a switchable rail:
//!
//! | Signal | Pin | Notes |
//! |---|---|---|
//! | Module power enable | P1.05 (D18) | `GPS_EN`; high powers the module |
//! | Standby / wake | P0.02 (D0) | High wakes the receiver; low lets it sleep |
//! | Module TX → MCU RX | P1.12 (D7) | 9600 baud — note the direction |
//! | Module RX ← MCU TX | P1.11 (D6) | Unused today; the receiver needs no commands |
//!
//! This is the only board in the family that can cut the receiver's power
//! outright, and on a solar node that is the point: GNSS is the largest
//! discretionary load here, and a panel-fed battery has no headroom to
//! spend on a module that is switched off but still warm. So "off" means
//! off — the enable drops, and with it the module's backup domain, its
//! ephemeris, and its clock. Nothing on this board keeps time across a
//! power cut; the next fix or a manual set is where the clock comes from.
//!
//! Standby is still driven on the way down. It sits on the module's side
//! of the load switch, and a pin driving into an unpowered module is
//! current through its protection diodes — the same reason the shutdown
//! path pins the enable rather than releasing it.
//!
//! The board also brings out a reset candidate on P1.03 (D17), which
//! Meshtastic names and neither firmware drives. It stays untouched: a
//! rail that can be cut is a stronger reset than a line whose connection
//! has never been confirmed.
//!
//! Both polarities are confirmed on hardware: `GPS_EN` is active-high,
//! and standby wakes on high like the T-Echo's identical module. The
//! delays below are generous rather than measured — nobody has probed
//! how much of either the L76K actually needs. See
//! `docs/hardware/sensecap-solar-node-p1-pro-hardware.md`.
//!
//! This is also the one board in the tree whose receiver defaults to
//! *on* (`GnssConfig::ALWAYS_ON`): a fixed outdoor node with a panel has
//! different arithmetic from a tracker in a pocket.

use embassy_nrf::Peri;
use embassy_nrf::gpio::{Level, Output, OutputDrive, Pin};
use embassy_time::{Duration, Timer};

/// The receiver's UART speed.
pub const BAUD: u32 = 9600;

/// How long the module's rail is given to settle before standby is
/// released. The L76K wants its supply valid before its control pins
/// mean anything, and this runs once per enable rather than per fix.
const RAIL_SETTLE: Duration = Duration::from_millis(50);

/// How long the receiver takes to start emitting sentences after power-up.
///
/// Not waited on for correctness — the parser resynchronizes at the next
/// `$` whatever arrives first — but powering on and immediately reading
/// otherwise spends a wake-up on a UART with nothing behind it yet.
const STARTUP: Duration = Duration::from_millis(150);

/// The Solar P1's GNSS power control.
///
/// Implements [`umsh_gnss::pump::Power`], which is the whole of its
/// public surface: the pump owns when the receiver runs, and this owns
/// how.
pub struct Gnss<'d> {
    enable: Output<'d>,
    standby: Output<'d>,
}

impl<'d> Gnss<'d> {
    /// Take the enable and standby pins, leaving the receiver unpowered.
    ///
    /// Both are driven, not tri-stated: a floating enable on a load
    /// switch is not an off switch, and driven levels are also what
    /// survive nRF52840 System OFF.
    pub fn new(enable: Peri<'d, impl Pin>, standby: Peri<'d, impl Pin>) -> Self {
        Self {
            enable: Output::new(enable, Level::Low, OutputDrive::Standard),
            standby: Output::new(standby, Level::Low, OutputDrive::Standard),
        }
    }
}

impl umsh_gnss::pump::Power for Gnss<'_> {
    async fn power_on(&mut self) {
        self.enable.set_high();
        Timer::after(RAIL_SETTLE).await;
        self.standby.set_high();
        Timer::after(STARTUP).await;
    }

    async fn power_off(&mut self) {
        // Standby first, then the rail. Asking the module to sleep before
        // taking its supply away is the ordering its datasheet wants, and
        // it costs a couple of instructions.
        self.standby.set_low();
        self.enable.set_low();
    }
}
