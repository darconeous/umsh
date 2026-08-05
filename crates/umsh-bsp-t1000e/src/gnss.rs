//! Power sequencing for the T1000-E's Airoha AG3335 GNSS receiver.
//!
//! Six control pins and a UART:
//!
//! | Signal | Pin | Notes |
//! |---|---|---|
//! | Backup-domain enable | P0.08 | `GPS_VRTC_EN` — high from boot, and stays high |
//! | Main enable | P1.11 | `GPS_EN`, active high |
//! | Reset | P1.15 | `GPS_RESET`, **active high** — pulsed, then held low |
//! | Sleep interrupt | P1.12 | `GPS_SLEEP_INT` — held high |
//! | RTC interrupt | P0.15 | `GPS_RTC_INT` — driven low; high is a wake request |
//! | Reset / stop | P1.14 | `GPS_RESETB` — pulled up to run, driven low to stop |
//! | MCU RX ← module TX | P0.14 | 115200 baud — carries NMEA |
//! | MCU TX → module RX | P0.13 | 115200 baud |
//!
//! Polarities and sequence follow the upstream variant definitions rather
//! than inference. Three of them are counter-intuitive enough to have cost
//! a bringup session between them:
//!
//! * **Reset is active high.** The line rests *low* while the receiver
//!   runs, and a pulse high resets it. Resting it high — the safe-looking
//!   choice, and the correct one for the L76K boards in this tree — holds
//!   the receiver in reset forever, with both UART lines sitting at their
//!   external pull-ups looking exactly like an idle port.
//! * **`GPS_RTC_INT` is an input to the module**, not a status output, and
//!   has to be driven low. Left floating, the receiver does not run.
//! * **`GPS_RESETB` is likewise an input**, despite the `_OUT` suffix it
//!   carries in some variant files. It needs a pull-up to run; upstream
//!   drives it low as part of stopping the module.
//!
//! # The backup domain is this board's real-time clock
//!
//! Unlike every other board in the tree, the T1000-E has no dedicated RTC
//! chip. What it has is the AG3335's own backup domain, gated by
//! `GPS_VRTC_EN` and independent of the main enable — so the receiver can
//! be powered down to a state where it neither receives nor draws
//! meaningful current, while its clock keeps counting.
//!
//! That is why [`Gnss::power_off`] leaves P0.08 high, and why the shutdown
//! path leaves it high through nRF52840 System OFF (driven levels are
//! retained). Cutting it would save a negligible amount of current and
//! cost the device its only knowledge of the time across a power cycle.
//! Upstream's own two teardown sequences make the same distinction — one
//! keeps this rail, one drops it — and this is the first.
//!
//! Reading that clock back is [`umsh_gnss::pump::rtc_read_once`]: the
//! backup domain cannot speak a UART by itself, so the read briefly
//! raises the main enable, takes the first dated sentence, and lowers it
//! again. It is a clock operation, gated on whether the receiver's time is
//! trusted rather than on whether positioning is switched on.

use embassy_nrf::Peri;
use embassy_nrf::gpio::{Flex, Level, Output, OutputDrive, Pin, Pull};
use embassy_time::{Duration, Timer};

/// The receiver's UART speed.
pub const BAUD: u32 = 115_200;

/// Settling time between steps of the power-on sequence.
///
/// Upstream's value. The sequence runs once per enable, so there is
/// nothing to gain by trimming it.
const STEP: Duration = Duration::from_millis(10);

/// How long the reset line is held asserted.
const RESET_HOLD: Duration = Duration::from_millis(10);

/// How long the receiver takes to start emitting sentences.
///
/// Not waited on for correctness — the parser resynchronizes at the next
/// `$` whatever arrives first — but powering on and immediately reading
/// otherwise spends a wake-up on a UART with nothing behind it yet.
const STARTUP: Duration = Duration::from_millis(100);

/// The T1000-E's GNSS power control.
///
/// Implements [`umsh_gnss::pump::Power`], which is the whole of its public
/// surface: the pump owns when the receiver runs, and this owns how.
pub struct Gnss<'d> {
    /// Backup domain. Raised in [`Gnss::new`] and never lowered — see the
    /// module documentation.
    #[expect(dead_code, reason = "held high for its lifetime; never read back")]
    vrtc: Output<'d>,
    enable: Output<'d>,
    sleep: Output<'d>,
    /// Active high: asserted by a pulse high, released low.
    reset: Output<'d>,
    rtc_int: Output<'d>,
    /// Input with a pull-up while the receiver runs, driven low to stop
    /// it. `Flex` because it is genuinely both.
    resetb: Flex<'d>,
}

impl<'d> Gnss<'d> {
    /// Take the six control pins, powering the backup domain and leaving
    /// the receiver itself off.
    ///
    /// Every pin is driven rather than tri-stated: a floating enable is
    /// what left an earlier board drawing current overnight, and a driven
    /// level is also what survives nRF52840 System OFF.
    pub fn new(
        vrtc: Peri<'d, impl Pin>,
        enable: Peri<'d, impl Pin>,
        sleep: Peri<'d, impl Pin>,
        reset: Peri<'d, impl Pin>,
        rtc_int: Peri<'d, impl Pin>,
        resetb: Peri<'d, impl Pin>,
    ) -> Self {
        let mut resetb = Flex::new(resetb);
        // Stopped, matching the enable levels below.
        resetb.set_as_output(OutputDrive::Standard);
        resetb.set_low();

        Self {
            // The clock starts counting as soon as this rises, which is as
            // early as the firmware can manage. It never falls again.
            vrtc: Output::new(vrtc, Level::High, OutputDrive::Standard),
            enable: Output::new(enable, Level::Low, OutputDrive::Standard),
            sleep: Output::new(sleep, Level::High, OutputDrive::Standard),
            // Asserted, because active high and the receiver starts off.
            reset: Output::new(reset, Level::High, OutputDrive::Standard),
            rtc_int: Output::new(rtc_int, Level::Low, OutputDrive::Standard),
            resetb,
        }
    }
}

impl umsh_gnss::pump::Power for Gnss<'_> {
    async fn power_on(&mut self) {
        self.enable.set_high();
        // Upstream raises the backup domain as the next step; here it has
        // been up since boot, so only its settling time is owed.
        Timer::after(STEP + STEP).await;

        self.reset.set_high();
        Timer::after(RESET_HOLD).await;
        self.reset.set_low();

        self.sleep.set_high();
        self.rtc_int.set_low();
        // Released: the module's own pull-up arrangement takes it from
        // here, and driving it high instead would fight whatever else is
        // on the net.
        self.resetb.set_as_input(Pull::Up);

        Timer::after(STARTUP).await;
    }

    async fn power_off(&mut self) {
        self.enable.set_low();
        self.reset.set_high();
        self.sleep.set_high();
        self.rtc_int.set_low();
        self.resetb.set_as_output(OutputDrive::Standard);
        self.resetb.set_low();
        // The backup domain stays up. It is a clock, not a receiver.
    }
}
