//! Power sequencing for the T-Beam Supreme's GNSS receiver.
//!
//! Two controls, unlike any nRF board in the tree:
//!
//! | Control | What | Notes |
//! |---|---|---|
//! | ALDO4 | The receiver's supply rail | PMIC-switched; this module owns it |
//! | GPIO7 | L76K wake/control | Documented for the L76K population only (§7.4) |
//!
//! "Off" here is genuinely off — the rail drops, and with it the
//! receiver's backup domain, so a power cycle costs the almanac and a
//! warm start. That is the right trade on this board because **the
//! clock does not live here**: the PCF8563 holds the time, so unlike
//! the Wio Tracker L1 (whose L76K backup domain *is* the board's RTC)
//! nothing is lost that matters. The battery keeps the receiver's
//! backup domain alive across power-off regardless (§17.2); the rail
//! only falls while firmware runs with GNSS disabled.
//!
//! The wake line rides along on both edges: high before the rail so an
//! L76K comes up running, low after the rail drops so an unpowered
//! module is not back-fed through its control pin (§17 item 8). On a
//! u-blox population the pin's function is unverified and driving it is
//! believed harmless; revisit if a u-blox unit misbehaves.
//!
//! The receiver's UART speaks NMEA into GPIO9 at 9600 baud; sentence
//! handling is `umsh-gnss`'s, and this module is deliberately the whole
//! of the board-specific part.

use embassy_embedded_hal::shared_bus::asynch::i2c::I2cDevice;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use esp_hal::Async;
use esp_hal::gpio::Output;
use umsh_pmic_axp2101::Axp2101;

use crate::{GNSS_RAIL, RAIL_MILLIVOLTS};

pub use crate::GNSS_BAUD as BAUD;

/// The PMU bus as tasks see it: one device handle per client over the
/// shared I²C controller.
pub type PmuI2cDevice =
    I2cDevice<'static, CriticalSectionRawMutex, esp_hal::i2c::master::I2c<'static, Async>>;

/// The one AXP2101, shared by everything that needs a rail, a battery
/// reading, or a power-off.
pub type SharedPmic = Mutex<CriticalSectionRawMutex, Axp2101<PmuI2cDevice>>;

/// Rail settle before the wake line means anything.
const RAIL_SETTLE: Duration = Duration::from_millis(10);

/// How long the receiver takes to start emitting sentences after power
/// arrives. Not waited on for correctness — the parser resynchronizes
/// at the next `$` — but reading earlier spends the wake-up on a UART
/// with nothing behind it yet.
const STARTUP: Duration = Duration::from_millis(100);

/// The T-Beam Supreme's GNSS power control.
///
/// Implements [`umsh_gnss::pump::Power`], which is the whole of its
/// public surface: the pump owns when the receiver runs, and this owns
/// how.
pub struct Gnss {
    pmic: &'static SharedPmic,
    wake: Output<'static>,
}

impl Gnss {
    /// Take the wake pin (driven low — receiver rail is off at boot and
    /// the control line must not back-feed it) and the shared PMIC.
    ///
    /// [`crate::power::bring_up`] has already set ALDO4's voltage and
    /// left it off; from here the rail is this module's alone.
    pub fn new(pmic: &'static SharedPmic, wake: Output<'static>) -> Self {
        Self { pmic, wake }
    }
}

impl umsh_gnss::pump::Power for Gnss {
    async fn power_on(&mut self) {
        {
            let mut pmic = self.pmic.lock().await;
            // A refused rail write leaves the receiver dark; the pump
            // sees silence and the enable surface reports it. Nothing
            // useful to do from here.
            let _ = pmic.enable_rail_at(GNSS_RAIL, RAIL_MILLIVOLTS).await;
        }
        Timer::after(RAIL_SETTLE).await;
        self.wake.set_high();
        Timer::after(STARTUP).await;
    }

    async fn power_off(&mut self) {
        {
            let mut pmic = self.pmic.lock().await;
            let _ = pmic.set_rail_enabled(GNSS_RAIL, false).await;
        }
        // After the rail, so the last state the module sees is a driven
        // wake — and what remains is a low line into a dead supply.
        self.wake.set_low();
    }
}
