//! `Vext` power-domain control (GPIO21, active high).
//!
//! GPIO21 gates two things at once (hardware doc §9.1): the external
//! `Vext` 3.3 V rail that powers the OLED, and the low-side MOSFET that
//! completes the battery measurement divider. That coupling is why this
//! is one owned handle rather than two independent pins: whoever needs
//! the OLED powered and whoever needs a valid battery reading must both
//! go through the same `Vext` value, so the type system rules out one
//! subsystem cutting power out from under the other.
//!
//! After [`Vext::disable`], the OLED has lost power and must go through
//! the full reset + init sequence again (see [`crate::display`]), and
//! GPIO13 no longer carries a valid battery voltage.

use embassy_time::Timer;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::peripherals::GPIO21;

/// How long to wait after switching the rail on before trusting either
/// the OLED supply or the battery divider. The rail itself settles fast;
/// the divider's 320 kΩ impedance and the OLED's power-on both justify a
/// few milliseconds of margin (hardware doc §9.4).
const SETTLE_MS: u64 = 10;

/// Owned handle to the shared `Vext` power domain.
pub struct Vext {
    pin: Output<'static>,
}

impl Vext {
    /// Claim GPIO21. The rail starts off.
    pub fn new(pin: GPIO21<'static>) -> Self {
        Self {
            pin: Output::new(pin, Level::Low, OutputConfig::default()),
        }
    }

    /// Switch the rail on and wait for it to settle. Idempotent: if the
    /// rail is already on, returns immediately without re-settling.
    pub async fn enable(&mut self) {
        if self.pin.output_level() == Level::High {
            return;
        }
        self.pin.set_high();
        Timer::after_millis(SETTLE_MS).await;
    }

    /// Switch the rail off. The OLED loses power and the battery divider
    /// disconnects.
    pub fn disable(&mut self) {
        self.pin.set_low();
    }

    pub fn is_on(&self) -> bool {
        self.pin.output_level() == Level::High
    }
}
