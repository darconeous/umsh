//! `Vext` power-domain control (GPIO36, **ACTIVE LOW**).
//!
//! GPIO36 gates the switched external 3.3 V rail that powers the OLED
//! and the `Ve` header pins (hardware doc §10.1). The polarity is the
//! opposite of the Heltec V2 — driving the pin LOW turns the rail ON —
//! and the board's pull-up defaults the rail off until firmware drives
//! the pin (§10.4). That inversion is the single most likely V2-habit
//! bug in this port, so it is encoded here and no caller ever sees the
//! raw level.
//!
//! Unlike the V2, the battery divider is NOT on this domain (its gate is
//! GPIO37 — see [`crate::battery`]); `Vext` only affects the OLED and
//! external sensors. After [`Vext::disable`], the OLED has lost power
//! and must go through the full reset + init sequence again (see
//! [`crate::display`]).

use embassy_time::Timer;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::peripherals::GPIO36;

/// How long to wait after switching the rail on before trusting the
/// OLED supply. The LDO (CE6260B33M on V3.2, §10.3) settles fast; a few
/// milliseconds of margin covers the OLED's own power-on as well.
const SETTLE_MS: u64 = 10;

/// Owned handle to the shared `Vext` power domain.
pub struct Vext {
    pin: Output<'static>,
}

impl Vext {
    /// Claim GPIO36. The rail starts off (pin driven high).
    pub fn new(pin: GPIO36<'static>) -> Self {
        Self {
            pin: Output::new(pin, Level::High, OutputConfig::default()),
        }
    }

    /// Switch the rail on (drive GPIO36 low) and wait for it to settle.
    /// Idempotent: if the rail is already on, returns immediately
    /// without re-settling.
    pub async fn enable(&mut self) {
        if self.pin.output_level() == Level::Low {
            return;
        }
        self.pin.set_low();
        Timer::after_millis(SETTLE_MS).await;
    }

    /// Switch the rail off (drive GPIO36 high). The OLED loses power.
    pub fn disable(&mut self) {
        self.pin.set_high();
    }

    pub fn is_on(&self) -> bool {
        self.pin.output_level() == Level::Low
    }
}
