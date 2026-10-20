//! The rail-sense divider on GPIO4 (ADC1 channel 3), 100 kΩ : 100 kΩ.
//! It reads the board's `+5V` rail through a switch that GPIO10 closes:
//! the cell on battery, VBUS less a diode on USB (§4.5). Which of those a
//! reading is, [`umsh_tdeck_peripherals::battery::Rail`] says.
//!
//! Calibrated millivolts at 11 dB attenuation, the median of a burst.

use esp_hal::Blocking;
use esp_hal::analog::adc::{Adc, AdcCalCurve, AdcConfig, AdcPin, Attenuation};
use esp_hal::peripherals::{ADC1, GPIO4};
pub use umsh_tdeck_peripherals::battery::Rail;

/// Samples per burst, after one discarded read.
const BURST: usize = 7;

type CalScheme = AdcCalCurve<ADC1<'static>>;

pub struct BatterySampler {
    adc: Adc<'static, ADC1<'static>, Blocking>,
    pin: AdcPin<GPIO4<'static>, ADC1<'static>, CalScheme>,
}

impl BatterySampler {
    pub fn new(adc1: ADC1<'static>, gpio4: GPIO4<'static>) -> Self {
        let mut config = AdcConfig::new();
        let pin = config.enable_pin_with_cal::<_, CalScheme>(gpio4, Attenuation::_11dB);
        Self {
            adc: Adc::new(adc1, config),
            pin,
        }
    }

    /// The rail in millivolts: the divider's reading doubled.
    pub async fn sample_mv(&mut self) -> u16 {
        let _ = self.read_raw();
        let mut burst = [0u16; BURST];
        for slot in &mut burst {
            *slot = self.read_raw();
        }
        burst.sort_unstable();
        burst[BURST / 2].saturating_mul(2)
    }

    fn read_raw(&mut self) -> u16 {
        loop {
            match self.adc.read_oneshot(&mut self.pin) {
                Ok(value) => return value,
                Err(nb::Error::WouldBlock) => continue,
                Err(nb::Error::Other(())) => return 0,
            }
        }
    }
}
