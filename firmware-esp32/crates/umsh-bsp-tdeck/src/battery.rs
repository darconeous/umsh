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

/// Polls of a oneshot conversion before it is given up on. A conversion
/// finishes in tens of microseconds, a small fraction of this many polls;
/// one still busy after them is not going to finish, and the sample is
/// reported unavailable rather than spinning the executor forever.
const READ_POLL_LIMIT: u32 = 10_000;

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

    /// The rail in millivolts: the divider's reading doubled. `None`
    /// when a conversion failed or never finished.
    pub async fn sample_mv(&mut self) -> Option<u16> {
        let mut burst = [0u16; BURST];
        if !self.read_burst(&mut burst) {
            return None;
        }
        burst.sort_unstable();
        Some(burst[BURST / 2].saturating_mul(2))
    }

    fn read_raw(&mut self) -> Option<u16> {
        for _ in 0..READ_POLL_LIMIT {
            match self.adc.read_oneshot(&mut self.pin) {
                Ok(value) => return Some(value),
                Err(nb::Error::WouldBlock) => continue,
                Err(nb::Error::Other(())) => return None,
            }
        }
        None
    }

    /// One discarded conversion, then a burst into `burst`. False when
    /// any of them was unavailable.
    fn read_burst(&mut self, burst: &mut [u16; BURST]) -> bool {
        self.read_raw().is_some()
            && burst
                .iter_mut()
                .all(|slot| self.read_raw().map(|value| *slot = value).is_some())
    }
}
