//! Battery voltage sampling (GPIO13 / ADC2 behind a 220 kΩ : 100 kΩ
//! divider whose ground leg is switched by `Vext`).
//!
//! The divider only reads truthfully while `Vext` is enabled (hardware
//! doc §9.2), which is why [`BatterySampler`] holds the shared
//! [`VextHandle`] — it raises the rail for the burst and puts it back
//! the way it found it, so a reading taken while the panel is dark does
//! not silently power the panel up behind the display task's back.
//!
//! GPIO13 is an ADC2 channel. On the classic ESP32, ADC2 is shared with
//! the radio: `Adc::new` panics if the esp-radio controller has already
//! claimed it, so the sampler must be constructed *before* radio init.
//! The firmware's boot order does this.
//!
//! The classic ESP32 ADC has no esp-hal calibration scheme; the
//! raw→millivolt conversion below is the nominal 6 dB transfer function
//! and is good to bucket precision, not lab precision (hardware doc
//! §9.5).

use embassy_time::Timer;
use esp_hal::Blocking;
use esp_hal::analog::adc::{Adc, AdcConfig, AdcPin, Attenuation};
use esp_hal::peripherals::{ADC2, GPIO13};

use crate::vext::VextHandle;

/// Samples per burst (after the discarded throwaway read).
const BURST: usize = 8;
/// Extra settle after `Vext` comes up before the burst; the divider's
/// source impedance is ~320 kΩ and the doc recommends a few ms.
const DIVIDER_SETTLE_MS: u64 = 5;
/// Nominal full-scale input in millivolts at 6 dB attenuation, 12-bit
/// resolution. A 4.2 V battery puts ~1313 mV on the pin, comfortably
/// inside the ~150–1750 mV linear range for this attenuation.
const FULL_SCALE_MV: u32 = 2_200;
const FULL_SCALE_CODE: u32 = 4_095;

/// Owned battery ADC: the ADC2 instance, the configured GPIO13 pin, and
/// the shared rail the divider hangs off.
pub struct BatterySampler {
    adc: Adc<'static, ADC2<'static>, Blocking>,
    pin: AdcPin<GPIO13<'static>, ADC2<'static>>,
    vext: VextHandle,
}

impl BatterySampler {
    /// Claim ADC2 and GPIO13. Panics if the radio already owns ADC2 —
    /// construct before radio init.
    pub fn new(adc2: ADC2<'static>, gpio13: GPIO13<'static>, vext: VextHandle) -> Self {
        let mut config = AdcConfig::new();
        let pin = config.enable_pin(gpio13, Attenuation::_6dB);
        Self {
            adc: Adc::new(adc2, config),
            pin,
            vext,
        }
    }

    /// Measure the battery terminal voltage in millivolts.
    ///
    /// Raises `Vext` if it was down, settles the divider, discards one
    /// read, then medians a burst and applies the ×3.2 divider ratio.
    /// The rail is left as it was found: a sample taken with the panel
    /// powered down does not leave it powered up and uninitialized.
    pub async fn sample_mv(&mut self) -> u16 {
        let was_on = self.vext.is_on();
        self.vext.enable().await;
        Timer::after_millis(DIVIDER_SETTLE_MS).await;

        let _ = self.read_raw();
        let mut burst = [0u16; BURST];
        for slot in &mut burst {
            *slot = self.read_raw();
        }

        if !was_on {
            self.vext.disable();
        }

        burst.sort_unstable();
        let median = u32::from(burst[BURST / 2]);

        let adc_mv = median * FULL_SCALE_MV / FULL_SCALE_CODE;
        let battery_mv = adc_mv * u32::from(crate::BATTERY_DIVIDER_RATIO_X10) / 10;
        battery_mv.min(u32::from(u16::MAX)) as u16
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
