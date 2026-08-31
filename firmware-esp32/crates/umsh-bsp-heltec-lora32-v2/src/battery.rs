//! Battery voltage sampling (GPIO13 / ADC2 behind a 220 kΩ : 100 kΩ
//! divider whose ground leg is switched by `Vext`).
//!
//! The divider only reads truthfully while `Vext` is enabled (hardware
//! doc §9.2), which is why [`BatterySampler`] holds the shared
//! [`VextHandle`] — it raises the rail for the burst and puts it back
//! the way it found it, so a reading taken while the panel is dark does
//! not silently power the panel up behind the display task's back.
//!
//! GPIO13 is an ADC2 channel. On the classic ESP32, ADC2 is shared
//! with the radio, and the sharing is exclusive both ways: `Adc::new`
//! panics while the esp-radio controller holds the claim, and esp-radio
//! init panics while an `Adc` instance does. So the sampler holds only
//! the *peripherals* and claims the ADC per sample, releasing it before
//! returning — and the caller must guarantee the radio is down for the
//! duration of the call (the firmware's ADC2 arbiter does).
//!
//! The classic ESP32 ADC has no esp-hal calibration scheme; the
//! raw→millivolt conversion below is the nominal 6 dB transfer function
//! and is good to bucket precision, not lab precision (hardware doc
//! §9.5).

use embassy_time::Timer;
use esp_hal::analog::adc::{Adc, AdcConfig, Attenuation};
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

/// Owned battery ADC peripherals: ADC2 and GPIO13, claimed only for
/// the duration of a sample, plus the shared rail the divider hangs
/// off.
pub struct BatterySampler {
    adc2: ADC2<'static>,
    gpio13: GPIO13<'static>,
    vext: VextHandle,
}

impl BatterySampler {
    /// Take ownership of the peripherals. Nothing is claimed here — the
    /// per-sample claim inside [`sample_mv`](Self::sample_mv) is what
    /// keeps ADC2 free for the radio the rest of the time.
    pub fn new(adc2: ADC2<'static>, gpio13: GPIO13<'static>, vext: VextHandle) -> Self {
        Self { adc2, gpio13, vext }
    }

    /// Measure the battery terminal voltage in millivolts.
    ///
    /// Claims ADC2 for the duration (the caller must guarantee the
    /// radio is down, or `Adc::new` panics), raises `Vext` if it was
    /// down, settles the divider, discards one read, then medians a
    /// burst and applies the ×3.2 divider ratio. Both the claim and the
    /// rail are left as they were found.
    pub async fn sample_mv(&mut self) -> u16 {
        let was_on = self.vext.is_on();
        self.vext.enable().await;
        Timer::after_millis(DIVIDER_SETTLE_MS).await;

        let mut config = AdcConfig::new();
        let mut pin = config.enable_pin(self.gpio13.reborrow(), Attenuation::_6dB);
        let mut adc = Adc::new(self.adc2.reborrow(), config);
        let mut read_raw = || loop {
            match adc.read_oneshot(&mut pin) {
                Ok(value) => return value,
                Err(nb::Error::WouldBlock) => continue,
                Err(nb::Error::Other(())) => return 0,
            }
        };

        let _ = read_raw();
        let mut burst = [0u16; BURST];
        for slot in &mut burst {
            *slot = read_raw();
        }
        drop(read_raw);
        // Dropping the `Adc` releases the ADC2 claim for the radio.
        drop(adc);

        if !was_on {
            self.vext.disable();
        }

        burst.sort_unstable();
        let median = u32::from(burst[BURST / 2]);

        let adc_mv = median * FULL_SCALE_MV / FULL_SCALE_CODE;
        let battery_mv = adc_mv * u32::from(crate::BATTERY_DIVIDER_RATIO_X10) / 10;
        battery_mv.min(u32::from(u16::MAX)) as u16
    }
}
