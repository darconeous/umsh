//! Battery voltage sampling (GPIO1 / ADC1 channel 0 behind a
//! 390 kΩ : 100 kΩ divider gated by GPIO37).
//!
//! Unlike the V2, the divider gate is its own pin — not the `Vext`
//! domain — so battery sampling has no coupling to the OLED supply and
//! needs no shared handle. The gate polarity is revision-dependent;
//! this BSP targets **V3.2** (high = divider on, hardware doc §11.3).
//! ADC1 also has no radio entanglement (the classic-ESP32 ADC2/RF
//! conflict does not exist here), so there is no
//! construct-before-radio-init ordering constraint.
//!
//! Each sample follows the §11.4 sequence: gate high → settle → discard
//! one conversion → median a burst → convert → gate low to kill the
//! ~85 µA divider current. Conversion uses esp-hal's curve-fitting
//! calibration scheme (`AdcCalCurve`), which corrects against the
//! chip's eFuse reference and returns millivolts directly — a real
//! accuracy improvement over the V2's nominal transfer function, though
//! the divider tolerance still caps end-to-end accuracy at bucket
//! precision (§11.5).

use embassy_time::Timer;
use esp_hal::Blocking;
use esp_hal::analog::adc::{Adc, AdcCalCurve, AdcConfig, AdcPin, Attenuation};
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::peripherals::{ADC1, GPIO1, GPIO37};

/// Samples per burst (after the discarded throwaway read).
const BURST: usize = 8;
/// Settle after the gate opens before the burst; the divider's ~490 kΩ
/// source impedance and the ADC input cap need a few ms (§11.4).
const DIVIDER_SETTLE_MS: u64 = 5;

type CalScheme = AdcCalCurve<ADC1<'static>>;

/// Owned battery ADC: ADC1, the configured GPIO1 pin, and the GPIO37
/// divider gate.
pub struct BatterySampler {
    adc: Adc<'static, ADC1<'static>, Blocking>,
    pin: AdcPin<GPIO1<'static>, ADC1<'static>, CalScheme>,
    gate: Output<'static>,
}

impl BatterySampler {
    /// Claim ADC1, GPIO1, and the GPIO37 gate (left low = divider off).
    ///
    /// 2.5 dB attenuation: a 4.2 V battery puts ~857 mV on the pin,
    /// inside the ~0–1250 mV calibrated range with headroom for a
    /// charging cell; 0 dB (~950 mV top) would saturate right where the
    /// interesting readings are.
    pub fn new(adc1: ADC1<'static>, gpio1: GPIO1<'static>, gpio37: GPIO37<'static>) -> Self {
        let mut config = AdcConfig::new();
        let pin = config.enable_pin_with_cal::<_, CalScheme>(gpio1, Attenuation::_2p5dB);
        Self {
            adc: Adc::new(adc1, config),
            pin,
            gate: Output::new(gpio37, Level::Low, OutputConfig::default()),
        }
    }

    /// Measure the battery terminal voltage in millivolts.
    ///
    /// Opens the divider gate, settles, discards one read, medians a
    /// burst of calibrated (millivolt) conversions, applies the ×4.9
    /// divider ratio, and closes the gate again.
    pub async fn sample_mv(&mut self) -> u16 {
        self.gate.set_high();
        Timer::after_millis(DIVIDER_SETTLE_MS).await;

        let _ = self.read_raw();
        let mut burst = [0u16; BURST];
        for slot in &mut burst {
            *slot = self.read_raw();
        }
        self.gate.set_low();

        burst.sort_unstable();
        let adc_mv = u32::from(burst[BURST / 2]);
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
