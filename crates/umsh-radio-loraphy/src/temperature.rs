//! Optional temperature acquisition performed by the radio owner in standby.

use lora_phy::{
    lr1110::{Lr1110, Lr1110Variant},
    mod_traits::{InterfaceVariant, RadioKind},
};

/// A chip-specific acquisition hook. The runner serializes it with RX/TX,
/// restores RX or sleep afterward, and never cancels an SPI transaction.
pub trait TemperatureSensor<RK: RadioKind> {
    const SUPPORTED: bool;
    /// Tenths of a kelvin, or unavailable. Called awake and in standby,
    /// with cold-start initialization (including TCXO setup) completed.
    async fn sample(&mut self, radio: &mut RK) -> Option<u16>;
}

pub struct NoTemperature;
impl<RK: RadioKind> TemperatureSensor<RK> for NoTemperature {
    const SUPPORTED: bool = false;
    async fn sample(&mut self, _: &mut RK) -> Option<u16> {
        None
    }
}

pub struct Lr1110Temperature;
impl<SPI, IV, C> TemperatureSensor<Lr1110<SPI, IV, C>> for Lr1110Temperature
where
    SPI: embedded_hal_async::spi::SpiDevice<u8>,
    IV: InterfaceVariant,
    C: Lr1110Variant,
{
    const SUPPORTED: bool = true;
    async fn sample(&mut self, radio: &mut Lr1110<SPI, IV, C>) -> Option<u16> {
        from_lr1110_raw(radio.get_temp().await.ok()?)
    }
}

/// Semtech's nominal Vana=1.35 V, Vbe25=0.7295 V, slope=-1.7 mV/°C:
/// https://github.com/Lora-net/SWDR001/blob/master/src/lr11xx_system.h
/// Temp[10:0] is an ADC code, despite the pinned lora-phy get_temp comment.
/// Use integer arithmetic and round once into 0.1 K, with ties upward.
pub fn from_lr1110_raw(raw: u16) -> Option<u16> {
    let raw = i64::from(raw & 0x07ff);
    let denominator = 2 * 2047 * 170;
    let numerator = 5963 * 2047 * 170 + 2 * (729500 * 2047 - raw * 1350000);
    if numerator < 0 {
        return None;
    }
    u16::try_from((numerator + denominator / 2) / denominator)
        .ok()
        .filter(|&value| value != u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn temperature_raw_codes_convert_to_tenths_kelvin() {
        assert_eq!(from_lr1110_raw(1106), Some(2982));
        assert_eq!(from_lr1110_raw(1200), Some(2617));
        assert_eq!(from_lr1110_raw(0), Some(7273));
        assert_eq!(from_lr1110_raw(2047), None); // below absolute zero
        assert_eq!(from_lr1110_raw(1106 | 0xf800), Some(2982));
    }
}
