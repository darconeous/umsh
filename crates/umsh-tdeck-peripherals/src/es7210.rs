//! The ES7210 microphone ADC (§13). Nothing records, so all it is ever
//! told is to power down.

use embedded_hal_async::i2c::I2c;

pub const ADDRESS: u8 = 0x40;

/// Espressif's stop sequence (esp-adf `es7210_stop`), register then value:
/// each microphone's power, the bias, ADC, and PGA pairs, the analog
/// block, every clock, and the chip itself.
const POWER_DOWN: [[u8; 2]; 9] = [
    [0x47, 0xff],
    [0x48, 0xff],
    [0x49, 0xff],
    [0x4a, 0xff],
    [0x4b, 0xff],
    [0x4c, 0xff],
    [0x40, 0xc0],
    [0x01, 0x7f],
    [0x06, 0x07],
];

/// Powers the ADC down until its rail next rises.
pub async fn power_down<I: I2c>(i2c: &mut I) -> Result<(), I::Error> {
    for write in &POWER_DOWN {
        i2c.write(ADDRESS, write).await?;
    }
    Ok(())
}
