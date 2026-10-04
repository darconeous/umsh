#![no_std]
//! BME280 temperature-only forced acquisition. No background sampling.
//!
//! Register map, timing and compensation: Bosch BST-BME280-DS001-23,
//! sections 4.2, 5 and 9.1:
//! <https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bme280-ds002.pdf>
//! Callers retain exclusive bus access for the complete operation and must not
//! cancel an I2C transfer on controllers without cancellation-safe DMA.

use embedded_hal_async::{delay::DelayNs, i2c::I2c};

pub mod service;

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Bus(E),
    WrongChip,
    Timeout,
    InvalidReading,
}

/// Detection performs no measurement and accepts only BME280 (not BMP280).
pub async fn probe<I: I2c>(bus: &mut I, address: u8) -> Result<(), Error<I::Error>> {
    let mut id = [0];
    bus.write_read(address, &[0xd0], &mut id)
        .await
        .map_err(Error::Bus)?;
    if id[0] == 0x60 {
        Ok(())
    } else {
        Err(Error::WrongChip)
    }
}

async fn idle<I: I2c, D: DelayNs>(
    bus: &mut I,
    address: u8,
    delay: &mut D,
) -> Result<(), Error<I::Error>> {
    // Also handles a previous full-oversampling conversion started by raw I2C.
    // NVM copying (bit 0) and measurement (bit 3) must both have finished.
    for _ in 0..40 {
        let mut status = [0];
        bus.write_read(address, &[0xf3], &mut status)
            .await
            .map_err(Error::Bus)?;
        if status[0] & 9 == 0 {
            return Ok(());
        }
        delay.delay_ms(5).await;
    }
    Err(Error::Timeout)
}

/// Fresh measurement in tenths of a kelvin. The chip returns to sleep after
/// each conversion; pressure, humidity and the IIR filter are disabled.
pub async fn sample<I: I2c, D: DelayNs>(
    bus: &mut I,
    address: u8,
    delay: &mut D,
) -> Result<u16, Error<I::Error>> {
    probe(bus, address).await?;
    bus.write(address, &[0xf4, 0]).await.map_err(Error::Bus)?;
    idle(bus, address, delay).await?;
    // Reload calibration after power loss/reset as well as on the initial get.
    let mut trim = [0; 6];
    bus.write_read(address, &[0x88], &mut trim)
        .await
        .map_err(Error::Bus)?;
    bus.write(address, &[0xf5, 0]).await.map_err(Error::Bus)?;
    bus.write(address, &[0xf2, 0]).await.map_err(Error::Bus)?;
    bus.write(address, &[0xf4, 0x21])
        .await
        .map_err(Error::Bus)?;
    // Temperature x1 requires at most 3.55 ms. Do not mistake the status
    // register's initial idle value for completion immediately after forcing.
    delay.delay_ms(5).await;
    idle(bus, address, delay).await?;
    let mut data = [0; 3];
    bus.write_read(address, &[0xfa], &mut data)
        .await
        .map_err(Error::Bus)?;
    let raw = (u32::from(data[0]) << 12) | (u32::from(data[1]) << 4) | u32::from(data[2] >> 4);
    compensate(trim, raw).ok_or(Error::InvalidReading)
}

fn compensate(trim: [u8; 6], raw: u32) -> Option<u16> {
    if raw == 0x80000 || raw > 0xfffff || trim == [0; 6] || trim == [0xff; 6] {
        return None;
    }
    let t1 = i64::from(u16::from_le_bytes([trim[0], trim[1]]));
    let t2 = i64::from(i16::from_le_bytes([trim[2], trim[3]]));
    let t3 = i64::from(i16::from_le_bytes([trim[4], trim[5]]));
    // Bosch integer compensation, widened so corrupt trims cannot overflow.
    let adc = i64::from(raw);
    let delta = (adc >> 4) - t1;
    let fine = (((adc >> 3) - (t1 << 1)) * t2 >> 11) + (((delta * delta) >> 12) * t3 >> 14);
    let hundredths_c = (fine * 5 + 128) >> 8;
    if !(-4000..=8500).contains(&hundredths_c) {
        return None;
    }
    Some(((hundredths_c + 27315 + 5) / 10) as u16)
}

#[cfg(test)]
mod tests;
