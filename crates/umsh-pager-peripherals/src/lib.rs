//! Async, allocation-free drivers for the Pager's peripheral chips.
//! Register references and the hardware qualification checklist are in
//! `docs/hardware/lilygo-t-lora-pager-hardware.md`.
#![no_std]

pub mod display;
pub mod input;
pub mod power;
pub mod rtc;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

async fn read<I: embedded_hal_async::i2c::I2c>(
    i2c: &mut I,
    address: u8,
    register: u8,
) -> Result<u8, I::Error> {
    let mut byte = [0];
    i2c.write_read(address, &[register], &mut byte).await?;
    Ok(byte[0])
}

async fn update<I: embedded_hal_async::i2c::I2c>(
    i2c: &mut I,
    address: u8,
    register: u8,
    mask: u8,
    value: u8,
) -> Result<(), I::Error> {
    let old = read(i2c, address, register).await?;
    i2c.write(address, &[register, (old & !mask) | (value & mask)])
        .await
}
