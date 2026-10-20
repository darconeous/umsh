//! LILYGO T-Deck and T-Deck Plus. One shared SPI bus (panel, radio,
//! MicroSD); GPIO10 switches the peripheral rail, V3V, that the radio,
//! keyboard, trackball, backlight, and I²C pull-ups hang off. Which parts
//! are fitted varies by unit and is found at boot. Register references and
//! the hardware checklist are in `docs/hardware/lilygo-t-deck-hardware.md`.
#![no_std]
pub mod battery;
pub mod display;
pub mod gnss;
pub mod radio;

pub const BOARD_NAME: &str = "LILYGO T-Deck";
pub const I2C_SDA: u8 = 18;
pub const I2C_SCL: u8 = 8;
pub const SPI_SCK: u8 = 40;
pub const SPI_MOSI: u8 = 41;
pub const SPI_MISO: u8 = 38;
/// The module's PSRAM, on the octal bus.
pub const PSRAM_MODE: esp_hal::psram::PsramMode = esp_hal::psram::PsramMode::OctalSpi;
/// The GNSS receiver's rates, in the order they are tried: the Plus's
/// u-blox MIA-M10Q's, then the L76K's (§12).
pub const GNSS_BAUDS: [u32; 2] = [38400, 9600];

use embassy_embedded_hal::shared_bus::asynch::{i2c::I2cDevice, spi::SpiDeviceWithConfig};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use esp_hal::{Async, gpio::Output, i2c::master::I2c, spi::master::SpiDma};
pub type I2cBus = Mutex<CriticalSectionRawMutex, I2c<'static, Async>>;
pub type I2cHandle = I2cDevice<'static, CriticalSectionRawMutex, I2c<'static, Async>>;
pub type SpiBus = Mutex<CriticalSectionRawMutex, SpiDma<'static, Async>>;
pub type SpiHandle =
    SpiDeviceWithConfig<'static, CriticalSectionRawMutex, SpiDma<'static, Async>, Output<'static>>;

#[cfg(feature = "ulcp-i2c")]
pub mod i2c;
