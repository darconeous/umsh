//! T-LoRa Pager SX1262. One shared SPI bus; XL9555 powers peripherals.
#![no_std]
pub mod display;
pub mod gnss;
pub mod radio;
pub use umsh_pager_peripherals::power as battery;

pub const BOARD_NAME: &str = "LILYGO T-LoRa Pager SX1262";
pub const GNSS_BAUD: u32 = 38400;
pub const I2C_SDA: u8 = 3;
pub const I2C_SCL: u8 = 2;
pub const SPI_SCK: u8 = 35;
pub const SPI_MOSI: u8 = 34;
pub const SPI_MISO: u8 = 33;

use embassy_embedded_hal::shared_bus::asynch::{i2c::I2cDevice, spi::SpiDeviceWithConfig};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use esp_hal::{Async, gpio::Output, i2c::master::I2c, spi::master::SpiDma};
pub type I2cBus = Mutex<CriticalSectionRawMutex, I2c<'static, Async>>;
pub type I2cHandle = I2cDevice<'static, CriticalSectionRawMutex, I2c<'static, Async>>;
pub type SpiBus = Mutex<CriticalSectionRawMutex, SpiDma<'static, Async>>;
pub type SpiHandle =
    SpiDeviceWithConfig<'static, CriticalSectionRawMutex, SpiDma<'static, Async>, Output<'static>>;
pub type SharedExpander = Mutex<CriticalSectionRawMutex, battery::Expander<I2cHandle>>;
