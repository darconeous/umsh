//! T-LoRa Pager, SX1262 or LR1121. One shared SPI bus; XL9555 powers
//! peripherals.
#![no_std]
pub mod audio;
pub mod display;
pub mod gnss;
pub mod radio;
pub use umsh_pager_peripherals::power as battery;

pub const BOARD_NAME: &str = "LILYGO T-LoRa Pager";
/// `PROP_DEV_MODEL` for each radio this board ships with: the release
/// manifest lists both under the one image.
pub const MODEL_SX1262: &str = "LILYGO T-LoRa Pager SX1262";
pub const MODEL_LR1121: &str = "LILYGO T-LoRa Pager LR1121";
pub const GNSS_BAUD: u32 = 38400;
pub const I2C_SDA: u8 = 3;
pub const I2C_SCL: u8 = 2;
pub const SPI_SCK: u8 = 35;
pub const SPI_MOSI: u8 = 34;
pub const SPI_MISO: u8 = 33;
/// The module's PSRAM, on the quad SPI bus.
pub const PSRAM_MODE: esp_hal::psram::PsramMode = esp_hal::psram::PsramMode::QuadSpi;

use embassy_embedded_hal::shared_bus::asynch::{i2c::I2cDevice, spi::SpiDeviceWithConfig};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use esp_hal::{Async, gpio::Output, i2c::master::I2c, spi::master::SpiDma};
pub type I2cBus = Mutex<CriticalSectionRawMutex, I2c<'static, Async>>;
pub type I2cHandle = I2cDevice<'static, CriticalSectionRawMutex, I2c<'static, Async>>;
pub type SpiBus = Mutex<CriticalSectionRawMutex, SpiDma<'static, Async>>;
pub type SpiHandle =
    SpiDeviceWithConfig<'static, CriticalSectionRawMutex, SpiDma<'static, Async>, Output<'static>>;
pub type SharedExpander = Mutex<CriticalSectionRawMutex, battery::Expander<I2cHandle>>;

#[cfg(feature = "ulcp-i2c")]
pub mod i2c;
