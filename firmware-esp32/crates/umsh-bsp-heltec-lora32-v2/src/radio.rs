//! SX1276 radio bring-up (SPI SCK=GPIO5 / MOSI=GPIO27 / MISO=GPIO19,
//! NSS=GPIO18, reset=GPIO14, DIO0=GPIO26).
//!
//! The SX127x family has no BUSY pin, and this board's RF switch is
//! driven by the radio's own RXTX output — so the
//! `GenericSx127xInterfaceVariant` is used with both RF-switch pins
//! `None`, which makes `wait_on_busy` and the `enable_rf_switch_*`
//! hooks no-ops. DIO0 carries every IRQ lora-phy needs; DIO1 (GPIO35)
//! and DIO2 (GPIO34) are wired but unused.
//!
//! The antenna is on the PA_BOOST port (`tx_boost: true`); the RFO path
//! is not connected. Crystal oscillator, no TCXO.
//!
//! Sync-word note: lora-phy carries the sync word as a single byte
//! (0x12 = private) at the `LoRa` level and the SX126x driver expands
//! it to the two-byte register form (0x12 → 0x14 0x24) internally, so
//! `LoRa::new(kind, false, delay)` yields interoperable sync words on
//! both this board and the SX1262 boards — no mapping needed here.

use embassy_time::{Delay, Timer};
use embedded_hal_async::spi::SpiDevice;
use esp_hal::Async;
use esp_hal::gpio::{Input, Output};
use esp_hal::spi::master::Spi;
use lora_phy::LoRa;
use lora_phy::iv::GenericSx127xInterfaceVariant;
use lora_phy::mod_params::RadioError;
use lora_phy::sx127x::{Config, Sx1276, Sx127x};

/// The radio's SPI device: the shared bus is exclusively the radio's on
/// this board, with NSS as the managed CS pin.
pub type RadioSpi =
    embedded_hal_bus::spi::ExclusiveDevice<Spi<'static, Async>, Output<'static>, Delay>;

/// Interface variant: reset + DIO0, no BUSY, no host-driven RF switch.
pub type RadioIv = GenericSx127xInterfaceVariant<Output<'static>, Input<'static>>;

/// The lora-phy `RadioKind` for this board.
pub type RadioKind = Sx127x<RadioSpi, RadioIv, Sx1276>;

/// The fully-assembled lora-phy driver.
pub type Radio = LoRa<RadioKind, Delay>;

/// `RegVersion` value for the SX1276 silicon on this board.
pub const EXPECTED_VERSION: u8 = 0x12;

const REG_VERSION: u8 = 0x42;

/// Reset the radio and read `RegVersion` (0x42) raw over SPI, before
/// the lora-phy driver takes ownership of the bus. Anything other than
/// [`EXPECTED_VERSION`] means the SPI wiring or the chip is bad —
/// surface it before blaming RF behavior.
///
/// The driver re-runs its own reset during `LoRa::new`, so the extra
/// reset pulse here is harmless.
pub async fn probe_version(
    spi: &mut RadioSpi,
    reset: &mut Output<'static>,
) -> Result<u8, RadioError> {
    reset.set_low();
    Timer::after_millis(10).await;
    reset.set_high();
    Timer::after_millis(10).await;

    // SX127x read transaction: address with MSB clear, then one dummy
    // clock byte; the register value comes back in the second byte.
    let mut buf = [REG_VERSION & 0x7F, 0x00];
    spi.transfer_in_place(&mut buf)
        .await
        .map_err(|_| RadioError::SPI)?;
    Ok(buf[1])
}

/// Assemble the board's `RadioKind` from the SPI device and control
/// pins. Follow with `LoRa::new(kind, false, Delay)` — private sync
/// word — and the parameter builders in `umsh-radio-loraphy`.
pub fn new_radio_kind(
    spi: RadioSpi,
    reset: Output<'static>,
    dio0: Input<'static>,
) -> Result<RadioKind, RadioError> {
    let iv = GenericSx127xInterfaceVariant::new(reset, dio0, None, None)?;
    Ok(Sx127x::new(
        spi,
        iv,
        Config {
            chip: Sx1276,
            tcxo_used: false,
            tx_boost: true,
            rx_boost: true,
        },
    ))
}
