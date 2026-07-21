//! SX1262 radio bring-up (SPI SCK=GPIO9 / MOSI=GPIO10 / MISO=GPIO11,
//! NSS=GPIO8, reset=GPIO12, BUSY=GPIO13, DIO1=GPIO14).
//!
//! Unlike the V2's SX127x this chip has a BUSY handshake (GPIO13) that
//! the driver waits on around every command, and two DIO lines with
//! fixed board roles that are **mandatory configuration, not tuning**
//! (hardware doc §4.6–4.7):
//!
//! - DIO2 drives the external RF switch (`SetDio2AsRfSwitchCtrl` — no
//!   MCU pin is involved in TX/RX switching).
//! - DIO3 powers the 1.8 V TCXO. A crystal-configured init will hang or
//!   start flaky; `TcxoCtrlVoltage::Ctrl1V8` is required.
//!
//! MeshCore declares NRESET unconnected; that is driver policy, not
//! hardware truth (§4.3) — GPIO12 is wired and we drive a real reset
//! pulse through the interface variant.
//!
//! MeshCore parity notes: `rx_boost` on (`SX126X_RX_BOOSTED_GAIN=1`),
//! LDO regulator mode (MeshCore leaves RadioLib's default), private
//! sync word via `LoRa::new(kind, false, delay)` (0x12 expands to
//! 0x14/0x24 in the driver). MeshCore's 140 mA current limit
//! (`SX126X_CURRENT_LIMIT=140`) has no lora-phy API; the chip default
//! OCP applies, which is fine at bring-up power levels.

use embassy_time::Delay;
use esp_hal::Async;
use esp_hal::gpio::{Input, Output};
use esp_hal::spi::master::Spi;
use lora_phy::LoRa;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::mod_params::RadioError;
use lora_phy::sx126x::{Config, Sx126x, Sx1262, TcxoCtrlVoltage};

/// The radio's SPI device: the shared bus is exclusively the radio's on
/// this board, with NSS as the managed CS pin.
pub type RadioSpi =
    embedded_hal_bus::spi::ExclusiveDevice<Spi<'static, Async>, Output<'static>, Delay>;

/// Interface variant: reset + DIO1 + BUSY, no host-driven RF switch
/// (DIO2 handles it inside the radio).
pub type RadioIv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;

/// The lora-phy `RadioKind` for this board.
pub type RadioKind = Sx126x<RadioSpi, RadioIv, Sx1262>;

/// The fully-assembled lora-phy driver.
pub type Radio = LoRa<RadioKind, Delay>;

/// Assemble the board's `RadioKind` from the SPI device and control
/// pins. Follow with `LoRa::new(kind, false, Delay)` — private sync
/// word — and the parameter builders in `umsh-radio-loraphy`.
pub fn new_radio_kind(
    spi: RadioSpi,
    reset: Output<'static>,
    dio1: Input<'static>,
    busy: Input<'static>,
) -> Result<RadioKind, RadioError> {
    let iv = GenericSx126xInterfaceVariant::new(reset, dio1, busy, None, None)?;
    Ok(Sx126x::new(
        spi,
        iv,
        Config {
            chip: Sx1262,
            tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
            use_dcdc: false,
            rx_boost: true,
        },
    ))
}
