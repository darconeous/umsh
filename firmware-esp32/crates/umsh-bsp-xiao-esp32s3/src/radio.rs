//! SX1262 radio bring-up (SPI SCK=GPIO7 / MOSI=GPIO9 / MISO=GPIO8,
//! NSS=GPIO41, reset=GPIO42, BUSY=GPIO40, DIO1=GPIO39, RX enable=GPIO38).
//!
//! The carrier splits the RF switch between the radio and the host: DIO2
//! drives the transmit side (`SetDio2AsRfSwitchCtrl`), and RF_SW1, the
//! receive side, hangs off GPIO38. The interface variant raises it only
//! while the radio receives. DIO3 powers the 1.8 V TCXO, so
//! `TcxoCtrlVoltage::Ctrl1V8` is required.
//!
//! MeshCore parity notes: `rx_boost` on (`SX126X_RX_BOOSTED_GAIN=1`),
//! DC-DC regulator (MeshCore's default), private sync word via
//! `LoRa::new(kind, false, delay)`. MeshCore's 140 mA current limit has
//! no lora-phy API; the chip default OCP applies.

use embassy_time::Delay;
use esp_hal::Async;
use esp_hal::gpio::{Input, Output};
use esp_hal::spi::master::Spi;
use lora_phy::LoRa;
use lora_phy::mod_params::RadioError;
use lora_phy::sx126x::{Config, Sx126x, Sx1262, TcxoCtrlVoltage};
use umsh_radio_loraphy::RadioProfile;

/// The radio's SPI device: the bus is the radio's alone, with NSS as the
/// managed CS pin.
pub type RadioSpi =
    embedded_hal_bus::spi::ExclusiveDevice<Spi<'static, Async>, Output<'static>, Delay>;

/// Interface variant: reset + DIO1 + BUSY + the receive enable. The
/// esp-aware variant, so the DIO1 wait is a light-sleep wake source
/// instead of a wake-lock holder.
pub type RadioIv = umsh_bsp_esp32::iv::EspInterfaceVariant;

/// The lora-phy `RadioKind` for this board.
pub type RadioKind = Sx126x<RadioSpi, RadioIv, Sx1262>;

/// The fully-assembled lora-phy driver.
pub type Radio = LoRa<RadioKind, Delay>;

/// The host-visible model and limits.
pub const PROFILE: RadioProfile = RadioProfile::sx1262(crate::BOARD_NAME);

/// Assemble the board's `RadioKind` and [`PROFILE`] from the SPI device
/// and control pins. Follow with `LoRa::new(kind, false, Delay)`—private sync
/// word—and the parameter builders in `umsh-radio-loraphy`.
pub async fn new_radio_kind(
    spi: RadioSpi,
    reset: Output<'static>,
    dio1: Input<'static>,
    busy: Input<'static>,
    rx_enable: Output<'static>,
) -> Result<(RadioKind, RadioProfile), RadioError> {
    let iv = umsh_bsp_esp32::iv::EspInterfaceVariant::sx126x(reset, dio1, busy)
        .with_rx_enable(rx_enable);
    Ok((
        Sx126x::new(
            spi,
            iv,
            Config {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
                use_dcdc: true,
                rx_boost: true,
            },
        ),
        PROFILE,
    ))
}
