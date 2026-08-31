//! SX1262 radio bring-up (SPI SCK=GPIO12 / MOSI=GPIO11 / MISO=GPIO13,
//! NSS=GPIO10, reset=GPIO5, BUSY=GPIO4, DIO1=GPIO1).
//!
//! Same chip and driver shape as the Heltec V3, with two board deltas:
//!
//! - **ALDO3 first.** The radio has a switched supply; reset, BUSY, and
//!   SPI mean nothing until [`crate::power::bring_up`] has run. A BUSY
//!   line that never moves during bring-up is an unpowered radio, not a
//!   broken one (hardware doc §4.4).
//! - **The TCXO voltage is genuinely open** (§4.7, §18.11). LILYGO's own
//!   example and current MeshCore land on 1.6 V through RadioLib's
//!   default; Meshtastic explicitly sets 1.8 V. The board constant below
//!   starts at the manufacturer's 1.6 V; if init hangs or the frequency
//!   is off on hardware, [`TCXO_VOLTAGE`] is the one line to flip.
//!
//! As on the Heltec V3: DIO2 drives the RF switch from inside the chip
//! (`SetDio2AsRfSwitchCtrl` — no MCU pin switches TX/RX), NRESET is
//! wired and driven, `rx_boost` on, DC-DC regulator mode (the chip's
//! buck converter roughly halves RX/TX supply current versus the LDO;
//! every nRF52 SX1262 board here already runs it), private sync word
//! via `LoRa::new(kind, false, delay)`.

use embassy_time::Delay;
use esp_hal::Async;
use esp_hal::gpio::{Input, Output};
use esp_hal::spi::master::Spi;
use lora_phy::LoRa;
use lora_phy::mod_params::RadioError;
use lora_phy::sx126x::{Config, Sx126x, Sx1262, TcxoCtrlVoltage};

/// DIO3 TCXO supply voltage — a board constant with an open question
/// behind it; see the module docs before changing it, and change nothing
/// else with it.
pub const TCXO_VOLTAGE: TcxoCtrlVoltage = TcxoCtrlVoltage::Ctrl1V6;

/// The radio's SPI device: the bus is exclusively the radio's on this
/// board (the SD/IMU bus is separate), with NSS as the managed CS pin.
pub type RadioSpi =
    embedded_hal_bus::spi::ExclusiveDevice<Spi<'static, Async>, Output<'static>, Delay>;

/// Interface variant: reset + DIO1 + BUSY, no host-driven RF switch
/// (DIO2 handles it inside the radio). The esp-aware variant, so the
/// DIO1 wait is a light-sleep wake source instead of a wake-lock
/// holder.
pub type RadioIv = umsh_bsp_esp32::iv::EspInterfaceVariant;

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
    let iv = umsh_bsp_esp32::iv::EspInterfaceVariant::sx126x(reset, dio1, busy);
    Ok(Sx126x::new(
        spi,
        iv,
        Config {
            chip: Sx1262,
            tcxo_ctrl: Some(TCXO_VOLTAGE),
            use_dcdc: true,
            rx_boost: true,
        },
    ))
}
