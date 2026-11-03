//! SX1262 module at CS9, RESET17, DIO1=45, BUSY13 on the shared SPI bus,
//! powered from V3V. The original T-Deck may have none (§10.1).
//!
//! TCXO at 1.8 V and DIO2 as the RF switch, as both mesh projects that
//! ship T-Deck images run it; checklist item 7 settles both.
use embassy_time::Delay;
use esp_hal::gpio::{Input, Output};
use lora_phy::{
    LoRa,
    mod_params::RadioError,
    sx126x::{Config, Sx126x, Sx1262, TcxoCtrlVoltage},
};
use umsh_radio_loraphy::RadioProfile;
pub type RadioSpi = crate::SpiHandle;
pub type RadioKind = Sx126x<RadioSpi, umsh_bsp_esp32::iv::EspInterfaceVariant, Sx1262>;
pub type Radio = LoRa<RadioKind, Delay>;

/// The host-visible model and limits.
pub const PROFILE: RadioProfile = RadioProfile::sx1262(crate::BOARD_NAME);

pub async fn new_radio_kind(
    spi: RadioSpi,
    reset: Output<'static>,
    dio1: Input<'static>,
    busy: Input<'static>,
) -> Result<(RadioKind, RadioProfile), RadioError> {
    Ok((
        Sx126x::new(
            spi,
            umsh_bsp_esp32::iv::EspInterfaceVariant::sx126x(reset, dio1, busy),
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
