//! SX1262 at CS36, RESET47, DIO1=14, BUSY48 on the shared SPI2 bus.
use embassy_time::Delay;
use esp_hal::gpio::{Input, Output};
use lora_phy::{
    LoRa,
    mod_params::RadioError,
    sx126x::{Config, Sx126x, Sx1262, TcxoCtrlVoltage},
};
pub type RadioSpi = crate::SpiHandle;
pub type RadioKind = Sx126x<RadioSpi, umsh_bsp_esp32::iv::EspInterfaceVariant, Sx1262>;
pub type Radio = LoRa<RadioKind, Delay>;
pub fn new_radio_kind(
    spi: RadioSpi,
    reset: Output<'static>,
    dio1: Input<'static>,
    busy: Input<'static>,
) -> Result<RadioKind, RadioError> {
    Ok(Sx126x::new(
        spi,
        umsh_bsp_esp32::iv::EspInterfaceVariant::sx126x(reset, dio1, busy),
        Config {
            chip: Sx1262,
            tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl3V0),
            use_dcdc: true,
            rx_boost: true,
        },
    ))
}
