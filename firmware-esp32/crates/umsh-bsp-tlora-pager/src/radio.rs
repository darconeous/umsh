//! SX1262 or LR1121 at CS36, RESET47, DIO1=14, BUSY48 on the shared SPI2
//! bus. LILYGO fits either module to the same board and both use those
//! pins, so the radio is probed at boot and the matching driver built.
//!
//! - **SX1262**: DIO2 drives the RF switch and DIO3 the 3.0 V TCXO from
//!   inside the radio. DC-DC regulator.
//! - **LR1121**: DIO5 and DIO6 drive the RF switch ([`RF_SWITCH_LR1121`]),
//!   DIO3 the 3.0 V TCXO (LilyGoLib `setTCXO(3.0)`; Meshtastic
//!   `LR11X0_DIO3_TCXO_VOLTAGE=3.0`). Sub-GHz on the high-power PA. LDO
//!   regulator, RadioLib's LR11x0 default and what LilyGoLib runs.
use embassy_time::Delay;
use esp_hal::gpio::{Input, Output};
use lora_phy::{
    LoRa,
    lr1110::{
        self, ChipType, Lr1110, RfSwitchConfig, radio_kind_params::PaSelection, variant::Lr1121,
    },
    sx126x::{self, Sx126x, Sx1262},
};
use umsh_bsp_esp32::iv::EspInterfaceVariant;
use umsh_radio_loraphy::{
    EitherRadioKind, RadioProfile,
    probe::{self, ChipFamily, ProbeError},
};

pub type RadioSpi = crate::SpiHandle;
pub type RadioKind = EitherRadioKind<
    Sx126x<RadioSpi, EspInterfaceVariant, Sx1262>,
    Lr1110<RadioSpi, EspInterfaceVariant, Lr1121>,
>;
pub type Radio = LoRa<RadioKind, Delay>;

/// LR1121 RF-switch DIO table, from LilyGoLib's `LilyGo_LoRa_Pager.cpp`
/// (Meshtastic's `tlora-pager/rfswitch.h` matches):
///
/// | Mode          | DIO5 | DIO6 | Mask |
/// |---------------|------|------|------|
/// | STBY          | LOW  | LOW  | 0x00 |
/// | RX            | LOW  | HIGH | 0x02 |
/// | TX, TX_HP     | HIGH | LOW  | 0x01 |
/// | TX_HF, GNSS, WIFI | LOW | LOW | 0x00 |
///
/// The reverse of lora-phy's legacy default table, so it must be given.
pub const RF_SWITCH_LR1121: RfSwitchConfig = RfSwitchConfig {
    standby: 0x00,
    rx: 0x02,
    tx: 0x01,
    tx_hp: 0x01,
    tx_hf: 0x00,
    gnss: 0x00,
    wifi: 0x00,
};

#[derive(Debug)]
pub enum RadioInitError {
    Probe(ProbeError),
    /// An LR11xx other than the LR1121, which no Pager ships with.
    Unsupported(ChipType),
}

/// Probe the fitted module and build its driver. Follow with
/// `LoRa::new(kind, false, Delay)`, under the same deadline as this.
pub async fn new_radio_kind(
    mut spi: RadioSpi,
    mut reset: Output<'static>,
    dio1: Input<'static>,
    mut busy: Input<'static>,
) -> Result<(RadioKind, RadioProfile), RadioInitError> {
    let family = probe::identify(&mut spi, &mut reset, &mut busy, &mut Delay)
        .await
        .map_err(RadioInitError::Probe)?;
    let iv = EspInterfaceVariant::sx126x(reset, dio1, busy);
    match family {
        ChipFamily::Sx126x => Ok((
            EitherRadioKind::A(Sx126x::new(
                spi,
                iv,
                sx126x::Config {
                    chip: Sx1262,
                    tcxo_ctrl: Some(sx126x::TcxoCtrlVoltage::Ctrl3V0),
                    use_dcdc: true,
                    rx_boost: true,
                },
            )),
            RadioProfile::sx1262(crate::MODEL_SX1262),
        )),
        ChipFamily::Lr11xx(version) if version.chip_type == ChipType::Lr1121 => Ok((
            EitherRadioKind::B(Lr1110::new(
                spi,
                iv,
                lr1110::Config {
                    chip: Lr1121::with_pa(PaSelection::Hp),
                    tcxo_ctrl: Some(lr1110::TcxoCtrlVoltage::Ctrl3V0),
                    use_dcdc: false,
                    rx_boost: true,
                    rf_switch: Some(RF_SWITCH_LR1121),
                },
            )),
            RadioProfile::lr11xx_hp(crate::MODEL_LR1121),
        )),
        ChipFamily::Lr11xx(version) => Err(RadioInitError::Unsupported(version.chip_type)),
    }
}
