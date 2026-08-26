//! Battery telemetry through the AXP2101.
//!
//! No divider, no gate pin, no ADC calibration curve: the PMIC measures
//! its own battery terminal and runs a fuel gauge (hardware doc §6.3).
//! What this board adds over the ADC boards is a real **charge state** —
//! the PMIC knows whether current is flowing into the cell, which the
//! Heltec V3 had no signal for at all.
//!
//! The gauge's percentage needs learning time and is not gospel right
//! after first boot; [`Reading::percent`] is `None` until the gauge
//! reports something inside 0–100, and the firmware falls back to its
//! OCV table until then. Whether the learned gauge or the OCV estimate
//! is the better steady-state source is a hardware-validation question,
//! deliberately left open here.

use embedded_hal_async::i2c::I2c;
use umsh_pmic_axp2101::{Axp2101, ChargeDirection, ChargeState, Error};

/// One battery observation, assembled from the PMIC's status and ADC
/// registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Battery terminal voltage; `None` with no cell attached.
    pub voltage_mv: Option<u16>,
    /// Fuel-gauge state of charge; `None` with no cell, or while the
    /// gauge is still unlearned.
    pub percent: Option<u8>,
    /// What the charger is doing.
    pub state: ChargeState,
    /// Which way charge is flowing.
    pub direction: ChargeDirection,
    /// Whether USB power is present.
    pub vbus: bool,
}

/// Read the full battery picture in one pass.
pub async fn read<I: I2c>(pmic: &mut Axp2101<I>) -> Result<Reading, Error<I::Error>> {
    Ok(Reading {
        voltage_mv: pmic.battery_millivolts().await?,
        percent: pmic.battery_percent().await?,
        state: pmic.charge_state().await?,
        direction: pmic.charge_direction().await?,
        vbus: pmic.vbus_present().await?,
    })
}
