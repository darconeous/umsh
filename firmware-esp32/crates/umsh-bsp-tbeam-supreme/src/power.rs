//! AXP2101 bring-up: the step that has to run before any peripheral is
//! probed (hardware doc §5.3, §19 step 3).
//!
//! Every output the part has, in one table. A channel this does not
//! name is a channel nobody decided about, left wherever the PMIC's
//! reset default put it — so the ones this board does not use are
//! switched off explicitly rather than merely not switched on:
//!
//! | Output | Load | State after `bring_up` |
//! |---|---|---|
//! | DCDC1 | ESP32-S3 core | untouched — unnameable in the driver |
//! | ALDO3 | SX1262 | on, 3.3 V |
//! | ALDO1 | OLED, BME280, QMC6309 | on, 3.3 V |
//! | ALDO4 | GNSS | configured 3.3 V, **off** — [`crate::gnss::Gnss`] owns it |
//! | BLDO1 | SD card | off — out of scope |
//! | ALDO2, BLDO2 | nothing on this carrier | **off** |
//! | DCDC2–5, DLDO1/2 | nothing on this carrier | **off** |
//! | CPUSLDO | unattributed | untouched — see `UnusedOutput` |
//!
//! The exported-rail entries are the T-Beam S3 Core module's outputs to
//! its carrier, and this carrier takes none of them (§5.2). Switching
//! them off is worth microamps today; it is worth a great deal more
//! once the idle floor is not dominated by a resident BLE controller.
//!
//! On a cold boot the sensor and SD rails are first held down for
//! ~250 ms, reproducing the LILYGO/MeshCore sequence that lets a device
//! caught mid-transaction by an unclean power-down release its bus
//! before anything probes it (§5.3). Warm restarts skip it — the rails
//! were under firmware control the whole time.

use embedded_hal_async::delay::DelayNs;
use embedded_hal_async::i2c::I2c;
use umsh_pmic_axp2101::{
    Axp2101, ChargeCurrent, ChargeLed, ChargeVoltage, Error, IrqMask, PowerOffPress, UnusedOutput,
};

use crate::{GNSS_RAIL, RADIO_RAIL, RAIL_MILLIVOLTS, SD_RAIL, SENSOR_RAIL, UNUSED_RAILS};

/// Charge configuration: 500 mA constant current into a 4.2 V target,
/// the known-working values LILYGO's reference code and MeshCore both
/// ship (§6.2). Do not raise the current merely because the PMIC's range
/// goes higher.
pub const CHARGE_CURRENT: ChargeCurrent = ChargeCurrent::Ma500;
pub const CHARGE_VOLTAGE: ChargeVoltage = ChargeVoltage::V4_2;

/// The interrupt sources the firmware acts on: power-key presses wake
/// the panel, supply/charge transitions re-announce the battery.
pub const IRQS: IrqMask = IrqMask::POWER_KEY_SHORT
    .union(IrqMask::POWER_KEY_LONG)
    .union(IrqMask::VBUS_INSERTED)
    .union(IrqMask::VBUS_REMOVED)
    .union(IrqMask::BATTERY_INSERTED)
    .union(IrqMask::BATTERY_REMOVED)
    .union(IrqMask::CHARGE_STARTED)
    .union(IrqMask::CHARGE_DONE);

/// Probe the PMIC and bring the board's power topology to its known
/// state. Runs before any other peripheral is touched.
///
/// `cold_boot` selects the rail-settle cycle above; pass true for a
/// power-on reset, false for a software or watchdog restart.
pub async fn bring_up<I: I2c, D: DelayNs>(
    pmic: &mut Axp2101<I>,
    delay: &mut D,
    cold_boot: bool,
) -> Result<(), Error<I::Error>> {
    // Refuse to configure rails at a chip that is not an AXP2101 —
    // writing rail registers blind can drive a supply somewhere wrong.
    pmic.probe().await?;

    if cold_boot {
        pmic.cold_boot_cycle(&[SENSOR_RAIL, SD_RAIL], delay).await?;
    }

    // Radio first: ALDO3 wants the longest settle before the SX1262
    // reset that follows bring-up.
    pmic.enable_rail_at(RADIO_RAIL, RAIL_MILLIVOLTS).await?;

    // Display, environmental sensor, and magnetometer share one rail.
    pmic.enable_rail_at(SENSOR_RAIL, RAIL_MILLIVOLTS).await?;

    // GNSS: configured to the right voltage now, switched on only by the
    // pump's `Power` impl when positioning actually runs.
    pmic.set_rail_voltage(GNSS_RAIL, RAIL_MILLIVOLTS).await?;
    pmic.set_rail_enabled(GNSS_RAIL, false).await?;

    // SD stays dark until something ships that uses it.
    pmic.set_rail_enabled(SD_RAIL, false).await?;

    // Everything this carrier does not consume, off explicitly.
    for rail in UNUSED_RAILS {
        pmic.set_rail_enabled(rail, false).await?;
    }
    for output in UnusedOutput::ALL {
        pmic.disable_unused(output).await?;
    }

    pmic.set_charge_current(CHARGE_CURRENT).await?;
    pmic.set_charge_voltage(CHARGE_VOLTAGE).await?;
    // The charge LED means "charging", driven by the charger itself.
    pmic.set_charge_led(ChargeLed::Charger).await?;

    pmic.enable_telemetry().await?;
    // The TS pin is populated on this board (§6.5), so the charger's
    // thermal protection has something real to act on. Whether the part
    // is an NTC or the fixed resistor often fitted in its place is still
    // open — `thermistor_raw` is there to answer it.
    pmic.set_thermistor_measurement(true).await?;

    // Events latched while the MCU was down would hold the IRQ line
    // asserted forever; clear before enabling (§5.5).
    pmic.clear_all_irqs().await?;
    pmic.set_irq_enabled(IRQS).await?;

    // The PMIC's own hard power-off on a 4 s POWER hold — the escape
    // hatch that works even with firmware wedged. MeshCore parity.
    pmic.set_power_off_press(PowerOffPress::S4).await?;

    Ok(())
}

/// Quiesce the switched rails ahead of a software power-off: GNSS and
/// sensor/display supplies down, radio rail down last. The caller has
/// already stopped the tasks that own those peripherals.
pub async fn shutdown_rails<I: I2c>(pmic: &mut Axp2101<I>) -> Result<(), Error<I::Error>> {
    pmic.set_rail_enabled(GNSS_RAIL, false).await?;
    pmic.set_rail_enabled(SENSOR_RAIL, false).await?;
    pmic.set_rail_enabled(SD_RAIL, false).await?;
    pmic.set_rail_enabled(RADIO_RAIL, false).await?;
    Ok(())
}
