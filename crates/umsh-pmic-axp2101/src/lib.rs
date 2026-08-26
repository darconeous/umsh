//! X-Powers AXP2101 PMIC, async, over `embedded-hal-async` I²C.
//!
//! On a board like the LILYGO T-Beam Supreme the PMIC is not a telemetry
//! peripheral, it is prerequisite hardware: the radio, GNSS, display,
//! sensors, and SD card each sit behind a rail this chip switches. A
//! failed I²C probe of any of them usually means the rail is still off,
//! not that the part is missing (hardware doc §5.3). So a board brings
//! this driver up before it probes anything else.
//!
//! The surface here is deliberately narrow — rails, charging, telemetry,
//! interrupts, and the power key. The AXP2101 does considerably more
//! (JEITA profiles, watchdogs, sleep sequencing, DLDO/CPUSLDO rails);
//! none of it is reachable through UMSH, so none of it is transcribed.
//!
//! **DCDC1 is never written.** On the boards UMSH supports it is the MCU
//! core supply, and the enable register that holds it is exposed for
//! reading only.
//!
//! Register provenance and the transcription caveat: see [`reg`].

#![no_std]

use embedded_hal_async::delay::DelayNs;
use embedded_hal_async::i2c::I2c;

pub mod reg;

#[cfg(test)]
mod tests;

pub use reg::{CHIP_ID, DEFAULT_ADDRESS};

/// How long the LILYGO and MeshCore bring-ups hold the sensor and SD
/// rails down on a cold boot, so a device that latched onto a bus during
/// an unclean shutdown lets go before anything probes it.
pub const COLD_BOOT_SETTLE_MS: u32 = 250;

// ─── Rails ────────────────────────────────────────────────────────────────

/// A switchable low-dropout rail.
///
/// The DCDC rails are absent on purpose: DCDC1 is the MCU core supply,
/// and the rest feed expansion interfaces no UMSH board owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rail {
    Aldo1,
    Aldo2,
    Aldo3,
    Aldo4,
    Bldo1,
    Bldo2,
}

impl Rail {
    /// This rail's bit in [`reg::LDO_ONOFF_CTRL0`].
    pub const fn enable_bit(self) -> u8 {
        match self {
            Rail::Aldo1 => 0,
            Rail::Aldo2 => 1,
            Rail::Aldo3 => 2,
            Rail::Aldo4 => 3,
            Rail::Bldo1 => 4,
            Rail::Bldo2 => 5,
        }
    }

    /// This rail's voltage register.
    pub const fn voltage_reg(self) -> u8 {
        match self {
            Rail::Aldo1 => reg::ALDO1_VOL,
            Rail::Aldo2 => reg::ALDO2_VOL,
            Rail::Aldo3 => reg::ALDO3_VOL,
            Rail::Aldo4 => reg::ALDO4_VOL,
            Rail::Bldo1 => reg::BLDO1_VOL,
            Rail::Bldo2 => reg::BLDO2_VOL,
        }
    }
}

/// Encode a rail voltage into its register field, rejecting values off
/// the 100 mV grid or outside the part's range.
pub const fn encode_rail_mv(millivolts: u16) -> Option<u8> {
    if millivolts < reg::LDO_VOL_MIN_MV
        || millivolts > reg::LDO_VOL_MAX_MV
        || (millivolts - reg::LDO_VOL_MIN_MV) % reg::LDO_VOL_STEP_MV != 0
    {
        return None;
    }
    Some(((millivolts - reg::LDO_VOL_MIN_MV) / reg::LDO_VOL_STEP_MV) as u8)
}

/// Decode a rail voltage register field back to millivolts.
pub const fn decode_rail_mv(field: u8) -> u16 {
    (field & reg::LDO_VOL_MASK) as u16 * reg::LDO_VOL_STEP_MV + reg::LDO_VOL_MIN_MV
}

// ─── Charger ──────────────────────────────────────────────────────────────

/// Constant-charge current settings. The gap below 100 mA is the part's:
/// codes 1–3 are not current steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChargeCurrent {
    Off = 0,
    Ma100 = 4,
    Ma125 = 5,
    Ma150 = 6,
    Ma175 = 7,
    Ma200 = 8,
    Ma300 = 9,
    Ma400 = 10,
    Ma500 = 11,
    Ma600 = 12,
    Ma700 = 13,
    Ma800 = 14,
    Ma900 = 15,
    Ma1000 = 16,
}

/// Charge termination voltage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChargeVoltage {
    V4_0 = 1,
    V4_1 = 2,
    V4_2 = 3,
    V4_35 = 4,
    V4_4 = 5,
}

/// What the charger is doing, from [`reg::STATUS2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeState {
    Trickle,
    Precharge,
    ConstantCurrent,
    ConstantVoltage,
    Done,
    NotCharging,
    /// A code the datasheet does not assign.
    Unknown(u8),
}

impl ChargeState {
    fn from_field(field: u8) -> Self {
        match field & reg::STATUS2_CHARGE_STATE_MASK {
            0 => ChargeState::Trickle,
            1 => ChargeState::Precharge,
            2 => ChargeState::ConstantCurrent,
            3 => ChargeState::ConstantVoltage,
            4 => ChargeState::Done,
            5 => ChargeState::NotCharging,
            other => ChargeState::Unknown(other),
        }
    }

    /// Whether current is actually going into the cell.
    pub fn is_charging(self) -> bool {
        matches!(
            self,
            ChargeState::Trickle
                | ChargeState::Precharge
                | ChargeState::ConstantCurrent
                | ChargeState::ConstantVoltage
        )
    }
}

/// Which way charge is flowing, from the direction field of
/// [`reg::STATUS2`]. Distinct from [`ChargeState`]: a full battery on
/// USB power reports `Standby` while its charge state reads `Done`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeDirection {
    Standby,
    Charging,
    Discharging,
    Unknown(u8),
}

/// Who drives the charge LED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeLed {
    /// The charger drives it — the board's default, and what LILYGO
    /// ships. Prefer this: the LED is wired to the PMIC's charge logic,
    /// not to a free GPIO, so firmware "status LED" use of it is a lie
    /// about what the light means (hardware doc §6.4, §14.5).
    Charger,
    Off,
    Blink1Hz,
    Blink4Hz,
    On,
}

// ─── Interrupts ───────────────────────────────────────────────────────────

/// AXP2101 interrupt sources, as a 24-bit mask across the three IRQ
/// registers. Only the events a UMSH board acts on are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqMask(pub u32);

impl IrqMask {
    pub const NONE: IrqMask = IrqMask(0);
    /// Every bit the part defines — used to clear stale status at boot.
    pub const ALL: IrqMask = IrqMask(0x00FF_FFFF);

    // Register 0x41.
    pub const POWER_KEY_LONG: IrqMask = IrqMask(1 << 10);
    pub const POWER_KEY_SHORT: IrqMask = IrqMask(1 << 11);
    pub const BATTERY_REMOVED: IrqMask = IrqMask(1 << 12);
    pub const BATTERY_INSERTED: IrqMask = IrqMask(1 << 13);
    pub const VBUS_REMOVED: IrqMask = IrqMask(1 << 14);
    pub const VBUS_INSERTED: IrqMask = IrqMask(1 << 15);

    // Register 0x42.
    pub const CHARGE_STARTED: IrqMask = IrqMask(1 << 19);
    pub const CHARGE_DONE: IrqMask = IrqMask(1 << 20);

    pub const fn union(self, other: IrqMask) -> IrqMask {
        IrqMask(self.0 | other.0)
    }

    pub const fn contains(self, other: IrqMask) -> bool {
        self.0 & other.0 == other.0 && other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn bytes(self) -> [u8; 3] {
        [self.0 as u8, (self.0 >> 8) as u8, (self.0 >> 16) as u8]
    }

    fn from_bytes(bytes: [u8; 3]) -> Self {
        IrqMask(bytes[0] as u32 | (bytes[1] as u32) << 8 | (bytes[2] as u32) << 16)
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The bus refused the transfer.
    Bus(E),
    /// `IC_TYPE` did not read back [`CHIP_ID`].
    WrongChip(u8),
    /// A voltage was off the 100 mV grid or outside the part's range.
    UnsupportedVoltage(u16),
}

impl<E> From<E> for Error<E> {
    fn from(e: E) -> Self {
        Error::Bus(e)
    }
}

type Result<T, E> = core::result::Result<T, Error<E>>;

// ─── Driver ───────────────────────────────────────────────────────────────

pub struct Axp2101<I> {
    i2c: I,
    addr: u8,
}

impl<I: I2c> Axp2101<I> {
    /// Bind the PMIC at the standard address.
    pub fn new(i2c: I) -> Self {
        Self::with_address(i2c, DEFAULT_ADDRESS)
    }

    pub fn with_address(i2c: I, addr: u8) -> Self {
        Self { i2c, addr }
    }

    pub fn release(self) -> I {
        self.i2c
    }

    // ── Register access ──

    async fn read(&mut self, register: u8) -> Result<u8, I::Error> {
        let mut buf = [0u8; 1];
        self.i2c
            .write_read(self.addr, &[register], &mut buf)
            .await?;
        Ok(buf[0])
    }

    async fn write(&mut self, register: u8, value: u8) -> Result<(), I::Error> {
        self.i2c.write(self.addr, &[register, value]).await?;
        Ok(())
    }

    /// Read-modify-write, preserving every bit outside `mask`.
    async fn update(&mut self, register: u8, mask: u8, value: u8) -> Result<(), I::Error> {
        let current = self.read(register).await?;
        let next = (current & !mask) | (value & mask);
        self.write(register, next).await
    }

    async fn set_bit(&mut self, register: u8, bit: u8, on: bool) -> Result<(), I::Error> {
        self.update(register, 1 << bit, if on { 1 << bit } else { 0 })
            .await
    }

    async fn get_bit(&mut self, register: u8, bit: u8) -> Result<bool, I::Error> {
        Ok(self.read(register).await? & (1 << bit) != 0)
    }

    /// Assemble a two-register ADC result: `mask` significant bits of the
    /// high register above a full low byte.
    async fn read_adc(&mut self, high: u8, low: u8, mask: u8) -> Result<u16, I::Error> {
        let h = self.read(high).await?;
        let l = self.read(low).await?;
        Ok(((h & mask) as u16) << 8 | l as u16)
    }

    // ── Identity ──

    /// Read `IC_TYPE`.
    pub async fn chip_id(&mut self) -> Result<u8, I::Error> {
        self.read(reg::IC_TYPE).await
    }

    /// Confirm an AXP2101 is answering. Call before touching any rail:
    /// writing rail registers at a chip that is not this one can drive a
    /// supply to the wrong voltage.
    pub async fn probe(&mut self) -> Result<(), I::Error> {
        let id = self.chip_id().await?;
        if id == CHIP_ID {
            Ok(())
        } else {
            Err(Error::WrongChip(id))
        }
    }

    // ── Rails ──

    pub async fn rail_enabled(&mut self, rail: Rail) -> Result<bool, I::Error> {
        self.get_bit(reg::LDO_ONOFF_CTRL0, rail.enable_bit()).await
    }

    pub async fn set_rail_enabled(&mut self, rail: Rail, on: bool) -> Result<(), I::Error> {
        self.set_bit(reg::LDO_ONOFF_CTRL0, rail.enable_bit(), on)
            .await
    }

    pub async fn set_rail_voltage(&mut self, rail: Rail, millivolts: u16) -> Result<(), I::Error> {
        let field = encode_rail_mv(millivolts).ok_or(Error::UnsupportedVoltage(millivolts))?;
        self.update(rail.voltage_reg(), reg::LDO_VOL_MASK, field)
            .await
    }

    pub async fn rail_voltage(&mut self, rail: Rail) -> Result<u16, I::Error> {
        Ok(decode_rail_mv(self.read(rail.voltage_reg()).await?))
    }

    /// Set a rail's voltage and switch it on, in that order — bringing a
    /// rail up at whatever the previous session left configured can
    /// overvolt what is behind it.
    pub async fn enable_rail_at(&mut self, rail: Rail, millivolts: u16) -> Result<(), I::Error> {
        self.set_rail_voltage(rail, millivolts).await?;
        self.set_rail_enabled(rail, true).await
    }

    /// Drop the given rails, wait [`COLD_BOOT_SETTLE_MS`], and leave them
    /// off.
    ///
    /// LILYGO's board init and MeshCore both do this on a cold boot so a
    /// peripheral that was mid-transaction when power was cut releases
    /// the bus before anything probes it. Restore the rails afterwards
    /// with [`enable_rail_at`](Self::enable_rail_at).
    pub async fn cold_boot_cycle<D: DelayNs>(
        &mut self,
        rails: &[Rail],
        delay: &mut D,
    ) -> Result<(), I::Error> {
        for &rail in rails {
            self.set_rail_enabled(rail, false).await?;
        }
        delay.delay_ms(COLD_BOOT_SETTLE_MS).await;
        Ok(())
    }

    // ── Charger ──

    pub async fn set_charge_current(&mut self, current: ChargeCurrent) -> Result<(), I::Error> {
        self.update(reg::ICC_CHG_SET, reg::ICC_CHG_MASK, current as u8)
            .await
    }

    pub async fn set_charge_voltage(&mut self, voltage: ChargeVoltage) -> Result<(), I::Error> {
        self.update(reg::CV_CHG_VOL_SET, reg::CV_CHG_MASK, voltage as u8)
            .await
    }

    pub async fn set_charge_led(&mut self, mode: ChargeLed) -> Result<(), I::Error> {
        let (keep, value) = match mode {
            ChargeLed::Charger => (reg::CHGLED_CHARGER_KEEP, reg::CHGLED_CHARGER_CTRL),
            ChargeLed::Off => (reg::CHGLED_MANUAL_KEEP, reg::CHGLED_MANUAL_CTRL),
            ChargeLed::Blink1Hz => (
                reg::CHGLED_MANUAL_KEEP,
                reg::CHGLED_MANUAL_CTRL | (1 << reg::CHGLED_PATTERN_SHIFT),
            ),
            ChargeLed::Blink4Hz => (
                reg::CHGLED_MANUAL_KEEP,
                reg::CHGLED_MANUAL_CTRL | (2 << reg::CHGLED_PATTERN_SHIFT),
            ),
            ChargeLed::On => (
                reg::CHGLED_MANUAL_KEEP,
                reg::CHGLED_MANUAL_CTRL | (3 << reg::CHGLED_PATTERN_SHIFT),
            ),
        };
        let current = self.read(reg::CHGLED_SET_CTRL).await?;
        self.write(reg::CHGLED_SET_CTRL, (current & keep) | value)
            .await
    }

    pub async fn charge_state(&mut self) -> Result<ChargeState, I::Error> {
        Ok(ChargeState::from_field(self.read(reg::STATUS2).await?))
    }

    pub async fn charge_direction(&mut self) -> Result<ChargeDirection, I::Error> {
        let field = (self.read(reg::STATUS2).await? >> reg::STATUS2_DIRECTION_SHIFT)
            & reg::STATUS2_DIRECTION_MASK;
        Ok(match field {
            reg::DIRECTION_STANDBY => ChargeDirection::Standby,
            reg::DIRECTION_CHARGING => ChargeDirection::Charging,
            reg::DIRECTION_DISCHARGING => ChargeDirection::Discharging,
            other => ChargeDirection::Unknown(other),
        })
    }

    // ── Telemetry ──

    /// Enable the battery, VBUS, and system voltage ADC channels.
    ///
    /// The TS (battery thermistor) channel is left alone: on boards that
    /// do not populate a thermistor, enabling it makes the charger act on
    /// a floating input.
    pub async fn enable_telemetry(&mut self) -> Result<(), I::Error> {
        for bit in [reg::ADC_CH_VBAT, reg::ADC_CH_VBUS, reg::ADC_CH_VSYS] {
            self.set_bit(reg::ADC_CHANNEL_CTRL, bit, true).await?;
        }
        Ok(())
    }

    pub async fn battery_present(&mut self) -> Result<bool, I::Error> {
        self.get_bit(reg::STATUS1, reg::STATUS1_BATTERY_PRESENT)
            .await
    }

    pub async fn vbus_present(&mut self) -> Result<bool, I::Error> {
        self.get_bit(reg::STATUS1, reg::STATUS1_VBUS_GOOD).await
    }

    /// Battery voltage in millivolts, or `None` with no cell attached —
    /// the ADC reads a meaningless value rather than nothing.
    pub async fn battery_millivolts(&mut self) -> Result<Option<u16>, I::Error> {
        if !self.battery_present().await? {
            return Ok(None);
        }
        Ok(Some(
            self.read_adc(reg::ADC_VBAT_H, reg::ADC_VBAT_L, reg::ADC_H5_MASK)
                .await?,
        ))
    }

    /// VBUS voltage in millivolts, or `None` when nothing is plugged in.
    pub async fn vbus_millivolts(&mut self) -> Result<Option<u16>, I::Error> {
        if !self.vbus_present().await? {
            return Ok(None);
        }
        Ok(Some(
            self.read_adc(reg::ADC_VBUS_H, reg::ADC_VBUS_L, reg::ADC_H6_MASK)
                .await?,
        ))
    }

    /// System voltage in millivolts.
    pub async fn system_millivolts(&mut self) -> Result<u16, I::Error> {
        self.read_adc(reg::ADC_VSYS_H, reg::ADC_VSYS_L, reg::ADC_H6_MASK)
            .await
    }

    /// Fuel-gauge state of charge, whole percent.
    ///
    /// `None` with no cell attached, and also when the gauge reports a
    /// value outside 0–100 — it returns 0xFF until it has learned the
    /// pack, which a caller must not show as 255%.
    pub async fn battery_percent(&mut self) -> Result<Option<u8>, I::Error> {
        if !self.battery_present().await? {
            return Ok(None);
        }
        let raw = self.read(reg::BAT_PERCENT_DATA).await?;
        Ok(if raw <= 100 { Some(raw) } else { None })
    }

    // ── Interrupts ──

    /// Clear every latched IRQ status bit.
    ///
    /// Do this before enabling interrupts at boot: the part latches
    /// events from before the MCU was running, and an unhandled latched
    /// bit holds the IRQ line asserted so no edge ever arrives.
    pub async fn clear_all_irqs(&mut self) -> Result<(), I::Error> {
        for register in reg::INTSTS {
            self.write(register, 0xFF).await?;
        }
        Ok(())
    }

    /// Replace the enabled-interrupt set.
    pub async fn set_irq_enabled(&mut self, mask: IrqMask) -> Result<(), I::Error> {
        for (register, byte) in reg::INTEN.iter().zip(mask.bytes()) {
            self.write(*register, byte).await?;
        }
        Ok(())
    }

    /// Read the latched interrupt status without clearing it.
    pub async fn irq_status(&mut self) -> Result<IrqMask, I::Error> {
        let mut bytes = [0u8; 3];
        for (slot, register) in bytes.iter_mut().zip(reg::INTSTS) {
            *slot = self.read(register).await?;
        }
        Ok(IrqMask::from_bytes(bytes))
    }

    /// Read the latched interrupt status and clear exactly the bits that
    /// were read, so an event arriving mid-call is not lost.
    pub async fn take_irqs(&mut self) -> Result<IrqMask, I::Error> {
        let mut bytes = [0u8; 3];
        for (slot, register) in bytes.iter_mut().zip(reg::INTSTS) {
            *slot = self.read(register).await?;
        }
        for (register, byte) in reg::INTSTS.iter().zip(bytes) {
            if byte != 0 {
                self.write(*register, byte).await?;
            }
        }
        Ok(IrqMask::from_bytes(bytes))
    }

    // ── Power key ──

    /// How long the POWER key must be held to power the board on.
    pub async fn set_power_on_press(&mut self, press: PowerOnPress) -> Result<(), I::Error> {
        self.update(reg::IRQ_OFF_ON_LEVEL_CTRL, reg::PRESS_ON_MASK, press as u8)
            .await
    }

    /// How long the POWER key must be held to force the board off. This
    /// is the PMIC's own hard power-off, independent of any firmware
    /// gesture.
    pub async fn set_power_off_press(&mut self, press: PowerOffPress) -> Result<(), I::Error> {
        self.update(
            reg::IRQ_OFF_ON_LEVEL_CTRL,
            reg::PRESS_OFF_MASK,
            (press as u8) << reg::PRESS_OFF_SHIFT,
        )
        .await
    }

    /// Ask the PMIC to cut power.
    ///
    /// Returns once the request is written; the rails fall shortly after,
    /// so a caller must not expect execution to continue meaningfully.
    /// The board comes back with a POWER key press — no firmware runs in
    /// between.
    pub async fn power_off(&mut self) -> Result<(), I::Error> {
        self.set_bit(reg::COMMON_CONFIG, reg::COMMON_CONFIG_SOFT_POWEROFF, true)
            .await
    }
}

/// POWER-key hold needed to switch the board on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerOnPress {
    Ms128 = 0,
    Ms512 = 1,
    S1 = 2,
    S2 = 3,
}

/// POWER-key hold needed to force the board off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerOffPress {
    S4 = 0,
    S6 = 1,
    S8 = 2,
    S10 = 3,
}
