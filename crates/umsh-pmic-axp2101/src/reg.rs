//! AXP2101 register map — only the registers UMSH touches.
//!
//! Values are transcribed from the AXP2101 datasheet and cross-checked
//! against X-Powers' own `XPowersLib` (`src/REG/AXP2101Constants.h` and
//! `src/XPowersAXP2101.hpp`), which is what LILYGO, Meshtastic, and
//! MeshCore all drive this part with. Where the two agreed the value is
//! recorded here; where a bit position is only implied by a library
//! accessor, the accessor is named in the comment so the next reader can
//! re-derive it.
//!
//! Nothing here is proven until a board answers. Transcription is the
//! single largest hardware-validation item in this driver.

/// The AXP2101's fixed 7-bit I²C address.
pub const DEFAULT_ADDRESS: u8 = 0x34;

/// Value `IC_TYPE` reports on an AXP2101.
pub const CHIP_ID: u8 = 0x4A;

// ─── Status ───────────────────────────────────────────────────────────────

/// Power/source status. Bit 3 = battery present, bit 5 = VBUS good.
pub const STATUS1: u8 = 0x00;
/// Charger status. Bits [2:0] = charge state, bits [6:5] = direction.
pub const STATUS2: u8 = 0x01;
pub const IC_TYPE: u8 = 0x03;

pub const STATUS1_BATTERY_PRESENT: u8 = 3;
pub const STATUS1_VBUS_GOOD: u8 = 5;

/// Mask selecting the charge-state field of [`STATUS2`].
pub const STATUS2_CHARGE_STATE_MASK: u8 = 0x07;
/// Shift to the charge-direction field of [`STATUS2`]: 0 standby,
/// 1 charging, 2 discharging.
pub const STATUS2_DIRECTION_SHIFT: u8 = 5;
pub const STATUS2_DIRECTION_MASK: u8 = 0x03;
pub const DIRECTION_STANDBY: u8 = 0x00;
pub const DIRECTION_CHARGING: u8 = 0x01;
pub const DIRECTION_DISCHARGING: u8 = 0x02;

// ─── Common configuration ─────────────────────────────────────────────────

/// Bit 0 is the software power-off request.
pub const COMMON_CONFIG: u8 = 0x10;
pub const COMMON_CONFIG_SOFT_POWEROFF: u8 = 0;

/// Power-key press timing. Bits [1:0] power-on press, bits [3:2]
/// power-off press (`setPowerKeyPressOnTime`/`OffTime`).
pub const IRQ_OFF_ON_LEVEL_CTRL: u8 = 0x27;
pub const PRESS_ON_MASK: u8 = 0x03;
pub const PRESS_OFF_SHIFT: u8 = 2;
pub const PRESS_OFF_MASK: u8 = 0x0C;

// ─── ADC ──────────────────────────────────────────────────────────────────

/// ADC channel enables: bit 0 VBAT, 1 TS, 2 VBUS, 3 VSYS, 4 TDIE.
pub const ADC_CHANNEL_CTRL: u8 = 0x30;
pub const ADC_CH_VBAT: u8 = 0;
pub const ADC_CH_VBUS: u8 = 2;
pub const ADC_CH_VSYS: u8 = 3;

/// VBAT result, high byte. 5 significant bits, then an 8-bit low byte.
pub const ADC_VBAT_H: u8 = 0x34;
pub const ADC_VBAT_L: u8 = 0x35;
/// VBUS result, high byte. 6 significant bits.
pub const ADC_VBUS_H: u8 = 0x38;
pub const ADC_VBUS_L: u8 = 0x39;
/// VSYS result, high byte. 6 significant bits.
pub const ADC_VSYS_H: u8 = 0x3A;
pub const ADC_VSYS_L: u8 = 0x3B;

pub const ADC_H5_MASK: u8 = 0x1F;
pub const ADC_H6_MASK: u8 = 0x3F;

// ─── Interrupts ───────────────────────────────────────────────────────────

/// IRQ enables, one register per IRQ byte.
pub const INTEN: [u8; 3] = [0x40, 0x41, 0x42];
/// IRQ status, write-1-to-clear, same byte order as [`INTEN`].
pub const INTSTS: [u8; 3] = [0x48, 0x49, 0x4A];

// ─── Charger ──────────────────────────────────────────────────────────────

/// Constant-charge current. Bits [4:0]; high bits reserved.
pub const ICC_CHG_SET: u8 = 0x62;
pub const ICC_CHG_MASK: u8 = 0x1F;

/// Charge target voltage. Bits [2:0].
pub const CV_CHG_VOL_SET: u8 = 0x64;
pub const CV_CHG_MASK: u8 = 0x07;

/// Charge-LED control. Bits [1:0] select the source, [5:4] the manual
/// pattern (`setChargingLedMode`).
pub const CHGLED_SET_CTRL: u8 = 0x69;
/// Preserved bits when writing a manual LED pattern.
pub const CHGLED_MANUAL_KEEP: u8 = 0xC8;
/// Source select for manual control.
pub const CHGLED_MANUAL_CTRL: u8 = 0x05;
/// Preserved bits when handing the LED back to the charger.
pub const CHGLED_CHARGER_KEEP: u8 = 0xF9;
/// Source select for charger-driven control (type A).
pub const CHGLED_CHARGER_CTRL: u8 = 0x01;
pub const CHGLED_PATTERN_SHIFT: u8 = 4;

// ─── Rails ────────────────────────────────────────────────────────────────

/// DCDC1–5 enables. **Read-only to UMSH**: DCDC1 is the ESP32-S3 core
/// supply on the T-Beam Supreme and writing this register can cut power
/// to the running MCU (hardware doc §5.2, §18.9).
pub const DC_ONOFF_DVM_CTRL: u8 = 0x80;

/// LDO enables: bit 0 ALDO1, 1 ALDO2, 2 ALDO3, 3 ALDO4, 4 BLDO1,
/// 5 BLDO2.
pub const LDO_ONOFF_CTRL0: u8 = 0x90;

/// Per-rail voltage registers, in [`LDO_ONOFF_CTRL0`] bit order.
pub const ALDO1_VOL: u8 = 0x92;
pub const ALDO2_VOL: u8 = 0x93;
pub const ALDO3_VOL: u8 = 0x94;
pub const ALDO4_VOL: u8 = 0x95;
pub const BLDO1_VOL: u8 = 0x96;
pub const BLDO2_VOL: u8 = 0x97;

/// Voltage field of an A/BLDO voltage register; the top three bits are
/// reserved and preserved on write.
pub const LDO_VOL_MASK: u8 = 0x1F;

/// A/BLDO output range, in millivolts.
pub const LDO_VOL_MIN_MV: u16 = 500;
pub const LDO_VOL_MAX_MV: u16 = 3500;
pub const LDO_VOL_STEP_MV: u16 = 100;

// ─── Fuel gauge ───────────────────────────────────────────────────────────

/// Battery state of charge, whole percent.
pub const BAT_PERCENT_DATA: u8 = 0xA4;
