//! Board BSP for the LILYGO T-Beam Supreme (ESP32-S3FN8 + SX1262 +
//! AXP2101 + SH1106 OLED + L76K/u-blox GNSS).
//!
//! See `docs/hardware/lilygo-t-beam-supreme-hardware.md` for the
//! authoritative hardware reference. Pin numbers here are GPIO numbers.
//!
//! The constraint that shapes everything on this board: **peripherals
//! sit behind AXP2101 rails, not a fixed 3.3 V plane** (hardware doc
//! §5.3). The radio, GNSS, display, and sensors are dead until their
//! rail is up, and a failed probe usually means "rail off", not
//! "part absent". [`power::bring_up`] runs first; nothing else is
//! touched before it.
//!
//! Other shared-resource constraints (hardware doc §14–16):
//! - The POWER button is the AXP2101's power key, not a GPIO. Power-off
//!   is a PMIC operation ([`umsh_pmic_axp2101::Axp2101::power_off`]) and
//!   power-on needs no firmware at all.
//! - GPIO6 carries GNSS PPS and drives the PPS LED directly; it is not
//!   a user LED and nothing here treats it as one.
//! - The charge LED belongs to the PMIC's charge logic (§6.4, §14.5).
//!   There is **no** firmware-owned status LED on this board.
//! - GPIO0 is the BOOT button and a strapping pin; read only after boot.
//! - GPIO19/20 carry native USB; never claim them.
//! - Two I²C buses: sensors/display on 17/18, PMU/RTC on 42/41. The
//!   Arduino `Wire`/`Wire1` naming in vendor code is not board truth
//!   (§8.3); either controller can serve either pin pair.
#![no_std]

pub mod battery;
pub mod display;
pub mod gnss;
pub mod platform;
pub mod power;
pub mod radio;

pub use umsh_pmic_axp2101::Rail;

/// Carries the radio, unlike the Heltec board names: the Supreme ships
/// in SX1262 and LR1121 populations that are otherwise the same board,
/// and only the SX1262 one runs this image (hardware doc §20).
pub const BOARD_NAME: &str = "LILYGO T-Beam Supreme SX1262";

// SX1262 radio: a dedicated SPI bus (not shared with the SD/IMU bus).
// DIO2 drives the RF switch and DIO3 the TCXO supply from inside the
// radio — mandatory driver configuration, not tuning (hardware doc
// §4.6–4.7). The radio is dead until ALDO3 is up.
pub const LORA_SCK: u8 = 12;
pub const LORA_MOSI: u8 = 11;
pub const LORA_MISO: u8 = 13;
pub const LORA_NSS: u8 = 10;
pub const LORA_RESET: u8 = 5;
pub const LORA_BUSY: u8 = 4;
pub const LORA_DIO1: u8 = 1;

// Sensor/display I²C bus. SH1106 at 0x3C or 0x3D depending on the
// magnetometer population — probed, never assumed (§2.4, §9.2). Also
// carries the BME280 (0x77/0x76) and magnetometer, both out of scope.
// Dead until ALDO1/ALDO2 are up.
pub const SENSOR_I2C_SDA: u8 = 17;
pub const SENSOR_I2C_SCL: u8 = 18;

// PMU/RTC I²C bus: AXP2101 at 0x34, PCF8563-compatible RTC at 0x51.
// Powered always — this bus is what turns everything else on.
pub const PMU_I2C_SDA: u8 = 42;
pub const PMU_I2C_SCL: u8 = 41;
/// AXP2101 interrupt, active low, needs a pull-up (§5.5).
pub const PMU_IRQ: u8 = 40;
/// RTC interrupt (§13.3). Documented for completeness; alarms are not
/// implemented and nothing claims this pin.
pub const RTC_INT: u8 = 14;

// GNSS UART, named by HOST direction (the family rule: `GNSS_UART_RX`
// is the MCU's RX and carries NMEA). Vendor `PIN_GPS_*` macros read
// backwards on this board (§7.2); do not "correct" these from them.
pub const GNSS_UART_RX: u8 = 9;
pub const GNSS_UART_TX: u8 = 8;
/// GNSS PPS input. Also hard-wired to the PPS LED (§7.5); reserved,
/// unused today.
pub const GNSS_PPS: u8 = 6;
/// L76K wake/control. Documented for the L76K population only — the
/// u-blox population's GPIO7 behavior is unverified (§7.4).
pub const GNSS_WAKE: u8 = 7;
pub const GNSS_BAUD: u32 = 9600;

/// BOOT button: active low, shared with the boot strap.
pub const USER_BUTTON: u8 = 0;

// SD card + QMI8658 IMU shared SPI bus (§12) — out of scope, pins
// recorded so nothing repurposes them: SCK=36, MOSI=35, MISO=37,
// SD CS=47 (rail BLDO1), IMU CS=34, IMU INT=33.

// External/QWIIC UART (§15), distinct from the GNSS UART. Unused.
pub const EXT_UART_TX: u8 = 43;
pub const EXT_UART_RX: u8 = 44;

// ─── Rail topology (hardware doc §5.2, §18.8) ─────────────────────────────
//
// The AXP2101 sits on the T-Beam S3 Core module, not on the carrier, so
// DCDC3/4/5 and BLDO2 are outputs the module *exports* to whatever
// carrier it is plugged into. This carrier consumes none of them, which
// is why they appear in [`UNUSED_RAILS`] and `UnusedOutput::ALL` rather
// than in the table below. A different carrier would want a different
// BSP, not a different driver.
//
// DCDC1 is the ESP32-S3 core supply and no type in the driver can name
// it.

/// SX1262 supply.
pub const RADIO_RAIL: Rail = Rail::Aldo3;
/// GNSS supply. Owned by [`gnss::Gnss`] — nothing else toggles it.
pub const GNSS_RAIL: Rail = Rail::Aldo4;
/// OLED + BME280 + QMC6309 magnetometer, all three confirmed against the
/// schematic on this one rail.
pub const SENSOR_RAIL: Rail = Rail::Aldo1;
/// SD card supply. Off — the SD card is out of scope.
pub const SD_RAIL: Rail = Rail::Bldo1;

/// Switchable rails this carrier does not consume.
///
/// ALDO2 is the interesting one: LILYGO's own code and MeshCore both
/// bring it up, and Meshtastic's comment claims it "cannot be turned
/// off". The schematic says otherwise — nothing on this carrier is on
/// it — so it goes off, and the failure mode if that reading is wrong
/// is a dead sensor bus, which the display and BME280 probes will
/// report immediately.
pub const UNUSED_RAILS: [Rail; 2] = [Rail::Aldo2, Rail::Bldo2];

/// Every switched rail this board runs at 3.3 V.
pub const RAIL_MILLIVOLTS: u16 = 3300;
