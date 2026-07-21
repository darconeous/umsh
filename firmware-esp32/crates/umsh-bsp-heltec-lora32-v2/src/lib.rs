//! Board BSP for the Heltec WiFi LoRa 32 V2 (classic ESP32 + SX1276/78 +
//! SSD1306 OLED).
//!
//! See `docs/heltec-lora32-v2-hardware.md` for the authoritative hardware
//! reference and `docs/firmware-plan-heltec-lora32-v2.md` for the bring-up
//! plan. Pin numbers here are GPIO numbers.
//!
//! Shared-resource constraints encoded in types:
//! - `Vext` (GPIO21, active high) gates BOTH the OLED supply and the battery
//!   divider — [`vext::Vext`] is the one owned handle, and both
//!   [`display`] bring-up and [`battery::BatterySampler`] borrow it.
//! - GPIO34/35 are input-only.
//! - GPIO0 is a strapping pin shared with the user button.
//! - UART0 (GPIO1/3) is shared with the CP2102 USB bridge.
#![no_std]

pub mod battery;
pub mod display;
pub mod radio;
pub mod vext;

pub const BOARD_NAME: &str = "Heltec WiFi LoRa 32 V2";

// SX1276/78 radio (SPI + control). No BUSY pin; the on-board RF switch is
// driven by the radio's RXTX output, so the InterfaceVariant treats
// busy-wait and RF-switch control as no-ops.
pub const LORA_SCK: u8 = 5;
pub const LORA_MOSI: u8 = 27;
pub const LORA_MISO: u8 = 19;
pub const LORA_NSS: u8 = 18;
pub const LORA_RESET: u8 = 14;
pub const LORA_DIO0: u8 = 26;
/// Input-only pin; wired but unused (DIO0 carries all IRQs we need).
pub const LORA_DIO1: u8 = 35;
/// Input-only pin; unused.
pub const LORA_DIO2: u8 = 34;

// SSD1306 128x64 I2C OLED, powered from Vext. Full power-up sequence
// (Vext up -> reset pulse -> init) required after every Vext cycle.
pub const OLED_SDA: u8 = 4;
pub const OLED_SCL: u8 = 15;
pub const OLED_RESET: u8 = 16;
pub const OLED_I2C_ADDR: u8 = 0x3C;

/// User button: active low, external pull-up, shared with the boot strap.
pub const USER_BUTTON: u8 = 0;

/// White status LED, active high.
pub const STATUS_LED: u8 = 25;

/// Vext enable, active high. Gates the OLED supply AND the battery divider.
pub const VEXT_ENABLE: u8 = 21;

/// Battery sense: ADC2 channel on GPIO13, divider ratio ~3.2, valid only
/// while Vext is enabled. ADC2 conflicts with Wi-Fi (never enabled here);
/// coexistence with the BLE controller is re-verified in Phase 4.
pub const BATTERY_ADC: u8 = 13;
pub const BATTERY_DIVIDER_RATIO_X10: u16 = 32;
