//! Board BSP for the Heltec WiFi LoRa 32 V3 (ESP32-S3FN8 + SX1262 +
//! SSD1306 OLED).
//!
//! See `docs/heltec-lora32-v3-hardware.md` for the authoritative hardware
//! reference and `docs/firmware-plan-heltec-lora32-v3.md` for the bring-up
//! plan. Pin numbers here are GPIO numbers.
//!
//! Shared-resource constraints encoded in types (hardware doc §16):
//! - `Vext` (GPIO36, **ACTIVE LOW** — the opposite of the Heltec V2)
//!   powers the OLED; the board pull-up defaults the rail OFF until
//!   firmware drives the pin low. [`vext::Vext`] hides the polarity.
//! - GPIO37 gates the battery divider (its own pin — NOT the `Vext`
//!   domain, unlike the V2) and its polarity is revision-dependent.
//!   This BSP targets **V3.2** (high = divider on) — earlier revisions are
//!   unsupported until one shows up. [`battery::BatterySampler`] owns it.
//! - GPIO0 is a strapping pin shared with the PRG button; GPIO3/45/46 are
//!   strapping pins this BSP never touches.
//! - UART0 (GPIO43/44) is shared with the CP2102 USB bridge.
//! - GPIO19/20 carry the native USB D−/D+ (not routed to the connector on
//!   stock boards); do not claim them.
#![no_std]

pub mod battery;
pub mod display;
pub mod platform;
pub mod radio;
pub mod vext;

pub const BOARD_NAME: &str = "Heltec WiFi LoRa 32 V3";

// SX1262 radio (SPI + control). DIO2 drives the on-board RF switch and
// DIO3 drives the 1.8 V TCXO supply — both are mandatory driver
// configuration, not tuning (hardware doc §4.6–4.7). Unlike MeshCore
// (which declares reset unconnected — driver policy, not hardware truth,
// §4.3) NRESET is wired and we drive it.
pub const LORA_SCK: u8 = 9;
pub const LORA_MOSI: u8 = 10;
pub const LORA_MISO: u8 = 11;
pub const LORA_NSS: u8 = 8;
pub const LORA_RESET: u8 = 12;
pub const LORA_BUSY: u8 = 13;
pub const LORA_DIO1: u8 = 14;

// SSD1306 128x64 I2C OLED, powered from Vext. Full power-up sequence
// (Vext up -> reset pulse -> init) required after every Vext cycle.
pub const OLED_SDA: u8 = 17;
pub const OLED_SCL: u8 = 18;
pub const OLED_RESET: u8 = 21;
pub const OLED_I2C_ADDR: u8 = 0x3C;

/// PRG button: active low, shared with the boot strap.
pub const USER_BUTTON: u8 = 0;

/// White status LED, active high.
pub const STATUS_LED: u8 = 35;

/// Vext enable, ACTIVE LOW (low = rail on). Powers the OLED.
pub const VEXT_ENABLE: u8 = 36;

/// Battery sense: ADC1 channel 0 on GPIO1, 390 kΩ : 100 kΩ divider
/// (×4.9 nominal), valid only while GPIO37 enables the divider. ADC1 has
/// no radio entanglement (unlike the classic-ESP32 ADC2).
pub const BATTERY_ADC: u8 = 1;
/// Battery-divider gate. V3.2: high = divider on. Pre-V3.2 boards use the
/// opposite polarity and are not supported by this BSP.
pub const BATTERY_ADC_CONTROL: u8 = 37;
pub const BATTERY_DIVIDER_RATIO_X10: u16 = 49;

// CP2102 USB-UART bridge on UART0.
pub const UART0_TX: u8 = 43;
pub const UART0_RX: u8 = 44;
