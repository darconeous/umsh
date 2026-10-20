//! Chip-level BSP for Espressif SoCs (classic ESP32 and ESP32-S3).
//!
//! Chip-generic building blocks live here: the flash storage backend, the
//! RF-gated `CryptoRng` wrapper, timing samples for the entropy pool,
//! deep-sleep helpers, USB host presence, panic capture to RTC slow
//! RAM, and the color panel and AW9364 backlight more than one board
//! carries. Board wiring (pins, display, power topology) belongs in the
//! per-board BSP crates.
#![no_std]

pub mod aw9364;
pub mod flash_store;
pub mod iv;
pub mod jitter;
pub mod panel;
pub mod panic_capture;
#[cfg(feature = "ble")]
pub mod rng;
#[cfg(feature = "esp32s3")]
pub mod temperature;
#[cfg(feature = "esp32s3")]
pub mod usb_sof;
