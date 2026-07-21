//! Chip-level BSP for Espressif SoCs (classic ESP32 now, ESP32-S3 when the
//! T-Lora Pager lands).
//!
//! Chip-generic building blocks live here: the flash storage backend, the
//! RF-gated `CryptoRng` wrapper, deep-sleep helpers, and panic capture to
//! RTC slow RAM. Board wiring (pins, display, power topology) belongs in the
//! per-board BSP crates.
#![no_std]

pub mod panic_capture;
