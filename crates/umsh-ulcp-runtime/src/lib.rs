//! Board-agnostic ULCP device runtime shared across firmware targets.
//!
//! This crate holds the parts of the ULCP device that have no board HAL
//! dependency, so the nRF52840 (T-Echo / T-1000E) and ESP32-S3 (Heltec V3)
//! firmwares consume one copy instead of maintaining divergent forks.
//!
//! Increment A moved the pure leaf modules: transport arbitration, the
//! persisted counter map re-export, the BLE pairing-policy helpers, and the
//! radio multiplexer. Increment C adds [`driver`]: the ULCP session run loop
//! (formerly the nRF `device_task`/`apply_effect`/`Emitter`), with every board
//! coupling routed through the [`driver::DeviceEnv`] trait.
//!
//! The storage layer followed: [`journal`] holds the two-page rotating
//! journal handle (mount scan, write-target rotation, boot walk-back) and
//! [`node_counters`] the device node's persisted frame counters. Both are
//! generic over the board's flash type, which is the only part of that
//! stack that is genuinely per-board — the nRF images drive
//! MPSL-coordinated NVMC, the ESP32 image its SPI part. Shared modules
//! emit diagnostics through [`log`], whose sink each board installs once
//! at boot.

#![cfg_attr(not(test), no_std)]

// Pure, dependency-free — always available.
pub mod ble_security;
pub mod log;
pub mod transport_policy;

// Gated so non-radio / non-persistent consumers stay lightweight.
#[cfg(feature = "counters")]
pub mod counter_map;
#[cfg(feature = "device-node")]
pub mod device_node;
#[cfg(feature = "driver")]
pub mod driver;
#[cfg(feature = "driver")]
pub mod duty_gate;
#[cfg(feature = "counters")]
pub mod journal;
#[cfg(feature = "counters")]
pub mod node_counters;
#[cfg(feature = "radio")]
pub mod radio_mux;
