//! Board-agnostic companion-radio NCP runtime shared across firmware targets.
//!
//! Phase 5 extraction (see `docs/firmware-plan-heltec-lora32-v3.md`). This
//! crate holds the parts of the companion NCP that have no board HAL
//! dependency, so the nRF52840 (T-Echo / T-1000E) and ESP32-S3 (Heltec V3)
//! firmwares consume one copy instead of maintaining divergent forks.
//!
//! Increment A moved the pure leaf modules: transport arbitration, the
//! persisted counter map re-export, the BLE pairing-policy helpers, and the
//! radio multiplexer. Increment C adds [`driver`]: the NCP session run loop
//! (formerly the nRF `ncp_task`/`apply_effect`/`Emitter`), with every board
//! coupling routed through the [`driver::NcpEnv`] trait.

#![cfg_attr(not(test), no_std)]

// Pure, dependency-free — always available.
pub mod ble_security;
pub mod transport_policy;

// Gated so non-radio / non-persistent consumers stay lightweight.
#[cfg(feature = "counters")]
pub mod counter_map;
#[cfg(feature = "driver")]
pub mod driver;
#[cfg(feature = "radio")]
pub mod radio_mux;
