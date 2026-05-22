//! nRF52840 clock + peripheral-config helpers.
//!
//! Currently provides one helper, [`default_config`], that returns an
//! `embassy_nrf::config::Config` with the settings we want every
//! nRF52840 UMSH firmware to start from:
//!
//! - HFXO (external high-frequency crystal) as the HF clock source —
//!   required for USB-CDC to be reliable.
//! - Internal RC oscillator as the LF clock source, for simplicity.
//!   Boards with a 32.768 kHz crystal can override this in the BSP
//!   if the timing precision matters (e.g. for BLE).
//! - Default interrupt priorities, leaving room for the SoftDevice
//!   to claim the top priorities if it is ever enabled later
//!   (see docs/firmware-plan-t1000e.md → BLE future-proofing).

use embassy_nrf::config::{Config, HfclkSource, LfclkSource};

/// Return the default `embassy_nrf::config::Config` for UMSH firmware
/// on nRF52840 boards.
///
/// Pass the returned config into `embassy_nrf::init(...)` at the start
/// of your binary's `main`.
///
/// LFCLK source: `InternalRC`. Most nRF52840-based UMSH boards have a
/// 32.768 kHz crystal that BLE needs, and `ExternalXtal` would be
/// preferable for accuracy, but `InternalRC` is the safest default
/// for bringup since it always starts. Switch to `ExternalXtal` once
/// per-board crystal presence is verified.
pub fn default_config() -> Config {
    let mut config = Config::default();
    config.hfclk_source = HfclkSource::ExternalXtal;
    config.lfclk_source = LfclkSource::InternalRC;
    config
}
