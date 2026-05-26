#![no_std]

//! Chip-level board support for nRF52840-based UMSH boards.
//!
//! This crate owns chip-wide concerns shared by every nRF52840-based board:
//! USB peripheral setup, GPREGRET-driven DFU entry, System OFF entry with
//! GPIO wake, retained-RAM helpers, and flash-backed implementations of the
//! `umsh-hal` storage traits.
//!
//! Board-level BSPs (e.g. [`umsh-bsp-t1000e`](../umsh_bsp_t1000e/index.html))
//! compose this crate with their own pinout and on-board peripherals.
//!
//! See `docs/firmware-architecture.md` for the BSP / UX / App / Binary triad.

pub mod panic_persist;
pub mod rescue;

#[cfg(target_os = "none")]
pub mod cdc_rescue;

#[cfg(target_os = "none")]
pub mod clocks;

#[cfg(target_os = "none")]
pub mod flash_store;

#[cfg(target_os = "none")]
pub mod gpregret;

// TODO: implement.
//
// Planned modules (see docs/firmware-plan-t1000e.md):
//   pub mod usb;           // embassy-nrf USB driver wrapper.
//   pub mod system_off;    // Configure DETECT and enter System OFF.
