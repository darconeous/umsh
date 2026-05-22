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
//! See `docs/firmware-architecture.md` for the BSP / App / Binary triad.

// TODO: implement.
//
// Planned modules (see docs/firmware-plan-t1000e.md):
//   pub mod clocks;        // HFXO start, LF source select.
//   pub mod usb;           // embassy-nrf USB driver wrapper.
//   pub mod gpregret;      // GPREGRET helpers for DFU entry.
//   pub mod system_off;    // Configure DETECT and enter System OFF.
//   pub mod retained_ram;  // Retained-RAM section for panic capture.
//   pub mod flash_store;   // CounterStore / KeyValueStore over NVMC.
