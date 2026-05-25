#![no_std]

//! Board support for the Seeed Wio Tracker L1 / L1 Pro (nRF52840).
//!
//! Composes [`umsh-bsp-nrf52840`](../umsh_bsp_nrf52840/index.html) with
//! the Wio Tracker L1 family's pinout and on-board peripherals.
//!
//! The same crate covers the L1, L1 Pro, and L1 Lite variants, which
//! share a pin map. The L1 e-ink variant has a different display path
//! (SPI1) and would warrant a separate BSP crate.
//!
//! Initial scope is *bringup only* (see
//! `docs/firmware-plan-wio-tracker-l1.md`):
//!
//! - USB-CDC handles (over the nRF native USB peripheral)
//! - user LED (P1.01, active-high) for heartbeat
//! - SH1106 OLED I²C bus (Phase 2)
//! - SX1262 LoRa radio + external RXEN pin (Phase 3)
//!
//! Future expansion (GNSS, joystick, Grove I²C, QSPI flash, buzzer,
//! battery measurement) is welcome but is not yet implemented.
//!
//! See `docs/seeed-wio-tracker-l1-pro-hardware.md` for the
//! firmware-derived hardware reference.

// TODO: implement (see docs/firmware-plan-wio-tracker-l1.md):
//   pub mod pins;        // typed pin handles per the Wio Tracker pinout.
//   pub mod board;       // `Board::init()` and the composed Platform impl.
//   pub mod indicators;  // user LED (P1.01, active-high).
//   pub mod display;     // SH1106 OLED I²C bus + address.
//   pub mod radio;       // SX1262 SPI + RXEN.
//   pub mod usb;         // USB-CDC plumbing on top of umsh-bsp-nrf52840.
