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
//! What lives here:
//!
//! - [`display`] — SH1106 OLED over I²C (SDA=P0.06, SCL=P0.05, addr 0x3D)
//! - [`power`] — `PowerControl` bridge, shutdown signal, and the SAADC
//!   battery monitor (AIN7/P0.31, divider gated active-high on P0.04)
//! - [`buzzer`] — piezo on P1.00, driven straight from PWM
//! - [`gnss`] — Quectel L76K standby control (P1.09); the module has no
//!   rail this board can cut, so its backup domain is the board's clock
//! - [`platform`] — the `Platform` type bundle used by the console
//!   bringup harness
//!
//! Concrete pins for the radio (SX1262 on TWISPI1 plus the external
//! RXEN on P1.08), the user LED (P1.01, active-high), the Back button
//! (P0.08), and the four-way pad with its center press (P1.04, P0.12,
//! P0.11, P1.03, P1.05 — up, down, left, right, press) are chosen by the
//! firmware, following the pattern the other nRF52840 tracker boards
//! use. All six switches are active-low with pull-ups.
//!
//! Not yet wired: the Grove expansion I²C bus and the QSPI external
//! flash.
//!
//! See `docs/hardware/seeed-wio-tracker-l1-pro-hardware.md` for the
//! firmware-derived hardware reference.

#[cfg(all(target_os = "none", feature = "buzzer"))]
pub mod buzzer;

#[cfg(all(target_os = "none", feature = "display"))]
pub mod display;

#[cfg(all(target_os = "none", feature = "gnss"))]
pub mod gnss;

#[cfg(all(target_os = "none", feature = "platform"))]
pub mod platform;

#[cfg(all(target_os = "none", feature = "power"))]
pub mod power;

#[cfg(all(target_os = "none", feature = "platform"))]
pub use platform::{WioMac, WioTrackerPlatform};
#[cfg(all(target_os = "none", feature = "power"))]
pub use power::PowerSignaler;
