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
//! - [`platform`] — the `Platform` type bundle used by the console
//!   bringup harness
//!
//! Concrete pins for the radio (SX1262 on TWISPI1 plus the external
//! RXEN on P1.08), the user LED (P1.01, active-high), and the nav button
//! (P0.08) are chosen by the firmware, following the pattern the other
//! nRF52840 tracker boards use.
//!
//! Not yet wired: the Quectel L76K GNSS UART, the joystick / trackball,
//! the Grove expansion I²C bus, and the QSPI external flash.
//!
//! See `docs/hardware/seeed-wio-tracker-l1-pro-hardware.md` for the
//! firmware-derived hardware reference.

#[cfg(all(target_os = "none", feature = "buzzer"))]
pub mod buzzer;

#[cfg(all(target_os = "none", feature = "display"))]
pub mod display;

#[cfg(all(target_os = "none", feature = "platform"))]
pub mod platform;

#[cfg(all(target_os = "none", feature = "power"))]
pub mod power;

#[cfg(all(target_os = "none", feature = "platform"))]
pub use platform::{WioMac, WioTrackerPlatform};
#[cfg(all(target_os = "none", feature = "power"))]
pub use power::PowerSignaler;
