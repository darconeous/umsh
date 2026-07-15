#![no_std]

//! Board support for the LilyGO T-Echo (nRF52840).
//!
//! Composes [`umsh-bsp-nrf52840`](../umsh_bsp_nrf52840/index.html) with
//! the T-Echo's pinout and on-board peripherals.
//!
//! Initial scope is *bringup only* (see `docs/firmware-plan-techo.md`):
//!
//! - peripheral power switch (P0.12, active-high)
//! - USB-CDC handles (over the nRF native USB peripheral)
//! - blue LED (P0.14, active-low)
//! - e-paper SPI bus + control pins for the SSD1681 display
//!
//! Future expansion (LoRa, GNSS, I²C peripherals, QSPI flash, buttons,
//! Plus-only back-panel) is welcome but is not yet implemented. The
//! T-Echo is not a tracker-class device — when a "real" T-Echo firmware
//! arrives, it should be designed against a new `umsh-ux-handheld` (or
//! similar) class rather than `umsh-ux-tracker`.
//!
//! See `docs/lilygo-techo-hardware.md` for the firmware-derived
//! hardware reference.

#[cfg(all(target_os = "none", feature = "display"))]
pub mod display;

#[cfg(all(target_os = "none", feature = "platform"))]
pub mod platform;

#[cfg(all(target_os = "none", feature = "power"))]
pub mod power;

#[cfg(all(target_os = "none", feature = "platform"))]
pub use platform::{TechoMac, TechoPlatform};
#[cfg(all(target_os = "none", feature = "power"))]
pub use power::{PowerSignaler, SHUTDOWN_SIGNAL};

// TODO: implement (see docs/firmware-plan-techo.md):
//   pub mod pins;          // typed pin handles per lilygo-techo-hardware.md.
//   pub mod board;          // `Board::init()` and the composed Platform impl.
//   pub mod power;          // P0.12 peripheral-rail switch.
//   pub mod indicators;      // blue LED (P0.14, active-low).
//   pub mod usb;            // USB-CDC plumbing on top of umsh-bsp-nrf52840.
