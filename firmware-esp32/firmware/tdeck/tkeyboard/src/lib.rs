//! What the T-Deck keyboard's ESP32-C3 does, apart from the hardware: the
//! matrix and its debouncing, the legends, the stock firmware's key
//! encoding and backlight, and the I²C protocol, composed by
//! [`Controller`]. All of it is synchronous and allocation-free, so the
//! firmware's tasks only move bytes and pin levels in and out of it, and
//! the host tests can hold it against a model of the stock firmware.
//!
//! The protocol is in `docs/tdeck-keyboard-firmware.md`; the hardware in
//! §8 of `docs/hardware/lilygo-t-deck-hardware.md`.
#![cfg_attr(not(test), no_std)]

pub mod backlight;
pub mod controller;
pub mod keymap;
pub mod legacy;
pub mod matrix;
pub mod protocol;

pub use controller::Controller;

#[cfg(test)]
mod tests;
