//! Async, allocation-free drivers and pure policy for the T-Deck's
//! peripherals, apart from its panel and radio. Register references and
//! the hardware checklist are in `docs/hardware/lilygo-t-deck-hardware.md`.
#![no_std]

pub mod battery;
pub mod es7210;
pub mod gt911;
pub mod keyboard;
pub mod trackball;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
