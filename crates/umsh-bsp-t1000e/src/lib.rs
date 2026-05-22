#![no_std]

//! Board support for the Seeed Studio SenseCAP T1000-E tracker.
//!
//! Composes [`umsh-bsp-nrf52840`](../umsh_bsp_nrf52840/index.html) with the
//! T1000-E's pinout and on-board peripherals — LR1110 LoRa, AG3335 GNSS,
//! QMA6100P accelerometer, buzzer, LED, button, battery ADC, switched
//! power rails — and exposes a `Board::init()` entry point that returns a
//! struct implementing `umsh::Platform` and the board-capability traits.
//!
//! See `docs/firmware-plan-t1000e.md` for the safety contract and phasing,
//! and `docs/t1000e-hardware.md` for the firmware-derived hardware reference.

pub mod panic_persist;

// TODO: implement.
//
// Planned modules (see docs/firmware-plan-t1000e.md):
//   pub mod pins;          // typed pin handles per t1000e-hardware.md.
//   pub mod board;          // `Board::init()` + the composed Platform impl.
//   pub mod rails;          // SwitchedRails (sensor/accel/buzzer enables).
//   pub mod radio;          // LR1110 wiring (SPI + IRQ + BUSY + RESET).
//   pub mod gnss;           // AG3335 over UART with power sequencing.
//   pub mod accel;          // QMA6100P over I2C.
//   pub mod inputs;          // Button (P0.06, active-high, DETECT-aware).
//   pub mod indicators;      // LED (P0.24), buzzer (P0.25 + EN P1.05).
//   pub mod battery;          // Battery ADC + charger-state pins.
