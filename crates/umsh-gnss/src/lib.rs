#![cfg_attr(not(test), no_std)]

//! GNSS receiver support for UMSH boards.
//!
//! The receivers differ in how they are powered and reset, and in almost
//! nothing else: they all emit NMEA 0183 over a UART, and what UMSH wants
//! out of them — a position, a fix quality, and the time — is the same
//! everywhere. So the board-specific part stays in each BSP and
//! everything above it lives here, shared by both cargo workspaces.
//!
//! The crate is `no_std`, allocation-free, and has no dependencies.

pub mod driver;
pub mod epoch;
pub mod nmea;
#[cfg(feature = "pump")]
pub mod pump;

pub use driver::{Driver, Fix, FixQuality};
pub use epoch::DateTime;
pub use nmea::{Assembler, Sentence};
