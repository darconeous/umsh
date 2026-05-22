#![no_std]

//! UMSH companion-radio CLI firmware logic.
//!
//! This crate is hardware-agnostic. It defines the embassy task topology,
//! the USB-CDC ↔ `umsh-cli` adapter, the button event FSM, the power-intent
//! channel, and the LED sequence engine. Concrete boards are passed in via
//! a `Board: Platform + HasButton + HasLed + ...` bound.
//!
//! Typical use from a `firmware/<app>-<board>` binary crate:
//!
//! ```ignore
//! #[embassy_executor::main]
//! async fn main(spawner: Spawner) -> ! {
//!     let board = umsh_bsp_t1000e::Board::init();
//!     umsh_app_companion_cli::run(spawner, board).await
//! }
//! ```
//!
//! See `docs/firmware-plan-t1000e.md` for the full design.

pub mod button;
pub mod buzzer;
pub mod led;
pub mod panic_persist;
pub mod power;
pub mod rescue;

// TODO: implement remaining modules (see docs/firmware-plan-t1000e.md):
//   pub mod cli_io;          // USB-CDC adapter to CliInput / CliOutput.
//   pub mod app;              // `run<B>(spawner, board) -> !` entry point.
