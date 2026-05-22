#![no_std]

//! Companion-radio CLI app for tracker-class UMSH boards.
//!
//! This crate is **app-specific policy**: it decides which button
//! event maps to which action, which CLI commands exist, and how the
//! MAC layer integrates with the user-facing surface. Mechanism
//! (button gesture FSM, LED heartbeat, buzzer melodies, low-battery
//! detection, power intents) lives in
//! [`umsh-ux-tracker`](../umsh_ux_tracker/index.html) and is shared
//! with any other tracker-class app (e.g. a future repeater
//! firmware).
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
//! See `docs/firmware-architecture.md` for the BSP / UX / App /
//! Binary layering, and `docs/firmware-plan-t1000e.md` for the full
//! design of the first concrete deployment.

// TODO: implement.
//
// Planned modules (see docs/firmware-plan-t1000e.md):
//   pub mod actions;          // button-event → action mapping.
//   pub mod cli_io;          // USB-CDC adapter to CliInput / CliOutput.
//   pub mod commands;        // CLI command dispatch (`dfu`, `poweroff`, …).
//   pub mod app;              // `run<B>(spawner, board) -> !` entry point.
