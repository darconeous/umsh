//! The harness behind the UMSH and ULCP fuzz targets.
//!
//! Everything a target does lives here, in an ordinary workspace crate with
//! no libFuzzer dependency. `fuzz/` holds only thin `fuzz_target!` wrappers
//! in a workspace of its own, so `cargo test` keeps this code compiling and
//! replays every committed seed and regression on stable. See
//! `tests/replay.rs`.

pub mod block_on;
pub mod device;
pub mod fixup;
pub mod mac;
pub mod script;
pub mod targets;
