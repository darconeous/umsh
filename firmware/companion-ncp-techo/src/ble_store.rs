//! BLE security snapshot journal: shared machinery from
//! `umsh-journal-store`, plus this firmware's flash placement.
//!
//! The record engine, snapshot codec, and their power-cut tests live in
//! the crate; only the page addresses — a `memory.x` fact — are decided
//! here.

pub use umsh_journal_store::ble::*;
pub use umsh_journal_store::record::*;

/// Flash pages owned by this journal, inside the NV storage region
/// (0x000E_4000..0x000F_4000; see `memory.x`).
pub const PAGE0: u32 = 0x000E_4000;
pub const PAGE1: u32 = PAGE0 + PAGE_SIZE;
