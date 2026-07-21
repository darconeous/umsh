//! Power-loss-safe two-page record journals shared by every UMSH
//! companion board.
//!
//! Extracted from the nRF companion NCP firmware so the ESP32-S3 port
//! reuses the same tested machinery. Three journal record formats ride
//! one shared engine:
//!
//! * [`record`] — the engine: the [`record::RecordWriter`] /
//!   [`record::PageEraser`] flash traits, the body-first/commit-word-last
//!   committed write, CRC32, and wraparound-safe generation comparison.
//! * [`ble`] — fixed-size BLE security snapshots (pairing PIN, local
//!   IRK, bonds).
//! * [`proto`] — variable-payload protocol records: opaque session
//!   snapshots, the device identity, and clear tombstones.
//! * [`counter`] — the device node's frame-counter map, serialized as
//!   one whole-map [`proto`] payload per flush.
//!
//! Flash **addresses** deliberately live with each firmware, not here:
//! which pages a journal owns is a memory-map fact (`memory.x` on nRF,
//! the partition table on ESP32). Structural constants — slot sizes,
//! payload bounds, the 4 KiB page size both chips share — are this
//! crate's. Mount scans and write-target rotation stay firmware-side
//! too: they are wrapped around each chip's read path (blocking NVMC
//! reads under MPSL on nRF) and the fault-injection hooks.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod ble;
pub mod counter;
pub mod proto;
pub mod record;
