//! Protocol snapshot / identity / counter journals: shared machinery
//! from `umsh-journal-store`, plus this firmware's flash placement.
//!
//! The record codec and its power-cut tests live in the crate; only the
//! journal page chain — a `memory.x` fact — is decided here.

pub use umsh_journal_store::proto::*;
pub use umsh_journal_store::record::PAGE_SIZE;

use super::ble_store;

/// Flash pages owned by the snapshot journal: the two 4 KB pages
/// immediately after the BLE store's, inside the NV storage region
/// (0x000E_4000..0x000F_4000; see `memory.x`).
pub const PAGE0: u32 = ble_store::PAGE1 + PAGE_SIZE;
pub const PAGE1: u32 = PAGE0 + PAGE_SIZE;

/// Flash pages owned by the device-identity journal: the next two
/// pages. The identity is persisted the moment it is installed or
/// generated, independently of snapshots (spec §PROP_DEV_PRIVATE_KEY),
/// so it gets a journal of its own: snapshot saves can never rotate
/// the identity record away, and each journal clears atomically with
/// one committed tombstone.
pub const IDENTITY_PAGE0: u32 = PAGE1 + PAGE_SIZE;
/// T-1000E user-facing Sleep/Silence preference journal. The shared T-Echo
/// image does not use it, but reserving it here keeps the flash map explicit.
pub const UX_PAGE0: u32 = IDENTITY_PAGE0 + 2 * PAGE_SIZE;
/// Device-node frame-counter journal (device-node plan increment 4):
/// the persisted TX reservation boundary for the device identity and
/// RX replay boundaries for its peers, batch-written as one
/// `counter_map` payload per flush. Separate journal because its write
/// cadence (every `COUNTER_PERSIST_BLOCK_SIZE` secured frames) must
/// never rotate a snapshot or the identity record away.
pub const COUNTER_PAGE0: u32 = UX_PAGE0 + 2 * PAGE_SIZE;

#[cfg(test)]
mod tests {
    use super::*;

    /// The journal chain stays inside the reserved NV region
    /// (0x000E_4000..0x000F_4000; see `memory.x`).
    #[test]
    fn journal_pages_stay_in_the_nv_region() {
        assert_eq!(ble_store::PAGE0, 0x000E_4000);
        assert_eq!(PAGE0, 0x000E_6000);
        assert_eq!(IDENTITY_PAGE0, 0x000E_8000);
        assert_eq!(UX_PAGE0, 0x000E_A000);
        assert_eq!(COUNTER_PAGE0, 0x000E_C000);
        assert!(COUNTER_PAGE0 + 2 * PAGE_SIZE <= 0x000F_4000);
    }
}
