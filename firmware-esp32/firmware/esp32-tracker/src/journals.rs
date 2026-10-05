//! ESP32 backing for the chip-agnostic record journals.
//!
//! The record engine, codecs, and power-cut recovery all live in
//! [`umsh_journal_store`] (proven by the same crate's host tests on the
//! nRF path). This module supplies the Espressif flash primitive, the
//! two-page rotation policy, and the runtime handles every image
//! mounts—the analogue of the `JournalFlash` / `ProtoStore` pair in
//! `techo/src/main.rs`, backed by `esp_storage::FlashStorage` behind an
//! embassy mutex instead of the MPSL-shared nRF NVMC. The BLE security
//! journal's handle is the transport's own, in `ble/store.rs`.
//!
//! ## Region placement
//!
//! All journals live in the [`flash_store::JOURNAL_RESERVED`] tail of
//! the discovered `umsh` partition, growing downward from the top:
//!
//! - topmost pair: BLE security journal (anchored at the top so bonds
//!   survive the reservation growing),
//! - next pair down: protocol snapshot journal,
//! - next pair down: device-identity journal,
//! - next pair down: device-node counter journal,
//! - next pair down: entropy-pool seed journal.
//!
//! The placement is the same in every image. One built without
//! Bluetooth leaves the topmost pair alone, so the bonds are still
//! there for an image that has it.
//!
//! The same constant shrinks the `sequential-storage` map range in
//! `new_storage`, so the map and the journals can never overlap.
//! Addresses come from the partition table, never a literal.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use esp_storage::FlashStorage;
use umsh_bsp_esp32::flash_store::JOURNAL_RESERVED;

use umsh_journal_store::record::{
    CommitError, PAGE_SIZE, PageEraser, RecordReader, RecordWriter, write_committed_record,
};
use umsh_journal_store::seed;

/// Newtype over the flash driver so the foreign journal traits can be
/// implemented for it (orphan rule—both `RecordWriter` and
/// `FlashStorage` are foreign). Reads go through the inner driver.
pub struct JournalFlash(pub FlashStorage<'static>);

/// The one flash driver, shared by every journal handle. Everything
/// runs on the single thread-mode executor, so the mutex is uncontended;
/// it exists to satisfy `'static` sharing, mirroring the nRF
/// `SharedFlash` shape.
pub type SharedFlash = Mutex<NoopRawMutex, JournalFlash>;

/// Wrap the opened flash driver for sharing (place in a `StaticCell`).
pub fn shared(flash: FlashStorage<'static>) -> SharedFlash {
    Mutex::new(JournalFlash(flash))
}

impl RecordWriter for JournalFlash {
    type Error = ();

    async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write(address, bytes).map_err(|_| ())?;
        // A seed write waiting for company can go out behind this one.
        crate::entropy::journal_written();
        Ok(())
    }
}

impl PageEraser for JournalFlash {
    type Error = ();

    async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
        self.0.erase(start, end).map_err(|_| ())
    }
}

impl RecordReader for JournalFlash {
    type Error = ();

    fn read_record(&mut self, address: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(address, bytes).map_err(|_| ())
    }
}

// ─── Journal placement inside the reserved tail ─────────────────────────

const _: () = assert!(
    JOURNAL_RESERVED >= 10 * PAGE_SIZE,
    "five journal page pairs must fit inside the map carve-out"
);

/// Protocol snapshot journal: the pair below the BLE journal.
pub fn proto_page0(partition: &core::ops::Range<u32>) -> u32 {
    partition.end - 4 * PAGE_SIZE
}

/// Device-identity journal: the pair below the snapshot journal.
pub fn identity_page0(partition: &core::ops::Range<u32>) -> u32 {
    partition.end - 6 * PAGE_SIZE
}

/// Device-node counter journal: the pair below the identity journal.
/// Separate journal because its write cadence (every
/// `COUNTER_PERSIST_BLOCK_SIZE` secured frames) must never rotate a
/// snapshot or the identity record away.
pub fn counter_page0(partition: &core::ops::Range<u32>) -> u32 {
    partition.end - 8 * PAGE_SIZE
}

/// Entropy-pool seed journal: the pair below the counter journal.
pub fn seed_page0(partition: &core::ops::Range<u32>) -> u32 {
    partition.end - 10 * PAGE_SIZE
}

// ─── Entropy-pool seed journal handle ───────────────────────────────────

/// Runtime handle for the two-page entropy-pool seed journal.
///
/// Mount scans both pages for the newest committed record; persist
/// writes body-then-commit into the next erased slot (erasing the
/// opposite page when full). The pool's crash-safety contract needs
/// exactly one property from this store: `persist` returns `Ok` only
/// after the commit word is on flash.
pub struct SeedStore {
    flash: &'static SharedFlash,
    page0: u32,
    generation: u32,
    seed: Option<[u8; 32]>,
    slot: Option<u32>,
}

impl SeedStore {
    /// Mount the journal over the shared flash.
    pub async fn mount(shared: &'static SharedFlash, partition: &core::ops::Range<u32>) -> Self {
        let page0 = seed_page0(partition);
        let mut flash = shared.lock().await;
        let mut latest: Option<(u32, seed::SeedRecord)> = None;
        for page in [page0, page0 + PAGE_SIZE] {
            let mut address = page;
            while address < page + PAGE_SIZE {
                let mut bytes = [0u8; seed::SLOT_SIZE];
                if flash.0.read(address, &mut bytes).is_ok() {
                    latest = seed::consider_record(latest, address, &bytes);
                }
                address += seed::SLOT_SIZE as u32;
            }
        }
        drop(flash);
        let (slot, generation, stored) = match latest {
            Some((slot, record)) => (Some(slot), record.generation, Some(record.seed)),
            None => (None, 0, None),
        };
        Self {
            flash: shared,
            page0,
            generation,
            seed: stored,
            slot,
        }
    }

    /// The stored seed, if any boot has ever committed one.
    pub fn seed(&self) -> Option<[u8; 32]> {
        self.seed
    }

    /// Write `seed` as the next committed record. Returns only after the
    /// commit word is on flash—the caller may release pool output once
    /// this is `Ok`.
    pub async fn persist(&mut self, seed: [u8; 32]) -> Result<(), ()> {
        let record = seed::SeedRecord {
            generation: self.generation.wrapping_add(1),
            seed,
        };
        let mut flash = self.flash.lock().await;
        let target = umsh_ulcp_runtime::journal::journal_write_target(
            &mut *flash,
            self.slot,
            self.page0,
            seed::SLOT_SIZE,
        )
        .await?;
        let bytes = record.encode();
        match write_committed_record(&mut *flash, target, &bytes).await {
            Ok(()) => {}
            Err(CommitError::Body(())) | Err(CommitError::Commit(())) => return Err(()),
        }
        drop(flash);
        self.generation = record.generation;
        self.seed = Some(seed);
        self.slot = Some(target);
        Ok(())
    }
}

// ─── Protocol snapshot / identity journal handle ────────────────────────

/// The stored protocol payload as read at boot (snapshot bytes or the
/// encoded identity, depending on which journal the handle mounts).
#[cfg(not(feature = "wifi"))]
pub type BootPayload = umsh_ulcp_runtime::journal::BootPayload;

/// This board's journal handle: the shared two-page rotating store
/// bound to the ESP32 flash driver.
pub type ProtoStore = umsh_ulcp_runtime::journal::ProtoStore<NoopRawMutex, JournalFlash>;
