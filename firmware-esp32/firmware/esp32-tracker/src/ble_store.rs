//! ESP32 backing for the chip-agnostic record journals.
//!
//! The record engine, codecs, and power-cut recovery all live in
//! [`umsh_journal_store`] (proven by the same crate's host tests on the
//! nRF path). This module supplies the Espressif flash primitive, the
//! two-page rotation policy, and the runtime handles — the exact
//! analogue of the `JournalFlash` / `BleStore` / `ProtoStore` trio in
//! `techo/src/main.rs`, backed by `esp_storage::FlashStorage`
//! behind an embassy mutex instead of the MPSL-shared nRF NVMC.
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
//! - next pair down: device-node counter journal.
//!
//! The same constant shrinks the `sequential-storage` map range in
//! `new_storage`, so the map and the journals can never overlap.
//! Addresses come from the partition table, never a literal.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use esp_storage::FlashStorage;
use trouble_host::prelude::*;
use umsh_bsp_esp32::flash_store::JOURNAL_RESERVED;

use umsh_journal_store::ble::{self, Snapshot};
use umsh_journal_store::record::{
    CommitError, PAGE_SIZE, PageEraser, RecordReader, RecordWriter, write_committed_record,
};

pub use umsh_journal_store::ble::{MAX_BONDS, SLOT_SIZE, StoredBond};

/// Newtype over the flash driver so the foreign journal traits can be
/// implemented for it (orphan rule — both `RecordWriter` and
/// `FlashStorage` are foreign). Reads go through the inner driver.
pub struct JournalFlash(pub FlashStorage<'static>);

/// The one flash driver, shared by all four journal handles. Everything
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
        self.0.write(address, bytes).map_err(|_| ())
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
    JOURNAL_RESERVED >= 8 * PAGE_SIZE,
    "four journal page pairs must fit inside the map carve-out"
);

/// BLE security journal: the topmost page pair (anchored — see module doc).
pub fn ble_page0(partition: &core::ops::Range<u32>) -> u32 {
    partition.end - 2 * PAGE_SIZE
}

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

// ─── BLE security journal handle ────────────────────────────────────────

/// Runtime handle for the two-page BLE security journal.
pub struct BleStore {
    flash: &'static SharedFlash,
    /// First page of this journal's two-page rotation (absolute flash address).
    page0: u32,
    snapshot: Snapshot,
    slot: Option<u32>,
}

impl BleStore {
    /// Mount the journal over the shared flash, anchored to the topmost
    /// page pair of `partition`.
    pub async fn mount(shared: &'static SharedFlash, partition: &core::ops::Range<u32>) -> Self {
        let page0 = ble_page0(partition);
        let mut flash = shared.lock().await;
        let mut latest: Option<(u32, Snapshot)> = None;
        for page in [page0, page0 + PAGE_SIZE] {
            let mut address = page;
            while address < page + PAGE_SIZE {
                let mut bytes = [0u8; SLOT_SIZE];
                if flash.0.read(address, &mut bytes).is_ok() {
                    latest = ble::consider_snapshot(latest, address, &bytes);
                }
                address += SLOT_SIZE as u32;
            }
        }
        drop(flash);
        let (slot, snapshot) = latest
            .map(|(slot, snapshot)| (Some(slot), snapshot))
            .unwrap_or((None, Snapshot::empty()));
        Self {
            flash: shared,
            page0,
            snapshot,
            slot,
        }
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    async fn persist(&mut self, mut snapshot: Snapshot) -> Result<(), ()> {
        snapshot.generation = self.snapshot.generation.wrapping_add(1);
        let mut flash = self.flash.lock().await;
        let target = umsh_ulcp_runtime::journal::journal_write_target(
            &mut *flash,
            self.slot,
            self.page0,
            SLOT_SIZE,
        )
        .await?;
        let bytes = snapshot.encode();
        match write_committed_record(&mut *flash, target, &bytes).await {
            Ok(()) => {}
            Err(CommitError::Body(())) | Err(CommitError::Commit(())) => return Err(()),
        }
        drop(flash);
        self.snapshot = snapshot;
        self.slot = Some(target);
        Ok(())
    }

    pub async fn set_pin(&mut self, pin: Option<u32>) -> Result<(), ()> {
        if self.snapshot.pin == pin {
            return Ok(());
        }
        let mut next = self.snapshot.clone();
        next.pin = pin;
        self.persist(next).await
    }

    pub async fn set_local_irk(&mut self, local_irk: [u8; 16]) -> Result<(), ()> {
        if self.snapshot.local_irk == Some(local_irk) {
            return Ok(());
        }
        let mut next = self.snapshot.clone();
        next.local_irk = Some(local_irk);
        self.persist(next).await
    }

    /// Persist `bond`, keeping the bond list LRU-ordered. Returns the
    /// evicted bond, if inserting a new one at [`MAX_BONDS`] capacity pushed
    /// out the least-recently-used entry. Idempotent: a repeated
    /// protected-edge write of an unchanged MRU bond does not touch flash.
    pub async fn add_bond(&mut self, bond: &BondInformation) -> Result<Option<StoredBond>, ()> {
        let stored = stored_bond(bond);
        let mut next = self.snapshot.clone();
        let evicted = match ble::upsert_bond(&mut next.bonds, stored) {
            ble::BondUpsert::Unchanged => return Ok(None),
            ble::BondUpsert::Updated => None,
            ble::BondUpsert::Inserted { evicted } => evicted,
        };
        self.persist(next).await?;
        Ok(evicted)
    }

    /// Move the bond matching `address_kind`/`address` to the MRU end and
    /// persist it, if it isn't already there. Called on reconnect via an
    /// existing bond, so the LRU order reflects actual use rather than only
    /// pairing events — without this the list is insertion-ordered and
    /// eviction takes the wrong bond.
    pub async fn touch_bond(&mut self, address_kind: u8, address: [u8; 6]) -> Result<bool, ()> {
        let mut next = self.snapshot.clone();
        if !ble::touch_bond(&mut next.bonds, address_kind, address) {
            return Ok(false);
        }
        self.persist(next).await?;
        Ok(true)
    }

    /// Drop every bond and the PIN, preserving the device's local IRK —
    /// the device's security-wipe operation.
    pub async fn clear_security(&mut self) -> Result<(), ()> {
        let mut next = Snapshot::empty();
        next.generation = self.snapshot.generation;
        next.local_irk = self.snapshot.local_irk;
        self.persist(next).await
    }
}

// ─── Protocol snapshot / identity journal handle ────────────────────────

/// The stored payload as read at boot (snapshot bytes or the encoded
/// identity, depending on which journal the handle mounts).
/// The stored protocol payload as read at boot.
pub type BootPayload = umsh_ulcp_runtime::journal::BootPayload;

/// This board's journal handle: the shared two-page rotating store
/// bound to the ESP32 flash driver.
pub type ProtoStore = umsh_ulcp_runtime::journal::ProtoStore<NoopRawMutex, JournalFlash>;

// ─── Trouble bond conversion helpers (verbatim from the nRF firmware) ────────

/// Encode a live trouble bond for the flash journal. `addr.to_bytes()`
/// prepends the address-kind byte, so `[0]` is the kind and `[1..]` is the
/// 6-byte address in wire order.
pub fn stored_bond(bond: &BondInformation) -> StoredBond {
    let address = bond.identity.addr.to_bytes();
    StoredBond {
        address_kind: address[0],
        address: address[1..].try_into().unwrap(),
        irk: bond.identity.irk.map(IdentityResolvingKey::to_le_bytes),
        ltk: bond.ltk.to_le_bytes(),
        security_level: match bond.security_level {
            SecurityLevel::NoEncryption => 0,
            SecurityLevel::Encrypted => 1,
            SecurityLevel::EncryptedAuthenticated => 2,
        },
        is_bonded: bond.is_bonded,
    }
}

/// A bond is durable only once its identity is stable across reconnects:
/// a public address, a random-static address, or an IRK for a private one.
pub fn bond_identity_is_persistable(bond: &BondInformation) -> bool {
    let address = bond.identity.addr.to_bytes();
    let public = address[0] & 1 == 0;
    let random_static = address[1] & 0xc0 == 0xc0;
    public || random_static || bond.identity.irk.is_some()
}

/// Rebuild a live trouble bond from a stored record, or `None` if the
/// stored security level is out of range.
pub fn trouble_bond(bond: &StoredBond) -> Option<BondInformation> {
    let mut raw = bond.address;
    raw.reverse();
    let identity = Identity {
        addr: Address::new(AddrKind::new(bond.address_kind), BdAddr::new(raw)),
        irk: bond.irk.and_then(IdentityResolvingKey::from_le_bytes),
    };
    let security_level = match bond.security_level {
        0 => SecurityLevel::NoEncryption,
        1 => SecurityLevel::Encrypted,
        2 => SecurityLevel::EncryptedAuthenticated,
        _ => return None,
    };
    Some(BondInformation::new(
        identity,
        LongTermKey::from_le_bytes(bond.ltk),
        security_level,
        bond.is_bonded,
    ))
}
