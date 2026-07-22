//! ESP32 backing for the chip-agnostic record journals.
//!
//! The record engine, codecs, and power-cut recovery all live in
//! [`umsh_journal_store`] (proven by the same crate's host tests on the
//! nRF path). This module supplies the Espressif flash primitive, the
//! two-page rotation policy, and the runtime handles — the exact
//! analogue of the `JournalFlash` / `BleStore` / `ProtoStore` trio in
//! `companion-ncp-techo/src/main.rs`, backed by `esp_storage::FlashStorage`
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
//! - next pair down: device-identity journal.
//!
//! The same constant shrinks the `sequential-storage` map range in
//! `new_storage`, so the map and the journals can never overlap.
//! Addresses come from the partition table, never a literal.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use esp_storage::FlashStorage;
use trouble_host::prelude::*;
use umsh_bsp_esp32::flash_store::JOURNAL_RESERVED;

use umsh_journal_store::ble::{self, Snapshot, StoredBond};
use umsh_journal_store::proto;
use umsh_journal_store::record::{
    CommitError, PAGE_SIZE, PageEraser, RecordWriter, erase_journal_page, write_committed_record,
};

pub use umsh_journal_store::ble::{MAX_BONDS, SLOT_SIZE};

/// Newtype over the flash driver so the foreign journal traits can be
/// implemented for it (orphan rule — both `RecordWriter` and
/// `FlashStorage` are foreign). Reads go through the inner driver.
pub struct JournalFlash(pub FlashStorage<'static>);

/// The one flash driver, shared by all three journal handles. Everything
/// runs on the single BLE task, so the mutex is uncontended; it exists to
/// satisfy `'static` sharing, mirroring the nRF `SharedFlash` shape.
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

// ─── Journal placement inside the reserved tail ─────────────────────────

const _: () = assert!(
    JOURNAL_RESERVED >= 6 * PAGE_SIZE,
    "three journal page pairs must fit inside the map carve-out"
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

/// Scan a two-page journal's slot range for a fully erased slot.
fn erased_journal_slot(
    flash: &mut JournalFlash,
    start: u32,
    end: u32,
    slot_size: usize,
) -> Option<u32> {
    let mut address = start;
    while address < end {
        let mut erased = true;
        let mut offset = 0usize;
        while offset < slot_size {
            let mut chunk = [0u8; 256];
            let take = (slot_size - offset).min(chunk.len());
            match flash.0.read(address + offset as u32, &mut chunk[..take]) {
                Ok(()) if chunk[..take].iter().all(|byte| *byte == 0xff) => {}
                _ => {
                    erased = false;
                    break;
                }
            }
            offset += take;
        }
        if erased {
            return Some(address);
        }
        address += slot_size as u32;
    }
    None
}

/// Pick the write target for a two-page rotating journal starting at
/// `page0`: the next erased slot after the current record, or the
/// opposite page after erasing it.
async fn journal_write_target(
    flash: &mut JournalFlash,
    current: Option<u32>,
    page0: u32,
    slot_size: usize,
) -> Result<u32, ()> {
    let page1 = page0 + PAGE_SIZE;
    let target = if let Some(current) = current {
        let page = if current < page1 { page0 } else { page1 };
        erased_journal_slot(flash, current + slot_size as u32, page + PAGE_SIZE, slot_size)
    } else {
        erased_journal_slot(flash, page0, page0 + PAGE_SIZE, slot_size)
    };
    match target {
        Some(target) => Ok(target),
        None => {
            let page = if current.is_some_and(|slot| slot < page1) {
                page1
            } else {
                page0
            };
            erase_journal_page(flash, page).await?;
            Ok(page)
        }
    }
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
        let target =
            journal_write_target(&mut flash, self.slot, self.page0, SLOT_SIZE).await?;
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

    /// Persist `bond`, returning `(bond_count, wrote_flash)`. `wrote_flash`
    /// is `false` when the bond already matched a stored record — the call
    /// is idempotent, so a repeated protected-edge write does not touch
    /// flash and the caller can skip timing/logging a no-op.
    pub async fn add_bond(&mut self, bond: &BondInformation) -> Result<(usize, bool), ()> {
        let stored = stored_bond(bond);
        let mut next = self.snapshot.clone();
        if let Some(existing) = next.bonds.iter_mut().find(|existing| {
            existing.address_kind == stored.address_kind && existing.address == stored.address
        }) {
            if *existing == stored {
                return Ok((self.snapshot.bonds.len(), false));
            }
            *existing = stored;
        } else {
            next.bonds.push(stored).map_err(|_| ())?;
        }
        self.persist(next).await?;
        Ok((self.snapshot.bonds.len(), true))
    }

    /// Kept for parity with the NCP's security-wipe path (and a future
    /// recovery build); unused by the spike's happy path.
    #[allow(dead_code)]
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
pub type BootPayload = heapless08::Vec<u8, { proto::MAX_PAYLOAD }>;

/// Runtime handle for one full-protocol record journal: the snapshot
/// journal or the device-identity journal, selected by its first page.
/// Port of the nRF NCP's `ProtoStore`.
pub struct ProtoStore {
    flash: &'static SharedFlash,
    /// First page of this journal's two-page rotation.
    page0: u32,
    generation: u32,
    slot: Option<u32>,
}

impl ProtoStore {
    pub async fn mount(
        shared: &'static SharedFlash,
        page0: u32,
    ) -> (Self, Option<BootPayload>) {
        let mut flash = shared.lock().await;
        let mut latest: Option<(u32, proto::Stored)> = None;
        for page in [page0, page0 + PAGE_SIZE] {
            let mut address = page;
            while address < page + PAGE_SIZE {
                let mut bytes = [0u8; proto::SLOT_SIZE];
                if flash.0.read(address, &mut bytes).is_ok() {
                    latest = proto::consider_record(latest, address, &bytes);
                }
                address += proto::SLOT_SIZE as u32;
            }
        }
        drop(flash);
        // A tombstone is authoritative "nothing saved": older snapshot
        // records still physically present are void.
        let (slot, generation, payload) = match latest {
            Some((slot, stored)) => {
                let payload = match stored.record {
                    proto::Record::Snapshot(payload) => Some(payload),
                    proto::Record::Cleared => None,
                };
                (Some(slot), stored.generation, payload)
            }
            None => (None, 0, None),
        };
        (
            Self {
                flash: shared,
                page0,
                generation,
                slot,
            },
            payload,
        )
    }

    pub async fn persist(&mut self, payload: &[u8]) -> Result<(), ()> {
        if payload.len() > proto::MAX_PAYLOAD {
            return Err(());
        }
        self.write(proto::RecordRef::Snapshot(payload)).await
    }

    /// The clear transaction is one committed tombstone record: if its
    /// write fails or is interrupted, the previous record remains
    /// authoritative. Pages are never erased as part of a clear — stale
    /// records are reclaimed by the ordinary rotation.
    pub async fn clear(&mut self) -> Result<(), ()> {
        self.write(proto::RecordRef::Cleared).await
    }

    async fn write(&mut self, record: proto::RecordRef<'_>) -> Result<(), ()> {
        let generation = self.generation.wrapping_add(1);
        let mut flash = self.flash.lock().await;
        let target =
            journal_write_target(&mut flash, self.slot, self.page0, proto::SLOT_SIZE).await?;
        match proto::write_record(&mut *flash, target, generation, record).await {
            Ok(()) => {
                drop(flash);
                self.generation = generation;
                self.slot = Some(target);
                Ok(())
            }
            Err(_) => Err(()),
        }
    }
}

// ─── Trouble bond conversion helpers (verbatim from the nRF NCP) ────────

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
