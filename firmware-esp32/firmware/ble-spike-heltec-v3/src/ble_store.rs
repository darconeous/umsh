//! ESP32 backing for the chip-agnostic BLE bond journal.
//!
//! The record engine, snapshot codec, and power-cut recovery all live in
//! [`umsh_journal_store`] (proven by the same crate's host tests on the
//! nRF path). This module supplies the Espressif flash primitive and the
//! two-page rotation policy — the exact analogue of the `JournalFlash` /
//! `BleStore` pair in `companion-ncp-techo/src/main.rs`, but backed by a
//! directly-owned `esp_storage::FlashStorage` instead of the MPSL-shared
//! nRF NVMC.
//!
//! Only the BLE app touches flash in this spike, so [`BleStore`] owns the
//! driver outright — there is no `SharedFlash` mutex. The full NCP
//! (Phase 5) will reintroduce sharing when the on-board device node and
//! the sequential-storage map contend for the same partition.
//!
//! ## Region placement
//!
//! The bond journal owns the [`flash_store::JOURNAL_RESERVED`] tail of
//! the discovered `umsh` partition, mirroring the nRF layout where the
//! journals sit at defined offsets. The same constant shrinks the
//! `sequential-storage` map range in `new_storage`, so the two can never
//! overlap — see its documentation for why the carve-out must be shared.
//! Addresses come from the partition table, never a literal.

use esp_storage::FlashStorage;
use trouble_host::prelude::*;
use umsh_bsp_esp32::flash_store::JOURNAL_RESERVED;

use umsh_journal_store::ble::{self, Snapshot, StoredBond};
use umsh_journal_store::record::{
    CommitError, PAGE_SIZE, PageEraser, RecordWriter, erase_journal_page, write_committed_record,
};

pub use umsh_journal_store::ble::{MAX_BONDS, SLOT_SIZE};

/// Newtype over the owned flash driver so the foreign journal traits can
/// be implemented for it (orphan rule — both `RecordWriter` and
/// `FlashStorage` are foreign). Reads go through the inner driver.
struct JournalFlash(FlashStorage<'static>);

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

/// Runtime handle for the two-page BLE security journal.
pub struct BleStore {
    flash: JournalFlash,
    /// First page of this journal's two-page rotation (absolute flash address).
    page0: u32,
    snapshot: Snapshot,
    slot: Option<u32>,
}

impl BleStore {
    /// Mount the journal over `flash`, anchored to the TOPMOST page pair
    /// of `partition`. The pair sits inside the [`JOURNAL_RESERVED`] tail
    /// that `flash_store::new_storage` excludes from the map range;
    /// anchoring to the top (rather than `end - JOURNAL_RESERVED`) keeps
    /// existing bonds in place when the reservation grows downward for
    /// Phase 5's additional journals.
    pub fn mount(flash: FlashStorage<'static>, partition: core::ops::Range<u32>) -> Self {
        const {
            assert!(
                JOURNAL_RESERVED >= 2 * PAGE_SIZE,
                "BLE journal page pair must fit inside the map carve-out"
            );
        }
        let page0 = partition.end - 2 * PAGE_SIZE;
        let mut flash = JournalFlash(flash);
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
        let (slot, snapshot) = latest
            .map(|(slot, snapshot)| (Some(slot), snapshot))
            .unwrap_or((None, Snapshot::empty()));
        Self {
            flash,
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
        let target =
            journal_write_target(&mut self.flash, self.slot, self.page0, SLOT_SIZE).await?;
        let bytes = snapshot.encode();
        match write_committed_record(&mut self.flash, target, &bytes).await {
            Ok(()) => {}
            Err(CommitError::Body(())) | Err(CommitError::Commit(())) => return Err(()),
        }
        self.snapshot = snapshot;
        self.slot = Some(target);
        Ok(())
    }

    pub async fn set_pin(&mut self, pin: Option<u32>) -> Result<(), ()> {
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
