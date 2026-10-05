//! The BLE security journal: bonds, the pairing PIN, and the local IRK.
//!
//! One more handle over the shared journal flash (see `journals.rs` for
//! the flash primitive and where each journal sits), plus the
//! conversions between a stored bond and a live trouble one.

use trouble_host::prelude::*;
use umsh_journal_store::ble::{self, Snapshot};
use umsh_journal_store::record::{CommitError, PAGE_SIZE, write_committed_record};

use crate::journals::SharedFlash;

pub use umsh_journal_store::ble::{MAX_BONDS, SLOT_SIZE, StoredBond};

/// BLE security journal: the topmost page pair of the partition.
pub fn ble_page0(partition: &core::ops::Range<u32>) -> u32 {
    partition.end - 2 * PAGE_SIZE
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

    pub async fn observe_device_name(&mut self, hash: [u8; 32]) -> Result<(), ()> {
        let mut next = self.snapshot.clone();
        if !next.observe_device_name(hash) {
            return Ok(());
        }
        self.persist(next).await
    }

    pub async fn acknowledge_device_name(
        &mut self,
        bond: &StoredBond,
        revision: u32,
    ) -> Result<bool, ()> {
        let mut next = self.snapshot.clone();
        if !next.acknowledge_device_name(bond, revision) {
            return Ok(false);
        }
        self.persist(next).await?;
        Ok(true)
    }

    /// Persist LRU order on reconnect only when the stored order changes.
    pub async fn touch_bond(&mut self, address_kind: u8, address: [u8; 6]) -> Result<bool, ()> {
        let mut next = self.snapshot.clone();
        if !ble::touch_bond(&mut next.bonds, address_kind, address) {
            return Ok(false);
        }
        self.persist(next).await?;
        Ok(true)
    }

    /// Atomically revoke every bond, clear the PIN, and replace the local IRK.
    pub async fn forget_hosts(&mut self, irk: [u8; 16]) -> Result<(), ()> {
        let next = self.snapshot.forget_hosts(irk).ok_or(())?;
        self.persist(next).await
    }
}

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
        name_refresh_pending: false,
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
