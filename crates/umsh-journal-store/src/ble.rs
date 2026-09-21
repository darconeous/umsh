//! Power-loss-safe BLE security snapshot encoding.
//!
//! Fixed-size snapshots (pairing PIN, local IRK, bonds) written through
//! the shared [`record`](crate::record) engine. Which two pages the
//! journal owns is the firmware's memory-map decision.

use crate::record::{crc32, generation_is_newer};

pub const MAX_BONDS: usize = 4;
pub const SLOT_SIZE: usize = 256;
pub const COMMIT_OFFSET: usize = SLOT_SIZE - 4;
const CRC_OFFSET: usize = COMMIT_OFFSET - 4;
const MAGIC: [u8; 4] = *b"UBLS";
// Version 1 may contain a bond captured at the first protected GATT edge,
// before SMP identity-key distribution completed. Do not restore those
// incomplete records.
// Version 5 marks the completed one-time privacy migration. Versions 3 and 4
// are mounted for atomic replacement, never restored into a running BLE host.
const VERSION: u8 = 5;
const BOND_SIZE: usize = 44;
const LOCAL_IRK_OFFSET: usize = 16;
const BONDS_OFFSET: usize = 32;
const NAME_OFFSET: usize = BONDS_OFFSET + MAX_BONDS * BOND_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredBond {
    pub address_kind: u8,
    pub address: [u8; 6],
    pub irk: Option<[u8; 16]>,
    pub ltk: [u8; 16],
    pub security_level: u8,
    pub is_bonded: bool,
    pub name_refresh_pending: bool,
}

/// Outcome of [`upsert_bond`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondUpsert {
    /// The bond's content and position were already current.
    Unchanged,
    /// An existing bond's content and/or MRU position changed.
    Updated,
    /// A new bond was appended, evicting the LRU entry first if the list
    /// was already at `MAX_BONDS`.
    Inserted { evicted: Option<StoredBond> },
}

/// Insert or refresh `bond` in `bonds`, which is kept ordered
/// least-recently-used-first / most-recently-used-last (index 0 is the
/// eviction candidate). A bond matching by `address_kind` + `address` is
/// refreshed in place and moved to the MRU end; a new bond is appended at
/// the MRU end, evicting the current LRU entry first if the list is full.
pub fn upsert_bond(
    bonds: &mut heapless::Vec<StoredBond, MAX_BONDS>,
    mut bond: StoredBond,
) -> BondUpsert {
    if let Some(index) = bonds.iter().position(|existing| {
        existing.address_kind == bond.address_kind && existing.address == bond.address
    }) {
        // Refreshing a retained bond must not consume a missed rename.
        bond.name_refresh_pending = bonds[index].name_refresh_pending;
        if bonds[index] == bond && index == bonds.len() - 1 {
            return BondUpsert::Unchanged;
        }
        bonds.remove(index);
        let _ = bonds.push(bond);
        return BondUpsert::Updated;
    }
    let evicted = if bonds.len() == MAX_BONDS {
        Some(bonds.remove(0))
    } else {
        None
    };
    let _ = bonds.push(bond);
    BondUpsert::Inserted { evicted }
}

/// Move the bond matching `address_kind` + `address` to the MRU end, if
/// present and not already there. Returns `true` when the order changed
/// (and the caller should persist), `false` when the bond was already MRU
/// or is not stored at all.
pub fn touch_bond(
    bonds: &mut heapless::Vec<StoredBond, MAX_BONDS>,
    address_kind: u8,
    address: [u8; 6],
) -> bool {
    let Some(index) = bonds
        .iter()
        .position(|existing| existing.address_kind == address_kind && existing.address == address)
    else {
        return false;
    };
    if index == bonds.len() - 1 {
        return false;
    }
    let bond = bonds.remove(index);
    let _ = bonds.push(bond);
    true
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u32,
    pub pin: Option<u32>,
    pub local_irk: Option<[u8; 16]>,
    pub bonds: heapless::Vec<StoredBond, MAX_BONDS>,
    pub device_name_hash: Option<[u8; 32]>,
    pub name_revision: u32,
    pub privacy_migration_pending: bool,
}

impl Snapshot {
    /// Record a configured name and give every retained host its own refresh.
    /// An older journal has no baseline; seed it without inventing a rename.
    pub fn observe_device_name(&mut self, hash: [u8; 32]) -> bool {
        if self.device_name_hash == Some(hash) {
            return false;
        }
        if self.device_name_hash.is_some() {
            self.name_revision = self.name_revision.wrapping_add(1);
            for bond in &mut self.bonds {
                bond.name_refresh_pending = true;
            }
        }
        self.device_name_hash = Some(hash);
        true
    }

    /// Clear only the confirmed host's pending bit. A confirmation for an old
    /// name or a replaced bond must not acknowledge a subsequent change.
    pub fn acknowledge_device_name(&mut self, confirmed: &StoredBond, revision: u32) -> bool {
        if self.name_revision != revision {
            return false;
        }
        let Some(bond) = self.bonds.iter_mut().find(|bond| *bond == confirmed) else {
            return false;
        };
        if !bond.name_refresh_pending {
            return false;
        }
        bond.name_refresh_pending = false;
        true
    }

    /// Prepare one atomic revocation record without mutating the live snapshot.
    /// A previously trusted peer must not be able to resolve the new IRK.
    pub fn forget_hosts(&self, new_irk: [u8; 16]) -> Option<Self> {
        if new_irk == [0; 16] || self.local_irk == Some(new_irk) {
            return None;
        }
        Some(Self {
            generation: self.generation,
            pin: None,
            local_irk: Some(new_irk),
            bonds: heapless::Vec::new(),
            device_name_hash: self.device_name_hash,
            name_revision: self.name_revision,
            privacy_migration_pending: false,
        })
    }

    pub const fn empty() -> Self {
        Self {
            generation: 0,
            pin: None,
            local_irk: None,
            bonds: heapless::Vec::new(),
            device_name_hash: None,
            name_revision: 0,
            privacy_migration_pending: false,
        }
    }

    pub fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut out = [0xff; SLOT_SIZE];
        out[..4].copy_from_slice(&MAGIC);
        // An unrelated write must not accidentally mark legacy security as
        // migrated. Only the atomic forget_hosts replacement clears this bit.
        out[4] = if self.privacy_migration_pending {
            4
        } else {
            VERSION
        };
        out[5] = self.bonds.len() as u8;
        out[6] = u8::from(self.pin.is_some());
        out[7] = u8::from(self.local_irk.is_some());
        out[8..12].copy_from_slice(&self.generation.to_le_bytes());
        out[12..16].copy_from_slice(&self.pin.unwrap_or(u32::MAX).to_le_bytes());
        out[LOCAL_IRK_OFFSET..BONDS_OFFSET].copy_from_slice(&self.local_irk.unwrap_or([0; 16]));
        for (index, bond) in self.bonds.iter().enumerate() {
            let start = BONDS_OFFSET + index * BOND_SIZE;
            out[start] = bond.address_kind;
            out[start + 1..start + 7].copy_from_slice(&bond.address);
            out[start + 7] = u8::from(bond.irk.is_some());
            out[start + 8..start + 24].copy_from_slice(&bond.irk.unwrap_or([0; 16]));
            out[start + 24..start + 40].copy_from_slice(&bond.ltk);
            out[start + 40] = bond.security_level;
            out[start + 41] = u8::from(bond.is_bonded);
            out[start + 42] = u8::from(bond.name_refresh_pending);
        }
        out[NAME_OFFSET] = u8::from(self.device_name_hash.is_some());
        out[NAME_OFFSET + 1..NAME_OFFSET + 33]
            .copy_from_slice(&self.device_name_hash.unwrap_or([0; 32]));
        out[NAME_OFFSET + 33..NAME_OFFSET + 37].copy_from_slice(&self.name_revision.to_le_bytes());
        let crc = crc32(&out[..CRC_OFFSET]);
        out[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; SLOT_SIZE]) -> Option<Self> {
        if bytes[COMMIT_OFFSET..] != [0, 0, 0, 0]
            || bytes[..4] != MAGIC
            || !matches!(bytes[4], 3 | 4 | VERSION)
            || usize::from(bytes[5]) > MAX_BONDS
            || crc32(&bytes[..CRC_OFFSET])
                != u32::from_le_bytes(bytes[CRC_OFFSET..COMMIT_OFFSET].try_into().ok()?)
        {
            return None;
        }
        let pin = match (bytes[6], u32::from_le_bytes(bytes[12..16].try_into().ok()?)) {
            (0, _) => None,
            (1, value @ 0..=999_999) => Some(value),
            _ => return None,
        };
        let local_irk = match bytes[7] {
            0 => None,
            1 => {
                let value: [u8; 16] = bytes[LOCAL_IRK_OFFSET..BONDS_OFFSET].try_into().ok()?;
                if value == [0; 16] {
                    return None;
                }
                Some(value)
            }
            _ => return None,
        };
        let mut bonds = heapless::Vec::new();
        for index in 0..usize::from(bytes[5]) {
            let start = BONDS_OFFSET + index * BOND_SIZE;
            let irk = match bytes[start + 7] {
                0 => None,
                1 => Some(bytes[start + 8..start + 24].try_into().ok()?),
                _ => return None,
            };
            let security_level = bytes[start + 40];
            if security_level > 2
                || bytes[start + 41] > 1
                || (bytes[4] >= 4 && bytes[start + 42] > 1)
            {
                return None;
            }
            bonds
                .push(StoredBond {
                    address_kind: bytes[start],
                    address: bytes[start + 1..start + 7].try_into().ok()?,
                    irk,
                    ltk: bytes[start + 24..start + 40].try_into().ok()?,
                    security_level,
                    is_bonded: bytes[start + 41] == 1,
                    name_refresh_pending: bytes[4] >= 4 && bytes[start + 42] == 1,
                })
                .ok()?;
        }
        Some(Self {
            generation: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            privacy_migration_pending: bytes[4] < VERSION,
            pin,
            local_irk,
            bonds,
            device_name_hash: if bytes[4] == 3 {
                None
            } else {
                match bytes[NAME_OFFSET] {
                    0 => None,
                    1 => Some(bytes[NAME_OFFSET + 1..NAME_OFFSET + 33].try_into().ok()?),
                    _ => return None,
                }
            },
            name_revision: if bytes[4] == 3 {
                0
            } else {
                u32::from_le_bytes(bytes[NAME_OFFSET + 33..NAME_OFFSET + 37].try_into().ok()?)
            },
        })
    }
}

/// Select the newest valid committed snapshot from `(flash_address, record)`
/// pairs. Invalid, corrupt, and incompletely committed records are ignored.
#[cfg(test)]
pub fn latest_snapshot<'a>(
    records: impl IntoIterator<Item = (u32, &'a [u8; SLOT_SIZE])>,
) -> Option<(u32, Snapshot)> {
    let mut latest: Option<(u32, Snapshot)> = None;
    for (address, bytes) in records {
        latest = consider_snapshot(latest, address, bytes);
    }
    latest
}

/// Consider one journal slot while mounting without retaining its flash buffer.
pub fn consider_snapshot(
    current: Option<(u32, Snapshot)>,
    address: u32,
    bytes: &[u8; SLOT_SIZE],
) -> Option<(u32, Snapshot)> {
    let Some(candidate) = Snapshot::decode(bytes) else {
        return current;
    };
    if current
        .as_ref()
        .is_none_or(|(_, snapshot)| generation_is_newer(candidate.generation, snapshot.generation))
    {
        Some((address, candidate))
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        CommitError, PAGE_SIZE, PageEraser, RecordWriter, erase_journal_page,
        write_committed_record,
    };
    use core::future::Future;
    use core::task::{Context, Poll, Waker};

    /// Test-only journal addresses (production addresses are the
    /// firmware's memory-map decision).
    const PAGE0: u32 = 0x000E_4000;
    const PAGE1: u32 = PAGE0 + PAGE_SIZE;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Default)]
    struct MockWriter {
        fail_call: Option<usize>,
        calls: std::vec::Vec<(u32, std::vec::Vec<u8>)>,
        erase_failure: bool,
        erases: std::vec::Vec<(u32, u32)>,
    }

    impl RecordWriter for MockWriter {
        type Error = usize;

        async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            let call = self.calls.len();
            self.calls.push((address, bytes.to_vec()));
            if self.fail_call == Some(call) {
                Err(call)
            } else {
                Ok(())
            }
        }
    }

    impl PageEraser for MockWriter {
        type Error = ();

        async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
            self.erases.push((start, end));
            if self.erase_failure { Err(()) } else { Ok(()) }
        }
    }

    fn sample() -> Snapshot {
        let mut snapshot = Snapshot {
            generation: 42,
            pin: Some(123_456),
            local_irk: Some([9; 16]),
            bonds: heapless::Vec::new(),
            device_name_hash: None,
            name_revision: 0,
            privacy_migration_pending: false,
        };
        snapshot
            .bonds
            .push(StoredBond {
                address_kind: 1,
                address: [1, 2, 3, 4, 5, 6],
                irk: Some([7; 16]),
                ltk: [8; 16],
                security_level: 2,
                is_bonded: true,
                name_refresh_pending: false,
            })
            .unwrap();
        snapshot
    }

    #[test]
    fn committed_snapshot_round_trips() {
        let snapshot = sample();
        let mut encoded = snapshot.encode();
        encoded[COMMIT_OFFSET..].fill(0);
        assert_eq!(Snapshot::decode(&encoded), Some(snapshot));
    }

    fn reboot(snapshot: &Snapshot) -> Snapshot {
        let mut encoded = snapshot.encode();
        encoded[COMMIT_OFFSET..].fill(0);
        Snapshot::decode(&encoded).unwrap()
    }

    fn legacy_record(version: u8) -> [u8; SLOT_SIZE] {
        let mut old = sample();
        old.observe_device_name([1; 32]);
        old.observe_device_name([2; 32]);
        let mut encoded = old.encode();
        encoded[4] = version;
        if version == 3 {
            encoded[BONDS_OFFSET + 42..BONDS_OFFSET + 44].fill(0xff);
            encoded[NAME_OFFSET..CRC_OFFSET].fill(0xff);
        }
        let crc = crc32(&encoded[..CRC_OFFSET]);
        encoded[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        encoded[COMMIT_OFFSET..].fill(0);
        encoded
    }

    #[test]
    fn privacy_migration_is_atomic_for_both_legacy_versions() {
        for version in [3, 4] {
            let old_bytes = legacy_record(version);
            let old = Snapshot::decode(&old_bytes).unwrap();
            assert!(old.privacy_migration_pending);
            assert_eq!(old.pin, sample().pin);
            assert_eq!(old.local_irk, sample().local_irk);
            assert_eq!(old.bonds[0].ltk, sample().bonds[0].ltk);
            assert!(old.forget_hosts([0; 16]).is_none());
            assert!(old.forget_hosts(old.local_irk.unwrap()).is_none());

            let mut next = old.forget_hosts([0x92; 16]).unwrap();
            next.generation += 1;
            assert!(!next.privacy_migration_pending);
            assert!(next.bonds.is_empty());
            assert_eq!(next.pin, None);
            assert_eq!(next.local_irk, Some([0x92; 16]));
            assert_eq!(next.device_name_hash, old.device_name_hash);
            assert_eq!(next.name_revision, old.name_revision);
            let encoded = next.encode();
            assert_eq!(encoded[4], 5);
            // Cut power at every body byte and every commit byte. The legacy
            // authority stays marked unusable until the entire clear commits.
            for written in 0..SLOT_SIZE {
                let mut interrupted = [0xff; SLOT_SIZE];
                interrupted[..written].copy_from_slice(&encoded[..written]);
                if written > COMMIT_OFFSET {
                    interrupted[COMMIT_OFFSET..written].fill(0);
                }
                assert_eq!(
                    latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &interrupted)]),
                    Some((PAGE0, old.clone())),
                    "version {version}, power cut after {written} bytes"
                );
            }
            let mut committed = encoded;
            committed[COMMIT_OFFSET..].fill(0);
            assert_eq!(
                latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &committed)]),
                Some((PAGE1, next.clone()))
            );
            // New bonds and PINs survive later boots without another cleanup.
            let mut next = reboot(&next);
            next.pin = Some(654_321);
            upsert_bond(&mut next.bonds, bond(2));
            assert_eq!(reboot(&reboot(&next)), next);
            assert!(!next.privacy_migration_pending);
        }
    }

    #[test]
    fn unrelated_legacy_writes_cannot_complete_privacy_migration() {
        for version in [3, 4] {
            let mut old = Snapshot::decode(&legacy_record(version)).unwrap();
            old.pin = Some(654_321);
            old.observe_device_name([3; 32]);
            assert_eq!(old.encode()[4], 4);
            let restored = reboot(&old);
            assert!(restored.privacy_migration_pending);
            assert_eq!(restored, old);
        }
    }

    #[test]
    fn fresh_install_needs_no_privacy_migration() {
        let mut fresh = Snapshot::empty();
        fresh.local_irk = Some([0x92; 16]);
        assert_eq!(fresh.encode()[4], 5);
        assert!(!reboot(&fresh).privacy_migration_pending);
    }

    #[test]
    fn version_three_preserves_security_without_inventing_a_rename() {
        let mut old = sample();
        let mut encoded = old.encode();
        encoded[4] = 3;
        encoded[BONDS_OFFSET + 42..BONDS_OFFSET + 44].fill(0xff);
        encoded[NAME_OFFSET..CRC_OFFSET].fill(0xff);
        let crc = crc32(&encoded[..CRC_OFFSET]);
        encoded[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        encoded[COMMIT_OFFSET..].fill(0);
        old.privacy_migration_pending = true;
        let mut restored = Snapshot::decode(&encoded).unwrap();
        assert_eq!(restored, old);
        assert!(restored.observe_device_name([1; 32]));
        assert!(!restored.bonds[0].name_refresh_pending);
        assert!(!restored.observe_device_name([1; 32]));
        assert_eq!(reboot(&restored), restored);
    }

    #[test]
    fn missed_rename_survives_reboot_and_each_phone_confirms_independently() {
        for first in [0, 1] {
            let mut snapshot = Snapshot::empty();
            snapshot.observe_device_name([1; 32]);
            upsert_bond(&mut snapshot.bonds, bond(1));
            upsert_bond(&mut snapshot.bonds, bond(2));
            assert!(snapshot.bonds.iter().all(|b| !b.name_refresh_pending));
            snapshot.observe_device_name([2; 32]);
            let mut snapshot = reboot(&snapshot);
            let confirmed = snapshot.bonds[first];
            assert!(snapshot.acknowledge_device_name(&confirmed, snapshot.name_revision));
            let mut snapshot = reboot(&snapshot);
            assert!(!snapshot.bonds[first].name_refresh_pending);
            assert!(snapshot.bonds[1 - first].name_refresh_pending);
            // A normal reconnect and an LRU touch do not create another refresh.
            assert!(!snapshot.observe_device_name([2; 32]));
            let other = snapshot.bonds[1 - first];
            assert!(snapshot.acknowledge_device_name(&other, snapshot.name_revision));
            assert!(
                reboot(&snapshot)
                    .bonds
                    .iter()
                    .all(|b| !b.name_refresh_pending)
            );
        }
    }

    #[test]
    fn stale_confirmation_and_bond_refresh_cannot_consume_new_rename() {
        let mut snapshot = Snapshot::empty();
        snapshot.observe_device_name([1; 32]);
        upsert_bond(&mut snapshot.bonds, bond(1));
        snapshot.observe_device_name([2; 32]);
        let confirmed = snapshot.bonds[0];
        let revision = snapshot.name_revision;
        upsert_bond(&mut snapshot.bonds, bond(1));
        assert!(snapshot.bonds[0].name_refresh_pending);
        snapshot.observe_device_name([3; 32]);
        snapshot.observe_device_name([2; 32]);
        assert!(!snapshot.acknowledge_device_name(&confirmed, revision));
        let mut replacement = bond(1);
        replacement.ltk = [9; 16];
        upsert_bond(&mut snapshot.bonds, replacement);
        assert!(!snapshot.acknowledge_device_name(&confirmed, snapshot.name_revision));
        assert!(snapshot.bonds[0].name_refresh_pending);
        let cleared = snapshot.forget_hosts([4; 16]).unwrap();
        assert!(cleared.bonds.is_empty());
        assert_eq!(cleared.device_name_hash, snapshot.device_name_hash);
    }

    #[test]
    fn eviction_and_fresh_pairing_do_not_inherit_another_phones_pending_name() {
        let mut snapshot = Snapshot::empty();
        snapshot.observe_device_name([1; 32]);
        for id in 1..=4 {
            upsert_bond(&mut snapshot.bonds, bond(id));
        }
        snapshot.observe_device_name([2; 32]);
        let evicted = snapshot.bonds[0];
        upsert_bond(&mut snapshot.bonds, bond(5));
        assert!(!snapshot.acknowledge_device_name(&evicted, snapshot.name_revision));
        let restored = reboot(&snapshot);
        assert!(restored.bonds[..3].iter().all(|b| b.name_refresh_pending));
        assert!(!restored.bonds[3].name_refresh_pending);
    }

    #[test]
    fn interrupted_name_acknowledgement_retains_pending_refresh() {
        let mut old = sample();
        old.observe_device_name([1; 32]);
        old.observe_device_name([2; 32]);
        let confirmed = old.bonds[0];
        let mut next = old.clone();
        next.generation += 1;
        assert!(next.acknowledge_device_name(&confirmed, next.name_revision));
        let mut old_bytes = old.encode();
        old_bytes[COMMIT_OFFSET..].fill(0);
        let new_bytes = next.encode();
        for written in 0..SLOT_SIZE {
            let mut interrupted = [0xff; SLOT_SIZE];
            interrupted[..written].copy_from_slice(&new_bytes[..written]);
            if written > COMMIT_OFFSET {
                interrupted[COMMIT_OFFSET..written].fill(0);
            }
            assert_eq!(
                latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &interrupted)]),
                Some((PAGE0, old.clone()))
            );
        }
        assert!(!reboot(&next).bonds[0].name_refresh_pending);
    }

    #[test]
    fn uncommitted_or_corrupt_snapshot_is_ignored() {
        let snapshot = sample();
        let encoded = snapshot.encode();
        assert_eq!(Snapshot::decode(&encoded), None);
        let mut corrupt = encoded;
        corrupt[COMMIT_OFFSET..].fill(0);
        corrupt[24] ^= 1;
        assert_eq!(Snapshot::decode(&corrupt), None);
    }

    #[test]
    fn journal_selects_newest_valid_record_across_wraparound() {
        let mut old = sample();
        old.generation = u32::MAX;
        let mut old_bytes = old.encode();
        old_bytes[COMMIT_OFFSET..].fill(0);

        let mut new = sample();
        new.generation = 0;
        new.pin = Some(654_321);
        let mut new_bytes = new.encode();
        new_bytes[COMMIT_OFFSET..].fill(0);

        assert_eq!(
            latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &new_bytes)]),
            Some((PAGE1, new))
        );
    }

    #[test]
    fn forget_hosts_rejects_zero_or_reused_irk_without_mutating_security() {
        let old = sample();
        let before = old.encode();
        assert!(old.forget_hosts([0; 16]).is_none());
        assert!(old.forget_hosts(old.local_irk.unwrap()).is_none());
        let new = old.forget_hosts([0x92; 16]).unwrap();
        assert_eq!(old.encode(), before);
        assert_eq!(new.generation, old.generation);
        assert!(new.bonds.is_empty());
        assert_eq!(new.pin, None);
        assert_eq!(new.local_irk, Some([0x92; 16]));
    }

    #[test]
    fn interrupted_new_record_never_replaces_committed_old_record() {
        let mut old = sample();
        old.generation = 7;
        let mut old_bytes = old.encode();
        old_bytes[COMMIT_OFFSET..].fill(0);

        let mut new = old.forget_hosts([0x92; 16]).unwrap();
        new.generation = 8;
        assert!(new.bonds.is_empty());
        assert_eq!(new.pin, None);
        assert_eq!(new.local_irk, Some([0x92; 16]));
        let encoded_new = new.encode();

        // Simulate power loss after every possible byte of the body write and
        // after each byte of the final commit-word write. Until all four
        // commit bytes are present, mount must recover the old snapshot.
        for body_bytes in 0..=COMMIT_OFFSET {
            let mut interrupted = [0xff; SLOT_SIZE];
            interrupted[..body_bytes].copy_from_slice(&encoded_new[..body_bytes]);
            assert_eq!(
                latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &interrupted)]),
                Some((PAGE0, old.clone())),
                "body power cut after {body_bytes} bytes"
            );
        }
        for commit_bytes in 0..4 {
            let mut interrupted = encoded_new;
            interrupted[COMMIT_OFFSET..COMMIT_OFFSET + commit_bytes].fill(0);
            assert_eq!(
                latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &interrupted)]),
                Some((PAGE0, old.clone())),
                "commit power cut after {commit_bytes} bytes"
            );
        }

        let mut committed = encoded_new;
        committed[COMMIT_OFFSET..].fill(0);
        assert_eq!(
            latest_snapshot([(PAGE0, &old_bytes), (PAGE1, &committed)]),
            Some((PAGE1, new))
        );
    }

    #[test]
    fn record_writer_faults_distinguish_body_and_commit_failures() {
        let bytes = sample().encode();

        let mut body_failure = MockWriter {
            fail_call: Some(0),
            ..Default::default()
        };
        assert_eq!(
            block_on(write_committed_record(&mut body_failure, PAGE0, &bytes)),
            Err(CommitError::Body(0))
        );
        assert_eq!(body_failure.calls.len(), 1);

        let mut commit_failure = MockWriter {
            fail_call: Some(1),
            ..Default::default()
        };
        assert_eq!(
            block_on(write_committed_record(&mut commit_failure, PAGE0, &bytes)),
            Err(CommitError::Commit(1))
        );
        assert_eq!(commit_failure.calls.len(), 2);
        assert_eq!(commit_failure.calls[0].0, PAGE0);
        assert_eq!(commit_failure.calls[0].1, bytes[..COMMIT_OFFSET]);
        assert_eq!(
            commit_failure.calls[1],
            (PAGE0 + COMMIT_OFFSET as u32, std::vec![0; 4])
        );
    }

    #[test]
    fn successful_record_write_commits_marker_last() {
        let bytes = sample().encode();
        let mut writer = MockWriter::default();
        assert_eq!(
            block_on(write_committed_record(&mut writer, PAGE1, &bytes)),
            Ok(())
        );
        assert_eq!(writer.calls.len(), 2);
        assert_eq!(writer.calls[0].0, PAGE1);
        assert_eq!(writer.calls[0].1, bytes[..COMMIT_OFFSET]);
        assert_eq!(
            writer.calls[1],
            (PAGE1 + COMMIT_OFFSET as u32, std::vec![0; 4])
        );
    }

    #[test]
    fn journal_page_erase_propagates_failure_and_uses_exact_bounds() {
        let mut failing = MockWriter {
            erase_failure: true,
            ..Default::default()
        };
        assert_eq!(block_on(erase_journal_page(&mut failing, PAGE1)), Err(()));
        assert_eq!(failing.erases, std::vec![(PAGE1, PAGE1 + PAGE_SIZE)]);

        let mut successful = MockWriter::default();
        assert_eq!(block_on(erase_journal_page(&mut successful, PAGE0)), Ok(()));
        assert_eq!(successful.erases, std::vec![(PAGE0, PAGE0 + PAGE_SIZE)]);
    }

    fn bond(id: u8) -> StoredBond {
        StoredBond {
            address_kind: 0,
            address: [id, 0, 0, 0, 0, 0],
            irk: None,
            ltk: [id; 16],
            security_level: 2,
            is_bonded: true,
            name_refresh_pending: false,
        }
    }

    fn addresses(bonds: &heapless::Vec<StoredBond, MAX_BONDS>) -> std::vec::Vec<u8> {
        bonds.iter().map(|b| b.address[0]).collect()
    }

    #[test]
    fn upsert_appends_new_bonds_at_mru_end_until_full() {
        let mut bonds = heapless::Vec::new();
        for id in 1..=4 {
            assert_eq!(
                upsert_bond(&mut bonds, bond(id)),
                BondUpsert::Inserted { evicted: None }
            );
        }
        assert_eq!(addresses(&bonds), std::vec![1, 2, 3, 4]);
    }

    #[test]
    fn upsert_evicts_lru_entry_when_full() {
        let mut bonds = heapless::Vec::new();
        for id in 1..=4 {
            upsert_bond(&mut bonds, bond(id));
        }
        // 1 is least-recently-used; inserting 5 should evict it.
        assert_eq!(
            upsert_bond(&mut bonds, bond(5)),
            BondUpsert::Inserted {
                evicted: Some(bond(1))
            }
        );
        assert_eq!(addresses(&bonds), std::vec![2, 3, 4, 5]);
    }

    #[test]
    fn upsert_of_existing_bond_moves_it_to_mru_end() {
        let mut bonds = heapless::Vec::new();
        for id in 1..=4 {
            upsert_bond(&mut bonds, bond(id));
        }
        // Re-pairing bond 2 (content unchanged) should move it to the end,
        // so the *new* LRU candidate becomes 1, not 2.
        assert_eq!(upsert_bond(&mut bonds, bond(2)), BondUpsert::Updated);
        assert_eq!(addresses(&bonds), std::vec![1, 3, 4, 2]);
    }

    #[test]
    fn upsert_of_bond_already_at_mru_end_with_same_content_is_unchanged() {
        let mut bonds = heapless::Vec::new();
        for id in 1..=4 {
            upsert_bond(&mut bonds, bond(id));
        }
        assert_eq!(upsert_bond(&mut bonds, bond(4)), BondUpsert::Unchanged);
        assert_eq!(addresses(&bonds), std::vec![1, 2, 3, 4]);
    }

    #[test]
    fn touch_moves_known_bond_to_mru_end_and_reports_change() {
        let mut bonds = heapless::Vec::new();
        for id in 1..=4 {
            upsert_bond(&mut bonds, bond(id));
        }
        assert!(touch_bond(&mut bonds, 0, [1, 0, 0, 0, 0, 0]));
        assert_eq!(addresses(&bonds), std::vec![2, 3, 4, 1]);
    }

    #[test]
    fn touch_of_bond_already_at_mru_end_is_a_no_op() {
        let mut bonds = heapless::Vec::new();
        for id in 1..=4 {
            upsert_bond(&mut bonds, bond(id));
        }
        assert!(!touch_bond(&mut bonds, 0, [4, 0, 0, 0, 0, 0]));
        assert_eq!(addresses(&bonds), std::vec![1, 2, 3, 4]);
    }

    #[test]
    fn touch_of_unknown_bond_is_a_no_op() {
        let mut bonds = heapless::Vec::new();
        upsert_bond(&mut bonds, bond(1));
        assert!(!touch_bond(&mut bonds, 0, [9, 0, 0, 0, 0, 0]));
        assert_eq!(addresses(&bonds), std::vec![1]);
    }
}
