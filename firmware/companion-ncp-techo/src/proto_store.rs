//! Full-protocol snapshot journal (spec §Saved State).
//!
//! Persists the opaque snapshot payload produced by
//! `Session::encode_snapshot` — the journal knows nothing about its
//! contents. Deliberately separate from the BLE bond/PIN journal
//! (`ble_store`): the two have different lifecycles (`CMD_CLEAR` erases
//! this journal but never touches bonds or the pairing PIN) and
//! different record sizes. The record machinery — two-page rotation,
//! CRC over the body, a trailing commit word written last, newest
//! generation wins — follows `ble_store`, whose `RecordWriter`/
//! `PageEraser` traits and committed-write helper are reused.

use super::ble_store::{self, CommitError, RecordWriter};

/// Flash pages owned by this journal: the two 4 KB pages immediately
/// after the BLE store's, inside the NV storage region
/// (0x000E_4000..0x000F_4000; see `memory.x`).
pub const PAGE_SIZE: u32 = ble_store::PAGE_SIZE;
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

/// A device-identity record payload: the Ed25519 private key followed
/// by its public key (stored so boot does not repeat the derivation).
pub const IDENTITY_PAYLOAD_LEN: usize = 64;

pub fn encode_identity(secret: &[u8; 32], public: &[u8; 32]) -> [u8; IDENTITY_PAYLOAD_LEN] {
    let mut payload = [0u8; IDENTITY_PAYLOAD_LEN];
    payload[..32].copy_from_slice(secret);
    payload[32..].copy_from_slice(public);
    payload
}

/// Split a persisted identity payload into (secret, public); anything
/// but the exact expected length is treated as no identity.
pub fn decode_identity(payload: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if payload.len() != IDENTITY_PAYLOAD_LEN {
        return None;
    }
    Some((
        payload[..32].try_into().expect("length checked"),
        payload[32..].try_into().expect("length checked"),
    ))
}

/// Two records per page; the snapshot payload is bounded by
/// `umsh_companion_ncp::SNAPSHOT_MAX` (1024) with headroom.
pub const SLOT_SIZE: usize = 2048;
pub const COMMIT_OFFSET: usize = SLOT_SIZE - 4;
const CRC_OFFSET: usize = COMMIT_OFFSET - 4;
const MAGIC: [u8; 4] = *b"UPRS";
const KIND_SNAPSHOT: u8 = 0;
const KIND_CLEARED: u8 = 1;
const HEADER_LEN: usize = 4 + 4 + 1 + 2;
/// Largest payload a record can carry.
pub const MAX_PAYLOAD: usize = CRC_OFFSET - HEADER_LEN;

/// What a journal record asserts about the saved protocol state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A saved snapshot with its opaque payload.
    Snapshot(heapless::Vec<u8, MAX_PAYLOAD>),
    /// A committed `CMD_CLEAR`: nothing is saved, and any older
    /// snapshot records still physically present are void. Erasing
    /// pages is never the clear transaction — a single committed
    /// tombstone is, so an interrupted clear can never resurrect an
    /// older snapshot from a surviving page.
    Cleared,
}

/// One journal record with its monotonically increasing generation;
/// the newest valid record is authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub generation: u32,
    pub record: Record,
}

impl Stored {
    pub fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut bytes = [0xFFu8; SLOT_SIZE];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..8].copy_from_slice(&self.generation.to_le_bytes());
        let (kind, payload): (u8, &[u8]) = match &self.record {
            Record::Snapshot(payload) => (KIND_SNAPSHOT, payload),
            Record::Cleared => (KIND_CLEARED, &[]),
        };
        bytes[8] = kind;
        bytes[9..11].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        bytes[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
        let crc = ble_store::crc32(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        // The commit word stays erased (0xFF); write_committed_record
        // writes zeros there only after the body lands.
        bytes
    }

    pub fn decode(bytes: &[u8; SLOT_SIZE]) -> Option<Self> {
        if bytes[..4] != MAGIC {
            return None;
        }
        if bytes[COMMIT_OFFSET..] != [0; 4] {
            return None;
        }
        let crc = u32::from_le_bytes(bytes[CRC_OFFSET..COMMIT_OFFSET].try_into().ok()?);
        if crc != ble_store::crc32(&bytes[..CRC_OFFSET]) {
            return None;
        }
        let generation = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let len = usize::from(u16::from_le_bytes(bytes[9..11].try_into().ok()?));
        if len > MAX_PAYLOAD {
            return None;
        }
        let record = match bytes[8] {
            KIND_SNAPSHOT => {
                let mut payload = heapless::Vec::new();
                payload
                    .extend_from_slice(&bytes[HEADER_LEN..HEADER_LEN + len])
                    .ok()?;
                Record::Snapshot(payload)
            }
            KIND_CLEARED if len == 0 => Record::Cleared,
            _ => return None,
        };
        Some(Self { generation, record })
    }
}

/// Consider one journal slot while mounting.
pub fn consider_record(
    current: Option<(u32, Stored)>,
    address: u32,
    bytes: &[u8; SLOT_SIZE],
) -> Option<(u32, Stored)> {
    let Some(candidate) = Stored::decode(bytes) else {
        return current;
    };
    if current.as_ref().is_none_or(|(_, stored)| {
        ble_store::generation_is_newer(candidate.generation, stored.generation)
    }) {
        Some((address, candidate))
    } else {
        current
    }
}

/// Write one committed record. Failure leaves any previously committed
/// record untouched: the body lands first and the commit word last, so
/// a mount never selects a partial write.
pub async fn write_record<W: RecordWriter>(
    writer: &mut W,
    target: u32,
    stored: &Stored,
) -> Result<(), CommitError<W::Error>> {
    let bytes = stored.encode();
    ble_store::write_committed_record(writer, target, &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ble_store::PageEraser;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    /// Mock flash that persists into a byte map and can cut power after
    /// a byte budget.
    struct MockFlash {
        bytes: std::collections::BTreeMap<u32, u8>,
        budget: Option<usize>,
    }

    impl MockFlash {
        fn new() -> Self {
            Self {
                bytes: std::collections::BTreeMap::new(),
                budget: None,
            }
        }

        fn slot(&self, address: u32) -> [u8; SLOT_SIZE] {
            let mut out = [0xFFu8; SLOT_SIZE];
            for (offset, byte) in out.iter_mut().enumerate() {
                if let Some(value) = self.bytes.get(&(address + offset as u32)) {
                    *byte = *value;
                }
            }
            out
        }

        fn mount(&self) -> Option<(u32, Stored)> {
            let mut latest = None;
            for page in [PAGE0, PAGE1] {
                let mut address = page;
                while address < page + PAGE_SIZE {
                    latest = consider_record(latest, address, &self.slot(address));
                    address += SLOT_SIZE as u32;
                }
            }
            latest
        }

        /// The snapshot payload a boot would restore: the newest valid
        /// record when it is a snapshot, nothing when it is a
        /// tombstone.
        fn mounted_snapshot(&self) -> Option<Stored> {
            match self.mount() {
                Some((_, stored)) if matches!(stored.record, Record::Snapshot(_)) => Some(stored),
                _ => None,
            }
        }
    }

    impl RecordWriter for MockFlash {
        type Error = ();

        async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            for (offset, byte) in bytes.iter().enumerate() {
                if let Some(budget) = &mut self.budget {
                    if *budget == 0 {
                        return Err(());
                    }
                    *budget -= 1;
                }
                self.bytes.insert(address + offset as u32, *byte);
            }
            Ok(())
        }
    }

    impl PageEraser for MockFlash {
        type Error = ();

        async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
            self.bytes.retain(|address, _| *address < start || *address >= end);
            Ok(())
        }
    }

    fn record(generation: u32, fill: u8, len: usize) -> Stored {
        let mut payload = heapless::Vec::new();
        payload.resize(len, fill).unwrap();
        Stored {
            generation,
            record: Record::Snapshot(payload),
        }
    }

    fn tombstone(generation: u32) -> Stored {
        Stored {
            generation,
            record: Record::Cleared,
        }
    }

    #[test]
    fn committed_record_round_trips_and_newest_generation_wins() {
        let mut flash = MockFlash::new();
        block_on(write_record(&mut flash, PAGE0, &record(1, 0xAA, 900))).unwrap();
        block_on(write_record(
            &mut flash,
            PAGE0 + SLOT_SIZE as u32,
            &record(2, 0xBB, 3),
        ))
        .unwrap();
        let (address, mounted) = flash.mount().unwrap();
        assert_eq!(address, PAGE0 + SLOT_SIZE as u32);
        assert_eq!(mounted, record(2, 0xBB, 3));
    }

    #[test]
    fn uncommitted_corrupt_and_oversize_records_are_ignored() {
        let mut flash = MockFlash::new();
        // Body without commit word.
        let bytes = record(1, 0xAA, 16).encode();
        block_on(RecordWriter::write_record(
            &mut flash,
            PAGE0,
            &bytes[..COMMIT_OFFSET],
        ))
        .unwrap();
        assert!(flash.mount().is_none());

        // Committed but corrupted body.
        block_on(write_record(&mut flash, PAGE0, &record(1, 0xAA, 16))).unwrap();
        flash.bytes.insert(PAGE0 + 12, 0x00);
        assert!(flash.mount().is_none());

        // A length field beyond capacity, and an unknown record kind.
        for (offset, bad) in [(9u32, (MAX_PAYLOAD as u16 + 1).to_le_bytes()), (8, [2, 0])] {
            let mut bytes = record(1, 0xAA, 16).encode();
            let at = offset as usize;
            bytes[at..at + 2].copy_from_slice(&bad);
            let crc = ble_store::crc32(&bytes[..CRC_OFFSET]);
            bytes[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
            let mut flash = MockFlash::new();
            block_on(RecordWriter::write_record(
                &mut flash,
                PAGE1,
                &bytes[..COMMIT_OFFSET],
            ))
            .unwrap();
            block_on(RecordWriter::write_record(
                &mut flash,
                PAGE1 + COMMIT_OFFSET as u32,
                &[0; 4],
            ))
            .unwrap();
            assert!(flash.mount().is_none());
        }
    }

    /// A committed tombstone is the clear transaction: it voids every
    /// older snapshot on either page without any erase, and an
    /// interrupted tombstone write leaves the previous snapshot
    /// authoritative.
    #[test]
    fn tombstone_clears_and_survives_interruption() {
        // Old snapshots on both pages, newest on PAGE1.
        let mut flash = MockFlash::new();
        block_on(write_record(&mut flash, PAGE0, &record(1, 0xAA, 40))).unwrap();
        block_on(write_record(&mut flash, PAGE1, &record(2, 0xBB, 40))).unwrap();
        assert_eq!(flash.mounted_snapshot().unwrap(), record(2, 0xBB, 40));

        // Cut the tombstone write at every distinct byte boundary: the
        // newest snapshot must remain authoritative — never the older
        // one. Every header byte, the CRC and commit regions, and
        // samples of the 0xFF-filled body (where all cuts are
        // physically identical: writing 0xFF to erased flash changes
        // nothing).
        let total = COMMIT_OFFSET + 4;
        for cut in (0..=HEADER_LEN + 1)
            .chain((HEADER_LEN..CRC_OFFSET).step_by(89))
            .chain(CRC_OFFSET - 1..total)
        {
            let mut flash = flash_with_two_snapshots();
            flash.budget = Some(cut);
            let target = PAGE0 + SLOT_SIZE as u32;
            assert!(block_on(write_record(&mut flash, target, &tombstone(3))).is_err());
            flash.budget = None;
            assert_eq!(
                flash.mounted_snapshot().expect("snapshot must survive"),
                record(2, 0xBB, 40),
                "cut at {cut} lost or replaced the committed snapshot"
            );
        }

        // The committed tombstone mounts as no snapshot, with both
        // older snapshot records still physically present.
        let mut flash = flash_with_two_snapshots();
        block_on(write_record(
            &mut flash,
            PAGE0 + SLOT_SIZE as u32,
            &tombstone(3),
        ))
        .unwrap();
        assert!(flash.mounted_snapshot().is_none());
        assert_eq!(flash.mount().unwrap().1, tombstone(3));

        // Clearing again is idempotent, and a later save supersedes.
        block_on(write_record(&mut flash, PAGE1 + SLOT_SIZE as u32, &tombstone(4))).unwrap();
        assert!(flash.mounted_snapshot().is_none());
        block_on(write_record(&mut flash, PAGE0, &record(5, 0xCC, 8))).unwrap();
        assert_eq!(flash.mounted_snapshot().unwrap(), record(5, 0xCC, 8));
    }

    fn flash_with_two_snapshots() -> MockFlash {
        let mut flash = MockFlash::new();
        block_on(write_record(&mut flash, PAGE0, &record(1, 0xAA, 40))).unwrap();
        block_on(write_record(&mut flash, PAGE1, &record(2, 0xBB, 40))).unwrap();
        flash
    }

    #[test]
    fn identity_payload_round_trips_and_pages_stay_in_the_nv_region() {
        let payload = encode_identity(&[0x11; 32], &[0x22; 32]);
        assert_eq!(decode_identity(&payload), Some(([0x11; 32], [0x22; 32])));
        assert_eq!(decode_identity(&payload[..63]), None);
        assert_eq!(decode_identity(&[]), None);
        // The identity journal sits after the snapshot journal, still
        // inside the reserved NV region (0x000E_4000..0x000F_4000).
        assert_eq!(IDENTITY_PAGE0, 0x000E_8000);
        assert_eq!(UX_PAGE0, 0x000E_A000);
        assert!(UX_PAGE0 + 2 * PAGE_SIZE <= 0x000F_4000);
    }

    /// Generation comparison survives wraparound: a record numbered 0
    /// supersedes one numbered u32::MAX.
    #[test]
    fn generation_wraparound_selects_the_newer_record() {
        let mut flash = MockFlash::new();
        block_on(write_record(&mut flash, PAGE0, &record(u32::MAX, 0xAA, 8))).unwrap();
        block_on(write_record(
            &mut flash,
            PAGE0 + SLOT_SIZE as u32,
            &tombstone(0),
        ))
        .unwrap();
        assert!(flash.mounted_snapshot().is_none());
        assert_eq!(flash.mount().unwrap().1, tombstone(0));
    }

    /// Cut the write at every byte boundary: a mount afterwards always
    /// yields the previously committed record, never a mixture.
    #[test]
    fn power_cut_at_every_byte_never_replaces_the_committed_record() {
        let old = record(7, 0x11, 700);
        let new = record(8, 0x22, 700);
        // Total bytes a full record write issues (body + commit word).
        let total = COMMIT_OFFSET + 4;
        for cut in 0..total {
            let mut flash = MockFlash::new();
            block_on(write_record(&mut flash, PAGE0, &old)).unwrap();
            flash.budget = Some(cut);
            let result = block_on(write_record(
                &mut flash,
                PAGE0 + SLOT_SIZE as u32,
                &new,
            ));
            assert!(result.is_err(), "cut at {cut} must fail the write");
            flash.budget = None;
            let (_, mounted) = flash.mount().expect("old record must survive");
            assert_eq!(mounted, old, "cut at {cut} corrupted the mount");
        }
        // And the complete write wins.
        let mut flash = MockFlash::new();
        block_on(write_record(&mut flash, PAGE0, &old)).unwrap();
        block_on(write_record(&mut flash, PAGE0 + SLOT_SIZE as u32, &new)).unwrap();
        assert_eq!(flash.mount().unwrap().1, new);
    }
}
