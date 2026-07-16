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

use super::ble_store::{self, CommitError, PageEraser, RecordWriter};

/// Flash pages owned by this journal: the two 4 KB pages immediately
/// after the BLE store's, inside the NV storage region
/// (0x000E_4000..0x000F_4000; see `memory.x`).
pub const PAGE_SIZE: u32 = ble_store::PAGE_SIZE;
pub const PAGE0: u32 = ble_store::PAGE1 + PAGE_SIZE;
pub const PAGE1: u32 = PAGE0 + PAGE_SIZE;

/// Two records per page; the snapshot payload is bounded by
/// `umsh_companion_ncp::SNAPSHOT_MAX` (1024) with headroom.
pub const SLOT_SIZE: usize = 2048;
pub const COMMIT_OFFSET: usize = SLOT_SIZE - 4;
const CRC_OFFSET: usize = COMMIT_OFFSET - 4;
const MAGIC: [u8; 4] = *b"UPRS";
const HEADER_LEN: usize = 4 + 4 + 2;
/// Largest payload a record can carry.
pub const MAX_PAYLOAD: usize = CRC_OFFSET - HEADER_LEN;

/// One decoded journal record: a monotonically increasing generation
/// and the opaque snapshot payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub generation: u32,
    pub payload: heapless::Vec<u8, MAX_PAYLOAD>,
}

impl Record {
    pub fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut bytes = [0xFFu8; SLOT_SIZE];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..8].copy_from_slice(&self.generation.to_le_bytes());
        bytes[8..10].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        bytes[HEADER_LEN..HEADER_LEN + self.payload.len()].copy_from_slice(&self.payload);
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
        let len = usize::from(u16::from_le_bytes(bytes[8..10].try_into().ok()?));
        if len > MAX_PAYLOAD {
            return None;
        }
        let mut payload = heapless::Vec::new();
        payload
            .extend_from_slice(&bytes[HEADER_LEN..HEADER_LEN + len])
            .ok()?;
        Some(Self {
            generation,
            payload,
        })
    }
}

/// Consider one journal slot while mounting.
pub fn consider_record(
    current: Option<(u32, Record)>,
    address: u32,
    bytes: &[u8; SLOT_SIZE],
) -> Option<(u32, Record)> {
    let Some(candidate) = Record::decode(bytes) else {
        return current;
    };
    if current.as_ref().is_none_or(|(_, record)| {
        ble_store::generation_is_newer(candidate.generation, record.generation)
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
    record: &Record,
) -> Result<(), CommitError<W::Error>> {
    let bytes = record.encode();
    ble_store::write_committed_record(writer, target, &bytes).await
}

pub async fn erase_page<E: PageEraser>(eraser: &mut E, page: u32) -> Result<(), E::Error> {
    ble_store::erase_journal_page(eraser, page).await
}

#[cfg(test)]
mod tests {
    use super::*;
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

        fn mount(&self) -> Option<(u32, Record)> {
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

    fn record(generation: u32, fill: u8, len: usize) -> Record {
        let mut payload = heapless::Vec::new();
        payload.resize(len, fill).unwrap();
        Record {
            generation,
            payload,
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

        // A length field beyond capacity.
        let mut bytes = record(1, 0xAA, 16).encode();
        bytes[8..10].copy_from_slice(&(MAX_PAYLOAD as u16 + 1).to_le_bytes());
        let crc = ble_store::crc32(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        block_on(RecordWriter::write_record(&mut flash, PAGE1, &bytes[..COMMIT_OFFSET])).unwrap();
        block_on(RecordWriter::write_record(
            &mut flash,
            PAGE1 + COMMIT_OFFSET as u32,
            &[0; 4],
        ))
        .unwrap();
        assert!(flash.mount().is_none());
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
