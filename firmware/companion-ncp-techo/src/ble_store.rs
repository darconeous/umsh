//! Power-loss-safe BLE security snapshot encoding.
//!
//! The embedded wrapper writes fixed-size snapshots into two alternating flash
//! pages. A record becomes visible only when its final commit word is written.

pub const MAX_BONDS: usize = 4;
pub const SLOT_SIZE: usize = 256;
pub const PAGE_SIZE: u32 = 4096;
pub const PAGE0: u32 = 0x000E_4000;
pub const PAGE1: u32 = PAGE0 + PAGE_SIZE;
pub const COMMIT_OFFSET: usize = SLOT_SIZE - 4;
const CRC_OFFSET: usize = COMMIT_OFFSET - 4;
const MAGIC: [u8; 4] = *b"UBLS";
// Version 1 may contain a bond captured at the first protected GATT edge,
// before SMP identity-key distribution completed. Do not restore those
// incomplete records.
const VERSION: u8 = 3;
const BOND_SIZE: usize = 44;
const LOCAL_IRK_OFFSET: usize = 16;
const BONDS_OFFSET: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredBond {
    pub address_kind: u8,
    pub address: [u8; 6],
    pub irk: Option<[u8; 16]>,
    pub ltk: [u8; 16],
    pub security_level: u8,
    pub is_bonded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u32,
    pub pin: Option<u32>,
    pub local_irk: Option<[u8; 16]>,
    pub bonds: heapless::Vec<StoredBond, MAX_BONDS>,
}

impl Snapshot {
    pub const fn empty() -> Self {
        Self {
            generation: 0,
            pin: None,
            local_irk: None,
            bonds: heapless::Vec::new(),
        }
    }

    pub fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut out = [0xff; SLOT_SIZE];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
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
        }
        let crc = crc32(&out[..CRC_OFFSET]);
        out[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; SLOT_SIZE]) -> Option<Self> {
        if bytes[COMMIT_OFFSET..] != [0, 0, 0, 0]
            || bytes[..4] != MAGIC
            || bytes[4] != VERSION
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
            if security_level > 2 || bytes[start + 41] > 1 {
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
                })
                .ok()?;
        }
        Some(Self {
            generation: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            pin,
            local_irk,
            bonds,
        })
    }
}

pub fn generation_is_newer(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
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

/// Flash writer used by the journal's two-stage record commit.
#[allow(async_fn_in_trait)]
pub trait RecordWriter {
    type Error;

    async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[allow(async_fn_in_trait)]
pub trait PageEraser {
    type Error;

    async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitError<E> {
    Body(E),
    Commit(E),
}

/// Write a snapshot body first and its visibility marker last.
///
/// The caller must not publish the corresponding in-RAM snapshot until this
/// returns `Ok(())`. A mount ignores either failure shape because the commit
/// word remains incomplete.
pub async fn write_committed_record<W: RecordWriter>(
    writer: &mut W,
    target: u32,
    bytes: &[u8; SLOT_SIZE],
) -> Result<(), CommitError<W::Error>> {
    writer
        .write_record(target, &bytes[..COMMIT_OFFSET])
        .await
        .map_err(CommitError::Body)?;
    writer
        .write_record(target + COMMIT_OFFSET as u32, &[0; 4])
        .await
        .map_err(CommitError::Commit)
}

pub async fn erase_journal_page<E: PageEraser>(eraser: &mut E, page: u32) -> Result<(), E::Error> {
    eraser.erase_page(page, page + PAGE_SIZE).await
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};

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
    fn generation_comparison_handles_wraparound() {
        assert!(generation_is_newer(0, u32::MAX));
        assert!(!generation_is_newer(u32::MAX, 0));
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
    fn interrupted_new_record_never_replaces_committed_old_record() {
        let mut old = sample();
        old.generation = 7;
        let mut old_bytes = old.encode();
        old_bytes[COMMIT_OFFSET..].fill(0);

        let mut new = sample();
        new.generation = 8;
        new.pin = Some(654_321);
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
            (PAGE0 + COMMIT_OFFSET as u32, vec![0; 4])
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
        assert_eq!(writer.calls[1], (PAGE1 + COMMIT_OFFSET as u32, vec![0; 4]));
    }

    #[test]
    fn journal_page_erase_propagates_failure_and_uses_exact_bounds() {
        let mut failing = MockWriter {
            erase_failure: true,
            ..Default::default()
        };
        assert_eq!(block_on(erase_journal_page(&mut failing, PAGE1)), Err(()));
        assert_eq!(failing.erases, vec![(PAGE1, PAGE1 + PAGE_SIZE)]);

        let mut successful = MockWriter::default();
        assert_eq!(block_on(erase_journal_page(&mut successful, PAGE0)), Ok(()));
        assert_eq!(successful.erases, vec![(PAGE0, PAGE0 + PAGE_SIZE)]);
    }
}
