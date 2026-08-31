//! Power-loss-safe entropy-pool seed records.
//!
//! One 32-byte seed per record, written through the shared
//! [`record`](crate::record) engine so a torn write can only ever cost
//! the *newest* seed, never the previous committed one. Which two pages
//! the journal owns is the firmware's memory-map decision.
//!
//! The seed is what `umsh_crypto::pool::EntropyPool` ratchets forward
//! at every boot; the write cadence is once per boot-that-drew plus the
//! occasional post-harvest refresh, so at 64 records per page the pair
//! sees an erase every couple hundred boots — wear is a non-issue.

use crate::record::{crc32, generation_is_newer};

pub const SLOT_SIZE: usize = 64;
pub const COMMIT_OFFSET: usize = SLOT_SIZE - 4;
const CRC_OFFSET: usize = COMMIT_OFFSET - 4;
const MAGIC: [u8; 4] = *b"URNG";
const VERSION: u8 = 1;
const SEED_OFFSET: usize = 12;

/// One committed pool seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedRecord {
    pub generation: u32,
    pub seed: [u8; 32],
}

impl SeedRecord {
    pub fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut out = [0xff; SLOT_SIZE];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5..8].fill(0);
        out[8..12].copy_from_slice(&self.generation.to_le_bytes());
        out[SEED_OFFSET..SEED_OFFSET + 32].copy_from_slice(&self.seed);
        let crc = crc32(&out[..CRC_OFFSET]);
        out[CRC_OFFSET..COMMIT_OFFSET].copy_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; SLOT_SIZE]) -> Option<Self> {
        if bytes[COMMIT_OFFSET..] != [0, 0, 0, 0]
            || bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || crc32(&bytes[..CRC_OFFSET])
                != u32::from_le_bytes(bytes[CRC_OFFSET..COMMIT_OFFSET].try_into().ok()?)
        {
            return None;
        }
        let seed: [u8; 32] = bytes[SEED_OFFSET..SEED_OFFSET + 32].try_into().ok()?;
        // An all-zero seed is far more plausibly erased-then-written
        // garbage than a real 256-bit value; refuse it rather than boot
        // a pool from it.
        if seed == [0; 32] {
            return None;
        }
        Some(Self {
            generation: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            seed,
        })
    }
}

/// Fold one slot's bytes into the newest-record scan.
pub fn consider_record(
    current: Option<(u32, SeedRecord)>,
    address: u32,
    bytes: &[u8; SLOT_SIZE],
) -> Option<(u32, SeedRecord)> {
    let Some(candidate) = SeedRecord::decode(bytes) else {
        return current;
    };
    if current
        .as_ref()
        .is_none_or(|(_, record)| generation_is_newer(candidate.generation, record.generation))
    {
        Some((address, candidate))
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SeedRecord {
        let mut seed = [0u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
        SeedRecord {
            generation: 7,
            seed,
        }
    }

    fn committed(record: &SeedRecord) -> [u8; SLOT_SIZE] {
        let mut bytes = record.encode();
        bytes[COMMIT_OFFSET..].fill(0);
        bytes
    }

    #[test]
    fn a_committed_record_round_trips() {
        let record = sample();
        assert_eq!(SeedRecord::decode(&committed(&record)), Some(record));
    }

    #[test]
    fn an_uncommitted_record_is_ignored() {
        // encode() leaves the commit word erased; only the engine's
        // second write makes the record visible.
        assert_eq!(SeedRecord::decode(&sample().encode()), None);
    }

    #[test]
    fn a_corrupt_body_is_ignored() {
        let mut bytes = committed(&sample());
        bytes[SEED_OFFSET] ^= 0x40;
        assert_eq!(SeedRecord::decode(&bytes), None);
    }

    #[test]
    fn an_all_zero_seed_is_refused() {
        let mut zeroed = sample();
        zeroed.seed = [0; 32];
        assert_eq!(SeedRecord::decode(&committed(&zeroed)), None);
    }

    #[test]
    fn the_newest_generation_wins_across_slots() {
        let old = committed(&sample());
        let new = committed(&SeedRecord {
            generation: 8,
            ..sample()
        });
        let latest = consider_record(None, 0x1000, &old);
        let latest = consider_record(latest, 0x1040, &new);
        assert_eq!(
            latest.map(|(address, r)| (address, r.generation)),
            Some((0x1040, 8))
        );
        // Order independence.
        let latest = consider_record(None, 0x1040, &new);
        let latest = consider_record(latest, 0x1000, &old);
        assert_eq!(latest.map(|(_, r)| r.generation), Some(8));
    }

    #[test]
    fn a_torn_newer_record_leaves_the_older_one_current() {
        let old = committed(&sample());
        // Body fully written, commit word never landed.
        let torn = SeedRecord {
            generation: 8,
            ..sample()
        }
        .encode();
        let latest = consider_record(None, 0x1000, &old);
        let latest = consider_record(latest, 0x1040, &torn);
        assert_eq!(latest.map(|(_, r)| r.generation), Some(7));
    }

    #[test]
    fn generation_wraparound_prefers_the_wrapped_record() {
        let pre_wrap = committed(&SeedRecord {
            generation: u32::MAX,
            ..sample()
        });
        let wrapped = committed(&SeedRecord {
            generation: 0,
            ..sample()
        });
        let latest = consider_record(None, 0x1000, &pre_wrap);
        let latest = consider_record(latest, 0x1040, &wrapped);
        assert_eq!(latest.map(|(_, r)| r.generation), Some(0));
    }
}
