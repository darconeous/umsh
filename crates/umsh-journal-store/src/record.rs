//! The shared journal record engine.
//!
//! Every journal in this crate writes fixed-size records into two
//! alternating flash pages. A record becomes visible only when its final
//! commit word is written, so a mount after power loss always recovers
//! the previous committed record, never a partial write.

/// Flash page size shared by every backend the journals run on (nRF52840
/// NVMC and ESP32-S3 SPI flash are both 4 KiB-erase parts).
pub const PAGE_SIZE: u32 = 4096;

/// Wraparound-safe generation comparison: a record numbered 0 supersedes
/// one numbered `u32::MAX`.
pub fn generation_is_newer(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
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

/// Write a record body first and its visibility marker last. The
/// record's last four bytes are the commit word (shared convention
/// across every journal in this crate).
///
/// The caller must not publish the corresponding in-RAM snapshot until this
/// returns `Ok(())`. A mount ignores either failure shape because the commit
/// word remains incomplete.
pub async fn write_committed_record<W: RecordWriter, const SLOT: usize>(
    writer: &mut W,
    target: u32,
    bytes: &[u8; SLOT],
) -> Result<(), CommitError<W::Error>> {
    let commit_offset = SLOT - 4;
    writer
        .write_record(target, &bytes[..commit_offset])
        .await
        .map_err(CommitError::Body)?;
    writer
        .write_record(target + commit_offset as u32, &[0; 4])
        .await
        .map_err(CommitError::Commit)
}

pub async fn erase_journal_page<E: PageEraser>(eraser: &mut E, page: u32) -> Result<(), E::Error> {
    eraser.erase_page(page, page + PAGE_SIZE).await
}

/// CRC32 (reflected, polynomial 0xEDB88320) over a record body; the
/// journals store it immediately before the commit word.
pub fn crc32(bytes: &[u8]) -> u32 {
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

    #[test]
    fn generation_comparison_handles_wraparound() {
        assert!(generation_is_newer(0, u32::MAX));
        assert!(!generation_is_newer(u32::MAX, 0));
    }
}
