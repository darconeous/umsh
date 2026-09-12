//! Full-page WiFi snapshots sharing the existing two-page journal reservation.
//! Mount accepts legacy half-page records. The first new commit goes to the
//! opposite page, so an interrupted upgrade cannot erase the saved configuration.
use crate::journal::{JournalFlash, SharedFlash, journal_write_target};
use embassy_sync::blocking_mutex::raw::RawMutex;
use umsh_journal_store::{
    proto,
    record::{self, PAGE_SIZE},
};

pub const SLOT_SIZE: usize = PAGE_SIZE as usize;
pub type BootPayload = heapless::Vec<u8, { SLOT_SIZE - 19 }>;

pub struct WifiStore<M: RawMutex + 'static, F: JournalFlash + 'static> {
    flash: &'static SharedFlash<M, F>,
    page0: u32,
    generation: u32,
    slot: Option<u32>,
    walked_back_to: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
    use record::{PageEraser, RecordReader, RecordWriter};
    use std::{boxed::Box, vec, vec::Vec};

    struct Flash {
        bytes: Vec<u8>,
        budget: usize,
    }
    impl RecordReader for Flash {
        type Error = ();
        fn read_record(&mut self, address: u32, out: &mut [u8]) -> Result<(), ()> {
            out.copy_from_slice(&self.bytes[address as usize..address as usize + out.len()]);
            Ok(())
        }
    }
    impl RecordWriter for Flash {
        type Error = ();
        async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), ()> {
            for (i, byte) in bytes.iter().enumerate() {
                if self.budget == 0 {
                    return Err(());
                }
                self.budget -= 1;
                self.bytes[address as usize + i] &= byte;
            }
            Ok(())
        }
    }
    impl PageEraser for Flash {
        type Error = ();
        async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), ()> {
            self.bytes[start as usize..end as usize].fill(255);
            Ok(())
        }
    }
    fn run<T>(future: impl core::future::Future<Output = T>) -> T {
        let mut future = core::pin::pin!(future);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(value) => value,
            _ => panic!("mock flash must not suspend"),
        }
    }

    #[test]
    fn legacy_upgrade_and_interrupted_commits_preserve_one_complete_snapshot() {
        let old = b"legacy configuration";
        let new = [0x42; 2560];
        for cut in (0..24).chain((24..4092).step_by(137)).chain(4092..=4096) {
            let mut bytes = vec![255; 8192];
            let mut record = proto::encode_record(7, proto::RecordRef::Snapshot(old));
            record[proto::COMMIT_OFFSET..].fill(0);
            // Exercise a legacy record in the second half of a page.
            bytes[2048..4096].copy_from_slice(&record);
            let flash = Box::leak(Box::new(Mutex::<NoopRawMutex, _>::new(Flash {
                bytes,
                budget: cut,
            })));
            let (mut store, mounted) = run(WifiStore::mount(flash, 0));
            assert_eq!(mounted.as_deref(), Some(old.as_slice()));
            let saved = run(store.persist(&new));
            let (_, mounted) = run(WifiStore::mount(flash, 0));
            assert_eq!(
                mounted.as_deref(),
                Some(if saved.is_ok() { &new } else { old.as_slice() })
            );
        }
    }

    #[test]
    fn clear_is_committed_and_an_invalid_payload_can_walk_back() {
        let flash = Box::leak(Box::new(Mutex::<NoopRawMutex, _>::new(Flash {
            bytes: vec![255; 8192],
            budget: usize::MAX,
        })));
        let (mut store, _) = run(WifiStore::mount(flash, 0));
        run(store.persist(b"first")).unwrap();
        run(store.persist(b"invalid protocol payload")).unwrap();
        let (mut store, _) = run(WifiStore::mount(flash, 0));
        let mut out = [0; 64];
        let len = run(store.older_snapshot(&mut out)).unwrap();
        assert_eq!(&out[..len], b"first");
        run(store.clear()).unwrap();
        assert!(run(WifiStore::mount(flash, 0)).1.is_none());
    }
}

/// A large record occupies the whole page. Only when it is invalid do
/// we examine the legacy slots within it; payloads cannot masquerade as
/// independently committed legacy records inside a valid large record.
fn newest<F: JournalFlash>(
    flash: &mut F,
    page0: u32,
    before: Option<u32>,
    buf: &mut [u8; SLOT_SIZE],
) -> Option<(u32, usize, u32)> {
    let mut winner: Option<(u32, usize, u32)> = None;
    for page in [page0, page0 + PAGE_SIZE] {
        if flash.read_record(page, buf).is_err() {
            continue;
        }
        let large = proto::probe_record(buf).is_some();
        let width = if large { SLOT_SIZE } else { proto::SLOT_SIZE };
        for offset in (0..SLOT_SIZE).step_by(width) {
            let Some(generation) = proto::probe_record(&buf[offset..offset + width]) else {
                continue;
            };
            if before.is_some_and(|before| !record::generation_is_newer(before, generation)) {
                continue;
            }
            if winner.is_none_or(|(_, _, old)| record::generation_is_newer(generation, old)) {
                winner = Some((page + offset as u32, width, generation));
            }
        }
    }
    winner
}

impl<M: RawMutex + 'static, F: JournalFlash + 'static> WifiStore<M, F> {
    pub async fn mount(
        flash: &'static SharedFlash<M, F>,
        page0: u32,
    ) -> (Self, Option<BootPayload>) {
        let mut locked = flash.lock().await;
        let mut buf = [0; SLOT_SIZE];
        let found = newest(&mut *locked, page0, None, &mut buf);
        let payload = found.and_then(|(address, size, _)| {
            locked.read_record(address, &mut buf[..size]).ok()?;
            let (_, payload) = proto::payload_bytes(&buf[..size])?;
            BootPayload::from_slice(payload?).ok()
        });
        let generation = found.map_or(0, |(_, _, generation)| generation);
        (
            Self {
                flash,
                page0,
                generation,
                slot: found.map(|(address, _, _)| address),
                walked_back_to: generation,
            },
            payload,
        )
    }

    pub async fn older_snapshot(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut flash = self.flash.lock().await;
        let mut buf = [0; SLOT_SIZE];
        let (address, size, generation) =
            newest(&mut *flash, self.page0, Some(self.walked_back_to), &mut buf)?;
        self.walked_back_to = generation;
        flash.read_record(address, &mut buf[..size]).ok()?;
        let (_, payload) = proto::payload_bytes(&buf[..size])?;
        let payload = payload?;
        out.get_mut(..payload.len())?.copy_from_slice(payload);
        Some(payload.len())
    }

    pub async fn persist(&mut self, payload: &[u8]) -> Result<(), ()> {
        if payload.len() > SLOT_SIZE - 19 {
            return Err(());
        }
        self.write(proto::RecordRef::Snapshot(payload)).await
    }

    pub async fn clear(&mut self) -> Result<(), ()> {
        self.write(proto::RecordRef::Cleared).await
    }

    async fn write(&mut self, record: proto::RecordRef<'_>) -> Result<(), ()> {
        let mut flash = self.flash.lock().await;
        // Normalize a legacy slot to its page before selecting the other page.
        let current_page = self
            .slot
            .map(|address| self.page0 + ((address - self.page0) / PAGE_SIZE) * PAGE_SIZE);
        let target = journal_write_target(&mut *flash, current_page, self.page0, SLOT_SIZE).await?;
        let generation = self.generation.wrapping_add(1);
        let bytes = proto::encode_record_sized::<SLOT_SIZE>(generation, record);
        record::write_committed_record(&mut *flash, target, &bytes)
            .await
            .map_err(|_| ())?;
        self.generation = generation;
        self.slot = Some(target);
        Ok(())
    }
}
