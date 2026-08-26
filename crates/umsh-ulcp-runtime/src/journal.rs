//! Two-page rotating journal handles, generic over the board's flash.
//!
//! `umsh-journal-store` owns the record *formats* and the committed-write
//! engine; this module owns the runtime handle wrapped around them — the
//! mount scan, the write-target rotation, and the boot path's walk-back.
//! Both were previously duplicated in each firmware, identical except for
//! which flash driver they closed over.
//!
//! The only genuinely per-board fact is that flash type: the nRF images
//! drive MPSL-coordinated NVMC, the ESP32 image its SPI flash part. It
//! enters as the `F` parameter, bounded by the `umsh-journal-store`
//! traits the board already implements, and a board's fault-injection
//! hooks stay in its own trait impls where they belong.

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;

use umsh_journal_store::proto;
use umsh_journal_store::record::{
    PAGE_SIZE, PageEraser, RecordReader, RecordWriter, erase_journal_page,
};

use crate::log::debug_log;

/// Everything a journal needs from a board's flash. Blanket-implemented,
/// so a board implements the three `umsh-journal-store` traits and gets
/// this for free.
pub trait JournalFlash:
    RecordWriter<Error = ()> + PageEraser<Error = ()> + RecordReader<Error = ()>
{
}

impl<F> JournalFlash for F where
    F: RecordWriter<Error = ()> + PageEraser<Error = ()> + RecordReader<Error = ()>
{
}

/// One flash driver shared between every journal on the board, behind
/// the async mutex that serializes access to it.
pub type SharedFlash<M, F> = Mutex<M, F>;

/// The stored protocol payload as read at boot.
pub type BootPayload = heapless::Vec<u8, { proto::MAX_PAYLOAD }>;

/// Scan a two-page journal's slot range for a fully erased slot.
fn erased_journal_slot<F: JournalFlash>(
    flash: &mut F,
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
            match flash.read_record(address + offset as u32, &mut chunk[..take]) {
                Ok(()) if chunk[..take].iter().all(|byte| *byte == 0xff) => {}
                Ok(()) => {
                    erased = false;
                    break;
                }
                Err(_) => {
                    debug_log(format_args!(
                        "store erased-slot read=FAILED address=0x{address:06x}"
                    ));
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
pub async fn journal_write_target<F: JournalFlash>(
    flash: &mut F,
    current: Option<u32>,
    page0: u32,
    slot_size: usize,
) -> Result<u32, ()> {
    let page1 = page0 + PAGE_SIZE;
    let target = if let Some(current) = current {
        let page = if current < page1 { page0 } else { page1 };
        erased_journal_slot(
            flash,
            current + slot_size as u32,
            page + PAGE_SIZE,
            slot_size,
        )
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
            debug_log(format_args!("store erase begin page=0x{page:06x}"));
            if erase_journal_page(flash, page).await.is_err() {
                debug_log(format_args!("store erase=FAILED page=0x{page:06x}"));
                return Err(());
            }
            debug_log(format_args!("store erase=ok page=0x{page:06x}"));
            Ok(page)
        }
    }
}

/// Runtime handle for one full-protocol record journal: the snapshot
/// journal, the device-identity journal, the device-node counter
/// journal, or a board's own preferences journal — selected by its first
/// page. Executes durable effects; a caller's RAM mirror is only updated
/// after these return.
pub struct ProtoStore<M: RawMutex + 'static, F: JournalFlash + 'static> {
    flash: &'static SharedFlash<M, F>,
    /// First page of this journal's two-page rotation.
    page0: u32,
    generation: u32,
    slot: Option<u32>,
    /// Oldest generation already handed to the boot restore. Only the
    /// snapshot-journal handle uses it, and only while the boot path is
    /// walking back past a rejected payload.
    walked_back_to: Option<u32>,
}

impl<M: RawMutex + 'static, F: JournalFlash + 'static> ProtoStore<M, F> {
    pub async fn mount(
        shared: &'static SharedFlash<M, F>,
        page0: u32,
    ) -> (Self, Option<BootPayload>) {
        let mut flash = shared.lock().await;
        let mut newest: Option<(u32, u32)> = None;
        let mut bytes = [0u8; proto::SLOT_SIZE];
        for page in [page0, page0 + PAGE_SIZE] {
            let mut address = page;
            while address < page + PAGE_SIZE {
                if flash.read_record(address, &mut bytes).is_ok() {
                    proto::consider_slot(&mut newest, address, &bytes);
                }
                address += proto::SLOT_SIZE as u32;
            }
        }
        // Read the winner once, after the scan, and copy its payload
        // straight into what this returns. The scan itself only tracks
        // addresses and generations, so a mount's working set is one slot
        // buffer no matter how many records are live — and no full record
        // is ever materialized on the way out.
        //
        // A tombstone is authoritative "nothing saved": older records
        // still physically present are void.
        let mut slot = None;
        let mut generation = 0;
        let mut payload: Option<BootPayload> = None;
        if let Some((address, _)) = newest
            && flash.read_record(address, &mut bytes).is_ok()
            && let Some((found, bytes)) = proto::payload_bytes(&bytes)
        {
            slot = Some(address);
            generation = found;
            payload = bytes.and_then(|bytes| BootPayload::from_slice(bytes).ok());
        }
        drop(flash);
        debug_log(format_args!(
            "proto-store mount page0=0x{page0:06x} slot={:?} generation={} payload={}",
            slot,
            generation,
            payload.as_ref().map_or(0, |payload| payload.len()),
        ));
        (
            Self {
                flash: shared,
                page0,
                generation,
                slot,
                walked_back_to: Some(generation),
            },
            payload,
        )
    }

    /// The shared flash this journal writes through.
    ///
    /// Exposed for whole-region operations that are not journal writes
    /// at all — a factory reset erases every page in the NV region,
    /// including journals no handle is currently mounted on.
    pub fn flash(&self) -> &'static SharedFlash<M, F> {
        self.flash
    }

    /// Copy the newest committed snapshot record strictly older than the
    /// last one handed out into `out`, for the boot path's walk-back past
    /// a payload the session rejected.
    ///
    /// Re-scans rather than retaining a runner-up at mount, so the mount
    /// path never buffers a second copy; the scan is only ever paid on a
    /// boot that already failed to restore. A tombstone ends the walk: it
    /// asserts "nothing saved", and older records physically behind it
    /// are void.
    pub async fn older_snapshot(&mut self, out: &mut [u8]) -> Option<usize> {
        let newer_than = self.walked_back_to?;
        let mut flash = self.flash.lock().await;
        let mut newest: Option<(u32, u32)> = None;
        let mut bytes = [0u8; proto::SLOT_SIZE];
        for page in [self.page0, self.page0 + PAGE_SIZE] {
            let mut address = page;
            while address < page + PAGE_SIZE {
                if flash.read_record(address, &mut bytes).is_ok() {
                    proto::consider_older_slot(&mut newest, address, &bytes, newer_than);
                }
                address += proto::SLOT_SIZE as u32;
            }
        }
        let (address, _) = newest?;
        if flash.read_record(address, &mut bytes).is_err() {
            return None;
        }
        drop(flash);
        let (generation, payload) = proto::payload_bytes(&bytes)?;
        self.walked_back_to = Some(generation);
        let Some(payload) = payload else {
            debug_log(format_args!("proto-store walk-back hit=tombstone"));
            self.walked_back_to = None;
            return None;
        };
        debug_log(format_args!(
            "proto-store walk-back generation={generation} payload={}",
            payload.len(),
        ));
        let len = payload.len().min(out.len());
        out[..len].copy_from_slice(&payload[..len]);
        (len == payload.len()).then_some(len)
    }

    pub async fn persist(&mut self, payload: &[u8]) -> Result<(), ()> {
        if payload.len() > proto::MAX_PAYLOAD {
            return Err(());
        }
        self.write(proto::RecordRef::Snapshot(payload)).await
    }

    /// The clear transaction is one committed tombstone record: if its
    /// write fails or is interrupted, the previous snapshot remains
    /// authoritative and the caller reports failure. Pages are never
    /// erased as part of a clear — stale records are reclaimed by the
    /// ordinary rotation.
    pub async fn clear(&mut self) -> Result<(), ()> {
        self.write(proto::RecordRef::Cleared).await
    }

    // The record travels by reference down to the single slot-image
    // encode: this future is held across awaits in several task pools,
    // and every avoided MAX_PAYLOAD copy is RAM off each of them.
    async fn write(&mut self, record: proto::RecordRef<'_>) -> Result<(), ()> {
        let generation = self.generation.wrapping_add(1);
        let mut flash = self.flash.lock().await;
        let target =
            journal_write_target(&mut *flash, self.slot, self.page0, proto::SLOT_SIZE).await?;
        match proto::write_record(&mut *flash, target, generation, record).await {
            Ok(()) => {
                debug_log(format_args!(
                    "proto-store commit generation={generation} slot=0x{target:06x} cleared={}",
                    matches!(record, proto::RecordRef::Cleared),
                ));
                self.generation = generation;
                self.slot = Some(target);
                Ok(())
            }
            Err(_) => {
                debug_log(format_args!(
                    "proto-store write=FAILED target=0x{target:06x}"
                ));
                Err(())
            }
        }
    }
}
