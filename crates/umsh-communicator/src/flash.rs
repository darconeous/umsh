//! The store kept in flash, as a `sequential-storage` map.
//!
//! [`FlashMapStore`] is the [`MemoryStore`] over a [`FlashMap`]: its records
//! are worked on in memory, and each one changed is written to the map at
//! the end of every step of a commit. Mounting reads the whole map once.
//!
//! The map is keyed by slot, not by record. A record keeps its slot while
//! it lives; a record forgotten has its slot marked free, and the slot is
//! given to the next new record. Marking a slot free is a write rather than
//! a removal, since `sequential-storage` finds an item to remove by reading
//! the whole partition; and since slots are reused, the free marks never
//! outnumber the most records ever kept at once.
//!
//! Each item is the record's key, after its length, then the record. A free
//! slot's item is empty.
//!
//! The partition's first sector is the store's header: [`HEADER`], the
//! store's mark and its format, and nothing else. The map keeps the rest.
//! `sequential-storage` keeps no mark of its own—it takes a page whose
//! first word is half zeros to be one of its own—so a partition holding
//! anything else would be read item by item before it failed to mount.
//! The header decides it in one read instead: a partition without one is
//! not this store's, and nothing past it is read. An erased header is a
//! partition never used, and is written once the map in it mounts.
//!
//! The map's calls are asynchronous, but over a blocking flash driver each
//! finishes on its first poll. The store polls each once, and treats one
//! that has not finished as a failed write.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::ops::Range;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use sequential_storage::cache::HeapKeyPointerCache;
use sequential_storage::map::{MapConfig, MapStorage};

use crate::durable::Durable;
use crate::memory::MemoryStore;
use crate::record::StoreError;

/// The chat store kept in flash.
pub type FlashMapStore<F> = MemoryStore<FlashMap<F>>;

/// The start of a partition holding this store: its mark, then the
/// version of its format.
const HEADER: [u8; 8] = [b'U', b'C', b'H', b'T', 0, 0, 0, 1];

/// What a partition's header says of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Header {
    /// This store, in this format.
    Ours,
    /// Erased: a partition never used.
    Erased,
    /// Anything else: not this store, or not in this format.
    Foreign,
}

/// Slots whose place in flash the map remembers, so that recycling a page
/// does not search for each of its items.
const CACHED_SLOTS: usize = 4096;

/// A store's records, kept in a `sequential-storage` map on `F`.
pub struct FlashMap<F: NorFlash> {
    map: Option<MapStorage<u32, F, HeapKeyPointerCache<u32>>>,
    /// Where the header sector starts.
    header: u32,
    /// The map's part of the partition: all of it after the header.
    range: Range<u32>,
    /// Where items are laid out on their way to and from flash.
    buffer: &'static mut [u8],
    /// Each record's slot, by its key.
    slots: BTreeMap<Vec<u8>, u32>,
    /// Slots marked free, to be given out again.
    free: Vec<u32>,
    /// The first slot never given out.
    next_slot: u32,
    /// An item, as it is written.
    item: Vec<u8>,
}

impl<F: NorFlash> FlashMap<F> {
    /// The store in `range` of `flash`, read and written through
    /// `buffer`: its header in the first sector, and the map in the rest.
    ///
    /// `buffer` holds the largest item: a message's record with its key,
    /// about 1.8 KB. Some drivers want it word-aligned, and in memory they
    /// can write from.
    pub fn new(flash: F, range: Range<u32>, buffer: &'static mut [u8]) -> Self {
        let header = range.start;
        let mut map = Self {
            map: None,
            header,
            range: header + F::ERASE_SIZE as u32..range.end,
            buffer,
            slots: BTreeMap::new(),
            free: Vec::new(),
            next_slot: 0,
            item: Vec::new(),
        };
        map.open(flash);
        map
    }

    fn open(&mut self, flash: F) {
        let pages = (self.range.end - self.range.start) as usize / F::ERASE_SIZE;
        self.map = Some(MapStorage::new(
            flash,
            MapConfig::new(self.range.clone()),
            HeapKeyPointerCache::new(pages, CACHED_SLOTS),
        ));
    }

    /// The flash the map is on.
    pub fn flash_mut(&mut self) -> &mut F {
        self.map().flash()
    }

    fn map(&mut self) -> &mut MapStorage<u32, F, HeapKeyPointerCache<u32>> {
        self.map.as_mut().expect("the map is open")
    }

    /// What the header sector says of the partition.
    fn header(&mut self) -> Result<Header, StoreError> {
        let mut bytes = alloc::vec![0u8; HEADER.len().next_multiple_of(F::READ_SIZE)];
        let at = self.header;
        now(self.map().flash().read(at, &mut bytes))?.map_err(|_| StoreError::Io)?;
        Ok(if bytes.iter().all(|&byte| byte == 0xFF) {
            Header::Erased
        } else if bytes.starts_with(&HEADER) {
            Header::Ours
        } else {
            Header::Foreign
        })
    }

    /// Write the header into its erased sector.
    fn write_header(&mut self) -> Result<(), StoreError> {
        let mut bytes = alloc::vec![0xFF; HEADER.len().next_multiple_of(F::WRITE_SIZE)];
        bytes[..HEADER.len()].copy_from_slice(&HEADER);
        let at = self.header;
        now(self.map().flash().write(at, &bytes))?.map_err(|_| StoreError::Io)
    }

    fn store(&mut self, slot: u32, item: &[u8]) -> Result<(), StoreError> {
        let map = self.map.as_mut().expect("the map is open");
        now(map.store_item(self.buffer, &slot, &item))?.map_err(error)
    }
}

impl<F: NorFlash> Durable for FlashMap<F> {
    const KEEPS: bool = true;

    fn write(&mut self, key: &[u8], record: Option<&[u8]>) -> Result<(), StoreError> {
        let Some(record) = record else {
            let Some(slot) = self.slots.remove(key) else {
                return Ok(());
            };
            self.store(slot, &[])?;
            self.free.push(slot);
            return Ok(());
        };
        let slot = match self.slots.get(key) {
            Some(&slot) => slot,
            None => {
                let slot = self.free.pop().unwrap_or_else(|| {
                    self.next_slot += 1;
                    self.next_slot - 1
                });
                self.slots.insert(key.to_vec(), slot);
                slot
            }
        };
        let mut item = core::mem::take(&mut self.item);
        item.clear();
        item.push(key.len() as u8);
        item.extend_from_slice(key);
        item.extend_from_slice(record);
        let stored = self.store(slot, &item);
        self.item = item;
        stored
    }

    fn read(&mut self, each: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), StoreError> {
        let header = self.header()?;
        if header == Header::Foreign {
            return Err(StoreError::Corrupt);
        }

        // A fresh cache: what the old one remembers may predate a power
        // cut.
        let map = self.map.take().expect("the map is open");
        let (flash, _) = map.destroy();
        self.open(flash);
        self.slots.clear();
        self.free.clear();
        self.next_slot = 0;

        // Each slot's newest item comes last.
        let mut newest: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let map = self.map.as_mut().expect("the map is open");
        let mut items = now(map.fetch_all_items(self.buffer))?.map_err(error)?;
        while let Some((slot, item)) = now(items.next::<&[u8]>(self.buffer))?.map_err(error)? {
            newest.insert(slot, item.to_vec());
        }

        for (slot, item) in newest {
            self.next_slot = self.next_slot.max(slot + 1);
            let record = item.split_first().and_then(|(&len, rest)| {
                (usize::from(len) <= rest.len()).then(|| rest.split_at(usize::from(len)))
            });
            match record {
                Some((key, record)) if !key.is_empty() => {
                    if let Some(older) = self.slots.insert(key.to_vec(), slot) {
                        self.free.push(older);
                    }
                    each(key, record);
                }
                _ => self.free.push(slot),
            }
        }
        if header == Header::Erased {
            self.write_header()?;
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        // The header goes last: until the map is erased, the partition
        // must still read as not this store's.
        now(self.map().erase_all())?.map_err(error)?;
        let at = self.header;
        now(self.map().flash().erase(at, at + F::ERASE_SIZE as u32))?
            .map_err(|_| StoreError::Io)?;
        self.write_header()?;
        self.slots.clear();
        self.free.clear();
        self.next_slot = 0;
        Ok(())
    }
}

fn error<E>(error: sequential_storage::Error<E>) -> StoreError {
    match error {
        sequential_storage::Error::FullStorage => StoreError::Full,
        sequential_storage::Error::Corrupted { .. } => StoreError::Corrupt,
        sequential_storage::Error::BufferTooSmall(_) => StoreError::BufferTooSmall,
        _ => StoreError::Io,
    }
}

/// `future`'s output, if it finishes on its first poll; a flash driver
/// that blocks always does.
fn now<T>(future: impl Future<Output = T>) -> Result<T, StoreError> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => Err(StoreError::Io),
    }
}

/// A NOR flash in memory, for tests and simulators. Its bits only clear
/// until their page is erased, and its power can be made to fail partway
/// through a write.
pub struct RamFlash {
    bytes: Vec<u8>,
    /// Words that may still be written, or pages erased, before power
    /// fails.
    budget: Option<usize>,
    /// Words written and pages erased so far.
    spent: usize,
}

/// What a [`RamFlash`] refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamFlashError {
    OutOfBounds,
    NotAligned,
    /// Its power has failed.
    Off,
}

impl NorFlashError for RamFlashError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            Self::OutOfBounds => NorFlashErrorKind::OutOfBounds,
            Self::NotAligned => NorFlashErrorKind::NotAligned,
            Self::Off => NorFlashErrorKind::Other,
        }
    }
}

impl RamFlash {
    /// `size` octets, erased.
    pub fn new(size: usize) -> Self {
        Self::from_bytes(alloc::vec![0xFF; size])
    }

    /// A flash holding `bytes`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            budget: None,
            spent: 0,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Power fails once `words` more words are written or pages erased: the
    /// write it fails in stops partway, and nothing more is written.
    pub fn fail_after(&mut self, words: usize) {
        self.budget = Some(words);
    }

    /// Power is back.
    pub fn power_on(&mut self) {
        self.budget = None;
    }

    /// Whether power has failed.
    pub fn failed(&self) -> bool {
        self.budget == Some(0)
    }

    /// Words written and pages erased so far.
    pub fn spent(&self) -> usize {
        self.spent
    }

    /// Spend one unit of the budget, if power holds.
    fn spend(&mut self) -> Result<(), RamFlashError> {
        match &mut self.budget {
            Some(0) => return Err(RamFlashError::Off),
            Some(left) => *left -= 1,
            None => {}
        }
        self.spent += 1;
        Ok(())
    }

    fn range(&self, offset: u32, len: usize, align: usize) -> Result<Range<usize>, RamFlashError> {
        let start = offset as usize;
        if !start.is_multiple_of(align) || !len.is_multiple_of(align) {
            return Err(RamFlashError::NotAligned);
        }
        let end = start.checked_add(len).ok_or(RamFlashError::OutOfBounds)?;
        if end > self.bytes.len() {
            return Err(RamFlashError::OutOfBounds);
        }
        Ok(start..end)
    }
}

impl ErrorType for RamFlash {
    type Error = RamFlashError;
}

impl ReadNorFlash for RamFlash {
    const READ_SIZE: usize = 4;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let range = self.range(offset, bytes.len(), Self::READ_SIZE)?;
        bytes.copy_from_slice(&self.bytes[range]);
        Ok(())
    }

    fn capacity(&self) -> usize {
        self.bytes.len()
    }
}

impl NorFlash for RamFlash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        let range = self.range(from, (to - from) as usize, Self::ERASE_SIZE)?;
        for page in range.step_by(Self::ERASE_SIZE) {
            self.spend()?;
            self.bytes[page..page + Self::ERASE_SIZE].fill(0xFF);
        }
        Ok(())
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let range = self.range(offset, bytes.len(), Self::WRITE_SIZE)?;
        for (at, word) in range
            .step_by(Self::WRITE_SIZE)
            .zip(bytes.chunks(Self::WRITE_SIZE))
        {
            self.spend()?;
            for (cell, &bit) in self.bytes[at..at + Self::WRITE_SIZE].iter_mut().zip(word) {
                *cell &= bit;
            }
        }
        Ok(())
    }
}

impl MultiwriteNorFlash for RamFlash {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::CommitStep;
    use crate::conformance::{self, Harness, Rig, direct, group};
    use crate::memory::Quota;
    use crate::store::ChatStore;

    /// 64 pages: room for every conformance test, and for recycling.
    const SIZE: usize = 64 * 4096;

    fn buffer() -> &'static mut [u8] {
        alloc::boxed::Box::leak(alloc::vec![0u8; 2048].into_boxed_slice())
    }

    fn mount(flash: RamFlash) -> FlashMapStore<RamFlash> {
        FlashMapStore::mount(
            FlashMap::new(flash, 0..SIZE as u32, buffer()),
            Quota::DEFAULT,
        )
        .unwrap()
    }

    struct Flash;

    impl Harness for Flash {
        type Store = FlashMapStore<RamFlash>;

        fn fresh(&mut self) -> Self::Store {
            mount(RamFlash::new(SIZE))
        }

        fn cut_power_after(&mut self, store: &mut Self::Store, step: CommitStep) {
            store.cut_power_after(step);
        }

        fn power_on(&mut self, store: &mut Self::Store) {
            store.power_on().unwrap();
        }
    }

    #[test]
    fn conformance() {
        conformance::run(&mut Flash);
    }

    /// A flash that counts its reads.
    struct Counted {
        flash: RamFlash,
        reads: usize,
    }

    impl ErrorType for Counted {
        type Error = RamFlashError;
    }

    impl ReadNorFlash for Counted {
        const READ_SIZE: usize = RamFlash::READ_SIZE;

        async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.reads += 1;
            self.flash.read(offset, bytes).await
        }

        fn capacity(&self) -> usize {
            self.flash.capacity()
        }
    }

    impl NorFlash for Counted {
        const WRITE_SIZE: usize = RamFlash::WRITE_SIZE;
        const ERASE_SIZE: usize = RamFlash::ERASE_SIZE;

        async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            self.flash.erase(from, to).await
        }

        async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            self.flash.write(offset, bytes).await
        }
    }

    impl MultiwriteNorFlash for Counted {}

    /// What another firmware left: no erased word, and every word's
    /// first byte more than half zeros, as `sequential-storage` takes for
    /// one of its own pages.
    fn foreign() -> RamFlash {
        RamFlash::from_bytes((0..SIZE).map(|at| (at % 251) as u8 & 0x3C).collect())
    }

    /// A partition holding something else is refused on its header's one
    /// read, not read item by item first.
    #[test]
    fn a_partition_holding_something_else_is_refused_at_once() {
        let mut map = FlashMap::new(
            Counted {
                flash: foreign(),
                reads: 0,
            },
            0..SIZE as u32,
            buffer(),
        );
        assert_eq!(map.read(&mut |_, _| {}), Err(StoreError::Corrupt));
        assert_eq!(map.flash_mut().reads, 1);
    }

    /// Cleared, a partition that held something else mounts as this
    /// store's from then on.
    #[test]
    fn a_cleared_partition_mounts_as_this_stores() {
        let mut store = FlashMapStore::mount_or_clear(
            FlashMap::new(foreign(), 0..SIZE as u32, buffer()),
            Quota::DEFAULT,
        )
        .unwrap();
        let bytes = store.durable_mut().flash_mut().bytes().to_vec();
        assert!(bytes.starts_with(&HEADER));
        assert_eq!(mount(RamFlash::from_bytes(bytes)).usage(), store.usage());
    }

    /// A partition never used mounts without an erase: its header is
    /// written, and nothing else.
    #[test]
    fn an_erased_partition_mounts_without_an_erase() {
        let mut store = mount(RamFlash::new(SIZE));
        let flash = store.durable_mut().flash_mut();
        assert_eq!(flash.spent(), HEADER.len() / RamFlash::WRITE_SIZE);
        assert!(flash.bytes().starts_with(&HEADER));
    }

    /// The store mounted again from the flash alone has what it had.
    #[test]
    fn a_remount_from_flash_keeps_everything() {
        let mut store = Flash.fresh();
        let mut rig = Rig::new();
        let mut said = Vec::new();
        for n in 0..40 {
            said.push(
                rig.say(&mut store, direct(), &alloc::format!("calm {n:03}"))
                    .1,
            );
            said.push(
                rig.say(&mut store, group(), &alloc::format!("busy {n:03}"))
                    .1,
            );
        }
        let bytes = store.durable_mut().flash_mut().bytes().to_vec();
        let mounted = mount(RamFlash::from_bytes(bytes));
        for &id in &said {
            assert_eq!(
                mounted.message(id).unwrap(),
                store.message(id).unwrap(),
                "{id:?}"
            );
        }
        assert_eq!(mounted.usage(), store.usage());
    }

    /// Flash that held something else is cleared, and the store over it
    /// takes commits.
    #[test]
    fn flash_that_held_something_else_is_cleared() {
        let bytes: Vec<u8> = (0..SIZE).map(|n| (n * 7 + 3) as u8).collect();
        let unread = FlashMapStore::mount(
            FlashMap::new(
                RamFlash::from_bytes(bytes.clone()),
                0..SIZE as u32,
                buffer(),
            ),
            Quota::DEFAULT,
        );
        assert!(unread.is_err());
        let mut store = FlashMapStore::mount_or_clear(
            FlashMap::new(RamFlash::from_bytes(bytes), 0..SIZE as u32, buffer()),
            Quota::DEFAULT,
        )
        .unwrap();
        assert_eq!(store.chats().count(), 0);
        let (_, id) = Rig::new().say(&mut store, direct(), "fresh");
        let bytes = store.durable_mut().flash_mut().bytes().to_vec();
        assert!(
            mount(RamFlash::from_bytes(bytes))
                .message(id)
                .unwrap()
                .is_some()
        );
    }

    /// Slots are reused, so a store that keeps evicting stays within a
    /// small flash however long it runs.
    #[test]
    fn eviction_does_not_fill_the_flash() {
        let mut store = FlashMapStore::mount(
            FlashMap::new(RamFlash::new(SIZE), 0..SIZE as u32, buffer()),
            Quota {
                bytes: 16 * 1024,
                keep_per_chat: 4,
                ..Quota::DEFAULT
            },
        )
        .unwrap();
        let mut rig = Rig::new();
        for n in 0..1500 {
            rig.say(&mut store, group(), &alloc::format!("busy {n:04}"));
        }
        let usage = store.usage();
        assert!(usage.bytes <= usage.quota);
    }

    /// Power failing at any word of a run of commits leaves a flash that
    /// mounts, holds no identifier given out twice, and takes commits
    /// again.
    #[test]
    fn power_fails_partway_through_a_write() {
        // The words the whole run writes, measured on a run without a cut.
        let mut probe = Flash.fresh();
        let mut rig = Rig::new();
        rig.say(&mut probe, direct(), "warm");
        let before = probe.durable_mut().flash_mut().spent();
        for n in 0..3 {
            rig.say(&mut probe, group(), &alloc::format!("busy {n}"));
        }
        let words = probe.durable_mut().flash_mut().spent() - before;

        for cut in (0..words).step_by(7) {
            let mut store = Flash.fresh();
            let mut rig = Rig::new();
            let (_, first) = rig.say(&mut store, direct(), "warm");
            store.durable_mut().flash_mut().fail_after(cut);
            let mut kept = alloc::vec![first];
            for n in 0..3 {
                match rig.try_say(&mut store, group(), &alloc::format!("busy {n}")) {
                    Some(id) => kept.push(id),
                    None => break,
                }
            }
            let mut flash = RamFlash::from_bytes(store.durable_mut().flash_mut().bytes().to_vec());
            flash.power_on();
            let mut mounted = mount(flash);
            let (_, next) = Rig::new().say(&mut mounted, group(), "after");
            assert!(kept.iter().all(|&id| id < next), "cut at {cut}");
            assert!(mounted.message(first).unwrap().is_some(), "cut at {cut}");
        }
    }
}
