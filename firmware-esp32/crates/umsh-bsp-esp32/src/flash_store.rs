//! ESP32 instantiation of the chip-agnostic [`umsh_flash_store`] engine.
//!
//! All of the map logic—identity, counters, key-value—
//! lives in [`umsh_flash_store`], generic over the async flash driver and
//! the sharing mutex. This module supplies the Espressif backing
//! (`BlockingAsync<esp_storage::FlashStorage>` + `CriticalSectionRawMutex`)
//! and locates the storage region, then re-exports the resulting concrete
//! types under `Esp*` names. It is the exact analogue of
//! `umsh_bsp_nrf52840::flash_store`.
//!
//! ## The region is discovered, never hardcoded
//!
//! [`new_storage`] reads the ESP-IDF partition table at boot and looks up
//! the data partition labeled [`STORAGE_PARTITION_LABEL`], deriving the
//! `sequential-storage` range from the table itself. A hardcoded offset
//! would silently corrupt an adjacent partition the moment the CSV moved;
//! this way a mismatch is a clean [`StorageInitError::PartitionNotFound`]
//! at startup instead. The partition table is MD5-validated by
//! `esp-bootloader-esp-idf` as a side effect.
//!
//! ## CPU stall warning
//!
//! Erasing or writing internal flash suspends the flash cache for the
//! duration of the operation—every task stalls, not just this one, and
//! no async scheduling can preempt it. This is the ESP32 analogue of the
//! nRF52840's ~85 ms NVMC halt. Callers MUST batch writes; see
//! [`umsh_flash_store`] for the batching contract.
//!
//! ## Dual-core caveat
//!
//! `esp-storage` defaults to [`MultiCoreStrategy::Error`] on multi-core
//! parts, which fails writes while the second core is running. UMSH
//! firmware never starts the app CPU, so the default is both correct and
//! the safest posture—it turns a would-be flash corruption into a
//! visible error. Do not relax it to `ignore` without parking core 1.
//!
//! [`MultiCoreStrategy::Error`]: esp_storage::MultiCoreStrategy

use core::cell::RefCell;
use core::ops::Range;

use embassy_embedded_hal::adapter::BlockingAsync;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use esp_bootloader_esp_idf::partitions::{self, PARTITION_TABLE_MAX_LEN};
use esp_hal::peripherals::FLASH;
use esp_storage::{FlashStorage, FlashStorageError};

/// Label of the data partition backing UMSH storage.
///
/// MUST match the `umsh` row in the board's `partitions.csv`. Firmware
/// flashed with the espflash default table has no such partition and will
/// fail with [`StorageInitError::PartitionNotFound`].
pub const STORAGE_PARTITION_LABEL: &str = "umsh";

/// The async flash driver: the blocking `esp-storage` flash adapted to
/// the `embedded-storage-async` traits.
pub type FlashDriver = BlockingAsync<FlashStorage<'static>>;

/// Errors surfaced by the ESP32-backed store.
pub type Error = umsh_flash_store::Error<FlashStorageError>;

/// Owns the flash driver and the `sequential-storage` map.
///
/// Construct once during board init with [`new_storage`], place the
/// result in a `StaticCell`, then hand `&'static` references to the view
/// constructors when building the `Mac` platform.
pub type EspStorage = umsh_flash_store::FlashStore<FlashDriver, CriticalSectionRawMutex>;

/// View implementing `umsh_hal::KeyValueStore` over a shared [`EspStorage`].
pub type EspKeyValueStore = umsh_flash_store::KeyValueView<FlashDriver, CriticalSectionRawMutex>;

/// View implementing `umsh_hal::CounterStore` over a shared [`EspStorage`].
pub type EspCounterStore = umsh_flash_store::CounterView<FlashDriver, CriticalSectionRawMutex>;

/// Why the storage region could not be located at boot.
#[derive(Debug)]
pub enum StorageInitError {
    /// The partition table could not be read or failed MD5 validation.
    PartitionTable(partitions::Error),
    /// No partition labeled [`STORAGE_PARTITION_LABEL`] exists. Almost
    /// always means the board was flashed with the default partition
    /// table instead of the board's `partitions.csv`.
    PartitionNotFound,
    /// The partition exists but cannot hold both the [`JOURNAL_RESERVED`]
    /// tail and the two pages `sequential-storage` needs to operate.
    TooSmall {
        /// Actual partition length in bytes.
        len: u32,
    },
}

/// Bytes at the TOP of the `umsh` partition reserved for the record
/// journals (`umsh_journal_store`) and therefore excluded from the
/// `sequential-storage` map range.
///
/// The map's garbage collector rotates writes through its entire range,
/// so the journal pages MUST be carved out here, at the single place the
/// range is derived—otherwise map GC would eventually wrap into the
/// journal and erase the BLE bonds. Both [`new_storage`] (map, bottom of
/// the partition) and journal placement (top of the partition, growing
/// downward) derive from this one constant.
///
/// Five page pairs, growing downward from the partition top:
/// BLE security journal (topmost pair—anchored there so bonds survive
/// the reservation growing), protocol snapshot journal, device-identity
/// journal, device-node counter journal (Phase 5), entropy-pool seed
/// journal. Growing this reservation shrinks the map range from the
/// top, which is safe (see [`new_storage`]); existing journals keep
/// their addresses because every pair anchors to the partition end.
pub const JOURNAL_RESERVED: u32 = 10 * FlashStorage::SECTOR_SIZE;

/// Locate the UMSH data partition and build the store over it.
///
/// Reads the partition table, resolves [`STORAGE_PARTITION_LABEL`] to a
/// flash range, and mounts the map lazily—nothing is erased or
/// formatted here. The map receives the partition minus the
/// [`JOURNAL_RESERVED`] tail. Shrinking the range on boards written by
/// earlier firmware is safe: `sequential-storage` fills from the bottom
/// of its range, so the excluded tail pages hold no map data.
pub fn new_storage(flash: FLASH<'static>) -> Result<EspStorage, StorageInitError> {
    let mut flash_storage = FlashStorage::new(flash);
    let range = storage_range(&mut flash_storage)?;
    Ok(EspStorage::new(
        BlockingAsync::new(flash_storage),
        range.start..range.end - JOURNAL_RESERVED,
    ))
}

/// Open the raw flash driver and resolve the UMSH partition's absolute
/// range, without mounting the `sequential-storage` map.
///
/// Used by firmware that needs raw byte-addressed access into the
/// partition—the record journals (`umsh_journal_store`) live in the
/// [`JOURNAL_RESERVED`] tail of this range rather than in the map.
/// Discovering the range here keeps the journal region tied to the
/// partition table, never hardcoded, exactly as [`new_storage`] does for
/// the map.
pub fn open_partition(
    flash: FLASH<'static>,
) -> Result<(FlashStorage<'static>, Range<u32>), StorageInitError> {
    let mut flash_storage = FlashStorage::new(flash);
    let range = storage_range(&mut flash_storage)?;
    Ok((flash_storage, range))
}

/// Resolve [`STORAGE_PARTITION_LABEL`] to an absolute flash range.
///
/// Split out from [`new_storage`] so the partition-table buffer is
/// released before the store is built.
fn storage_range(flash: &mut FlashStorage<'static>) -> Result<Range<u32>, StorageInitError> {
    let range = find_partition(flash, STORAGE_PARTITION_LABEL)?;
    let len = range.end - range.start;
    // The map needs at least two pages to garbage-collect, after the
    // journal reservation is carved off the top.
    if len < 2 * FlashStorage::SECTOR_SIZE + JOURNAL_RESERVED {
        return Err(StorageInitError::TooSmall { len });
    }
    Ok(range)
}

/// The absolute flash range of the partition labeled `label`, as the
/// partition table gives it.
pub fn find_partition(
    flash: &mut FlashStorage<'static>,
    label: &str,
) -> Result<Range<u32>, StorageInitError> {
    let mut buf = [0u8; PARTITION_TABLE_MAX_LEN];
    let table = partitions::read_partition_table(flash, &mut buf)
        .map_err(StorageInitError::PartitionTable)?;
    let entry = table
        .iter()
        .find(|e| e.label_as_str() == label)
        .ok_or(StorageInitError::PartitionNotFound)?;
    Ok(entry.offset()..entry.offset() + entry.len())
}

// ─── One driver, lent per operation ─────────────────────────────────────

/// The flash driver, lent for one operation at a time.
///
/// Every operation is a blocking call that finishes before anything else
/// runs, so lending the driver for each one is all the sharing it needs.
/// The journals' handles, which are asynchronous, and the chat store's,
/// which is not, reach the one driver this way, and none holds it across
/// an await.
pub struct Flash {
    driver: RefCell<FlashStorage<'static>>,
    bounce: RefCell<Bounce>,
}

/// One piece of a [`Bounced`] transfer, in internal RAM.
#[repr(align(4))]
struct Bounce([u8; BOUNCE]);

/// How much of a [`Bounced`] transfer goes at once: a whole number of
/// words.
const BOUNCE: usize = 256;

impl Flash {
    pub fn new(driver: FlashStorage<'static>) -> Self {
        Self {
            driver: RefCell::new(driver),
            bounce: RefCell::new(Bounce([0; BOUNCE])),
        }
    }

    /// Lends the driver for one operation.
    pub fn with<R>(&self, operation: impl FnOnce(&mut FlashStorage<'static>) -> R) -> R {
        operation(&mut self.driver.borrow_mut())
    }
}

/// [`Flash`] for a caller whose buffers may be in PSRAM, as the chat
/// store's are.
///
/// A flash operation cannot reach external RAM, so each transfer passes
/// through a buffer in internal RAM, a piece at a time, without the
/// driver's sector-sized copy on the stack. An erase goes a sector at a
/// time, the driver lent for each, so that interrupts are taken between
/// sectors rather than held off for a whole block.
pub struct Bounced(&'static Flash);

impl Bounced {
    pub fn new(flash: &'static Flash) -> Self {
        Self(flash)
    }
}

impl ErrorType for Bounced {
    type Error = FlashStorageError;
}

impl ReadNorFlash for Bounced {
    const READ_SIZE: usize = FlashStorage::READ_SIZE;

    async fn read(&mut self, mut offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let mut bounce = self.0.bounce.borrow_mut();
        for piece in bytes.chunks_mut(BOUNCE) {
            let staged = &mut bounce.0[..piece.len()];
            self.0.with(|driver| driver.read_nor(offset, staged))?;
            piece.copy_from_slice(staged);
            offset += piece.len() as u32;
        }
        Ok(())
    }

    fn capacity(&self) -> usize {
        self.0.with(|driver| driver.capacity())
    }
}

impl NorFlash for Bounced {
    const WRITE_SIZE: usize = FlashStorage::WRITE_SIZE;
    const ERASE_SIZE: usize = FlashStorage::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        let sector = FlashStorage::SECTOR_SIZE;
        for start in (from..to).step_by(sector as usize) {
            self.0
                .with(|driver| driver.erase(start, (start + sector).min(to)))?;
        }
        Ok(())
    }

    async fn write(&mut self, mut offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let mut bounce = self.0.bounce.borrow_mut();
        for piece in bytes.chunks(BOUNCE) {
            let staged = &mut bounce.0[..piece.len()];
            staged.copy_from_slice(piece);
            self.0.with(|driver| driver.write_nor(offset, staged))?;
            offset += piece.len() as u32;
        }
        Ok(())
    }
}

impl MultiwriteNorFlash for Bounced {}
