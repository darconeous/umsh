//! ESP32 instantiation of the chip-agnostic [`umsh_flash_store`] engine.
//!
//! All of the map logic — identity, peers, channels, counters, key-value —
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
//! the data partition labelled [`STORAGE_PARTITION_LABEL`], deriving the
//! `sequential-storage` range from the table itself. A hardcoded offset
//! would silently corrupt an adjacent partition the moment the CSV moved;
//! this way a mismatch is a clean [`StorageInitError::PartitionNotFound`]
//! at startup instead. The partition table is MD5-validated by
//! `esp-bootloader-esp-idf` as a side effect.
//!
//! ## CPU stall warning
//!
//! Erasing or writing internal flash suspends the flash cache for the
//! duration of the operation — every task stalls, not just this one, and
//! no async scheduling can preempt it. This is the ESP32 analogue of the
//! nRF52840's ~85 ms NVMC halt. Callers MUST batch writes; see
//! [`umsh_flash_store`] for the batching contract.
//!
//! ## Dual-core caveat
//!
//! `esp-storage` defaults to [`MultiCoreStrategy::Error`] on multi-core
//! parts, which fails writes while the second core is running. UMSH
//! firmware never starts the app CPU, so the default is both correct and
//! the safest posture — it turns a would-be flash corruption into a
//! visible error. Do not relax it to `ignore` without parking core 1.
//!
//! [`MultiCoreStrategy::Error`]: esp_storage::MultiCoreStrategy

use core::ops::Range;

use embassy_embedded_hal::adapter::BlockingAsync;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
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

/// View implementing `umsh_hal::PeerStore` over a shared [`EspStorage`].
pub type EspPeerStore = umsh_flash_store::PeerView<FlashDriver, CriticalSectionRawMutex>;

/// View implementing `umsh_hal::ChannelStore` over a shared [`EspStorage`].
pub type EspChannelStore = umsh_flash_store::ChannelView<FlashDriver, CriticalSectionRawMutex>;

/// Why the storage region could not be located at boot.
#[derive(Debug)]
pub enum StorageInitError {
    /// The partition table could not be read or failed MD5 validation.
    PartitionTable(partitions::Error),
    /// No partition labelled [`STORAGE_PARTITION_LABEL`] exists. Almost
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
/// range is derived — otherwise map GC would eventually wrap into the
/// journal and erase the BLE bonds. Both [`new_storage`] (map, bottom of
/// the partition) and journal placement (top of the partition, growing
/// downward) derive from this one constant.
///
/// Three page pairs, growing downward from the partition top:
/// BLE security journal (topmost pair — anchored there so bonds survive
/// the reservation growing), protocol snapshot journal, device-identity
/// journal. Grows in page pairs as more journals (counters) move to the
/// ESP32 in Phase 5.
pub const JOURNAL_RESERVED: u32 = 6 * FlashStorage::SECTOR_SIZE;

/// Locate the UMSH data partition and build the store over it.
///
/// Reads the partition table, resolves [`STORAGE_PARTITION_LABEL`] to a
/// flash range, and mounts the map lazily — nothing is erased or
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
/// partition — the record journals (`umsh_journal_store`) live in the
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
    let mut buf = [0u8; PARTITION_TABLE_MAX_LEN];
    let table =
        partitions::read_partition_table(flash, &mut buf).map_err(StorageInitError::PartitionTable)?;

    let entry = table
        .iter()
        .find(|e| e.label_as_str() == STORAGE_PARTITION_LABEL)
        .ok_or(StorageInitError::PartitionNotFound)?;

    let offset = entry.offset();
    let len = entry.len();
    // The map needs at least two pages to garbage-collect, after the
    // journal reservation is carved off the top.
    if len < 2 * FlashStorage::SECTOR_SIZE + JOURNAL_RESERVED {
        return Err(StorageInitError::TooSmall { len });
    }
    Ok(offset..offset + len)
}
