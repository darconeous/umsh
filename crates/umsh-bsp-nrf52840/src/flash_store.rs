//! NVMC-backed instantiation of the chip-agnostic [`umsh_flash_store`]
//! engine.
//!
//! All of the map logic — identity, peers, channels, counters, key-value —
//! lives in [`umsh_flash_store`], generic over the async flash driver and
//! the sharing mutex. This module supplies the nRF52840 backing
//! (`BlockingAsync<Nvmc>` + `ThreadModeRawMutex`) and the fixed storage
//! region, then re-exports the resulting concrete types under their
//! historical `Nvmc*` names.
//!
//! See `docs/firmware-storage-plan.md` for the architectural rationale and
//! [`umsh_flash_store`] for the key layout and the CPU-stall warning
//! (every NVMC page erase blocks the entire executor for ~85 ms — callers
//! MUST batch writes).

use core::ops::Range;

use embassy_embedded_hal::adapter::BlockingAsync;
use embassy_nrf::nvmc::Nvmc;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;

pub use umsh_flash_store::{
    ALIAS_HEADER_LEN, MAX_ALIAS_LEN, MAX_CHANNEL_NAME_LEN, MAX_CHANNELS, MAX_KEY_LEN, MAX_PEERS,
    MAX_PEER_RECORD_LEN, SCRATCH_LEN,
};

/// Storage range reserved on internal NVMC.
///
/// MUST match what every dependent firmware's `memory.x` excludes from
/// the `FLASH` region — the linker must not place code or rodata here.
/// 16 pages × 4 KB = 64 KB.
pub const NV_STORE_RANGE: Range<u32> = 0x000E_4000..0x000F_4000;

/// The async flash driver: the blocking NVMC peripheral adapted to the
/// `embedded-storage-async` traits.
pub type FlashDriver = BlockingAsync<Nvmc<'static>>;

/// Errors surfaced by the NVMC-backed store.
pub type Error = umsh_flash_store::Error<embassy_nrf::nvmc::Error>;

/// Owns the NVMC flash driver and the `sequential-storage` map.
///
/// Construct once during board init with [`new_storage`], place the
/// result in a `StaticCell`, then hand `&'static` references to the view
/// constructors when building the `Mac` platform.
pub type NvmcStorage = umsh_flash_store::FlashStore<FlashDriver, ThreadModeRawMutex>;

/// Build the NVMC-backed store over [`NV_STORE_RANGE`].
///
/// Wraps the blocking NVMC peripheral for the async storage traits and
/// pins the storage region here so firmware never has to name it. Does
/// NOT erase or format the flash — the map mounts lazily on first
/// access.
pub fn new_storage(nvmc: Nvmc<'static>) -> NvmcStorage {
    NvmcStorage::new(BlockingAsync::new(nvmc), NV_STORE_RANGE)
}

/// View implementing `umsh_hal::KeyValueStore` over a shared [`NvmcStorage`].
pub type NvmcKeyValueStore = umsh_flash_store::KeyValueView<FlashDriver, ThreadModeRawMutex>;

/// View implementing `umsh_hal::CounterStore` over a shared [`NvmcStorage`].
pub type NvmcCounterStore = umsh_flash_store::CounterView<FlashDriver, ThreadModeRawMutex>;

/// View implementing `umsh_hal::PeerStore` over a shared [`NvmcStorage`].
pub type NvmcPeerStore = umsh_flash_store::PeerView<FlashDriver, ThreadModeRawMutex>;

/// View implementing `umsh_hal::ChannelStore` over a shared [`NvmcStorage`].
pub type NvmcChannelStore = umsh_flash_store::ChannelView<FlashDriver, ThreadModeRawMutex>;
