//! NVMC-backed implementation of the `umsh-hal` storage traits.
//!
//! Carves out the fixed 64 KB region `0xE4000..0xF4000` at the top of
//! internal flash for [`sequential-storage`](https://docs.rs/sequential-storage).
//! See `docs/firmware-storage-plan.md` for the full architectural
//! rationale (sizing, why not littlefs/ekv, accepted limitations).
//!
//! The same map serves both `KeyValueStore` and `CounterStore`. Logical
//! separation is by ASCII key prefix decided at the call site:
//!
//! | Prefix       | Trait           | Payload                              |
//! |--------------|-----------------|--------------------------------------|
//! | `id.sk`      | KeyValueStore   | local Ed25519 secret scalar (32 B)   |
//! | `peer:<pk>`  | KeyValueStore   | serialised peer record               |
//! | `ch:<id>`    | KeyValueStore   | channel name + key + flags           |
//! | `mac.tx:<pk>`| CounterStore    | TX reservation boundary (u32 LE)     |
//! | `mac.rx:<pk>`| CounterStore    | RX replay-window boundary (u32 LE)   |
//!
//! ## CPU stall warning
//!
//! Every page erase blocks the entire executor for ~85 ms — the
//! nRF52840 NVMC hardware halts the CPU during erase/write and no
//! amount of async scheduling can preempt it. Callers MUST batch
//! writes; the MAC's TX-side `COUNTER_PERSIST_BLOCK_SIZE = 128` and
//! the planned RX-side mirror keep this manageable for counters, and
//! peer-record writes should be debounced at the application layer.
//!
//! ## Sharing model
//!
//! [`NvmcStorage`] owns the flash + map behind an async mutex.
//! [`NvmcKeyValueStore`] and [`NvmcCounterStore`] are zero-cost view
//! types that each hold a `&'static NvmcStorage`. They exist as
//! separate types because the `umsh-hal` traits both define `load` and
//! `store` methods — implementing both on a single type would force
//! every caller to disambiguate via UFCS. Keep them split.

use core::ops::Range;

use embassy_embedded_hal::adapter::BlockingAsync;
use embassy_nrf::nvmc::Nvmc;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::mutex::Mutex;
use heapless::Vec;
use sequential_storage::cache::NoCache;
use sequential_storage::map::{MapConfig, MapStorage};

/// Storage range reserved on internal NVMC.
///
/// MUST match what every dependent firmware's `memory.x` excludes from
/// the `FLASH` region — the linker must not place code or rodata here.
/// 16 pages × 4 KB = 64 KB.
pub const NV_STORE_RANGE: Range<u32> = 0x000E_4000..0x000F_4000;

/// Maximum stored key length. Covers an 8-byte ASCII prefix plus a
/// 32-byte Ed25519 pubkey with headroom for shorter prefixes / new
/// namespaces.
pub const MAX_KEY_LEN: usize = 64;

/// Per-call scratch buffer size used for sequential-storage's serialise
/// / deserialise workspace. Must hold the largest (serialised key +
/// value) pair the store ever sees. 512 B comfortably covers a 64 B
/// key plus a ~256 B peer record.
pub const SCRATCH_LEN: usize = 512;

/// Heapless `Vec` used as the in-memory key representation, with the
/// `sequential-storage` `Key` impl provided by the `heapless` feature.
type StoreKey = Vec<u8, MAX_KEY_LEN>;

type FlashDriver = BlockingAsync<Nvmc<'static>>;

type Map = MapStorage<StoreKey, FlashDriver, NoCache>;

/// Errors surfaced by this module.
#[derive(Debug)]
pub enum Error {
    /// Caller-supplied key exceeded [`MAX_KEY_LEN`].
    KeyTooLong,
    /// Stored value did not fit in the caller-supplied buffer on load.
    ValueTooLong,
    /// `sequential-storage` returned an error (corruption, full storage,
    /// underlying NVMC failure, …).
    Storage(sequential_storage::Error<embassy_nrf::nvmc::Error>),
}

impl From<sequential_storage::Error<embassy_nrf::nvmc::Error>> for Error {
    fn from(err: sequential_storage::Error<embassy_nrf::nvmc::Error>) -> Self {
        Self::Storage(err)
    }
}

/// Owns the flash driver and the `sequential-storage` map.
///
/// Construct once during board init, place in a `StaticCell`, then hand
/// `&'static` references to [`NvmcKeyValueStore::new`] and
/// [`NvmcCounterStore::new`] when building the `Mac` platform.
pub struct NvmcStorage {
    map: Mutex<ThreadModeRawMutex, Map>,
}

impl NvmcStorage {
    /// Wrap the given NVMC peripheral. Does NOT erase or format the
    /// flash — the underlying map mounts lazily on first access.
    pub fn new(nvmc: Nvmc<'static>) -> Self {
        let flash = BlockingAsync::new(nvmc);
        // `MapConfig::new` is a `const fn` that panics on bad geometry
        // (range not page-aligned, fewer than 2 pages, etc.). Wrapping
        // it in `const { … }` turns any such mistake into a
        // compile-time error rather than a boot-time panic.
        let cfg = const { MapConfig::new(NV_STORE_RANGE) };
        Self {
            map: Mutex::new(MapStorage::new(flash, cfg, NoCache::new())),
        }
    }

    async fn load_bytes(&self, key: &[u8], out: &mut [u8]) -> Result<Option<usize>, Error> {
        let store_key = make_key(key)?;
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut guard = self.map.lock().await;
        let result: Option<&[u8]> = guard.fetch_item(&mut scratch, &store_key).await?;
        match result {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() > out.len() {
                    return Err(Error::ValueTooLong);
                }
                out[..bytes.len()].copy_from_slice(bytes);
                Ok(Some(bytes.len()))
            }
        }
    }

    async fn store_bytes(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let store_key = make_key(key)?;
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut guard = self.map.lock().await;
        guard.store_item(&mut scratch, &store_key, &value).await?;
        Ok(())
    }

    async fn delete_bytes(&self, key: &[u8]) -> Result<(), Error> {
        let store_key = make_key(key)?;
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut guard = self.map.lock().await;
        guard.remove_item(&mut scratch, &store_key).await?;
        Ok(())
    }
}

fn make_key(bytes: &[u8]) -> Result<StoreKey, Error> {
    StoreKey::from_slice(bytes).map_err(|_| Error::KeyTooLong)
}

// ─── Identity helpers ─────────────────────────────────────────────────────────

/// Key under which the local Ed25519 secret scalar is stored.
const SK_KEY: &[u8] = b"id.sk";

impl NvmcStorage {
    /// Load the local Ed25519 secret key from storage.
    ///
    /// Returns `Ok(Some(sk))` when a valid 32-byte key is present,
    /// `Ok(None)` when no key has been stored yet (first boot), and
    /// `Err` on a storage or hardware failure.
    pub async fn load_sk(&self) -> Result<Option<[u8; 32]>, Error> {
        let mut buf = [0u8; 32];
        match self.load_bytes(SK_KEY, &mut buf).await? {
            Some(32) => Ok(Some(buf)),
            // Missing or wrong length — treat as "not yet written".
            Some(_) | None => Ok(None),
        }
    }

    /// Persist the local Ed25519 secret key.
    ///
    /// Call this exactly once on first boot, after generating the key
    /// from the hardware TRNG. Subsequent boots should use [`load_sk`].
    ///
    /// [`load_sk`]: Self::load_sk
    pub async fn store_sk(&self, sk: &[u8; 32]) -> Result<(), Error> {
        self.store_bytes(SK_KEY, sk).await
    }
}

/// View implementing [`umsh_hal::KeyValueStore`] on top of a shared
/// [`NvmcStorage`]. The view itself is essentially a thin pointer; the
/// real storage lives in the static `NvmcStorage`.
pub struct NvmcKeyValueStore {
    storage: &'static NvmcStorage,
}

impl NvmcKeyValueStore {
    /// Construct a KV view over the shared static storage.
    pub fn new(storage: &'static NvmcStorage) -> Self {
        Self { storage }
    }
}

impl umsh_hal::KeyValueStore for NvmcKeyValueStore {
    type Error = Error;

    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        self.storage.load_bytes(key, buf).await
    }

    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.storage.store_bytes(key, value).await
    }

    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error> {
        self.storage.delete_bytes(key).await
    }
}

/// View implementing [`umsh_hal::CounterStore`] on top of a shared
/// [`NvmcStorage`]. Counters are stored as little-endian u32 values
/// keyed by the caller-supplied context bytes (the MAC layer is
/// expected to prefix them with `mac.tx:` / `mac.rx:` per the layout
/// in `docs/firmware-storage-plan.md`).
pub struct NvmcCounterStore {
    storage: &'static NvmcStorage,
}

impl NvmcCounterStore {
    /// Construct a counter view over the shared static storage.
    pub fn new(storage: &'static NvmcStorage) -> Self {
        Self { storage }
    }
}

impl umsh_hal::CounterStore for NvmcCounterStore {
    type Error = Error;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        match self.storage.load_bytes(context, &mut buf).await? {
            Some(4) => Ok(u32::from_le_bytes(buf)),
            // Missing entry, or a corrupt one of unexpected size — treat
            // as "no boundary persisted yet" so the MAC layer reseeds.
            Some(_) | None => Ok(0),
        }
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        let bytes = value.to_le_bytes();
        self.storage.store_bytes(context, &bytes).await
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        // `sequential-storage` commits synchronously inside `store_item`,
        // so there is no deferred queue to drain here. The `flush`
        // method exists in `umsh_hal::CounterStore` for backends that
        // batch in RAM; for us it is a no-op.
        Ok(())
    }
}
