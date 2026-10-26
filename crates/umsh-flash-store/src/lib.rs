//! Chip-agnostic implementation of the `umsh-hal` storage traits on top
//! of [`sequential-storage`](https://docs.rs/sequential-storage).
//!
//! This is the storage engine every UMSH board shares. It is generic over
//! the async flash driver (`F: MultiwriteNorFlash`) and the sharing mutex
//! (`M: RawMutex`); chip BSPs supply concrete backings and alias the
//! types.
//!
//! The same map serves every trait. Logical separation is by ASCII key
//! prefix decided at the call site:
//!
//! | Prefix       | Trait           | Payload                              |
//! |--------------|-----------------|--------------------------------------|
//! | `id.sk`      | (direct)        | local Ed25519 secret scalar (32 B)   |
//! | `ux.tracker` | (direct)        | encoded tracker preferences (1 B)    |
//! | `mac.tx:<pk>`| CounterStore    | TX reservation boundary (u32 LE)     |
//! | `mac.rx:<pk>`| CounterStore    | RX replay-window boundary (u32 LE)   |
//!
//! ## CPU stall warning
//!
//! Page erases block the executor for a long time on every backend we
//! use—the nRF52840 NVMC halts the CPU for ~85 ms, and the ESP32
//! suspends the flash cache for the duration of the write. No amount of
//! async scheduling can preempt either. Callers MUST batch writes; the
//! MAC's TX-side `COUNTER_PERSIST_BLOCK_SIZE = 128` and the RX-side
//! mirror keep this manageable for counters.
//!
//! ## Sharing model
//!
//! [`FlashStore`] owns the flash + map behind an async mutex.
//! [`KeyValueView`] and [`CounterView`] are zero-cost view types that
//! each hold a `&'static FlashStore`. They exist as separate types
//! because the `umsh-hal` traits both define `load` and `store`
//! methods—implementing both on a single type would force every caller
//! to disambiguate via UFCS. Keep them split.
#![no_std]

use core::ops::Range;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use embedded_storage_async::nor_flash::MultiwriteNorFlash;
use heapless::Vec;
use sequential_storage::cache::NoCache;
use sequential_storage::map::{MapConfig, MapStorage};

/// Maximum stored key length. Covers an 8-byte ASCII prefix plus a
/// 32-byte Ed25519 pubkey with headroom for shorter prefixes / new
/// namespaces.
pub const MAX_KEY_LEN: usize = 64;

/// Per-call scratch buffer size used for sequential-storage's serialise
/// / deserialise workspace. Must hold the largest (serialised key +
/// value) pair the store ever sees.
pub const SCRATCH_LEN: usize = 512;

/// Heapless `Vec` used as the in-memory key representation, with the
/// `sequential-storage` `Key` impl provided by the `heapless` feature.
type StoreKey = Vec<u8, MAX_KEY_LEN>;

/// Errors surfaced by this module, generic over the flash driver's own
/// error type.
#[derive(Debug)]
pub enum Error<E> {
    /// Caller-supplied key exceeded [`MAX_KEY_LEN`].
    KeyTooLong,
    /// Stored value did not fit in the caller-supplied buffer on load.
    ValueTooLong,
    /// A stored record contained unexpected bytes.
    CorruptedData,
    /// `sequential-storage` returned an error (corruption, full storage,
    /// underlying flash failure, …).
    Storage(sequential_storage::Error<E>),
}

impl<E> From<sequential_storage::Error<E>> for Error<E> {
    fn from(err: sequential_storage::Error<E>) -> Self {
        Self::Storage(err)
    }
}

/// Owns the flash driver and the `sequential-storage` map.
///
/// Construct once during board init, place in a `StaticCell`, then hand
/// `&'static` references to the view constructors when building the
/// `Mac` platform.
pub struct FlashStore<F, M>
where
    F: MultiwriteNorFlash,
    M: RawMutex,
{
    map: Mutex<M, MapStorage<StoreKey, F, NoCache>>,
}

impl<F, M> FlashStore<F, M>
where
    F: MultiwriteNorFlash,
    M: RawMutex,
{
    /// Wrap an async flash driver over `range`. Does NOT erase or format
    /// the flash—the underlying map mounts lazily on first access.
    ///
    /// `range` must be page-aligned and at least two pages long;
    /// `MapConfig::new` panics otherwise. Callers pass a board constant,
    /// so a bad geometry is a boot-time panic rather than a silent
    /// corruption.
    pub fn new(flash: F, range: Range<u32>) -> Self {
        let cfg = MapConfig::new(range);
        Self {
            map: Mutex::new(MapStorage::new(flash, cfg, NoCache::new())),
        }
    }

    async fn load_bytes(
        &self,
        key: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, Error<F::Error>> {
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

    async fn store_bytes(&self, key: &[u8], value: &[u8]) -> Result<(), Error<F::Error>> {
        let store_key = make_key(key)?;
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut guard = self.map.lock().await;
        guard.store_item(&mut scratch, &store_key, &value).await?;
        Ok(())
    }

    async fn delete_bytes(&self, key: &[u8]) -> Result<(), Error<F::Error>> {
        let store_key = make_key(key)?;
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut guard = self.map.lock().await;
        guard.remove_item(&mut scratch, &store_key).await?;
        Ok(())
    }
}

fn make_key<E>(bytes: &[u8]) -> Result<StoreKey, Error<E>> {
    StoreKey::from_slice(bytes).map_err(|_| Error::KeyTooLong)
}

// ─── Identity helpers ─────────────────────────────────────────────────────────

/// Key under which the local Ed25519 secret scalar is stored.
const SK_KEY: &[u8] = b"id.sk";
const TRACKER_PREFERENCES_KEY: &[u8] = b"ux.tracker";

impl<F, M> FlashStore<F, M>
where
    F: MultiwriteNorFlash,
    M: RawMutex,
{
    /// Load the board-independent encoded tracker preferences byte.
    pub async fn load_tracker_preferences(&self) -> Result<Option<u8>, Error<F::Error>> {
        let mut byte = [0u8; 1];
        match self.load_bytes(TRACKER_PREFERENCES_KEY, &mut byte).await? {
            Some(1) => Ok(Some(byte[0])),
            Some(_) => Err(Error::CorruptedData),
            None => Ok(None),
        }
    }

    /// Persist the board-independent encoded tracker preferences byte.
    pub async fn store_tracker_preferences(&self, value: u8) -> Result<(), Error<F::Error>> {
        self.store_bytes(TRACKER_PREFERENCES_KEY, &[value]).await
    }

    /// Load the local Ed25519 secret key from storage.
    ///
    /// Returns `Ok(Some(sk))` when a valid 32-byte key is present,
    /// `Ok(None)` when no key has been stored yet (first boot), and
    /// `Err` on a storage or hardware failure.
    pub async fn load_sk(&self) -> Result<Option<[u8; 32]>, Error<F::Error>> {
        let mut buf = [0u8; 32];
        match self.load_bytes(SK_KEY, &mut buf).await? {
            Some(32) => Ok(Some(buf)),
            // Missing or wrong length—treat as "not yet written".
            Some(_) | None => Ok(None),
        }
    }

    /// Persist the local Ed25519 secret key.
    ///
    /// Call this exactly once on first boot, after generating the key
    /// from the hardware TRNG. Subsequent boots should use [`load_sk`].
    ///
    /// [`load_sk`]: Self::load_sk
    pub async fn store_sk(&self, sk: &[u8; 32]) -> Result<(), Error<F::Error>> {
        self.store_bytes(SK_KEY, sk).await
    }
}

/// View implementing [`umsh_hal::KeyValueStore`] on top of a shared
/// [`FlashStore`]. The view itself is essentially a thin pointer; the
/// real storage lives in the static [`FlashStore`].
pub struct KeyValueView<F, M>
where
    F: MultiwriteNorFlash + 'static,
    M: RawMutex + 'static,
{
    storage: &'static FlashStore<F, M>,
}

impl<F, M> KeyValueView<F, M>
where
    F: MultiwriteNorFlash + 'static,
    M: RawMutex + 'static,
{
    /// Construct a KV view over the shared static storage.
    pub fn new(storage: &'static FlashStore<F, M>) -> Self {
        Self { storage }
    }
}

impl<F, M> umsh_hal::KeyValueStore for KeyValueView<F, M>
where
    F: MultiwriteNorFlash + 'static,
    M: RawMutex + 'static,
{
    type Error = Error<F::Error>;

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
/// [`FlashStore`]. Counters are stored as little-endian u32 values
/// keyed by the caller-supplied context bytes (the MAC layer is
/// expected to prefix them with `mac.tx:` / `mac.rx:`).
pub struct CounterView<F, M>
where
    F: MultiwriteNorFlash + 'static,
    M: RawMutex + 'static,
{
    storage: &'static FlashStore<F, M>,
}

impl<F, M> CounterView<F, M>
where
    F: MultiwriteNorFlash + 'static,
    M: RawMutex + 'static,
{
    /// Construct a counter view over the shared static storage.
    pub fn new(storage: &'static FlashStore<F, M>) -> Self {
        Self { storage }
    }
}

impl<F, M> umsh_hal::CounterStore for CounterView<F, M>
where
    F: MultiwriteNorFlash + 'static,
    M: RawMutex + 'static,
{
    type Error = Error<F::Error>;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        match self.storage.load_bytes(context, &mut buf).await? {
            Some(4) => Ok(u32::from_le_bytes(buf)),
            // Missing entry, or a corrupt one of unexpected size—treat
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
