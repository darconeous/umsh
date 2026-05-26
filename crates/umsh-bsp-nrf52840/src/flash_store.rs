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
//! | `id.sk`      | (direct)        | local Ed25519 secret scalar (32 B)   |
//! | `peers`      | PeerStore       | packed pubkey index (32 B × N)       |
//! | `peer:<pk>`  | PeerStore       | alias len (1 B) + alias (≤16 B)      |
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
//! [`NvmcKeyValueStore`], [`NvmcCounterStore`], and [`NvmcPeerStore`] are
//! zero-cost view types that each hold a `&'static NvmcStorage`. They exist
//! as separate types because the `umsh-hal` traits both define `load` and
//! `store` methods — implementing both on a single type would force every
//! caller to disambiguate via UFCS. Keep them split.

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

/// Maximum number of peers tracked in the peer index.
/// 8 × 32 = 256 bytes, comfortably under the 512-byte scratch limit.
pub const MAX_PEERS: usize = 8;

/// Maximum alias length in bytes (UTF-8).
pub const MAX_ALIAS_LEN: usize = 16;

/// Fixed-size alias header prepended to every peer record.
///
/// Layout:
/// ```text
/// Byte 0      alias_len  (0 = no alias, 1–16 = alias present)
/// Bytes 1–16  alias data (16-byte slot; only alias_len bytes significant)
/// ```
pub const ALIAS_HEADER_LEN: usize = 1 + MAX_ALIAS_LEN; // 17 bytes

/// Maximum total peer record size.
///
/// `ALIAS_HEADER_LEN` (17) + serialised `NodeIdentityPayload` (≤239 B).
/// Full NodeIdentityPayload with all optional fields is well under 150 B,
/// so 256 B provides ample headroom for future additions.
pub const MAX_PEER_RECORD_LEN: usize = 256;

/// Errors surfaced by this module.
#[derive(Debug)]
pub enum Error {
    /// Caller-supplied key exceeded [`MAX_KEY_LEN`].
    KeyTooLong,
    /// Stored value did not fit in the caller-supplied buffer on load.
    ValueTooLong,
    /// The peer index already holds [`MAX_PEERS`] entries.
    PeerIndexFull,
    /// A stored record contained unexpected bytes (e.g. invalid UTF-8 alias).
    CorruptedData,
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

// ─── Peer storage helpers ─────────────────────────────────────────────────────

/// Key under which the packed peer index is stored (`peers`).
const PEER_INDEX_KEY: &[u8] = b"peers";
/// Prefix for individual peer records (`peer:` + 32-byte pubkey = 37 bytes).
const PEER_KEY_PREFIX: &[u8] = b"peer:";

fn make_peer_key(pk: &[u8; 32]) -> Result<StoreKey, Error> {
    let mut key = StoreKey::new();
    let r1 = key.extend_from_slice(PEER_KEY_PREFIX);
    let r2 = key.extend_from_slice(pk);
    if r1.is_err() || r2.is_err() {
        return Err(Error::KeyTooLong);
    }
    Ok(key)
}

impl NvmcStorage {
    /// Load every persisted peer into `out`.
    ///
    /// Each entry is a raw 32-byte public key plus an optional alias string
    /// (up to 16 UTF-8 bytes). Entries beyond `N` are silently dropped.
    pub async fn load_all_peers<const N: usize>(
        &self,
        out: &mut Vec<([u8; 32], Option<heapless::String<MAX_ALIAS_LEN>>), N>,
    ) -> Result<(), Error> {
        let mut index_buf = [0u8; 32 * MAX_PEERS];
        let n = match self.load_bytes(PEER_INDEX_KEY, &mut index_buf).await? {
            None => return Ok(()),
            Some(n) if n % 32 == 0 => n,
            Some(_) => return Err(Error::CorruptedData),
        };
        for chunk in index_buf[..n].chunks_exact(32) {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(chunk);
            let alias = self.load_peer_alias(&pk).await?;
            let _ = out.push((pk, alias));
        }
        Ok(())
    }

    /// Read the full raw peer record into a [`MAX_PEER_RECORD_LEN`]-byte buffer.
    ///
    /// Returns `(buf, len)` when present. The alias header occupies
    /// `buf[0..ALIAS_HEADER_LEN]` and any identity bytes follow at
    /// `buf[ALIAS_HEADER_LEN..len]`.
    async fn read_peer_record(
        &self,
        pk: &[u8; 32],
    ) -> Result<Option<([u8; MAX_PEER_RECORD_LEN], usize)>, Error> {
        let key = make_peer_key(pk)?;
        let mut buf = [0u8; MAX_PEER_RECORD_LEN];
        match self.load_bytes(&key, &mut buf).await? {
            None => Ok(None),
            Some(n) => Ok(Some((buf, n))),
        }
    }

    async fn load_peer_alias(
        &self,
        pk: &[u8; 32],
    ) -> Result<Option<heapless::String<MAX_ALIAS_LEN>>, Error> {
        let (buf, n) = match self.read_peer_record(pk).await? {
            None => return Ok(None),
            Some(x) => x,
        };
        if n < 1 {
            return Ok(None);
        }
        let alias_len = buf[0] as usize;
        if alias_len == 0 || n < 1 + alias_len {
            return Ok(None);
        }
        let s = core::str::from_utf8(&buf[1..1 + alias_len])
            .map_err(|_| Error::CorruptedData)?;
        Ok(heapless::String::try_from(s).ok())
    }

    /// Upsert the alias for `pk`.
    ///
    /// Writes the alias header and appends `pk` to the peer index if not
    /// already present. Any previously stored identity bytes are preserved.
    /// `alias`, if supplied, must be at most [`MAX_ALIAS_LEN`] bytes.
    pub async fn store_peer_entry(
        &self,
        pk: &[u8; 32],
        alias: Option<&[u8]>,
    ) -> Result<(), Error> {
        let key = make_peer_key(pk)?;

        // Read existing record to preserve any identity bytes.
        let (mut value, existing_len) = match self.read_peer_record(pk).await? {
            Some((buf, n)) => (buf, n),
            None => ([0u8; MAX_PEER_RECORD_LEN], ALIAS_HEADER_LEN),
        };
        let identity_end = existing_len.max(ALIAS_HEADER_LEN);

        // Overwrite the alias header in-place.
        value[0] = 0;
        if let Some(a) = alias {
            if a.len() > MAX_ALIAS_LEN {
                return Err(Error::ValueTooLong);
            }
            value[0] = a.len() as u8;
            value[1..1 + a.len()].copy_from_slice(a);
            // Zero the padding in the alias slot so the record stays canonical.
            value[1 + a.len()..ALIAS_HEADER_LEN].fill(0);
        } else {
            value[1..ALIAS_HEADER_LEN].fill(0);
        }

        self.store_bytes(&key, &value[..identity_end]).await?;

        // Update peer index: load, add if missing, store.
        let mut index_buf = [0u8; 32 * MAX_PEERS];
        let existing_n = match self.load_bytes(PEER_INDEX_KEY, &mut index_buf).await? {
            Some(n) => n,
            None => 0,
        };
        let already_present = index_buf[..existing_n]
            .chunks_exact(32)
            .any(|c| c == pk.as_slice());
        if !already_present {
            let new_n = existing_n + 32;
            if new_n > index_buf.len() {
                return Err(Error::PeerIndexFull);
            }
            index_buf[existing_n..new_n].copy_from_slice(pk);
            self.store_bytes(PEER_INDEX_KEY, &index_buf[..new_n]).await?;
        }
        Ok(())
    }

    /// Update (or clear) the serialised `NodeIdentityPayload` for `pk`.
    ///
    /// The alias header is preserved. Pass an empty slice to remove the
    /// identity portion while keeping the alias. The peer must already be in
    /// the peer index (i.e. `store_peer_entry` called first).
    pub async fn update_peer_identity(
        &self,
        pk: &[u8; 32],
        identity_bytes: &[u8],
    ) -> Result<(), Error> {
        let new_len = ALIAS_HEADER_LEN + identity_bytes.len();
        if new_len > MAX_PEER_RECORD_LEN {
            return Err(Error::ValueTooLong);
        }
        let key = make_peer_key(pk)?;

        // Read existing record to preserve alias header.
        let (mut value, _) = match self.read_peer_record(pk).await? {
            Some(x) => x,
            None => ([0u8; MAX_PEER_RECORD_LEN], 0), // peer not yet stored
        };

        value[ALIAS_HEADER_LEN..new_len].copy_from_slice(identity_bytes);
        self.store_bytes(&key, &value[..new_len]).await?;
        Ok(())
    }

    /// Load the raw serialised identity bytes for `pk` into `out`.
    ///
    /// Returns the number of bytes written when an identity record is present,
    /// `None` when no identity has been stored yet.
    pub async fn load_peer_identity(
        &self,
        pk: &[u8; 32],
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let (buf, n) = match self.read_peer_record(pk).await? {
            None => return Ok(None),
            Some(x) => x,
        };
        if n <= ALIAS_HEADER_LEN {
            return Ok(None);
        }
        let identity = &buf[ALIAS_HEADER_LEN..n];
        if identity.len() > out.len() {
            return Err(Error::ValueTooLong);
        }
        out[..identity.len()].copy_from_slice(identity);
        Ok(Some(identity.len()))
    }

    /// Return `true` if `pk` appears in the peer index.
    ///
    /// Used to guard `update_peer_identity` so that identity bytes received
    /// over the air are only stored for peers the user has explicitly added.
    pub async fn peer_exists(&self, pk: &[u8; 32]) -> Result<bool, Error> {
        let mut index_buf = [0u8; 32 * MAX_PEERS];
        let n = match self.load_bytes(PEER_INDEX_KEY, &mut index_buf).await? {
            Some(n) => n,
            None => return Ok(false),
        };
        Ok(index_buf[..n].chunks_exact(32).any(|c| c == pk.as_slice()))
    }

    /// Remove the peer record for `pk` from both the per-key record and the
    /// peer index. A no-op if the peer was not previously stored.
    pub async fn delete_peer_entry(&self, pk: &[u8; 32]) -> Result<(), Error> {
        // Best-effort delete of the individual record.
        let key = make_peer_key(pk)?;
        let _ = self.delete_bytes(&key).await;

        // Remove from index.
        let mut index_buf = [0u8; 32 * MAX_PEERS];
        let n = match self.load_bytes(PEER_INDEX_KEY, &mut index_buf).await? {
            Some(n) => n,
            None => return Ok(()),
        };
        let mut new_buf = [0u8; 32 * MAX_PEERS];
        let mut new_n = 0usize;
        for chunk in index_buf[..n].chunks_exact(32) {
            if chunk != pk.as_slice() {
                new_buf[new_n..new_n + 32].copy_from_slice(chunk);
                new_n += 32;
            }
        }
        if new_n == 0 {
            let _ = self.delete_bytes(PEER_INDEX_KEY).await;
        } else {
            self.store_bytes(PEER_INDEX_KEY, &new_buf[..new_n]).await?;
        }
        Ok(())
    }
}

// ─── Channel storage helpers ──────────────────────────────────────────────────

/// Key under which the packed channel index is stored.
const CH_INDEX_KEY: &[u8] = b"channels";
/// Prefix for individual channel records (`ch:` + name).
const CH_KEY_PREFIX: &[u8] = b"ch:";
/// Maximum channel name length in bytes (UTF-8). Matches CliSession's alias cap.
pub const MAX_CHANNEL_NAME_LEN: usize = 16;
/// Fixed slot size for one channel-name entry in the index:
/// 1 byte length + 16 bytes name data.
const CH_NAME_SLOT_LEN: usize = 1 + MAX_CHANNEL_NAME_LEN;
/// Maximum number of channels tracked in the channel index.
pub const MAX_CHANNELS: usize = 8;

fn make_channel_key(name: &[u8]) -> Result<StoreKey, Error> {
    if name.len() > MAX_CHANNEL_NAME_LEN {
        return Err(Error::KeyTooLong);
    }
    let mut key = StoreKey::new();
    let r1 = key.extend_from_slice(CH_KEY_PREFIX);
    let r2 = key.extend_from_slice(name);
    if r1.is_err() || r2.is_err() {
        return Err(Error::KeyTooLong);
    }
    Ok(key)
}

impl NvmcStorage {
    /// Load every persisted channel into `out`.
    ///
    /// Each entry is a name string (up to 16 UTF-8 bytes) and a 32-byte key.
    /// Entries beyond `N` are silently dropped.
    pub async fn load_all_channels<const N: usize>(
        &self,
        out: &mut Vec<(heapless::String<MAX_CHANNEL_NAME_LEN>, [u8; 32]), N>,
    ) -> Result<(), Error> {
        let mut index_buf = [0u8; CH_NAME_SLOT_LEN * MAX_CHANNELS];
        let n = match self.load_bytes(CH_INDEX_KEY, &mut index_buf).await? {
            None => return Ok(()),
            Some(n) if n % CH_NAME_SLOT_LEN == 0 => n,
            Some(_) => return Err(Error::CorruptedData),
        };
        for slot in index_buf[..n].chunks_exact(CH_NAME_SLOT_LEN) {
            let name_len = slot[0] as usize;
            if name_len == 0 || name_len > MAX_CHANNEL_NAME_LEN {
                continue;
            }
            let name_bytes = &slot[1..1 + name_len];
            let name = match core::str::from_utf8(name_bytes) {
                Ok(s) => match heapless::String::try_from(s) {
                    Ok(h) => h,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let key_bytes = match self.load_channel_key(name_bytes).await? {
                Some(k) => k,
                None => continue,
            };
            let _ = out.push((name, key_bytes));
        }
        Ok(())
    }

    async fn load_channel_key(&self, name: &[u8]) -> Result<Option<[u8; 32]>, Error> {
        let key = make_channel_key(name)?;
        let mut buf = [0u8; 32];
        match self.load_bytes(&key, &mut buf).await? {
            Some(32) => Ok(Some(buf)),
            _ => Ok(None),
        }
    }

    /// Upsert the channel record for `name`.
    ///
    /// Writes the 32-byte key into the per-name record and appends the name
    /// to the channel index if not already present.
    pub async fn store_channel_entry(
        &self,
        name: &[u8],
        key: &[u8; 32],
    ) -> Result<(), Error> {
        if name.len() > MAX_CHANNEL_NAME_LEN {
            return Err(Error::ValueTooLong);
        }
        // Write individual record.
        let ch_key = make_channel_key(name)?;
        self.store_bytes(&ch_key, key).await?;

        // Update index: load, add slot if missing, store.
        let mut index_buf = [0u8; CH_NAME_SLOT_LEN * MAX_CHANNELS];
        let existing_n = match self.load_bytes(CH_INDEX_KEY, &mut index_buf).await? {
            Some(n) => n,
            None => 0,
        };
        let already_present = index_buf[..existing_n]
            .chunks_exact(CH_NAME_SLOT_LEN)
            .any(|slot| slot[0] as usize == name.len() && &slot[1..1 + name.len()] == name);
        if !already_present {
            let new_n = existing_n + CH_NAME_SLOT_LEN;
            if new_n > index_buf.len() {
                return Err(Error::PeerIndexFull);
            }
            index_buf[existing_n] = name.len() as u8;
            index_buf[existing_n + 1..existing_n + 1 + name.len()].copy_from_slice(name);
            // Zero remaining padding in the slot.
            index_buf[existing_n + 1 + name.len()..new_n].fill(0);
            self.store_bytes(CH_INDEX_KEY, &index_buf[..new_n]).await?;
        }
        Ok(())
    }

    /// Remove the channel record for `name` from both the per-name record and
    /// the channel index. A no-op if the channel was not previously stored.
    pub async fn delete_channel_entry(&self, name: &[u8]) -> Result<(), Error> {
        // Best-effort delete of the individual record.
        if let Ok(ch_key) = make_channel_key(name) {
            let _ = self.delete_bytes(&ch_key).await;
        }

        // Remove from index.
        let mut index_buf = [0u8; CH_NAME_SLOT_LEN * MAX_CHANNELS];
        let n = match self.load_bytes(CH_INDEX_KEY, &mut index_buf).await? {
            Some(n) => n,
            None => return Ok(()),
        };
        let mut new_buf = [0u8; CH_NAME_SLOT_LEN * MAX_CHANNELS];
        let mut new_n = 0usize;
        for slot in index_buf[..n].chunks_exact(CH_NAME_SLOT_LEN) {
            let slot_name_len = slot[0] as usize;
            let matches = slot_name_len == name.len()
                && &slot[1..1 + slot_name_len.min(MAX_CHANNEL_NAME_LEN)] == name;
            if !matches {
                new_buf[new_n..new_n + CH_NAME_SLOT_LEN].copy_from_slice(slot);
                new_n += CH_NAME_SLOT_LEN;
            }
        }
        if new_n == 0 {
            let _ = self.delete_bytes(CH_INDEX_KEY).await;
        } else {
            self.store_bytes(CH_INDEX_KEY, &new_buf[..new_n]).await?;
        }
        Ok(())
    }
}

/// View implementing [`umsh_hal::ChannelStore`] on top of a shared
/// [`NvmcStorage`].
pub struct NvmcChannelStore {
    storage: &'static NvmcStorage,
}

impl NvmcChannelStore {
    /// Construct a channel-store view over the shared static storage.
    pub fn new(storage: &'static NvmcStorage) -> Self {
        Self { storage }
    }
}

impl umsh_hal::ChannelStore for NvmcChannelStore {
    type Error = Error;

    async fn store_channel(&self, name: &[u8], key: &[u8; 32]) -> Result<(), Self::Error> {
        self.storage.store_channel_entry(name, key).await
    }

    async fn delete_channel(&self, name: &[u8]) -> Result<(), Self::Error> {
        self.storage.delete_channel_entry(name).await
    }
}

/// View implementing [`umsh_hal::PeerStore`] on top of a shared
/// [`NvmcStorage`]. Follows the same view-type pattern as
/// [`NvmcKeyValueStore`] and [`NvmcCounterStore`].
pub struct NvmcPeerStore {
    storage: &'static NvmcStorage,
}

impl NvmcPeerStore {
    /// Construct a peer-store view over the shared static storage.
    pub fn new(storage: &'static NvmcStorage) -> Self {
        Self { storage }
    }
}

impl umsh_hal::PeerStore for NvmcPeerStore {
    type Error = Error;

    async fn store_peer(&self, key: &[u8; 32], alias: Option<&[u8]>) -> Result<(), Self::Error> {
        self.storage.store_peer_entry(key, alias).await
    }

    async fn delete_peer(&self, key: &[u8; 32]) -> Result<(), Self::Error> {
        self.storage.delete_peer_entry(key).await
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
