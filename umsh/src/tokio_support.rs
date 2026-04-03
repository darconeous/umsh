//! Tokio-friendly runtime adapters and simple std-backed stores.

use core::marker::PhantomData;
use std::{
    collections::BTreeMap,
    fs,
    io,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use embedded_hal_async::delay::DelayNs;
use umsh_hal::{Clock, CounterStore, KeyValueStore};

#[cfg(feature = "software-crypto")]
use crate::{
    crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    Platform,
};

/// [`DelayNs`] adapter backed by `tokio::time::sleep`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioDelay;

impl DelayNs for TokioDelay {
    async fn delay_ns(&mut self, ns: u32) {
        tokio::time::sleep(Duration::from_nanos(u64::from(ns))).await;
    }
}

/// Monotonic clock backed by `std::time::Instant`.
#[derive(Clone, Debug)]
pub struct StdClock {
    origin: Instant,
}

impl Default for StdClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl StdClock {
    /// Create a clock whose epoch starts at construction time.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Clock for StdClock {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

/// Thread-local cryptographic RNG seeded from the operating system.
pub use rand::rngs::ThreadRng;

/// Errors returned by the std-backed file and memory stores.
#[derive(Debug)]
pub enum FileStoreError {
    Io(io::Error),
    BufferTooSmall,
    Poisoned,
}

impl From<io::Error> for FileStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Counter store that persists one file per context key.
#[derive(Clone, Debug)]
pub struct TokioFileCounterStore {
    root: PathBuf,
}

impl TokioFileCounterStore {
    /// Create the store rooted at `root`, creating the directory if needed.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, io::Error> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, context: &[u8]) -> PathBuf {
        self.root.join(format!("{}.ctr", hex_encode(context)))
    }
}

impl CounterStore for TokioFileCounterStore {
    type Error = FileStoreError;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        match fs::read(self.path_for(context)) {
            Ok(bytes) if bytes.len() == 4 => Ok(u32::from_be_bytes(bytes.try_into().expect("fixed counter bytes"))),
            Ok(_) => Ok(0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(FileStoreError::Io(error)),
        }
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        fs::write(self.path_for(context), value.to_be_bytes()).map_err(FileStoreError::Io)
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Key-value store that persists one file per key.
#[derive(Clone, Debug)]
pub struct TokioFileKeyValueStore {
    root: PathBuf,
}

impl TokioFileKeyValueStore {
    /// Create the store rooted at `root`, creating the directory if needed.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, io::Error> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, key: &[u8]) -> PathBuf {
        self.root.join(format!("{}.bin", hex_encode(key)))
    }
}

impl KeyValueStore for TokioFileKeyValueStore {
    type Error = FileStoreError;

    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match fs::read(self.path_for(key)) {
            Ok(value) => {
                if value.len() > buf.len() {
                    return Err(FileStoreError::BufferTooSmall);
                }
                buf[..value.len()].copy_from_slice(&value);
                Ok(Some(value.len()))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(FileStoreError::Io(error)),
        }
    }

    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        fs::write(self.path_for(key), value).map_err(FileStoreError::Io)
    }

    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error> {
        match fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(FileStoreError::Io(error)),
        }
    }
}

/// In-memory counter store convenient for host-side tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryCounterStore {
    entries: Arc<Mutex<BTreeMap<Vec<u8>, u32>>>,
}

impl CounterStore for MemoryCounterStore {
    type Error = FileStoreError;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        Ok(*lock_entries(&self.entries)?.get(context).unwrap_or(&0))
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        lock_entries(&self.entries)?.insert(context.to_vec(), value);
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// In-memory key-value store convenient for host-side tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryKeyValueStore {
    entries: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl KeyValueStore for MemoryKeyValueStore {
    type Error = FileStoreError;

    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let entries = lock_entries(&self.entries)?;
        let Some(value) = entries.get(key) else {
            return Ok(None);
        };
        if value.len() > buf.len() {
            return Err(FileStoreError::BufferTooSmall);
        }
        buf[..value.len()].copy_from_slice(value);
        Ok(Some(value.len()))
    }

    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        lock_entries(&self.entries)?.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error> {
        lock_entries(&self.entries)?.remove(key);
        Ok(())
    }
}

/// Convenience [`crate::Platform`] implementation for Tokio-based hosts.
#[cfg(feature = "software-crypto")]
pub struct TokioPlatform<R, CS = TokioFileCounterStore, KV = TokioFileKeyValueStore>(
    PhantomData<(R, CS, KV)>,
);

#[cfg(feature = "software-crypto")]
impl<R, CS, KV> Platform for TokioPlatform<R, CS, KV>
where
    R: umsh_hal::Radio,
    CS: CounterStore,
    KV: KeyValueStore,
{
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = R;
    type Delay = TokioDelay;
    type Clock = StdClock;
    type Rng = ThreadRng;
    type CounterStore = CS;
    type KeyValueStore = KV;
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn lock_entries<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, FileStoreError> {
    mutex.lock().map_err(|_| FileStoreError::Poisoned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("umsh-{name}-{unique}"))
    }

    #[tokio::test]
    async fn file_counter_store_round_trips_values() {
        let root = temp_dir("counter-store");
        let store = TokioFileCounterStore::new(&root).unwrap();
        assert_eq!(store.load(b"peer").await.unwrap(), 0);
        store.store(b"peer", 42).await.unwrap();
        assert_eq!(store.load(b"peer").await.unwrap(), 42);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn file_key_value_store_round_trips_values() {
        let root = temp_dir("kv-store");
        let store = TokioFileKeyValueStore::new(&root).unwrap();
        store.store(b"node", b"value").await.unwrap();
        let mut buf = [0u8; 16];
        let len = store.load(b"node", &mut buf).await.unwrap().unwrap();
        assert_eq!(&buf[..len], b"value");
        store.delete(b"node").await.unwrap();
        assert_eq!(store.load(b"node", &mut buf).await.unwrap(), None);
        let _ = fs::remove_dir_all(root);
    }
}