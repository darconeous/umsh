//! Tokio-friendly runtime adapters and simple std-backed stores.

use core::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs, io,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use embedded_hal_async::delay::DelayNs;
use umsh_hal::{Clock, CounterStore, KeyValueStore};

#[cfg(feature = "software-crypto")]
use crate::{
    Platform,
    crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
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
///
/// Implements [`Clock::poll_delay_until`] using `tokio::time::Sleep` so that
/// the MAC coordinator can efficiently await timer deadlines.
#[derive(Debug)]
pub struct StdClock {
    origin: Instant,
    pending_sleep: RefCell<Option<Pin<Box<tokio::time::Sleep>>>>,
}

impl Clone for StdClock {
    fn clone(&self) -> Self {
        Self {
            origin: self.origin,
            pending_sleep: RefCell::new(None),
        }
    }
}

impl Default for StdClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            pending_sleep: RefCell::new(None),
        }
    }
}

impl StdClock {
    /// Create a clock whose epoch starts at construction time.
    ///
    /// [`Clock::now_ms`] is specified as milliseconds since boot, so a
    /// host that answers `PROP_UPTIME` must construct this when the thing
    /// it stands for comes up rather than lazily on first use. Cloning
    /// preserves the origin, so handing copies around is safe.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Clock for StdClock {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn poll_delay_until(&self, cx: &mut Context<'_>, deadline_ms: u64) -> Poll<()> {
        let now = self.now_ms();
        if now >= deadline_ms {
            return Poll::Ready(());
        }

        let remaining = Duration::from_millis(deadline_ms - now);
        let target = tokio::time::Instant::now() + remaining;

        let mut cell = self.pending_sleep.borrow_mut();
        let sleep = cell.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        sleep.as_mut().reset(target);
        sleep.as_mut().poll(cx)
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

/// The UDP multicast radio: the desktop simulations' shared medium, and
/// the LAN bearer. It lives in `umsh-lan-bearer`, which every host and
/// the iOS core share.
pub use umsh_lan_bearer::radio::{RxMode, UdpMulticastRadio, UdpMulticastRadioError};
pub use umsh_lan_bearer::socket::{LanConfig, LanSocket};

/// Counter store that persists one file per context key.
///
/// Each store replaces its file atomically—a synced temporary renamed
/// over the original—so a crash leaves the old boundary or the new one,
/// never a torn record that would read back as something lower.
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
        match tokio::fs::read(self.path_for(context)).await {
            Ok(bytes) => match <[u8; 4]>::try_from(bytes.as_slice()) {
                Ok(bytes) => Ok(u32::from_be_bytes(bytes)),
                // Reading this as zero would restart the counter below
                // values already sent, which is the one thing a counter
                // store exists to prevent.
                Err(_) => Err(FileStoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("counter record is {} bytes, not 4", bytes.len()),
                ))),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(FileStoreError::Io(error)),
        }
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        let destination = self.path_for(context);
        let temporary = destination.with_extension("ctr.pending");
        let written = async {
            let mut file = tokio::fs::File::create(&temporary).await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &value.to_be_bytes()).await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&temporary, &destination).await?;
            // The rename is durable only once the directory is.
            #[cfg(unix)]
            tokio::fs::File::open(&self.root).await?.sync_all().await?;
            Ok(())
        }
        .await;
        if written.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        written.map_err(FileStoreError::Io)
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
    use core::future::poll_fn;
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use umsh_hal::{Radio, TxOptions};

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
        assert!(
            !store
                .path_for(b"peer")
                .with_extension("ctr.pending")
                .exists(),
            "the temporary is renamed away"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_counter_record_of_the_wrong_length_is_an_error_not_zero() {
        let root = temp_dir("counter-store-torn");
        let store = TokioFileCounterStore::new(&root).unwrap();
        fs::write(store.path_for(b"peer"), [0x00, 0x01]).unwrap();
        assert!(store.load(b"peer").await.is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn udp_multicast_radio_exchanges_frames_between_instances() {
        let port = 40_000
            + (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .subsec_nanos()
                % 10_000) as u16;
        let group = Ipv4Addr::new(239, 255, 134, 121);

        let mut left = UdpMulticastRadio::bind_v4(group, port).await.unwrap();
        let mut right = UdpMulticastRadio::bind_v4(group, port).await.unwrap();

        left.transmit(b"ping", TxOptions::default()).await.unwrap();

        let mut buf = [0u8; 16];
        let rx = tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| right.poll_receive(cx, &mut buf)),
        )
        .await
        .expect("udp multicast receive should complete")
        .unwrap();

        assert_eq!(rx.len, 4);
        assert_eq!(&buf[..rx.len], b"ping");
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
