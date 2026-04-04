//! Tokio-friendly runtime adapters and simple std-backed stores.

use core::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use embedded_hal_async::delay::DelayNs;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, TxError, TxOptions};

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

/// Errors returned by the UDP multicast radio simulator.
#[derive(Debug)]
pub enum UdpMulticastRadioError {
    Io(io::Error),
    InvalidConfig(&'static str),
    FrameTooLarge(usize),
}

impl From<io::Error> for UdpMulticastRadioError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Configuration for [`UdpMulticastRadio`].
#[derive(Clone, Copy, Debug)]
pub struct UdpMulticastRadioConfig {
    pub bind_addr: Ipv4Addr,
    pub group_addr: Ipv4Addr,
    pub interface_addr: Ipv4Addr,
    pub port: u16,
    pub max_frame_size: usize,
    pub t_frame_ms: u32,
    pub rssi: i16,
    pub snr: i8,
    pub loopback: bool,
}

impl UdpMulticastRadioConfig {
    /// Create a simple host-local multicast configuration.
    pub fn localhost(group_addr: Ipv4Addr, port: u16) -> Self {
        Self {
            bind_addr: Ipv4Addr::UNSPECIFIED,
            group_addr,
            interface_addr: Ipv4Addr::LOCALHOST,
            port,
            max_frame_size: 256,
            t_frame_ms: 10,
            rssi: -40,
            snr: 10,
            loopback: true,
        }
    }
}

/// Host-side radio simulator backed by UDP multicast.
///
/// Raw UMSH frames are sent and received over IPv4 multicast with no additional
/// framing. Multicast loopback is enabled by default so that multiple processes
/// on the same host can exchange frames via the loopback interface.
pub struct UdpMulticastRadio {
    socket: UdpSocket,
    group_addr: SocketAddrV4,
    max_frame_size: usize,
    t_frame_ms: u32,
    rssi: i16,
    snr: i8,
    recv_buf: Vec<u8>,
}

impl UdpMulticastRadio {
    /// Bind a UDP multicast simulator socket using a simple localhost-oriented configuration.
    pub async fn bind_v4(group_addr: Ipv4Addr, port: u16) -> Result<Self, UdpMulticastRadioError> {
        Self::bind_with_config(UdpMulticastRadioConfig::localhost(group_addr, port)).await
    }

    /// Bind a UDP multicast simulator socket using the provided configuration.
    pub async fn bind_with_config(config: UdpMulticastRadioConfig) -> Result<Self, UdpMulticastRadioError> {
        if !config.group_addr.is_multicast() {
            return Err(UdpMulticastRadioError::InvalidConfig("group_addr must be an IPv4 multicast address"));
        }
        if config.max_frame_size == 0 {
            return Err(UdpMulticastRadioError::InvalidConfig("max_frame_size must be non-zero"));
        }

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddrV4::new(config.bind_addr, config.port).into())?;
        socket.join_multicast_v4(&config.group_addr, &config.interface_addr)?;
        socket.set_multicast_if_v4(&config.interface_addr)?;
        socket.set_multicast_loop_v4(config.loopback)?;

        let group = SocketAddrV4::new(config.group_addr, config.port);
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;

        Ok(Self {
            socket,
            group_addr: group,
            max_frame_size: config.max_frame_size,
            t_frame_ms: config.t_frame_ms,
            rssi: config.rssi,
            snr: config.snr,
            recv_buf: vec![0u8; config.max_frame_size],
        })
    }
}

impl Radio for UdpMulticastRadio {
    type Error = UdpMulticastRadioError;

    async fn transmit(&mut self, data: &[u8], _options: TxOptions) -> Result<(), TxError<Self::Error>> {
        if data.len() > self.max_frame_size {
            return Err(TxError::Io(UdpMulticastRadioError::FrameTooLarge(data.len())));
        }

        let sent = self.socket
            .send_to(data, self.group_addr)
            .await
            .map_err(UdpMulticastRadioError::Io)
            .map_err(TxError::Io)?;
        eprintln!("[udp-radio] TX {} bytes to {}", sent, self.group_addr);
        Ok(())
    }

    fn poll_receive(&mut self, cx: &mut core::task::Context<'_>, buf: &mut [u8]) -> core::task::Poll<Result<RxInfo, Self::Error>> {
        let mut read_buf = ReadBuf::new(&mut self.recv_buf);
        let len = match self.socket.poll_recv(cx, &mut read_buf) {
            core::task::Poll::Ready(Ok(())) => read_buf.filled().len(),
            core::task::Poll::Ready(Err(error)) => {
                return core::task::Poll::Ready(Err(UdpMulticastRadioError::Io(error)));
            }
            core::task::Poll::Pending => return core::task::Poll::Pending,
        };
        if len == 0 {
            return core::task::Poll::Pending;
        }

        let copy_len = len.min(buf.len());
        buf[..copy_len].copy_from_slice(&self.recv_buf[..copy_len]);
        eprintln!("[udp-radio] RX {} bytes", copy_len);
        core::task::Poll::Ready(Ok(RxInfo {
            len: copy_len,
            rssi: self.rssi,
            snr: self.snr,
        }))
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn t_frame_ms(&self) -> u32 {
        self.t_frame_ms
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
    use core::future::poll_fn;
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
    async fn udp_multicast_radio_exchanges_frames_between_instances() {
        let port = 40_000 + (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .subsec_nanos() % 10_000) as u16;
        let group = Ipv4Addr::new(239, 255, 42, 42);

        let mut left = UdpMulticastRadio::bind_v4(group, port).await.unwrap();
        let mut right = UdpMulticastRadio::bind_v4(group, port).await.unwrap();

        left.transmit(b"ping", TxOptions::default()).await.unwrap();

        let mut buf = [0u8; 16];
        let rx = tokio::time::timeout(Duration::from_secs(1), poll_fn(|cx| right.poll_receive(cx, &mut buf)))
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