//! Std-only simulated radio network and dummy platform components for tests.
//!
//! This module is intended for development, simulation, and examples. The
//! simulated network types are useful outside unit tests, but the dummy crypto
//! and RNG implementations are deliberately insecure and must not be used for
//! real deployments.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    vec::Vec,
};
use core::convert::Infallible;

use embedded_hal_async::delay::DelayNs;
use rand::{Rng, TryCryptoRng, TryRng};
use umsh_core::PublicKey;
use umsh_crypto::{
    AesCipher, AesProvider, CryptoEngine, NodeIdentity, Sha256Provider, SharedSecret,
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo};

use crate::{
    Mac, OperatingPolicy, Platform, RepeaterConfig, DEFAULT_ACKS, DEFAULT_CHANNELS, DEFAULT_DUP,
    DEFAULT_FRAME, DEFAULT_IDENTITIES, DEFAULT_PEERS, DEFAULT_TX,
};

const DEFAULT_RSSI: i16 = -40;
const DEFAULT_SNR: i8 = 10;

/// Convenience alias for a `Mac` instantiated with the simulated test components.
pub type TestMac<
    const IDENTITIES: usize = DEFAULT_IDENTITIES,
    const PEERS: usize = DEFAULT_PEERS,
    const CHANNELS: usize = DEFAULT_CHANNELS,
    const ACKS: usize = DEFAULT_ACKS,
    const TX: usize = DEFAULT_TX,
    const FRAME: usize = DEFAULT_FRAME,
    const DUP: usize = DEFAULT_DUP,
> = Mac<
    TestPlatform,
    IDENTITIES,
    PEERS,
    CHANNELS,
    ACKS,
    TX,
    FRAME,
    DUP,
>;

/// Platform bundle for the simulated test components.
pub struct TestPlatform;

impl Platform for TestPlatform {
    type Identity = DummyIdentity;
    type Aes = DummyAes;
    type Sha = DummySha;
    type Radio = SimulatedRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = DummyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}

/// Create a test MAC coordinator using the simulated components.
pub fn make_test_mac<
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
>(
    radio: SimulatedRadio,
    clock: DummyClock,
) -> TestMac<IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP> {
    Mac::new(
        radio,
        CryptoEngine::new(DummyAes, DummySha),
        clock,
        DummyRng::default(),
        DummyCounterStore,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

/// Shared simulated radio topology and frame queues.
#[derive(Clone)]
pub struct SimulatedNetwork {
    inner: Rc<RefCell<NetworkState>>,
}

struct NetworkState {
    inboxes: Vec<VecDeque<QueuedFrame>>,
    links: Vec<Vec<LinkProfile>>,
}

struct QueuedFrame {
    data: Vec<u8>,
    rssi: i16,
    snr: i8,
}

#[derive(Clone, Copy)]
struct LinkProfile {
    connected: bool,
    rssi: i16,
    snr: i8,
}

impl Default for LinkProfile {
    fn default() -> Self {
        Self {
            connected: false,
            rssi: DEFAULT_RSSI,
            snr: DEFAULT_SNR,
        }
    }
}

impl Default for SimulatedNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedNetwork {
    /// Create an empty simulated network.
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(NetworkState {
                inboxes: Vec::new(),
                links: Vec::new(),
            })),
        }
    }

    /// Add a radio with default limits.
    pub fn add_radio(&self) -> SimulatedRadio {
        self.add_radio_with_config(256, 10)
    }

    /// Add a radio with explicit frame-size and airtime limits.
    pub fn add_radio_with_config(&self, max_frame_size: usize, t_frame_ms: u32) -> SimulatedRadio {
        let mut state = self.inner.borrow_mut();
        let id = state.inboxes.len();
        for row in &mut state.links {
            row.push(LinkProfile::default());
        }
        state.inboxes.push(VecDeque::new());
        state.links.push(vec![LinkProfile::default(); id + 1]);
        SimulatedRadio {
            network: self.clone(),
            id,
            max_frame_size,
            t_frame_ms,
        }
    }

    /// Connect `from` to `to` with default signal values.
    pub fn connect(&self, from: usize, to: usize) {
        self.set_link(from, to, true, DEFAULT_RSSI, DEFAULT_SNR);
    }

    /// Connect two radios in both directions.
    pub fn connect_bidirectional(&self, a: usize, b: usize) {
        self.connect(a, b);
        self.connect(b, a);
    }

    /// Remove the directed link from `from` to `to`.
    pub fn disconnect(&self, from: usize, to: usize) {
        self.set_link(from, to, false, DEFAULT_RSSI, DEFAULT_SNR);
    }

    /// Configure one directed link with explicit signal values.
    pub fn set_link(&self, from: usize, to: usize, connected: bool, rssi: i16, snr: i8) {
        let mut state = self.inner.borrow_mut();
        let Some(row) = state.links.get_mut(from) else {
            panic!("unknown simulated radio id {from}");
        };
        let Some(link) = row.get_mut(to) else {
            panic!("unknown simulated radio id {to}");
        };
        *link = LinkProfile {
            connected,
            rssi,
            snr,
        };
    }

    /// Inject a frame directly into one radio's receive queue.
    pub fn inject_frame(&self, to: usize, frame: &[u8]) {
        self.inject_frame_with_info(to, frame, DEFAULT_RSSI, DEFAULT_SNR);
    }

    /// Inject a frame directly into one radio's receive queue with explicit metadata.
    pub fn inject_frame_with_info(&self, to: usize, frame: &[u8], rssi: i16, snr: i8) {
        let mut state = self.inner.borrow_mut();
        let Some(queue) = state.inboxes.get_mut(to) else {
            panic!("unknown simulated radio id {to}");
        };
        queue.push_back(QueuedFrame {
            data: frame.to_vec(),
            rssi,
            snr,
        });
    }

    fn transmit(&self, from: usize, frame: &[u8]) {
        let mut state = self.inner.borrow_mut();
        let Some(row) = state.links.get(from) else {
            panic!("unknown simulated radio id {from}");
        };
        let deliveries: Vec<(usize, i16, i8)> = row
            .iter()
            .enumerate()
            .filter_map(|(to, link)| link.connected.then_some((to, link.rssi, link.snr)))
            .collect();
        for (to, rssi, snr) in deliveries {
            state.inboxes[to].push_back(QueuedFrame {
                data: frame.to_vec(),
                rssi,
                snr,
            });
        }
    }

    fn receive(&self, id: usize, buf: &mut [u8]) -> RxInfo {
        let mut state = self.inner.borrow_mut();
        let Some(queue) = state.inboxes.get_mut(id) else {
            panic!("unknown simulated radio id {id}");
        };
        let Some(frame) = queue.pop_front() else {
            return RxInfo {
                len: 0,
                rssi: 0,
                snr: 0,
            };
        };
        let len = frame.data.len().min(buf.len());
        buf[..len].copy_from_slice(&frame.data[..len]);
        RxInfo {
            len,
            rssi: frame.rssi,
            snr: frame.snr,
        }
    }
}

/// Radio implementation backed by a [`SimulatedNetwork`].
#[derive(Clone)]
pub struct SimulatedRadio {
    network: SimulatedNetwork,
    id: usize,
    max_frame_size: usize,
    t_frame_ms: u32,
}

impl SimulatedRadio {
    /// Return the radio's stable identifier within the simulated network.
    pub fn id(&self) -> usize {
        self.id
    }
}

impl Radio for SimulatedRadio {
    type Error = ();

    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.network.transmit(self.id, data);
        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error> {
        Ok(self.network.receive(self.id, buf))
    }

    async fn cad(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn t_frame_ms(&self) -> u32 {
        self.t_frame_ms
    }
}

/// Minimal `NodeIdentity` implementation used by tests and simulations.
///
/// This type is not suitable for production use.
#[derive(Clone)]
pub struct DummyIdentity {
    public_key: PublicKey,
}

impl DummyIdentity {
    /// Construct a dummy identity from fixed public-key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            public_key: PublicKey(bytes),
        }
    }
}

impl NodeIdentity for DummyIdentity {
    type Error = ();

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    async fn sign(&self, _message: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok([0u8; 64])
    }

    async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error> {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.public_key.0[index] ^ peer.0[index];
        }
        Ok(SharedSecret(out))
    }
}

/// Dummy XOR-based cipher used by tests.
///
/// This type is intentionally insecure.
pub struct DummyCipher {
    key: [u8; 16],
}

impl AesCipher for DummyCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        for (byte, key) in block.iter_mut().zip(self.key.iter()) {
            *byte ^= *key;
        }
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.encrypt_block(block);
    }
}

/// Dummy AES provider used by tests.
///
/// This type is intentionally insecure.
#[derive(Clone, Copy)]
pub struct DummyAes;

impl AesProvider for DummyAes {
    type Cipher = DummyCipher;

    fn new_cipher(&self, key: &[u8; 16]) -> Self::Cipher {
        DummyCipher { key: *key }
    }
}

/// Dummy SHA/HMAC provider used by tests.
///
/// This type is intentionally insecure.
#[derive(Clone, Copy)]
pub struct DummySha;

impl Sha256Provider for DummySha {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in data {
            for (index, byte) in chunk.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
        }
        out
    }

    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in key.iter().enumerate() {
            out[index % 32] ^= *byte;
        }
        for chunk in data {
            for (index, byte) in chunk.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
        }
        out
    }
}

/// Mutable monotonic test clock.
#[derive(Clone, Default)]
pub struct DummyClock {
    now_ms: Rc<Cell<u64>>,
}

impl DummyClock {
    /// Create the clock starting at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            now_ms: Rc::new(Cell::new(now_ms)),
        }
    }

    /// Advance the clock by `delta_ms`.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.now_ms
            .set(self.now_ms.get().saturating_add(delta_ms));
    }

    /// Set the current clock value.
    pub fn set_ms(&self, now_ms: u64) {
        self.now_ms.set(now_ms);
    }
}

impl Clock for DummyClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.get()
    }
}

/// No-op async delay used only to satisfy the platform bundle in tests.
#[derive(Clone, Copy, Default)]
pub struct DummyDelay;

impl DelayNs for DummyDelay {
    async fn delay_ns(&mut self, _ns: u32) {}
}

/// Deterministic byte-filling RNG used by tests.
///
/// This type is intentionally predictable.
#[derive(Clone, Default)]
pub struct DummyRng(pub u8);

impl TryRng for DummyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for byte in dest.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for DummyRng {}

/// No-op counter store used by tests.
#[derive(Clone, Copy, Default)]
pub struct DummyCounterStore;

impl CounterStore for DummyCounterStore {
    type Error = ();

    async fn load(&self, _context: &[u8]) -> Result<u32, Self::Error> {
        Ok(0)
    }

    async fn store(&self, _context: &[u8], _value: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// No-op key-value store used only to satisfy the platform bundle in tests.
#[derive(Clone, Copy, Default)]
pub struct DummyKeyValueStore;

impl KeyValueStore for DummyKeyValueStore {
    type Error = ();

    async fn load(&self, _key: &[u8], _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    async fn store(&self, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete(&self, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}