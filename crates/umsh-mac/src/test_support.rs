//! Std-only simulated radio network and dummy platform components for tests.
//!
//! This module is intended for development, simulation, and examples. The
//! simulated network types are useful outside unit tests, but the dummy crypto
//! and RNG implementations are deliberately insecure and must not be used for
//! real deployments.

use core::convert::Infallible;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    vec::Vec,
};

use core::task::{Context, Poll};
use embedded_hal_async::delay::DelayNs;
use rand::{Rng, TryCryptoRng, TryRng};
use umsh_core::PublicKey;
use umsh_crypto::{
    AesCipher, AesProvider, CryptoEngine, NodeIdentity, Sha256Provider, SharedSecret,
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, Snr, TxError, TxOptions};

use crate::{
    DEFAULT_ACKS, DEFAULT_CHANNELS, DEFAULT_DUP, DEFAULT_FRAME, DEFAULT_IDENTITIES, DEFAULT_PEERS,
    DEFAULT_TX, Mac, OperatingPolicy, Platform, RepeaterConfig,
};

const DEFAULT_RSSI: i16 = -40;
const DEFAULT_SNR: Snr = Snr::from_decibels(10);

/// Convenience alias for a `Mac` instantiated with the simulated test components.
pub type TestMac<
    const IDENTITIES: usize = DEFAULT_IDENTITIES,
    const PEERS: usize = DEFAULT_PEERS,
    const CHANNELS: usize = DEFAULT_CHANNELS,
    const ACKS: usize = DEFAULT_ACKS,
    const TX: usize = DEFAULT_TX,
    const FRAME: usize = DEFAULT_FRAME,
    const DUP: usize = DEFAULT_DUP,
> = Mac<TestPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

/// Convenience alias for a `Mac` instantiated with the modeled simulated components.
pub type ModeledTestMac<
    const IDENTITIES: usize = DEFAULT_IDENTITIES,
    const PEERS: usize = DEFAULT_PEERS,
    const CHANNELS: usize = DEFAULT_CHANNELS,
    const ACKS: usize = DEFAULT_ACKS,
    const TX: usize = DEFAULT_TX,
    const FRAME: usize = DEFAULT_FRAME,
    const DUP: usize = DEFAULT_DUP,
> = Mac<ModeledTestPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

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

/// Platform bundle for the modeled simulated components.
pub struct ModeledTestPlatform;

impl Platform for ModeledTestPlatform {
    type Identity = DummyIdentity;
    type Aes = DummyAes;
    type Sha = DummySha;
    type Radio = ModeledRadio;
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

/// Create a test MAC coordinator using the modeled simulated components.
pub fn make_modeled_test_mac<
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
>(
    radio: ModeledRadio,
    clock: DummyClock,
) -> ModeledTestMac<IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP> {
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
    snr: Snr,
}

#[derive(Clone, Copy)]
struct LinkProfile {
    connected: bool,
    rssi: i16,
    snr: Snr,
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
    pub fn set_link(&self, from: usize, to: usize, connected: bool, rssi: i16, snr: Snr) {
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
    pub fn inject_frame_with_info(&self, to: usize, frame: &[u8], rssi: i16, snr: Snr) {
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
        let deliveries: Vec<(usize, i16, Snr)> = row
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
                snr: Snr::from_decibels(0),
                lqi: None,
            };
        };
        let len = frame.data.len().min(buf.len());
        buf[..len].copy_from_slice(&frame.data[..len]);
        RxInfo {
            len,
            rssi: frame.rssi,
            snr: frame.snr,
            lqi: None,
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

    async fn transmit(
        &mut self,
        data: &[u8],
        _options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        self.network.transmit(self.id, data);
        Ok(())
    }

    fn poll_receive(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>> {
        let rx = self.network.receive(self.id, buf);
        if rx.len == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(rx))
        }
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn t_frame_ms(&self) -> u32 {
        self.t_frame_ms
    }
}

/// Link model used by [`ModeledNetwork`] to derive receive metadata and loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeledLinkProfile {
    pub connected: bool,
    pub base_rssi: i16,
    pub base_snr: Snr,
    pub rssi_jitter_dbm: i16,
    pub snr_jitter_centibels: i16,
    pub propagation_delay_ms: u32,
    pub drop_per_thousand: u16,
}

impl Default for ModeledLinkProfile {
    fn default() -> Self {
        Self {
            connected: false,
            base_rssi: DEFAULT_RSSI,
            base_snr: DEFAULT_SNR,
            rssi_jitter_dbm: 2,
            snr_jitter_centibels: 10,
            propagation_delay_ms: 0,
            drop_per_thousand: 0,
        }
    }
}

impl ModeledLinkProfile {
    /// Return a connected profile with the default modeled signal characteristics.
    pub fn connected() -> Self {
        Self {
            connected: true,
            ..Self::default()
        }
    }
}

/// Shared simulated network with scheduled delivery, jitter, packet loss, and coarse collision modeling.
#[derive(Clone)]
pub struct ModeledNetwork {
    inner: Rc<RefCell<ModeledNetworkState>>,
    clock: DummyClock,
}

struct ModeledNetworkState {
    inboxes: Vec<VecDeque<QueuedFrame>>,
    links: Vec<Vec<ModeledLinkProfile>>,
    in_flight: Vec<InFlightTransmission>,
    scheduled: Vec<ScheduledDelivery>,
    rng: ModeledRng,
}

struct InFlightTransmission {
    from: usize,
    start_ms: u64,
    end_ms: u64,
}

struct ScheduledDelivery {
    to: usize,
    available_at_ms: u64,
    start_ms: u64,
    end_ms: u64,
    data: Vec<u8>,
    rssi: i16,
    snr: Snr,
    collided: bool,
}

impl ModeledNetwork {
    /// Create an empty modeled network with a shared clock starting at 0 ms.
    pub fn new() -> Self {
        Self::with_clock(DummyClock::new(0))
    }

    /// Create an empty modeled network using a caller-supplied shared clock.
    pub fn with_clock(clock: DummyClock) -> Self {
        Self {
            inner: Rc::new(RefCell::new(ModeledNetworkState {
                inboxes: Vec::new(),
                links: Vec::new(),
                in_flight: Vec::new(),
                scheduled: Vec::new(),
                rng: ModeledRng::new(0x554d_5348),
            })),
            clock,
        }
    }

    /// Return the shared modeled clock.
    pub fn clock(&self) -> DummyClock {
        self.clock.clone()
    }

    /// Advance the shared simulation time.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.clock.advance_ms(delta_ms);
        self.promote_due_frames();
    }

    /// Override the deterministic RNG seed used for loss/jitter sampling.
    pub fn reseed(&self, seed: u64) {
        self.inner.borrow_mut().rng = ModeledRng::new(seed);
    }

    /// Add a modeled radio with default limits.
    pub fn add_radio(&self) -> ModeledRadio {
        self.add_radio_with_config(256, 100)
    }

    /// Add a modeled radio with explicit frame-size and airtime limits.
    pub fn add_radio_with_config(&self, max_frame_size: usize, t_frame_ms: u32) -> ModeledRadio {
        let mut state = self.inner.borrow_mut();
        let id = state.inboxes.len();
        for row in &mut state.links {
            row.push(ModeledLinkProfile::default());
        }
        state.inboxes.push(VecDeque::new());
        state.links.push(vec![ModeledLinkProfile::default(); id + 1]);
        ModeledRadio {
            network: self.clone(),
            id,
            max_frame_size,
            t_frame_ms,
        }
    }

    /// Connect `from` to `to` using the default modeled link profile.
    pub fn connect(&self, from: usize, to: usize) {
        self.set_link_profile(from, to, ModeledLinkProfile::connected());
    }

    /// Connect two radios in both directions using the default modeled link profile.
    pub fn connect_bidirectional(&self, a: usize, b: usize) {
        self.connect(a, b);
        self.connect(b, a);
    }

    /// Remove the directed link from `from` to `to`.
    pub fn disconnect(&self, from: usize, to: usize) {
        self.set_link_profile(from, to, ModeledLinkProfile::default());
    }

    /// Configure one directed link with an explicit modeled profile.
    pub fn set_link_profile(&self, from: usize, to: usize, profile: ModeledLinkProfile) {
        let mut state = self.inner.borrow_mut();
        let Some(row) = state.links.get_mut(from) else {
            panic!("unknown modeled radio id {from}");
        };
        let Some(link) = row.get_mut(to) else {
            panic!("unknown modeled radio id {to}");
        };
        *link = profile;
    }

    /// Return whether any future deliveries are still pending.
    pub fn has_pending_deliveries(&self) -> bool {
        !self.inner.borrow().scheduled.is_empty()
    }

    fn promote_due_frames(&self) {
        let now_ms = self.clock.now_ms();
        let mut state = self.inner.borrow_mut();
        state.in_flight.retain(|tx| tx.end_ms > now_ms);
        let mut index = 0usize;
        while index < state.scheduled.len() {
            if state.scheduled[index].available_at_ms > now_ms {
                index += 1;
                continue;
            }
            let delivery = state.scheduled.swap_remove(index);
            if delivery.collided {
                continue;
            }
            state.inboxes[delivery.to].push_back(QueuedFrame {
                data: delivery.data,
                rssi: delivery.rssi,
                snr: delivery.snr,
            });
        }
    }

    fn channel_busy(&self, from: usize, now_ms: u64) -> bool {
        let state = self.inner.borrow();
        state.in_flight.iter().any(|tx| {
            tx.from != from
                && tx.start_ms <= now_ms
                && now_ms < tx.end_ms
                && state
                    .links
                    .get(tx.from)
                    .and_then(|row| row.get(from))
                    .map(|profile| profile.connected)
                    .unwrap_or(false)
        })
    }

    fn transmit(
        &self,
        from: usize,
        frame: &[u8],
        t_frame_ms: u32,
        options: TxOptions,
    ) -> Result<(), TxError<()>> {
        self.promote_due_frames();
        let now_ms = self.clock.now_ms();
        if options.cad_timeout_ms.is_some() && self.channel_busy(from, now_ms) {
            return Err(TxError::CadTimeout);
        }

        let mut state = self.inner.borrow_mut();
        let Some(row) = state.links.get(from) else {
            panic!("unknown modeled radio id {from}");
        };
        let start_ms = now_ms;
        let end_ms = now_ms.saturating_add(u64::from(t_frame_ms));
        let deliveries: Vec<(usize, ModeledLinkProfile)> = row
            .iter()
            .enumerate()
            .filter_map(|(to, link)| link.connected.then_some((to, *link)))
            .collect();

        for (to, profile) in deliveries {
            if profile.drop_per_thousand > 0
                && state.rng.random_u16(1000) < profile.drop_per_thousand
            {
                continue;
            }

            let rssi_jitter = if profile.rssi_jitter_dbm > 0 {
                state
                    .rng
                    .random_i16_inclusive(-profile.rssi_jitter_dbm, profile.rssi_jitter_dbm)
            } else {
                0
            };
            let snr_jitter = if profile.snr_jitter_centibels > 0 {
                state.rng.random_i16_inclusive(
                    -profile.snr_jitter_centibels,
                    profile.snr_jitter_centibels,
                )
            } else {
                0
            };
            let propagation_delay_ms = u64::from(profile.propagation_delay_ms);
            let available_at_ms = end_ms.saturating_add(propagation_delay_ms);
            let mut delivery = ScheduledDelivery {
                to,
                available_at_ms,
                start_ms,
                end_ms,
                data: frame.to_vec(),
                rssi: profile.base_rssi.saturating_add(rssi_jitter),
                snr: Snr::from_centibels(
                    profile
                        .base_snr
                        .as_centibels()
                        .saturating_add(snr_jitter),
                ),
                collided: false,
            };

            for existing in &mut state.scheduled {
                if existing.to != to {
                    continue;
                }
                if existing.start_ms < end_ms && start_ms < existing.end_ms {
                    existing.collided = true;
                    delivery.collided = true;
                }
            }

            state.scheduled.push(delivery);
        }

        state.in_flight.push(InFlightTransmission {
            from,
            start_ms,
            end_ms,
        });
        Ok(())
    }

    fn receive(&self, id: usize, buf: &mut [u8]) -> RxInfo {
        self.promote_due_frames();
        let mut state = self.inner.borrow_mut();
        let Some(queue) = state.inboxes.get_mut(id) else {
            panic!("unknown modeled radio id {id}");
        };
        let Some(frame) = queue.pop_front() else {
            return RxInfo {
                len: 0,
                rssi: 0,
                snr: Snr::from_decibels(0),
                lqi: None,
            };
        };
        let len = frame.data.len().min(buf.len());
        buf[..len].copy_from_slice(&frame.data[..len]);
        RxInfo {
            len,
            rssi: frame.rssi,
            snr: frame.snr,
            lqi: None,
        }
    }
}

impl Default for ModeledNetwork {
    fn default() -> Self {
        Self::new()
    }
}

/// Radio implementation backed by a [`ModeledNetwork`].
#[derive(Clone)]
pub struct ModeledRadio {
    network: ModeledNetwork,
    id: usize,
    max_frame_size: usize,
    t_frame_ms: u32,
}

#[derive(Clone, Copy)]
struct ModeledRng(u64);

impl ModeledRng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x.max(1);
        x as u32
    }

    fn random_u16(&mut self, upper_exclusive: u16) -> u16 {
        if upper_exclusive == 0 {
            0
        } else {
            (self.next_u32() % u32::from(upper_exclusive)) as u16
        }
    }

    fn random_i16_inclusive(&mut self, min: i16, max: i16) -> i16 {
        if min >= max {
            min
        } else {
            let span = (i32::from(max) - i32::from(min) + 1) as u32;
            (i32::from(min) + (self.next_u32() % span) as i32) as i16
        }
    }
}

impl ModeledRadio {
    /// Return the radio's stable identifier within the modeled network.
    pub fn id(&self) -> usize {
        self.id
    }
}

impl Radio for ModeledRadio {
    type Error = ();

    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        self.network.transmit(self.id, data, self.t_frame_ms, options)
    }

    fn poll_receive(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>> {
        let rx = self.network.receive(self.id, buf);
        if rx.len == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(rx))
        }
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
        self.now_ms.set(self.now_ms.get().saturating_add(delta_ms));
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
