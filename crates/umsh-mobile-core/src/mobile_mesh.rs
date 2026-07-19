//! Rust-owned mobile mesh session.
//!
//! The platform adapter moves complete raw frames between this object and a
//! companion transport. It never constructs MAC commands, advances counters,
//! or correlates ping replies.

use core::{
    cell::RefCell,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    collections::BTreeMap,
    fmt,
    rc::Rc,
    sync::{Arc, Mutex, mpsc as std_mpsc},
    time::{Duration, Instant},
};

use embedded_hal_async::delay::DelayNs;
use tokio::sync::mpsc;
use umsh_core::PublicKey;
use umsh_crypto::{
    CryptoEngine,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, Snr, TxError, TxOptions};
use umsh_mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::Host;
use umsh_sync::AsyncRefCell;

use crate::{MobileCounterStore, MobileError, MobileIdentity};

const MAX_FRAME_SIZE: usize = 256;
const DEFAULT_FRAME_TIME_MS: u32 = 800;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileMeshError {
    InvalidPeer,
    SessionUnavailable,
    OperationInProgress,
    CounterPersistenceFailed,
    SendFailed,
}

impl fmt::Display for MobileMeshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPeer => "MESH_INVALID_PEER",
            Self::SessionUnavailable => "MESH_SESSION_UNAVAILABLE",
            Self::OperationInProgress => "MESH_OPERATION_IN_PROGRESS",
            Self::CounterPersistenceFailed => "MESH_COUNTER_PERSISTENCE_FAILED",
            Self::SendFailed => "MESH_SEND_FAILED",
        })
    }
}

impl std::error::Error for MobileMeshError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileMeshPingOutcome {
    Reply,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshPingEventRecord {
    pub operation_id: u64,
    pub outcome: MobileMeshPingOutcome,
    pub round_trip_milliseconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshSessionUpdateRecord {
    /// Complete raw UMSH frames ready for the companion PHY transport.
    pub outbound_frames: Vec<Vec<u8>>,
    pub ping_events: Vec<MobileMeshPingEventRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshRxRecord {
    pub data: Vec<u8>,
    pub rssi_dbm: Option<i16>,
    pub lqi: Option<u8>,
    pub snr_cb: Option<i16>,
}

enum WorkerCommand {
    Ping {
        operation_id: u64,
        peer: PublicKey,
        timeout_ms: u64,
    },
    Receive(MobileMeshRxRecord),
    Shutdown,
}

struct InboundFrame {
    record: MobileMeshRxRecord,
}

#[derive(Debug)]
enum BridgeRadioError {
    Closed,
    FrameTooLarge,
}

struct BridgeRadio {
    inbound: mpsc::UnboundedReceiver<InboundFrame>,
    outbound: std_mpsc::Sender<Vec<u8>>,
}

impl Radio for BridgeRadio {
    type Error = BridgeRadioError;

    async fn transmit(
        &mut self,
        data: &[u8],
        _options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(TxError::Io(BridgeRadioError::FrameTooLarge));
        }
        self.outbound
            .send(data.to_vec())
            .map_err(|_| TxError::Io(BridgeRadioError::Closed))
    }

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>> {
        match self.inbound.poll_recv(cx) {
            Poll::Ready(Some(frame)) => {
                if frame.record.data.len() > buf.len() {
                    return Poll::Ready(Err(BridgeRadioError::FrameTooLarge));
                }
                let len = frame.record.data.len();
                buf[..len].copy_from_slice(&frame.record.data);
                Poll::Ready(Ok(RxInfo {
                    len,
                    rssi: frame.record.rssi_dbm.unwrap_or(0),
                    snr: Snr::from_centibels(frame.record.snr_cb.unwrap_or(0)),
                    lqi: frame.record.lqi.and_then(core::num::NonZeroU8::new),
                }))
            }
            Poll::Ready(None) => Poll::Ready(Err(BridgeRadioError::Closed)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn max_frame_size(&self) -> usize {
        MAX_FRAME_SIZE
    }
    fn t_frame_ms(&self) -> u32 {
        DEFAULT_FRAME_TIME_MS
    }
}

#[derive(Clone)]
struct SharedCounterStore(Arc<MobileCounterStore>);

impl CounterStore for SharedCounterStore {
    type Error = crate::CounterStoreError;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        self.0.load_boundary(context.to_vec())
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        self.0.commit_boundary(context.to_vec(), value)
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        CounterStore::flush(self.0.as_ref()).await
    }
}

#[derive(Clone, Default)]
struct MemoryKeyValueStore(Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>);

impl KeyValueStore for MemoryKeyValueStore {
    type Error = MobileMeshError;

    async fn load(&self, key: &[u8], out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let values = self
            .0
            .lock()
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        let Some(value) = values.get(key) else {
            return Ok(None);
        };
        if value.len() > out.len() {
            return Err(MobileMeshError::SessionUnavailable);
        }
        out[..value.len()].copy_from_slice(value);
        Ok(Some(value.len()))
    }

    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.0
            .lock()
            .map_err(|_| MobileMeshError::SessionUnavailable)?
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error> {
        self.0
            .lock()
            .map_err(|_| MobileMeshError::SessionUnavailable)?
            .remove(key);
        Ok(())
    }
}

#[derive(Clone)]
struct MobileClock {
    origin: Instant,
    sleep: Rc<RefCell<Option<Pin<Box<tokio::time::Sleep>>>>>,
}

impl MobileClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            sleep: Rc::new(RefCell::new(None)),
        }
    }
}

impl Clock for MobileClock {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn poll_delay_until(&self, cx: &mut Context<'_>, deadline_ms: u64) -> Poll<()> {
        let now = self.now_ms();
        if now >= deadline_ms {
            return Poll::Ready(());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(deadline_ms - now);
        let mut slot = self.sleep.borrow_mut();
        let sleep = slot.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        sleep.as_mut().reset(deadline);
        sleep.as_mut().poll(cx)
    }
}

#[derive(Clone, Copy, Default)]
struct MobileDelay;

impl DelayNs for MobileDelay {
    async fn delay_ns(&mut self, ns: u32) {
        tokio::time::sleep(Duration::from_nanos(u64::from(ns))).await;
    }
}

struct MobilePlatform(PhantomData<()>);

impl umsh_mac::Platform for MobilePlatform {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = BridgeRadio;
    type Delay = MobileDelay;
    type Clock = MobileClock;
    type Rng = rand::rngs::ThreadRng;
    type CounterStore = SharedCounterStore;
    type KeyValueStore = MemoryKeyValueStore;
}

type MobileMac = Mac<MobilePlatform>;

/// Long-lived Rust protocol engine used by the mobile app.
///
/// `ping` is the only ping operation exposed to Swift. The existing Rust node
/// layer owns its nonce, authenticated echo request, counter reservation,
/// response matching, and timeout.
#[derive(uniffi::Object)]
pub struct MobileMeshSession {
    commands: mpsc::UnboundedSender<WorkerCommand>,
    outbound: Mutex<std_mpsc::Receiver<Vec<u8>>>,
    events: Mutex<std_mpsc::Receiver<MobileMeshPingEventRecord>>,
    next_operation_id: Mutex<u64>,
}

#[uniffi::export]
impl MobileMeshSession {
    #[uniffi::constructor]
    pub fn new(
        identity: Arc<MobileIdentity>,
        counter_store: Arc<MobileCounterStore>,
    ) -> Result<Arc<Self>, MobileMeshError> {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound) = std_mpsc::channel();
        let (event_tx, events) = std_mpsc::channel();
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let worker_identity = identity.take_for_session()?;

        std::thread::Builder::new()
            .name("umsh-mobile-mesh".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = ready_tx.send(Err(MobileMeshError::SessionUnavailable));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(
                    &runtime,
                    run_worker(
                        worker_identity,
                        SharedCounterStore(counter_store),
                        command_rx,
                        outbound_tx,
                        event_tx,
                        ready_tx,
                    ),
                );
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;

        ready_rx
            .recv()
            .map_err(|_| MobileMeshError::SessionUnavailable)??;
        Ok(Arc::new(Self {
            commands,
            outbound: Mutex::new(outbound),
            events: Mutex::new(events),
            next_operation_id: Mutex::new(1),
        }))
    }

    pub fn ping(&self, peer_address: String, timeout_ms: u64) -> Result<u64, MobileMeshError> {
        let peer = decode_peer(&peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let operation_id = {
            let mut next = self
                .next_operation_id
                .lock()
                .map_err(|_| MobileMeshError::SessionUnavailable)?;
            let current = *next;
            *next = next.wrapping_add(1).max(1);
            current
        };
        self.commands
            .send(WorkerCommand::Ping {
                operation_id,
                peer,
                timeout_ms,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        Ok(operation_id)
    }

    pub fn receive(&self, frame: MobileMeshRxRecord) -> Result<(), MobileMeshError> {
        if frame.data.is_empty() || frame.data.len() > MAX_FRAME_SIZE {
            return Err(MobileMeshError::SessionUnavailable);
        }
        self.commands
            .send(WorkerCommand::Receive(frame))
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    pub fn poll_update(&self) -> MobileMeshSessionUpdateRecord {
        let mut outbound_frames = Vec::new();
        if let Ok(receiver) = self.outbound.lock() {
            outbound_frames.extend(receiver.try_iter());
        }
        let mut ping_events = Vec::new();
        if let Ok(receiver) = self.events.lock() {
            ping_events.extend(receiver.try_iter());
        }
        MobileMeshSessionUpdateRecord {
            outbound_frames,
            ping_events,
        }
    }
}

impl Drop for MobileMeshSession {
    fn drop(&mut self) {
        let _ = self.commands.send(WorkerCommand::Shutdown);
    }
}

async fn run_worker(
    identity: SoftwareIdentity,
    counter_store: SharedCounterStore,
    mut commands: mpsc::UnboundedReceiver<WorkerCommand>,
    outbound: std_mpsc::Sender<Vec<u8>>,
    events: std_mpsc::Sender<MobileMeshPingEventRecord>,
    ready: std_mpsc::SyncSender<Result<(), MobileMeshError>>,
) {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let radio = BridgeRadio {
        inbound: inbound_rx,
        outbound,
    };
    let mac = MobileMac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        MobileClock::new(),
        rand::rng(),
        counter_store,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    );
    let cell = AsyncRefCell::new(mac);
    let handle = MacHandle::new(&cell);
    let identity_id = match handle.add_identity(identity).await {
        Ok(id) => id,
        Err(_) => {
            let _ = ready.send(Err(MobileMeshError::SessionUnavailable));
            return;
        }
    };
    if handle.load_persisted_counter(identity_id).await.is_err() {
        let _ = ready.send(Err(MobileMeshError::CounterPersistenceFailed));
        return;
    }

    let mut host = Host::new(handle);
    let node = host.add_node(identity_id);
    let pending = Rc::new(RefCell::new(BTreeMap::<[u8; 32], u64>::new()));
    let pong_pending = pending.clone();
    let pong_events = events.clone();
    let pong_subscription = node.on_pong(move |peer, milliseconds| {
        if let Some(operation_id) = pong_pending.borrow_mut().remove(&peer.0) {
            let _ = pong_events.send(MobileMeshPingEventRecord {
                operation_id,
                outcome: MobileMeshPingOutcome::Reply,
                round_trip_milliseconds: Some(milliseconds),
            });
        }
    });
    let timeout_pending = pending.clone();
    let timeout_events = events.clone();
    let timeout_subscription = node.on_ping_timeout(move |peer| {
        if let Some(operation_id) = timeout_pending.borrow_mut().remove(&peer.0) {
            let _ = timeout_events.send(MobileMeshPingEventRecord {
                operation_id,
                outcome: MobileMeshPingOutcome::TimedOut,
                round_trip_milliseconds: None,
            });
        }
    });
    let _subscriptions = (pong_subscription, timeout_subscription);
    let _ = ready.send(Ok(()));
    let mut protocol_timeout_tick = tokio::time::interval(Duration::from_millis(50));
    protocol_timeout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                match command {
                    Some(WorkerCommand::Ping { operation_id, peer, timeout_ms }) => {
                        if pending.borrow().contains_key(&peer.0) {
                            emit_ping_failure(&events, operation_id);
                            continue;
                        }
                        let result = match node.peer(peer).await {
                            Ok(connection) => connection
                                .ping(6, &SendOptions::default().with_flood_hops(5), timeout_ms)
                                .await
                                .map(|_| ())
                                .map_err(|_| MobileMeshError::SendFailed),
                            Err(_) => Err(MobileMeshError::SendFailed),
                        };
                        if result.is_ok() {
                            pending.borrow_mut().insert(peer.0, operation_id);
                            // This write is caused by a real authenticated send. It is
                            // deliberately not performed during startup. Do not move it
                            // into session construction: reboot loops must remain read-only.
                            if handle.service_counter_persistence().await.is_err() {
                                emit_ping_failure(&events, operation_id);
                                return;
                            }
                        }
                        if result.is_err() {
                            emit_ping_failure(&events, operation_id);
                        }
                    }
                    Some(WorkerCommand::Receive(record)) => {
                        let _ = inbound_tx.send(InboundFrame { record });
                    }
                    Some(WorkerCommand::Shutdown) | None => return,
                }
            }
            result = host.pump_once() => {
                if result.is_err() { return; }
            }
            _ = protocol_timeout_tick.tick() => {
                host.service_protocol_timeouts().await;
            }
        }
    }
}

fn decode_peer(address: &str) -> Result<PublicKey, MobileError> {
    let bytes = umsh_core::base58::decode(address.as_bytes())?;
    Ok(PublicKey(bytes))
}

fn emit_ping_failure(events: &std_mpsc::Sender<MobileMeshPingEventRecord>, operation_id: u64) {
    let _ = events.send(MobileMeshPingEventRecord {
        operation_id,
        outcome: MobileMeshPingOutcome::Failed,
        round_trip_milliseconds: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_crypto::NodeIdentity;

    fn identity(seed: u8) -> Arc<MobileIdentity> {
        let identity = SoftwareIdentity::from_secret_bytes(&[seed; 32]);
        let public_identity = crate::public_identity_record(identity.public_key());
        Arc::new(MobileIdentity {
            identity: Mutex::new(Some(identity)),
            public_identity,
        })
    }

    fn address(identity: &MobileIdentity) -> String {
        identity.public_identity.canonical_address.clone()
    }

    #[test]
    fn two_rust_sessions_complete_an_authenticated_ping() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(7);
        let bob_identity = identity(9);
        let alice_root = directory.path().join("alice");
        let bob_root = directory.path().join("bob");
        let alice_store = MobileCounterStore::new(alice_root.display().to_string()).unwrap();
        let bob_store = MobileCounterStore::new(bob_root.display().to_string()).unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store).unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store).unwrap();

        // Constructing or repeatedly rebooting a session is read-only. The
        // first reservation write must be caused by an actual authenticated
        // send, never by startup.
        assert!(!alice_root.exists());
        assert!(!bob_root.exists());

        // Each endpoint knows the other peer, as it would from its durable peer
        // registry in the application. Starting both pings registers both keys
        // through the same public Rust API without test-only MAC access.
        let operation = alice.ping(address(&bob_identity), 2_000).unwrap();
        let _ = bob.ping(address(&alice_identity), 2_000).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                assert!(
                    alice_root.exists(),
                    "Alice released a frame before persisting its reservation"
                );
                bob.receive(MobileMeshRxRecord {
                    data: frame,
                    rssi_dbm: Some(-40),
                    lqi: None,
                    snr_cb: Some(100),
                })
                .unwrap();
            }
            if let Some(event) = alice_update.ping_events.into_iter().next() {
                assert_eq!(event.operation_id, operation);
                assert_eq!(event.outcome, MobileMeshPingOutcome::Reply);
                assert!(event.round_trip_milliseconds.is_some());
                break;
            }

            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
                assert!(
                    bob_root.exists(),
                    "Bob released a frame before persisting its reservation"
                );
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame,
                        rssi_dbm: Some(-42),
                        lqi: None,
                        snr_cb: Some(90),
                    })
                    .unwrap();
            }
            assert!(Instant::now() < deadline, "ping did not complete");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn silent_peer_completes_with_timeout_event() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(11);
        let silent_peer = identity(13);
        let store =
            MobileCounterStore::new(directory.path().join("local").display().to_string()).unwrap();
        let session = MobileMeshSession::new(local_identity, store).unwrap();
        let operation = session.ping(address(&silent_peer), 100).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);

        loop {
            let update = session.poll_update();
            if let Some(event) = update.ping_events.into_iter().next() {
                assert_eq!(event.operation_id, operation);
                assert_eq!(event.outcome, MobileMeshPingOutcome::TimedOut);
                assert_eq!(event.round_trip_milliseconds, None);
                break;
            }
            assert!(Instant::now() < deadline, "silent ping never timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
