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
use tokio::sync::{mpsc, oneshot};
use umsh_core::{PayloadType, PublicKey};
use umsh_crypto::{
    CryptoEngine, NodeIdentity,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, Snr, TxError, TxOptions};
use umsh_mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::{Host, LocalNode, MacBackend, PacketFamily, SendProgressTicket};
use umsh_sync::AsyncRefCell;
use umsh_text::engine::{ArchiveResult, DeliveryState};
use umsh_text::model::{ConversationKey, SenderScope};
use umsh_text::validate::{DeliveryPath, Envelope};

use crate::mobile_chat::{
    MobileChatArchiveLookupRecord, MobileChatArchiveResultKind, MobileChatCheckpointRecord,
    MobileChatComposeBatchRecord, MobileChatDeliveryRecord, MobileChatMutationRecord,
    MobileChatState, transmission_peer,
};
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
    ChatComposeFailed,
    ChatBatchMissing,
}

impl fmt::Display for MobileMeshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPeer => "MESH_INVALID_PEER",
            Self::SessionUnavailable => "MESH_SESSION_UNAVAILABLE",
            Self::OperationInProgress => "MESH_OPERATION_IN_PROGRESS",
            Self::CounterPersistenceFailed => "MESH_COUNTER_PERSISTENCE_FAILED",
            Self::SendFailed => "MESH_SEND_FAILED",
            Self::ChatComposeFailed => "MESH_CHAT_COMPOSE_FAILED",
            Self::ChatBatchMissing => "MESH_CHAT_BATCH_MISSING",
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
    /// Total radio links traversed by the response, when the wire metadata can
    /// determine it. A direct response is one hop.
    pub hop_count: Option<u8>,
    /// Authenticated intermediate-router hints, in source-to-destination order.
    /// The two endpoints are not included.
    pub route_hints: Vec<Vec<u8>>,
    /// Signal measurements for the final radio hop into this device.
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshSessionUpdateRecord {
    /// Complete raw UMSH frames ready for the companion PHY transport.
    pub outbound_frames: Vec<Vec<u8>>,
    pub ping_events: Vec<MobileMeshPingEventRecord>,
    /// Chat effects remain in the facade until Swift durably applies them and
    /// acknowledges this batch. Repeated polls may return the same batch.
    pub chat_batch_id: Option<u64>,
    pub chat_mutations: Vec<MobileChatMutationRecord>,
    pub chat_deliveries: Vec<MobileChatDeliveryRecord>,
    pub chat_archive_lookups: Vec<MobileChatArchiveLookupRecord>,
    pub chat_diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshRxRecord {
    pub data: Vec<u8>,
    pub rssi_dbm: Option<i16>,
    pub lqi: Option<u8>,
    pub snr_cb: Option<i16>,
}

enum WorkerCommand {
    RegisterPeers {
        peers: Vec<PublicKey>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    Ping {
        operation_id: u64,
        peer: PublicKey,
        timeout_ms: u64,
    },
    RestoreChat {
        checkpoints: Vec<MobileChatCheckpointRecord>,
        response: oneshot::Sender<()>,
    },
    ComposeText {
        peer: PublicKey,
        client_token: u32,
        body: String,
        response: oneshot::Sender<Result<MobileChatComposeBatchRecord, MobileMeshError>>,
    },
    CommitChatBatch {
        batch_id: u64,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    RejectChatBatch {
        batch_id: u64,
        checkpoints: Vec<MobileChatCheckpointRecord>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    ChatArchiveResult {
        request_id: u32,
        kind: MobileChatArchiveResultKind,
        payload: Vec<u8>,
    },
    Receive(MobileMeshRxRecord),
    Shutdown,
}

struct InboundFrame {
    record: MobileMeshRxRecord,
}

struct InboundText {
    peer: PublicKey,
    payload: Vec<u8>,
    received_at_ms: Option<u64>,
}

struct InFlightChatTransmission {
    transmission_id: u32,
    ticket: SendProgressTicket,
    sent_reported: bool,
}

#[derive(Clone)]
enum MobileChatWorkerEvent {
    Mutation(MobileChatMutationRecord),
    Delivery(MobileChatDeliveryRecord),
    ArchiveLookup(MobileChatArchiveLookupRecord),
    Diagnostic(String),
}

struct PendingChatEventBatch {
    id: u64,
    events: Vec<MobileChatWorkerEvent>,
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
    chat_events: Mutex<std_mpsc::Receiver<MobileChatWorkerEvent>>,
    pending_chat_events: Mutex<Option<PendingChatEventBatch>>,
    next_chat_batch_id: Mutex<u64>,
    next_operation_id: Mutex<u64>,
}

#[uniffi::export]
impl MobileMeshSession {
    #[uniffi::constructor]
    pub async fn new(
        identity: Arc<MobileIdentity>,
        counter_store: Arc<MobileCounterStore>,
    ) -> Result<Arc<Self>, MobileMeshError> {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound) = std_mpsc::channel();
        let (event_tx, events) = std_mpsc::channel();
        let (chat_event_tx, chat_events) = std_mpsc::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
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
                        chat_event_tx,
                        ready_tx,
                    ),
                );
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;

        ready_rx
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)??;
        Ok(Arc::new(Self {
            commands,
            outbound: Mutex::new(outbound),
            events: Mutex::new(events),
            chat_events: Mutex::new(chat_events),
            pending_chat_events: Mutex::new(None),
            next_chat_batch_id: Mutex::new(1),
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

    pub async fn register_peers(&self, peer_addresses: Vec<String>) -> Result<(), MobileMeshError> {
        let peers = peer_addresses
            .iter()
            .map(|address| decode_peer(address).map_err(|_| MobileMeshError::InvalidPeer))
            .collect::<Result<Vec<_>, _>>()?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RegisterPeers { peers, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    pub fn receive(&self, frame: MobileMeshRxRecord) -> Result<(), MobileMeshError> {
        if frame.data.is_empty() || frame.data.len() > MAX_FRAME_SIZE {
            return Err(MobileMeshError::SessionUnavailable);
        }
        self.commands
            .send(WorkerCommand::Receive(frame))
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    pub async fn restore_chat(
        &self,
        checkpoints: Vec<MobileChatCheckpointRecord>,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RestoreChat {
                checkpoints,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    pub async fn compose_text(
        &self,
        peer_address: String,
        client_token: u32,
        body: String,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        let peer = decode_peer(&peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::ComposeText {
                peer,
                client_token,
                body,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    pub async fn commit_chat_batch(&self, batch_id: u64) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::CommitChatBatch { batch_id, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    pub async fn reject_chat_batch(
        &self,
        batch_id: u64,
        checkpoints: Vec<MobileChatCheckpointRecord>,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RejectChatBatch {
                batch_id,
                checkpoints,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    pub fn apply_chat_archive_result(
        &self,
        request_id: u32,
        kind: MobileChatArchiveResultKind,
        payload: Vec<u8>,
    ) -> Result<(), MobileMeshError> {
        self.commands
            .send(WorkerCommand::ChatArchiveResult {
                request_id,
                kind,
                payload,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    pub fn acknowledge_chat_batch(&self, batch_id: u64) -> Result<(), MobileMeshError> {
        let mut pending = self
            .pending_chat_events
            .lock()
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        if pending.as_ref().is_some_and(|batch| batch.id == batch_id) {
            *pending = None;
        }
        Ok(())
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
        let mut chat_mutations = Vec::new();
        let mut chat_deliveries = Vec::new();
        let mut chat_archive_lookups = Vec::new();
        let mut chat_diagnostics = Vec::new();
        let mut chat_batch_id = None;
        if let Ok(mut pending) = self.pending_chat_events.lock() {
            if pending.is_none()
                && let Ok(receiver) = self.chat_events.lock()
            {
                let events = receiver.try_iter().collect::<Vec<_>>();
                if !events.is_empty()
                    && let Ok(mut next) = self.next_chat_batch_id.lock()
                {
                    let id = *next;
                    *next = next.wrapping_add(1).max(1);
                    *pending = Some(PendingChatEventBatch { id, events });
                }
            }
            if let Some(batch) = pending.as_ref() {
                chat_batch_id = Some(batch.id);
                for event in batch.events.iter().cloned() {
                    match event {
                        MobileChatWorkerEvent::Mutation(record) => chat_mutations.push(record),
                        MobileChatWorkerEvent::Delivery(record) => chat_deliveries.push(record),
                        MobileChatWorkerEvent::ArchiveLookup(record) => {
                            chat_archive_lookups.push(record);
                        }
                        MobileChatWorkerEvent::Diagnostic(record) => chat_diagnostics.push(record),
                    }
                }
            }
        }
        MobileMeshSessionUpdateRecord {
            outbound_frames,
            ping_events,
            chat_batch_id,
            chat_mutations,
            chat_deliveries,
            chat_archive_lookups,
            chat_diagnostics,
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
    chat_events: std_mpsc::Sender<MobileChatWorkerEvent>,
    ready: oneshot::Sender<Result<(), MobileMeshError>>,
) {
    let local_key = *identity.public_key();
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
    let mut chat = MobileChatState::new(local_key);
    let inbound_text = Rc::new(RefCell::new(Vec::<InboundText>::new()));
    let inbound_text_callback = inbound_text.clone();
    let text_subscription = node.on_receive(move |packet| {
        if packet.payload_type() != PayloadType::TextMessage
            || packet.packet_family() != PacketFamily::Unicast
        {
            return false;
        }
        let Some(peer) = packet.from_key() else {
            return false;
        };
        inbound_text_callback.borrow_mut().push(InboundText {
            peer,
            payload: packet.payload().to_vec(),
            received_at_ms: packet.received_at_ms(),
        });
        true
    });
    let mut in_flight_chat = Vec::<InFlightChatTransmission>::new();
    let pending = Rc::new(RefCell::new(BTreeMap::<[u8; 32], u64>::new()));
    let pong_pending = pending.clone();
    let pong_events = events.clone();
    let pong_subscription = node.on_pong_with_metadata(move |peer, metadata| {
        if let Some(operation_id) = pong_pending.borrow_mut().remove(&peer.0) {
            let _ = pong_events.send(MobileMeshPingEventRecord {
                operation_id,
                outcome: MobileMeshPingOutcome::Reply,
                round_trip_milliseconds: Some(metadata.round_trip_ms),
                hop_count: metadata.hop_count,
                route_hints: metadata
                    .route_hints
                    .iter()
                    .map(|hint| hint.0.to_vec())
                    .collect(),
                rssi_dbm: metadata.rssi_dbm,
                snr_centibels: metadata.snr_centibels,
                lqi: metadata.lqi,
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
                hop_count: None,
                route_hints: Vec::new(),
                rssi_dbm: None,
                snr_centibels: None,
                lqi: None,
            });
        }
    });
    let _subscriptions = (pong_subscription, timeout_subscription, text_subscription);
    let _ = ready.send(Ok(()));
    let mut protocol_timeout_tick = tokio::time::interval(Duration::from_millis(50));
    protocol_timeout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                match command {
                    Some(WorkerCommand::RegisterPeers { peers, response }) => {
                        let mut result = Ok(());
                        for peer in peers {
                            if node.peer(peer).await.is_err() {
                                result = Err(MobileMeshError::SendFailed);
                                break;
                            }
                        }
                        let _ = response.send(result);
                    }
                    Some(WorkerCommand::Ping { operation_id, peer, timeout_ms }) => {
                        if pending.borrow().contains_key(&peer.0) {
                            emit_ping_failure(&events, operation_id);
                            continue;
                        }
                        let result = match node.peer(peer).await {
                            Ok(connection) => connection
                                .ping(
                                    6,
                                    &SendOptions::default()
                                        .with_flood_hops(5)
                                        .with_trace_route(),
                                    timeout_ms,
                                )
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
                    Some(WorkerCommand::RestoreChat { checkpoints, response }) => {
                        chat.restore(&checkpoints, handle.now_ms().await);
                        let _ = response.send(());
                    }
                    Some(WorkerCommand::ComposeText {
                        peer,
                        client_token,
                        body,
                        response,
                    }) => {
                        // Rejecting a persisted batch rebuilds the reducer from
                        // durable checkpoints. Keep that recovery operation
                        // unambiguous by allowing only one uncommitted compose.
                        let result = if chat.pending_batches.is_empty() {
                            match chat.compose_text(
                                peer,
                                client_token,
                                &body,
                                handle.now_ms().await,
                            ) {
                                Ok(composed) => {
                                    for delivery in composed.deliveries {
                                        let _ = chat_events.send(
                                            MobileChatWorkerEvent::Delivery(delivery),
                                        );
                                    }
                                    for diagnostic in composed.diagnostics {
                                        let _ = chat_events.send(
                                            MobileChatWorkerEvent::Diagnostic(diagnostic),
                                        );
                                    }
                                    Ok(composed.record)
                                }
                                Err(()) => Err(MobileMeshError::ChatComposeFailed),
                            }
                        } else {
                            Err(MobileMeshError::OperationInProgress)
                        };
                        let _ = response.send(result);
                    }
                    Some(WorkerCommand::CommitChatBatch { batch_id, response }) => {
                        let result = match chat.pending_batches.remove(&batch_id) {
                            Some(batch) => {
                                let now_ms = handle.now_ms().await;
                                let sent = queue_chat_transmissions(
                                    &node,
                                    batch.transmissions,
                                    &mut in_flight_chat,
                                    &mut chat,
                                    now_ms,
                                )
                                .await;
                                publish_chat_drain(chat.drain(), &chat_events);
                                if sent > 0
                                    && handle.service_counter_persistence().await.is_err()
                                {
                                    Err(MobileMeshError::CounterPersistenceFailed)
                                } else {
                                    Ok(())
                                }
                            }
                            None => Err(MobileMeshError::ChatBatchMissing),
                        };
                        let fatal = result == Err(MobileMeshError::CounterPersistenceFailed);
                        let _ = response.send(result);
                        if fatal {
                            return;
                        }
                    }
                    Some(WorkerCommand::RejectChatBatch {
                        batch_id,
                        checkpoints,
                        response,
                    }) => {
                        let result = match chat.pending_batches.remove(&batch_id) {
                            Some(batch) => {
                                for transmission in batch.transmissions {
                                    chat.engine.transmit_update(
                                        transmission.transmission_id,
                                        DeliveryState::Failed,
                                        handle.now_ms().await,
                                    );
                                }
                                publish_chat_drain(chat.drain(), &chat_events);
                                chat = MobileChatState::new(local_key);
                                chat.restore(&checkpoints, handle.now_ms().await);
                                Ok(())
                            }
                            None => Err(MobileMeshError::ChatBatchMissing),
                        };
                        let _ = response.send(result);
                    }
                    Some(WorkerCommand::ChatArchiveResult {
                        request_id,
                        kind,
                        payload,
                    }) => {
                        let now_ms = handle.now_ms().await;
                        match kind {
                            MobileChatArchiveResultKind::Found => chat.engine.archive_result(
                                request_id,
                                ArchiveResult::Found { payload: &payload },
                                now_ms,
                            ),
                            MobileChatArchiveResultKind::Deleted => chat.engine.archive_result(
                                request_id,
                                ArchiveResult::Deleted,
                                now_ms,
                            ),
                            MobileChatArchiveResultKind::Evicted => chat.engine.archive_result(
                                request_id,
                                ArchiveResult::Evicted,
                                now_ms,
                            ),
                            MobileChatArchiveResultKind::Unknown => chat.engine.archive_result(
                                request_id,
                                ArchiveResult::Unknown,
                                now_ms,
                            ),
                        }
                        let drain = chat.drain();
                        let transmissions = drain.transmissions.clone();
                        publish_chat_drain(drain, &chat_events);
                        if !transmissions.is_empty() {
                            let sent = queue_chat_transmissions(
                                &node,
                                transmissions,
                                &mut in_flight_chat,
                                &mut chat,
                                now_ms,
                            )
                            .await;
                            publish_chat_drain(chat.drain(), &chat_events);
                            if sent > 0 && handle.service_counter_persistence().await.is_err() {
                                return;
                            }
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
                let received = inbound_text.borrow_mut().drain(..).collect::<Vec<_>>();
                for text in received {
                    let received_at_ms = match text.received_at_ms {
                        Some(value) => value,
                        None => handle.now_ms().await,
                    };
                    let envelope = Envelope {
                        path: DeliveryPath::Unicast,
                        conversation: ConversationKey::Direct { peer: text.peer },
                        sender: SenderScope::Peer(text.peer),
                    };
                    let _ = chat.engine.receive(
                        &envelope,
                        Some(text.peer),
                        &text.payload,
                        received_at_ms,
                    );
                    let drain = chat.drain();
                    let transmissions = drain.transmissions.clone();
                    publish_chat_drain(drain, &chat_events);
                    if !transmissions.is_empty() {
                        let sent = queue_chat_transmissions(
                            &node,
                            transmissions,
                            &mut in_flight_chat,
                            &mut chat,
                            received_at_ms,
                        )
                        .await;
                        publish_chat_drain(chat.drain(), &chat_events);
                        if sent > 0 && handle.service_counter_persistence().await.is_err() {
                            return;
                        }
                    }
                }
            }
            _ = protocol_timeout_tick.tick() => {
                host.service_protocol_timeouts().await;
                let now_ms = handle.now_ms().await;
                chat.engine.tick(now_ms);
                service_chat_tickets(&mut chat, &mut in_flight_chat, now_ms);
                let drain = chat.drain();
                let transmissions = drain.transmissions.clone();
                publish_chat_drain(drain, &chat_events);
                if !transmissions.is_empty() {
                    let sent = queue_chat_transmissions(
                        &node,
                        transmissions,
                        &mut in_flight_chat,
                        &mut chat,
                        now_ms,
                    )
                    .await;
                    publish_chat_drain(chat.drain(), &chat_events);
                    if sent > 0 && handle.service_counter_persistence().await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

async fn queue_chat_transmissions<M: MacBackend>(
    node: &LocalNode<M>,
    transmissions: Vec<umsh_text::engine::Transmission>,
    in_flight: &mut Vec<InFlightChatTransmission>,
    chat: &mut MobileChatState,
    now_ms: u64,
) -> usize {
    let mut queued = 0;
    for transmission in transmissions {
        let Some(peer) = transmission_peer(&transmission) else {
            chat.engine.transmit_update(
                transmission.transmission_id,
                DeliveryState::Failed,
                now_ms,
            );
            continue;
        };
        let mut payload = Vec::with_capacity(transmission.payload.len() + 1);
        payload.push(PayloadType::TextMessage as u8);
        payload.extend_from_slice(transmission.payload.as_slice());
        let Ok(connection) = node.peer(peer).await else {
            chat.engine.transmit_update(
                transmission.transmission_id,
                DeliveryState::Failed,
                now_ms,
            );
            continue;
        };
        let Ok(ticket) = connection
            .send(&payload, &SendOptions::default().with_ack_requested(true))
            .await
        else {
            chat.engine.transmit_update(
                transmission.transmission_id,
                DeliveryState::Failed,
                now_ms,
            );
            continue;
        };
        in_flight.push(InFlightChatTransmission {
            transmission_id: transmission.transmission_id,
            ticket,
            sent_reported: false,
        });
        queued += 1;
    }
    queued
}

fn service_chat_tickets(
    chat: &mut MobileChatState,
    in_flight: &mut Vec<InFlightChatTransmission>,
    now_ms: u64,
) {
    let mut index = 0;
    while index < in_flight.len() {
        let entry = &mut in_flight[index];
        if entry.ticket.was_transmitted() && !entry.sent_reported {
            chat.engine
                .transmit_update(entry.transmission_id, DeliveryState::Sent, now_ms);
            entry.sent_reported = true;
        }
        if entry.ticket.was_acked() {
            chat.engine
                .transmit_update(entry.transmission_id, DeliveryState::Acked, now_ms);
            in_flight.swap_remove(index);
        } else if entry.ticket.has_failed() {
            chat.engine
                .transmit_update(entry.transmission_id, DeliveryState::Failed, now_ms);
            in_flight.swap_remove(index);
        } else {
            index += 1;
        }
    }
}

fn publish_chat_drain(
    drain: crate::mobile_chat::ChatDrain,
    events: &std_mpsc::Sender<MobileChatWorkerEvent>,
) {
    for mutation in drain.mutations {
        let _ = events.send(MobileChatWorkerEvent::Mutation(mutation));
    }
    for delivery in drain.deliveries {
        let _ = events.send(MobileChatWorkerEvent::Delivery(delivery));
    }
    for lookup in drain.lookups {
        let _ = events.send(MobileChatWorkerEvent::ArchiveLookup(lookup));
    }
    for diagnostic in drain.diagnostics {
        let _ = events.send(MobileChatWorkerEvent::Diagnostic(diagnostic));
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
        hop_count: None,
        route_hints: Vec::new(),
        rssi_dbm: None,
        snr_centibels: None,
        lqi: None,
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

    #[tokio::test]
    async fn two_rust_sessions_complete_an_authenticated_ping() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(7);
        let bob_identity = identity(9);
        let alice_root = directory.path().join("alice");
        let bob_root = directory.path().join("bob");
        let alice_store = MobileCounterStore::new(alice_root.display().to_string()).unwrap();
        let bob_store = MobileCounterStore::new(bob_root.display().to_string()).unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();
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
                assert_eq!(event.hop_count, Some(1));
                assert!(event.route_hints.is_empty());
                assert_eq!(event.rssi_dbm, Some(-42));
                assert_eq!(event.snr_centibels, Some(90));
                assert_eq!(event.lqi, None);
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

    #[tokio::test]
    async fn silent_peer_completes_with_timeout_event() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(11);
        let silent_peer = identity(13);
        let store =
            MobileCounterStore::new(directory.path().join("local").display().to_string()).unwrap();
        let session = MobileMeshSession::new(local_identity, store).await.unwrap();
        let operation = session.ping(address(&silent_peer), 100).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);

        loop {
            let update = session.poll_update();
            if let Some(event) = update.ping_events.into_iter().next() {
                assert_eq!(event.operation_id, operation);
                assert_eq!(event.outcome, MobileMeshPingOutcome::TimedOut);
                assert_eq!(event.round_trip_milliseconds, None);
                assert_eq!(event.hop_count, None);
                assert!(event.route_hints.is_empty());
                assert_eq!(event.rssi_dbm, None);
                break;
            }
            assert!(Instant::now() < deadline, "silent ping never timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[tokio::test]
    async fn chat_checkpoint_batch_gates_transmission_and_delivers_owned_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(21);
        let bob_identity = identity(22);
        let alice_root = directory.path().join("chat-alice");
        let alice_store = MobileCounterStore::new(alice_root.display().to_string()).unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("chat-bob").display().to_string())
                .unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();
        let alice_address = address(&alice_identity);
        alice
            .register_peers(vec![address(&bob_identity)])
            .await
            .unwrap();
        bob.register_peers(vec![alice_address.clone()])
            .await
            .unwrap();

        let batch = alice
            .compose_text(address(&bob_identity), 77, "hello from Rust".to_owned())
            .await
            .unwrap();
        assert_eq!(batch.checkpoint.peer_address, address(&bob_identity));
        assert!(!batch.archives.is_empty());
        assert_eq!(batch.mutations.len(), 1);
        assert_eq!(batch.mutations[0].body.as_deref(), Some("hello from Rust"));
        assert_eq!(batch.mutations[0].fragment_count, Some(1));
        assert_eq!(
            alice
                .compose_text(address(&bob_identity), 78, "second".to_owned())
                .await,
            Err(MobileMeshError::OperationInProgress)
        );
        assert!(alice.poll_update().outbound_frames.is_empty());
        assert!(
            !alice_root.exists(),
            "compose alone must not touch counters"
        );

        alice.commit_chat_batch(batch.batch_id).await.unwrap();
        assert!(alice_root.exists());

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                bob.receive(MobileMeshRxRecord {
                    data: frame,
                    rssi_dbm: Some(-55),
                    lqi: Some(200),
                    snr_cb: Some(70),
                })
                .unwrap();
            }
            let bob_update = bob.poll_update();
            if let Some(mutation) = bob_update.chat_mutations.first() {
                assert_eq!(mutation.body.as_deref(), Some("hello from Rust"));
                assert_eq!(
                    mutation.sender_address.as_deref(),
                    Some(alice_address.as_str())
                );
                assert_eq!(
                    mutation.direction,
                    Some(crate::MobileChatDirection::Inbound)
                );
                let batch_id = bob_update.chat_batch_id.expect("owned chat batch");
                assert_eq!(
                    bob.poll_update().chat_batch_id,
                    Some(batch_id),
                    "unacknowledged chat effects must be replayed"
                );
                bob.acknowledge_chat_batch(batch_id).unwrap();
                assert!(bob.poll_update().chat_mutations.is_empty());
                break;
            }
            assert!(Instant::now() < deadline, "chat frame did not arrive");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
