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
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc as std_mpsc,
    },
    time::Duration,
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
use umsh_node::{
    Host, LocalNode, MacBackend, NodeCapabilities, NodeIdentityPayload, NodeRole, PacketFamily,
    SendProgressTicket, Transport,
};
use umsh_sync::AsyncRefCell;
use umsh_text::engine::{ArchiveResult, DeliveryState};
use umsh_text::model::{ConversationKey, SenderScope};
use umsh_text::validate::{DeliveryPath, Envelope};

use crate::mobile_chat::{
    MobileChatArchiveLookupRecord, MobileChatArchiveResultKind, MobileChatCheckpointRecord,
    MobileChatComposeBatchRecord, MobileChatDeliveryRecord, MobileChatMutationRecord,
    MobileChatOriginalRef, MobileChatState, transmission_peer,
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

/// A node-identity advertisement received over the mesh. Only frames whose
/// source address carried the full public key are surfaced; the platform
/// verifies the embedded signature before trusting or persisting any claim.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshAdvertisementRecord {
    /// Canonical Base58 address of the claimed sender.
    pub peer_address: String,
    /// Raw node-identity payload bytes (without the payload-type byte),
    /// decodable with `decode_node_identity`.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshSessionUpdateRecord {
    /// Complete raw UMSH frames ready for the companion PHY transport. Each
    /// frame must be completed after the companion reports the physical radio
    /// result; queue acceptance is not transmit completion.
    pub outbound_frames: Vec<MobileMeshOutboundFrameRecord>,
    pub ping_events: Vec<MobileMeshPingEventRecord>,
    pub advertisement_events: Vec<MobileMeshAdvertisementRecord>,
    /// Chat effects remain in the facade until Swift durably applies them and
    /// acknowledges this batch. Repeated polls may return the same batch.
    pub chat_batch_id: Option<u64>,
    pub chat_mutations: Vec<MobileChatMutationRecord>,
    pub chat_deliveries: Vec<MobileChatDeliveryRecord>,
    pub chat_archive_lookups: Vec<MobileChatArchiveLookupRecord>,
    pub chat_diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshOutboundFrameRecord {
    pub id: u64,
    pub data: Vec<u8>,
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
    ComposeChat {
        peer: PublicKey,
        client_token: u32,
        request: ChatComposeRequest,
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
    Advertise {
        name: Option<String>,
        timestamp: Option<u32>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    SignIdentityBundle {
        name: Option<String>,
        timestamp: Option<u32>,
        response: oneshot::Sender<Result<Vec<u8>, MobileMeshError>>,
    },
    FailOutboundTransmissions,
    Receive(MobileMeshRxRecord),
    Shutdown,
}

enum ChatComposeRequest {
    Text {
        body: String,
    },
    Edit {
        original: MobileChatOriginalRef,
        body: String,
    },
    Delete {
        original: MobileChatOriginalRef,
    },
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
    peer: PublicKey,
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

struct BridgeTransmitCompletions {
    next_id: AtomicU64,
    failure_generation: AtomicU64,
    /// A link-wide failure was declared and its `FailOutboundTransmissions`
    /// command has not yet been processed by the worker. While set, no new
    /// transmission may reach the platform: the MAC's in-progress drain loop
    /// would otherwise keep dispatching the frames queued behind the one the
    /// failure caught mid-flight, because each later `transmit` call samples
    /// the generation only after the bump. The worker clears the flag when
    /// it processes the queued command and cancels the affected tickets.
    poisoned: AtomicBool,
    pending: Mutex<BTreeMap<u64, oneshot::Sender<bool>>>,
}

impl BridgeTransmitCompletions {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            failure_generation: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    fn generation(&self) -> u64 {
        self.failure_generation.load(Ordering::SeqCst)
    }

    fn allocate(
        &self,
        generation: u64,
        completion: oneshot::Sender<bool>,
    ) -> Result<Option<u64>, BridgeRadioError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
        let mut pending = self.pending.lock().map_err(|_| BridgeRadioError::Closed)?;
        if self.poisoned.load(Ordering::SeqCst)
            || generation != self.failure_generation.load(Ordering::SeqCst)
        {
            return Ok(None);
        }
        pending.insert(id, completion);
        Ok(Some(id))
    }

    /// Declare a link-wide failure: refuse new platform dispatches until the
    /// worker processes the corresponding cancellation command.
    fn poison(&self) {
        self.poisoned.store(true, Ordering::SeqCst);
        self.failure_generation.fetch_add(1, Ordering::SeqCst);
    }

    fn clear_poison(&self) {
        self.poisoned.store(false, Ordering::SeqCst);
    }

    fn complete(&self, id: u64, transmitted: bool) -> bool {
        self.pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&id))
            .is_some_and(|completion| completion.send(transmitted).is_ok())
    }

    fn fail_all(&self) {
        self.failure_generation.fetch_add(1, Ordering::SeqCst);
        let completions = self
            .pending
            .lock()
            .map(|mut pending| core::mem::take(&mut *pending))
            .unwrap_or_default();
        for completion in completions.into_values() {
            let _ = completion.send(false);
        }
    }
}

struct BridgeRadio {
    inbound: mpsc::UnboundedReceiver<InboundFrame>,
    outbound: std_mpsc::Sender<MobileMeshOutboundFrameRecord>,
    completions: Arc<BridgeTransmitCompletions>,
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
        let (completion_tx, completion_rx) = oneshot::channel();
        let generation = self.completions.generation();
        let Some(id) = self
            .completions
            .allocate(generation, completion_tx)
            .map_err(TxError::Io)?
        else {
            // A link-wide failure raced this send before it reached the
            // platform. Its queued cancellation owns the ticket outcome.
            return Ok(());
        };
        if self
            .outbound
            .send(MobileMeshOutboundFrameRecord {
                id,
                data: data.to_vec(),
            })
            .is_err()
        {
            let _ = self.completions.complete(id, false);
            return Err(TxError::Io(BridgeRadioError::Closed));
        }

        // Awaiting here is deliberate: Radio::transmit completes only after
        // the frame has actually left the companion PHY. Returning at
        // bridge-queue acceptance starts MAC ACK timers too early and causes
        // fragmented sends to retransmit frames that are still waiting in
        // the companion queue. This is an async wait, not a thread block, so
        // the worker keeps servicing commands and timers while the frame is
        // in flight; the MAC itself stays serialized behind its own borrow.
        match completion_rx.await {
            Ok(true) => Ok(()),
            // The public completion API poisons the bridge and queues
            // FailOutboundTransmissions before releasing this wait. Return
            // success here solely to keep an ordinary rejected frame from
            // terminating the long-lived MAC driver; the queued command
            // cancels its ACK ticket immediately.
            Ok(false) => Ok(()),
            Err(_) => Err(TxError::Io(BridgeRadioError::Closed)),
        }
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

/// MAC clock backed by tokio's time source. Using `tokio::time::Instant`
/// (rather than `std::time::Instant`) means a runtime started with paused
/// time drives this clock too, so every MAC deadline can be fast-forwarded
/// deterministically in tests.
#[derive(Clone)]
struct MobileClock {
    origin: tokio::time::Instant,
    sleep: Rc<RefCell<Option<Pin<Box<tokio::time::Sleep>>>>>,
}

impl MobileClock {
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            sleep: Rc::new(RefCell::new(None)),
        }
    }
}

impl Clock for MobileClock {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn poll_delay_until(&self, cx: &mut Context<'_>, deadline_ms: u64) -> Poll<()> {
        let deadline = self.origin + Duration::from_millis(deadline_ms);
        if tokio::time::Instant::now() >= deadline {
            return Poll::Ready(());
        }
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
const MOBILE_CHAT_TRANSMIT_WINDOW: usize = 8;

/// Long-lived Rust protocol engine used by the mobile app.
///
/// `ping` is the only ping operation exposed to Swift. The existing Rust node
/// layer owns its nonce, authenticated echo request, counter reservation,
/// response matching, and timeout.
#[derive(uniffi::Object)]
pub struct MobileMeshSession {
    commands: mpsc::UnboundedSender<WorkerCommand>,
    outbound: Mutex<std_mpsc::Receiver<MobileMeshOutboundFrameRecord>>,
    transmit_completions: Arc<BridgeTransmitCompletions>,
    events: Mutex<std_mpsc::Receiver<MobileMeshPingEventRecord>>,
    advertisements: Mutex<std_mpsc::Receiver<MobileMeshAdvertisementRecord>>,
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
        Self::build(identity, counter_store, false).await
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

    /// Broadcast a signed node-identity advertisement describing this phone.
    ///
    /// The bundle always carries the standalone EdDSA signature because a
    /// broadcast frame has no MIC to authenticate it.
    pub async fn advertise_identity(
        &self,
        name: Option<String>,
        timestamp: Option<u32>,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::Advertise {
                name,
                timestamp,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Build and sign this phone's node-identity bundle without transmitting
    /// it, for embedding in the shareable `umsh:n:` URI and QR code.
    pub async fn sign_identity_bundle(
        &self,
        name: Option<String>,
        timestamp: Option<u32>,
    ) -> Result<Vec<u8>, MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::SignIdentityBundle {
                name,
                timestamp,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
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

    /// Report the actual physical companion-radio result for an outbound
    /// frame. This is intentionally distinct from accepting the frame into the
    /// BLE/CRP queue: the MAC starts ACK and retry timing only after success.
    pub fn complete_outbound_frame(
        &self,
        frame_id: u64,
        transmitted: bool,
    ) -> Result<(), MobileMeshError> {
        if !transmitted {
            // A rejected frame fails the whole outbound batch. Poison before
            // releasing this frame's wait so the MAC drain cannot dispatch
            // the frames queued behind it (see fail_outbound_transmissions).
            self.transmit_completions.poison();
            self.commands
                .send(WorkerCommand::FailOutboundTransmissions)
                .map_err(|_| MobileMeshError::SessionUnavailable)?;
        }
        self.transmit_completions
            .complete(frame_id, transmitted)
            .then_some(())
            .ok_or(MobileMeshError::SessionUnavailable)
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
        self.compose_chat(&peer_address, client_token, ChatComposeRequest::Text { body })
            .await
    }

    /// Compose an edit of a previously sent message. The original may come
    /// from an earlier app launch: its persisted `(wire_id, epoch)` is used
    /// when the facade session no longer holds a live handle, and the engine
    /// rejects it (`ChatComposeFailed`) if stream continuity was lost since.
    pub async fn compose_edit(
        &self,
        peer_address: String,
        client_token: u32,
        original: MobileChatOriginalRef,
        body: String,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        self.compose_chat(
            &peer_address,
            client_token,
            ChatComposeRequest::Edit { original, body },
        )
        .await
    }

    /// Compose a deletion (empty edit on the wire) of a previously sent
    /// message. Same original-reference rules as [`Self::compose_edit`].
    pub async fn compose_delete(
        &self,
        peer_address: String,
        client_token: u32,
        original: MobileChatOriginalRef,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        self.compose_chat(
            &peer_address,
            client_token,
            ChatComposeRequest::Delete { original },
        )
        .await
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

    /// Fail every chat transmission currently owned by the mobile radio
    /// bridge. The platform calls this when companion-link delivery failed
    /// after the MAC had accepted the frames, ensuring optimistic UI rows do
    /// not remain in `Sending` indefinitely.
    pub fn fail_outbound_transmissions(&self) -> Result<(), MobileMeshError> {
        // Poison before anything else: from this instant until the worker
        // processes the command below (the sole clearer), every frame the
        // MAC's in-progress drain loop tries to hand to the platform is
        // suppressed instead of dispatched. Without this, releasing the
        // blocked transmit lets the drain advance to the next queued frame,
        // which samples the post-bump generation and goes out as if healthy.
        self.transmit_completions.poison();
        self.commands
            .send(WorkerCommand::FailOutboundTransmissions)
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        // Release a transmit wait already in progress; the drain it unblocks
        // is defused by the poison above.
        self.transmit_completions.fail_all();
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
        let mut advertisement_events = Vec::new();
        if let Ok(receiver) = self.advertisements.lock() {
            advertisement_events.extend(receiver.try_iter());
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
            advertisement_events,
            chat_batch_id,
            chat_mutations,
            chat_deliveries,
            chat_archive_lookups,
            chat_diagnostics,
        }
    }
}

impl MobileMeshSession {
    async fn compose_chat(
        &self,
        peer_address: &str,
        client_token: u32,
        request: ChatComposeRequest,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        let peer = decode_peer(peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::ComposeChat {
                peer,
                client_token,
                request,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Construct a session whose worker runtime starts with tokio's clock
    /// paused (test builds only). Timers auto-advance whenever the worker is
    /// otherwise idle, so multi-second protocol deadlines — MAC ACK
    /// timeouts, ping timeouts, repair timers — resolve in wall-clock
    /// milliseconds without changing any production code path.
    #[cfg(test)]
    async fn new_with_virtual_time(
        identity: Arc<MobileIdentity>,
        counter_store: Arc<MobileCounterStore>,
    ) -> Result<Arc<Self>, MobileMeshError> {
        Self::build(identity, counter_store, true).await
    }

    async fn build(
        identity: Arc<MobileIdentity>,
        counter_store: Arc<MobileCounterStore>,
        virtual_time: bool,
    ) -> Result<Arc<Self>, MobileMeshError> {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound) = std_mpsc::channel();
        let (event_tx, events) = std_mpsc::channel();
        let (advertisement_tx, advertisements) = std_mpsc::channel();
        let (chat_event_tx, chat_events) = std_mpsc::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker_identity = identity.take_for_session()?;
        let transmit_completions = Arc::new(BridgeTransmitCompletions::new());
        let worker_transmit_completions = transmit_completions.clone();

        std::thread::Builder::new()
            .name("umsh-mobile-mesh".to_owned())
            .spawn(move || {
                let mut builder = tokio::runtime::Builder::new_current_thread();
                builder.enable_time();
                #[cfg(test)]
                if virtual_time {
                    builder.start_paused(true);
                }
                #[cfg(not(test))]
                let _ = virtual_time;
                let runtime = match builder.build() {
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
                        worker_transmit_completions,
                        event_tx,
                        advertisement_tx,
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
            transmit_completions,
            events: Mutex::new(events),
            advertisements: Mutex::new(advertisements),
            chat_events: Mutex::new(chat_events),
            pending_chat_events: Mutex::new(None),
            next_chat_batch_id: Mutex::new(1),
            next_operation_id: Mutex::new(1),
        }))
    }
}

impl Drop for MobileMeshSession {
    fn drop(&mut self) {
        self.transmit_completions.fail_all();
        let _ = self.commands.send(WorkerCommand::Shutdown);
    }
}

/// Build the signed standalone node-identity bundle for this phone: role
/// Chat, capabilities Mobile + Text messages, optional display name
/// (truncated to the 24-byte wire limit on a character boundary). The
/// result is ROLE through the trailing 64-byte signature, without the
/// payload-type byte.
async fn build_signed_identity_bundle(
    signer: &SoftwareIdentity,
    name: Option<&str>,
    timestamp: Option<u32>,
) -> Result<Vec<u8>, MobileMeshError> {
    let name = name
        .map(|name| {
            let mut end = name.len().min(24);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            name[..end].to_owned()
        })
        .filter(|name| !name.is_empty());
    let payload = NodeIdentityPayload {
        role: NodeRole::Chat,
        capabilities: NodeCapabilities::MOBILE | NodeCapabilities::TEXT_MESSAGES,
        name,
        location: None,
        altitude_m: None,
        timestamp,
        supported_regions: None,
        nonce: None,
        signature: None,
    };
    let mut buf = [0u8; 192];
    let len = payload
        .encode_for_signing(&mut buf)
        .map_err(|_| MobileMeshError::SendFailed)?;
    let signature = signer
        .sign(&buf[..len])
        .await
        .map_err(|_| MobileMeshError::SendFailed)?;
    let mut bundle = buf[..len].to_vec();
    bundle.extend_from_slice(&signature);
    Ok(bundle)
}

async fn run_worker(
    identity: SoftwareIdentity,
    counter_store: SharedCounterStore,
    mut commands: mpsc::UnboundedReceiver<WorkerCommand>,
    outbound: std_mpsc::Sender<MobileMeshOutboundFrameRecord>,
    transmit_completions: Arc<BridgeTransmitCompletions>,
    events: std_mpsc::Sender<MobileMeshPingEventRecord>,
    advertisements: std_mpsc::Sender<MobileMeshAdvertisementRecord>,
    chat_events: std_mpsc::Sender<MobileChatWorkerEvent>,
    ready: oneshot::Sender<Result<(), MobileMeshError>>,
) {
    let local_key = *identity.public_key();
    // The MAC takes ownership of the identity below; standalone bundle
    // signing (advertisements, QR bundles) uses this retained clone.
    let signer = identity.clone();
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let worker_completions = transmit_completions.clone();
    let radio = BridgeRadio {
        inbound: inbound_rx,
        outbound,
        completions: transmit_completions,
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
    let advertisement_events = advertisements.clone();
    let advertisement_subscription = node.on_receive(move |packet| {
        if packet.payload_type() != PayloadType::NodeIdentity {
            return false;
        }
        // Hint-only sources cannot name a key to verify the bundle's
        // signature against, so they are not surfaced at all.
        let Some(peer) = packet.from_key() else {
            return false;
        };
        let peer_address: String = umsh_core::base58::encode(&peer.0)
            .into_iter()
            .map(char::from)
            .collect();
        let _ = advertisement_events.send(MobileMeshAdvertisementRecord {
            peer_address,
            payload: packet.payload().to_vec(),
        });
        true
    });
    let mut in_flight_chat = Vec::<InFlightChatTransmission>::new();
    let mut chat_pipeline_ready = BTreeSet::<[u8; 32]>::new();
    let mut pending_chat_transmissions = VecDeque::<umsh_text::engine::Transmission>::new();
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
    let _subscriptions = (
        pong_subscription,
        timeout_subscription,
        text_subscription,
        advertisement_subscription,
    );
    let _ = ready.send(Ok(()));
    let mut protocol_timeout_tick = tokio::time::interval(Duration::from_millis(50));
    protocol_timeout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The worker runs as two sibling loops polled by one outer select.
    //
    // `Radio::transmit` awaits the companion's physical TX completion while
    // `MacHandle` holds the coordinator borrow, so the pump must keep being
    // polled while a command arm waits on that borrow — a single select
    // whose arm bodies suspend the task would deadlock: the arm waits on
    // the borrow, and the pump future that owns it is never re-polled to
    // release it. As sibling futures of the outer select, the pump makes
    // progress whenever the command loop is waiting.
    let inbound_ready = tokio::sync::Notify::new();
    let timeout_servicer = host.protocol_timeout_servicer();

    let pump_loop = async {
        loop {
            if host.pump_once().await.is_err() {
                return;
            }
            if !inbound_text.borrow().is_empty() {
                inbound_ready.notify_one();
            }
        }
    };

    let command_loop = async {
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
                        Some(WorkerCommand::Advertise { name, timestamp, response }) => {
                            let result = match build_signed_identity_bundle(
                                &signer,
                                name.as_deref(),
                                timestamp,
                            )
                            .await
                            {
                                Ok(bundle) => {
                                    let mut frame = Vec::with_capacity(bundle.len() + 1);
                                    frame.push(PayloadType::NodeIdentity as u8);
                                    frame.extend_from_slice(&bundle);
                                    node.send_all(
                                        &frame,
                                        &SendOptions::default().with_full_source(),
                                    )
                                    .await
                                    .map(|_| ())
                                    .map_err(|_| MobileMeshError::SendFailed)
                                }
                                Err(error) => Err(error),
                            };
                            if result.is_ok()
                                && handle.service_counter_persistence().await.is_err()
                            {
                                let _ = response.send(Err(MobileMeshError::SendFailed));
                                return;
                            }
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::SignIdentityBundle { name, timestamp, response }) => {
                            let result = build_signed_identity_bundle(
                                &signer,
                                name.as_deref(),
                                timestamp,
                            )
                            .await;
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::RestoreChat { checkpoints, response }) => {
                            chat.restore(&checkpoints, handle.now_ms().await);
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::ComposeChat {
                            peer,
                            client_token,
                            request,
                            response,
                        }) => {
                            // Rejecting a persisted batch rebuilds the reducer from
                            // durable checkpoints. Keep that recovery operation
                            // unambiguous by allowing only one uncommitted compose.
                            let result = if chat.pending_batches.is_empty() {
                                let now_ms = handle.now_ms().await;
                                let composed = match &request {
                                    ChatComposeRequest::Text { body } => {
                                        chat.compose_text(peer, client_token, body, now_ms)
                                    }
                                    ChatComposeRequest::Edit { original, body } => chat
                                        .compose_edit(peer, client_token, original, body, now_ms),
                                    ChatComposeRequest::Delete { original } => {
                                        chat.compose_delete(peer, client_token, original, now_ms)
                                    }
                                };
                                match composed {
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
                                        &mut pending_chat_transmissions,
                                        &mut in_flight_chat,
                                        &chat_pipeline_ready,
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
                            if !transmissions.is_empty() || !pending_chat_transmissions.is_empty() {
                                let sent = queue_chat_transmissions(
                                    &node,
                                    transmissions,
                                    &mut pending_chat_transmissions,
                                    &mut in_flight_chat,
                                    &chat_pipeline_ready,
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
                        Some(WorkerCommand::FailOutboundTransmissions) => {
                            let now_ms = handle.now_ms().await;
                            for transmission in pending_chat_transmissions.drain(..) {
                                chat.engine.transmit_update(
                                    transmission.transmission_id,
                                    DeliveryState::Failed,
                                    now_ms,
                                );
                            }
                            for transmission in in_flight_chat.drain(..) {
                                if let Some(receipt) = transmission.ticket.receipt() {
                                    let _ = handle.cancel_pending_ack(identity_id, receipt).await;
                                }
                                chat.engine.transmit_update(
                                    transmission.transmission_id,
                                    DeliveryState::Failed,
                                    now_ms,
                                );
                            }
                            publish_chat_drain(chat.drain(), &chat_events);
                            // Every frame the failure covered is now cancelled;
                            // new transmissions may reach the platform again.
                            worker_completions.clear_poison();
                        }
                        Some(WorkerCommand::Receive(record)) => {
                            let _ = inbound_tx.send(InboundFrame { record });
                        }
                        Some(WorkerCommand::Shutdown) | None => return,
                    }
                }
                _ = inbound_ready.notified() => {
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
                        if !transmissions.is_empty() || !pending_chat_transmissions.is_empty() {
                            let sent = queue_chat_transmissions(
                                &node,
                                transmissions,
                                &mut pending_chat_transmissions,
                                &mut in_flight_chat,
                                &chat_pipeline_ready,
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
                    timeout_servicer.service().await;
                    let now_ms = handle.now_ms().await;
                    chat.engine.tick(now_ms);
                    service_chat_tickets(
                        &mut chat,
                        &mut in_flight_chat,
                        &mut chat_pipeline_ready,
                        now_ms,
                    );
                    let drain = chat.drain();
                    let transmissions = drain.transmissions.clone();
                    publish_chat_drain(drain, &chat_events);
                    if !transmissions.is_empty() || !pending_chat_transmissions.is_empty() {
                        let sent = queue_chat_transmissions(
                            &node,
                            transmissions,
                            &mut pending_chat_transmissions,
                            &mut in_flight_chat,
                            &chat_pipeline_ready,
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
    };

    // Either loop ending (pump error, shutdown command, fatal persistence
    // failure) ends the session.
    tokio::select! {
        _ = pump_loop => {}
        _ = command_loop => {}
    }
}

async fn queue_chat_transmissions<M: MacBackend>(
    node: &LocalNode<M>,
    transmissions: Vec<umsh_text::engine::Transmission>,
    pending: &mut VecDeque<umsh_text::engine::Transmission>,
    in_flight: &mut Vec<InFlightChatTransmission>,
    pipeline_ready: &BTreeSet<[u8; 32]>,
    chat: &mut MobileChatState,
    now_ms: u64,
) -> usize {
    pending.extend(transmissions);
    // Keep a bounded pipeline aligned with the companion NCP's target-selected
    // TX queue. The durable pending queue below handles messages larger than
    // this window without imposing the mobile RAM choice on embedded MACs.
    if in_flight.len() >= MOBILE_CHAT_TRANSMIT_WINDOW {
        return 0;
    }
    let mut queued = 0;
    while let Some(transmission) = pending.pop_front() {
        let Some(peer) = transmission_peer(&transmission) else {
            chat.engine.transmit_update(
                transmission.transmission_id,
                DeliveryState::Failed,
                now_ms,
            );
            continue;
        };
        if !pipeline_ready.contains(&peer.0) && in_flight.iter().any(|entry| entry.peer == peer) {
            // First contact may require counter synchronization. Confirm one
            // authenticated frame before opening this peer's full pipeline.
            pending.push_front(transmission);
            break;
        }
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
        let ticket = match connection
            .send(&payload, &SendOptions::default().with_ack_requested(true))
            .await
        {
            Ok(ticket) => ticket,
            Err(_) => {
                // With a registered peer and an engine-bounded payload, the
                // expected failure here is temporary MAC queue / pending-ACK
                // capacity. Preserve ordering and retry after tickets advance.
                pending.push_front(transmission);
                break;
            }
        };
        in_flight.push(InFlightChatTransmission {
            transmission_id: transmission.transmission_id,
            peer,
            ticket,
            sent_reported: false,
        });
        queued += 1;
        if in_flight.len() >= MOBILE_CHAT_TRANSMIT_WINDOW {
            break;
        }
    }
    queued
}

fn service_chat_tickets(
    chat: &mut MobileChatState,
    in_flight: &mut Vec<InFlightChatTransmission>,
    pipeline_ready: &mut BTreeSet<[u8; 32]>,
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
            pipeline_ready.insert(entry.peer.0);
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
    use crate::MobileChatDeliveryState;
    use std::time::Instant;
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
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                assert!(
                    alice_root.exists(),
                    "Alice released a frame before persisting its reservation"
                );
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
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
                bob.complete_outbound_frame(frame.id, true).unwrap();
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
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
    async fn broadcast_advertisement_reaches_peer_with_valid_signature() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(21);
        let bob_identity = identity(23);
        let alice_store =
            MobileCounterStore::new(directory.path().join("alice").display().to_string()).unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("bob").display().to_string()).unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity, bob_store).await.unwrap();

        // The signed bundle used for QR/URI sharing verifies out of band.
        let bundle = alice
            .sign_identity_bundle(Some("Alice's Phone".to_owned()), Some(1_760_000_000))
            .await
            .unwrap();
        let record =
            crate::decode_node_identity(address(&alice_identity), bundle.clone()).unwrap();
        assert_eq!(record.signature, crate::IdentitySignatureState::Valid);
        assert_eq!(record.name.as_deref(), Some("Alice's Phone"));
        assert_eq!(record.role_label, "Chat");
        let uri = crate::node_uri_with_identity(address(&alice_identity), bundle).unwrap();
        assert!(crate::inspect_node_uri(uri).unwrap().identity_payload.is_some());

        alice
            .advertise_identity(Some("Alice's Phone".to_owned()), None)
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            for frame in alice.poll_update().outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-50),
                    lqi: None,
                    snr_cb: None,
                })
                .unwrap();
            }
            let bob_update = bob.poll_update();
            if let Some(event) = bob_update.advertisement_events.into_iter().next() {
                assert_eq!(event.peer_address, address(&alice_identity));
                let received =
                    crate::decode_node_identity(event.peer_address, event.payload).unwrap();
                assert_eq!(received.signature, crate::IdentitySignatureState::Valid);
                assert_eq!(received.name.as_deref(), Some("Alice's Phone"));
                break;
            }
            assert!(Instant::now() < deadline, "advertisement not received");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The virtual-time seam: with the worker runtime's clock paused, a
    /// 30-second protocol timeout resolves in wall-clock milliseconds. This
    /// is the harness for exercising MAC ACK timeouts, repair timers, and
    /// retry cadences deterministically without real sleeps.
    #[tokio::test]
    async fn virtual_time_fast_forwards_protocol_timeouts() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(61);
        let silent_peer = identity(62);
        let store = MobileCounterStore::new(directory.path().join("virtual").display().to_string())
            .unwrap();
        let session = MobileMeshSession::new_with_virtual_time(local_identity, store)
            .await
            .unwrap();
        let started = Instant::now();
        let operation = session.ping(address(&silent_peer), 30_000).unwrap();

        let deadline = started + Duration::from_secs(5);
        loop {
            let update = session.poll_update();
            for frame in update.outbound_frames {
                session.complete_outbound_frame(frame.id, true).unwrap();
            }
            if let Some(event) = update.ping_events.into_iter().next() {
                assert_eq!(event.operation_id, operation);
                assert_eq!(event.outcome, MobileMeshPingOutcome::TimedOut);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "virtual-time ping timeout never fired"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a 30s virtual timeout must not take real-time seconds"
        );
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
            for frame in update.outbound_frames {
                session.complete_outbound_frame(frame.id, true).unwrap();
            }
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

        // First-contact counter synchronization plus the acknowledged fragment
        // pipeline can cross several scheduler ticks under loaded CI.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-55),
                    lqi: Some(200),
                    snr_cb: Some(70),
                })
                .unwrap();
            }
            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames.iter().cloned() {
                bob.complete_outbound_frame(frame.id, true).unwrap();
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-55),
                        lqi: Some(200),
                        snr_cb: Some(70),
                    })
                    .unwrap();
            }
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

    #[tokio::test]
    async fn fragmented_chat_message_crosses_mobile_radio_bridge() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(31);
        let bob_identity = identity(32);
        let alice_store =
            MobileCounterStore::new(directory.path().join("long-alice").display().to_string())
                .unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("long-bob").display().to_string())
                .unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();
        let alice_address = address(&alice_identity);
        let bob_address = address(&bob_identity);
        alice
            .register_peers(vec![bob_address.clone()])
            .await
            .unwrap();
        bob.register_peers(vec![alice_address.clone()])
            .await
            .unwrap();

        let body = "fragmented mobile message ".repeat(16);
        let batch = alice
            .compose_text(bob_address, 91, body.clone())
            .await
            .unwrap();
        let fragment_count = usize::from(batch.mutations[0].fragment_count.unwrap_or(1));
        assert!(fragment_count > 1);
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        // First-contact counter synchronization plus the acknowledged fragment
        // pipeline can cross several scheduler ticks under loaded CI.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut outbound_lengths = Vec::new();
        let mut return_lengths = Vec::new();
        let mut receiver_complete = false;
        let mut sender_delivered = false;
        loop {
            let alice_update = alice.poll_update();
            let alice_frames = alice_update.outbound_frames;
            assert!(
                alice_frames.len() <= 1,
                "the mobile bridge must wait for physical TX completion"
            );
            for frame in alice_frames {
                outbound_lengths.push(frame.data.len());
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-55),
                    lqi: Some(200),
                    snr_cb: Some(70),
                })
                .unwrap();
            }
            sender_delivered |= alice_update
                .chat_deliveries
                .iter()
                .any(|delivery| delivery.state == MobileChatDeliveryState::Acknowledged);
            if let Some(batch_id) = alice_update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }
            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames.iter().cloned() {
                return_lengths.push(frame.data.len());
                bob.complete_outbound_frame(frame.id, true).unwrap();
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-55),
                        lqi: Some(200),
                        snr_cb: Some(70),
                    })
                    .unwrap();
            }
            if let Some(mutation) = bob_update
                .chat_mutations
                .iter()
                .find(|mutation| mutation.complete == Some(true))
            {
                assert_eq!(mutation.body.as_deref(), Some(body.as_str()));
                receiver_complete = true;
            }
            if let Some(batch_id) = bob_update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            if receiver_complete && sender_delivered {
                assert!(
                    outbound_lengths.len() <= fragment_count * 2 + 4,
                    "fragment delivery was unexpectedly amplified: {outbound_lengths:?}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fragmented chat did not complete at both endpoints; receiver_complete={receiver_complete}, sender_delivered={sender_delivered}, outbound lengths: {outbound_lengths:?}; return lengths: {return_lengths:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn companion_link_failure_terminates_pending_chat_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(41);
        let peer_identity = identity(42);
        let store =
            MobileCounterStore::new(directory.path().join("failed-send").display().to_string())
                .unwrap();
        let session = MobileMeshSession::new(local_identity, store).await.unwrap();
        session
            .register_peers(vec![address(&peer_identity)])
            .await
            .unwrap();
        let batch = session
            .compose_text(address(&peer_identity), 17, "will fail".into())
            .await
            .unwrap();
        session.commit_chat_batch(batch.batch_id).await.unwrap();
        session.fail_outbound_transmissions().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let update = session.poll_update();
            if update
                .chat_deliveries
                .iter()
                .any(|delivery| delivery.state == MobileChatDeliveryState::Failed)
            {
                break;
            }
            if let Some(batch_id) = update.chat_batch_id {
                session.acknowledge_chat_batch(batch_id).unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "companion failure did not terminate chat delivery"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A companion-link failure declared while one fragment awaits physical
    /// TX completion must also stop the fragments queued behind it in the
    /// MAC: without the poisoned window, the drain loop keeps handing them
    /// to the platform after `fail_all` bumps the generation, so a single
    /// BLE hiccup fans out into several wasted physical transmissions.
    #[tokio::test]
    async fn mid_batch_failure_suppresses_fragments_queued_behind_the_blocked_one() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(51);
        let bob_identity = identity(52);
        let alice_store =
            MobileCounterStore::new(directory.path().join("mid-alice").display().to_string())
                .unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("mid-bob").display().to_string())
                .unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();
        let bob_address = address(&bob_identity);
        alice
            .register_peers(vec![bob_address.clone()])
            .await
            .unwrap();
        bob.register_peers(vec![address(&alice_identity)])
            .await
            .unwrap();

        // Warmup: one acknowledged message opens the fragment pipeline, so a
        // later multi-fragment commit enqueues every fragment into the MAC.
        let warmup = alice
            .compose_text(bob_address.clone(), 1, "warmup".to_owned())
            .await
            .unwrap();
        alice.commit_chat_batch(warmup.batch_id).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-50),
                    lqi: None,
                    snr_cb: Some(80),
                })
                .unwrap();
            }
            let acked = alice_update
                .chat_deliveries
                .iter()
                .any(|delivery| delivery.state == MobileChatDeliveryState::Acknowledged);
            if let Some(batch_id) = alice_update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }
            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames.iter().cloned() {
                bob.complete_outbound_frame(frame.id, true).unwrap();
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-50),
                        lqi: None,
                        snr_cb: Some(80),
                    })
                    .unwrap();
            }
            if let Some(batch_id) = bob_update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            if acked {
                break;
            }
            assert!(Instant::now() < deadline, "warmup exchange never acked");
            std::thread::sleep(Duration::from_millis(5));
        }

        // Fragmented message: all fragments enter the MAC queue; the drain
        // blocks on the first fragment's physical completion.
        let body = "storm test payload ".repeat(24);
        let batch = alice
            .compose_text(bob_address, 2, body.clone())
            .await
            .unwrap();
        assert!(batch.mutations[0].fragment_count.unwrap_or(1) > 1);
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        // Wait for the first fragment to reach the platform (the worker is
        // now blocked awaiting its completion), then declare link failure
        // without completing it.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let update = alice.poll_update();
            if let Some(batch_id) = update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }
            if !update.outbound_frames.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "first fragment never reached the platform"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let fail_at = Instant::now();
        alice.fail_outbound_transmissions().unwrap();

        // The queued fragments behind the blocked one must not surface as
        // new platform transmissions, and every fragment must fail promptly
        // (the failure report must not wait out MAC listen/ack windows).
        let mut saw_failed = false;
        let quiet_deadline = fail_at + Duration::from_millis(1_000);
        while Instant::now() < quiet_deadline {
            let update = alice.poll_update();
            assert!(
                update.outbound_frames.is_empty(),
                "fragments queued behind a failed batch were still dispatched"
            );
            saw_failed |= update
                .chat_deliveries
                .iter()
                .any(|delivery| delivery.state == MobileChatDeliveryState::Failed);
            if let Some(batch_id) = update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(saw_failed, "batch failure never reported to the transcript");

        // Recovery: once the cancellation is processed, new sends flow again.
        let retry = alice
            .compose_text(address(&bob_identity), 3, "after failure".to_owned())
            .await
            .unwrap();
        alice.commit_chat_batch(retry.batch_id).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let update = alice.poll_update();
            if let Some(batch_id) = update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }
            if !update.outbound_frames.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "transmissions never resumed after failure recovery"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
