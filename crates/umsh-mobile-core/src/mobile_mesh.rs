//! Rust-owned mobile mesh session.
//!
//! The platform adapter moves complete raw frames between this object and a
//! ULCP transport. It never constructs MAC commands, advances counters,
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
use umsh_core::{ChannelKey, ChannelTag, NodeHint, PayloadType, PublicKey};
use umsh_crypto::{
    CryptoEngine, NodeIdentity,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, Snr, TxError, TxOptions};
use umsh_mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::{
    Host, LocalNode, MacBackend, NodeCapabilities, NodeIdentityPayload, NodeIdentityProfile,
    NodeRole, PacketFamily, SendProgressTicket, Transport,
};
use umsh_sync::AsyncRefCell;
use umsh_text::engine::{ArchiveResult, DeliveryState, Destination};
use umsh_text::model::{ConversationKey, SenderScope};
use umsh_text::validate::{DeliveryPath, Envelope};

use crate::mobile_chat::{
    ChannelRegistry, MobileChatArchiveLookupRecord, MobileChatArchiveResultKind,
    MobileChatCheckpointRecord, MobileChatComposeBatchRecord, MobileChatDeliveryRecord,
    MobileChatDirection, MobileChatMutationKind, MobileChatMutationRecord, MobileChatOriginalRef,
    MobileChatPresence, MobileChatRxMetadataRecord, MobileChatSenderResolutionRecord,
    MobileChatState,
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
    /// A channel key was not exactly 32 octets.
    InvalidChannelKey,
    /// The MAC's channel table is full.
    ChannelCapacity,
    /// The conversation address was malformed, or named a channel this
    /// session holds no key for.
    UnknownConversation,
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
            Self::InvalidChannelKey => "MESH_INVALID_CHANNEL_KEY",
            Self::ChannelCapacity => "MESH_CHANNEL_CAPACITY",
            Self::UnknownConversation => "MESH_UNKNOWN_CONVERSATION",
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

/// How the MAC will address the next frame sent to a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileMeshRouteKind {
    /// Nothing has been learned for this peer, so the next send falls back to
    /// the default delivery mode. Also reported for a peer the MAC does not
    /// have registered at all.
    Unknown,
    /// The peer answered without any intermediate router.
    Direct,
    /// An explicit source route, learned by reversing an inbound trace route.
    Source,
    /// Flood delivery with a learned hop budget.
    Flood,
}

/// The route the MAC currently has cached for one peer.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshRouteRecord {
    pub kind: MobileMeshRouteKind,
    /// Router hints in source-to-destination order. Populated for `Source`
    /// routes only; the two endpoints are not included.
    pub hints: Vec<Vec<u8>>,
    /// Hop budget carried by a `Flood` route.
    pub flood_hops: Option<u8>,
    /// Two-octet region codes learned with a `Flood` route.
    pub flood_regions: Vec<Vec<u8>>,
}

impl MobileMeshRouteRecord {
    fn unknown() -> Self {
        Self {
            kind: MobileMeshRouteKind::Unknown,
            hints: Vec::new(),
            flood_hops: None,
            flood_regions: Vec::new(),
        }
    }
}

impl From<Option<umsh_mac::CachedRoute>> for MobileMeshRouteRecord {
    fn from(route: Option<umsh_mac::CachedRoute>) -> Self {
        match route {
            None => Self::unknown(),
            Some(umsh_mac::CachedRoute::Direct) => Self {
                kind: MobileMeshRouteKind::Direct,
                ..Self::unknown()
            },
            Some(umsh_mac::CachedRoute::Source(hops)) => Self {
                kind: MobileMeshRouteKind::Source,
                hints: hops.iter().map(|hop| hop.0.to_vec()).collect(),
                ..Self::unknown()
            },
            Some(umsh_mac::CachedRoute::Flood { hops, regions }) => Self {
                kind: MobileMeshRouteKind::Flood,
                flood_hops: Some(hops),
                flood_regions: regions.iter().map(|region| region.to_vec()).collect(),
                ..Self::unknown()
            },
        }
    }
}

/// A node-identity bundle received over the mesh, either as a broadcast
/// advertisement or as the reply to an Identity Request.
///
/// Only frames whose sender the MAC could name are surfaced. How the claims
/// may be trusted depends on how they arrived, which is what
/// `source_authenticated` reports.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshAdvertisementRecord {
    /// Canonical Base58 address of the claimed sender.
    pub peer_address: String,
    /// Raw node-identity payload bytes (without the payload-type byte),
    /// decodable with `decode_node_identity`.
    pub payload: Vec<u8>,
    /// Whether the MAC authenticated the sender of the frame that carried
    /// this bundle.
    ///
    /// A unicast Identity Request reply is authenticated by its MIC, so it
    /// carries no detached signature and decodes as `Unsigned` — it is
    /// nonetheless trustworthy, and the platform must accept it. A broadcast
    /// advertisement has no MIC, so it is `false` and the platform must
    /// require a `Valid` embedded signature before trusting any claim.
    pub source_authenticated: bool,
}

/// Evidence that a peer was on the air, emitted for every accepted frame
/// regardless of what it carried.
///
/// A beacon is the case this exists for: it has no payload, so it produces no
/// advertisement, no message, and no ping reply, yet it is the cheapest
/// possible proof that a node is still reachable. Presence is not a claim
/// about content, so nothing here needs to be authenticated to be useful —
/// it says only that a frame naming this sender was accepted.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshPeerHeardRecord {
    /// Canonical Base58 address of the sender, when the frame named a full
    /// public key or the MAC could resolve one. `None` for a hint-only
    /// source, which the platform may still resolve against its own peer
    /// list — see `node_hint`.
    pub peer_address: Option<String>,
    /// The 3-byte source node hint, when the frame carried one. Hints are
    /// ambiguous by design: a platform matching one against saved peers must
    /// treat a multi-way match as no match at all.
    pub node_hint: Option<Vec<u8>>,
    /// Whether the MAC authenticated this frame's sender. A beacon is an
    /// unauthenticated broadcast, so this is usually `false`; it is reported
    /// so the platform can tell "a frame claiming to be from X" from "a frame
    /// proven to be from X".
    pub source_authenticated: bool,
}

/// Platform-side listener invoked when `poll_update` has new data waiting.
///
/// Called on the worker thread; implementations must only schedule a drain
/// on their own executor and return. Notifications are coalesced: at most
/// one call fires per pending-to-drained cycle, so a burst of protocol
/// activity costs one crossing, and the platform needs no polling cadence.
#[uniffi::export(with_foreign)]
pub trait MobileMeshWakeListener: Send + Sync {
    fn on_update_pending(&self);
}

/// Coalescing wake flag shared between the worker's producer channels and
/// `poll_update`. `notify` fires the listener only on the false-to-true
/// transition; `drained` re-arms it.
struct WakeSignal {
    pending: AtomicBool,
    listener: Mutex<Option<Arc<dyn MobileMeshWakeListener>>>,
}

impl WakeSignal {
    fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            listener: Mutex::new(None),
        }
    }

    fn notify(&self) {
        if self.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let listener = self
            .listener
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned());
        if let Some(listener) = listener {
            listener.on_update_pending();
        }
    }

    fn drained(&self) {
        self.pending.store(false, Ordering::Release);
    }

    fn set_listener(&self, listener: Option<Arc<dyn MobileMeshWakeListener>>) {
        let already_pending = {
            let Ok(mut slot) = self.listener.lock() else {
                return;
            };
            *slot = listener.clone();
            self.pending.load(Ordering::Acquire)
        };
        // Data enqueued before registration must not wait for the next
        // protocol event to surface.
        if already_pending && let Some(listener) = listener {
            listener.on_update_pending();
        }
    }
}

/// A producer channel endpoint that arms the wake signal on every enqueue.
struct NotifyingSender<T> {
    tx: std_mpsc::Sender<T>,
    wake: Arc<WakeSignal>,
}

impl<T> Clone for NotifyingSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            wake: self.wake.clone(),
        }
    }
}

impl<T> NotifyingSender<T> {
    fn send(&self, value: T) -> Result<(), std_mpsc::SendError<T>> {
        self.tx.send(value)?;
        self.wake.notify();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshSessionUpdateRecord {
    /// Complete raw UMSH frames ready for the ULCP PHY transport. Each
    /// frame must be completed after the device reports the physical radio
    /// result; queue acceptance is not transmit completion.
    pub outbound_frames: Vec<MobileMeshOutboundFrameRecord>,
    pub ping_events: Vec<MobileMeshPingEventRecord>,
    pub advertisement_events: Vec<MobileMeshAdvertisementRecord>,
    pub peer_heard_events: Vec<MobileMeshPeerHeardRecord>,
    /// Chat effects remain in the facade until Swift durably applies them and
    /// acknowledges this batch. Repeated polls may return the same batch.
    pub chat_batch_id: Option<u64>,
    pub chat_mutations: Vec<MobileChatMutationRecord>,
    pub chat_deliveries: Vec<MobileChatDeliveryRecord>,
    pub chat_archive_lookups: Vec<MobileChatArchiveLookupRecord>,
    /// Channel members whose claimed hint has resolved to a full address. The
    /// platform should upgrade rows it stored anonymously under that hint.
    pub chat_sender_resolutions: Vec<MobileChatSenderResolutionRecord>,
    pub chat_diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshOutboundFrameRecord {
    pub id: u64,
    pub data: Vec<u8>,
    /// `TX_FLAG_NOCCA`: the device should transmit this frame without the
    /// pre-transmit channel-activity check. Set for immediate MAC acks, which
    /// own the channel-access window the moment the received frame ends; clear
    /// for originated and forwarded traffic, which must listen before talking.
    pub nocca: bool,
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
    RemovePeers {
        peers: Vec<PublicKey>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    RegisterChannels {
        keys: Vec<ChannelKey>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    RemoveChannels {
        keys: Vec<ChannelKey>,
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
        conversation_address: String,
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
    RequestIdentity {
        peer: PublicKey,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    DiscoverIdentities {
        role_code: Option<u8>,
        capability_bits: Option<u8>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    RequestIdentityByHint {
        conversation_address: String,
        hint: NodeHint,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    SetDiscoverable {
        enabled: bool,
        name: Option<String>,
        response: oneshot::Sender<()>,
    },
    SetChatDisplayName {
        name: String,
        response: oneshot::Sender<()>,
    },
    PeerRoute {
        peer: PublicKey,
        response: oneshot::Sender<MobileMeshRouteRecord>,
    },
    ClearPeerRoute {
        peer: PublicKey,
        response: oneshot::Sender<bool>,
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

/// Who a received text frame came from, and over what.
enum InboundTextSource {
    /// Authenticated unicast from a known peer.
    Direct { peer: PublicKey },
    /// Multicast to a channel. The sender claims a hint; the full key is
    /// present only when they addressed the frame with it.
    ChannelGroup {
        channel: ChannelTag,
        hint: NodeHint,
        full_key: Option<PublicKey>,
    },
    /// Blind unicast to us over a channel key, from an addressable peer.
    ChannelDirect {
        channel: ChannelTag,
        peer: PublicKey,
    },
}

struct InboundText {
    source: InboundTextSource,
    payload: Vec<u8>,
    received_at_ms: Option<u64>,
    rx: MobileChatRxMetadataRecord,
}

struct InFlightChatTransmission {
    transmission_id: u32,
    /// The peer whose first-contact pipeline this send gates on. Channel
    /// sends have no such peer: multicast is unaddressed and blind unicast
    /// carries no ACK to confirm with.
    gate_peer: Option<PublicKey>,
    ticket: SendProgressTicket,
    sent_reported: bool,
    /// No acknowledgement will ever arrive, so transmission is the terminal
    /// success state rather than a step toward one.
    non_ack: bool,
    /// When this entry entered the window, and whether it has already been
    /// reported as overdue. A frame that never resolves holds a slot in a
    /// window of eight; eight of them stop chat entirely, and from the outside
    /// that looks like messages hanging on "Sending" for no reason.
    queued_at_ms: u64,
    stall_reported: bool,
}

/// How long an in-flight transmission may go unresolved before it is called
/// out. Longer than any ordinary ACK wait, so this fires on trouble rather
/// than on a slow link.
const CHAT_TRANSMISSION_STALL_MS: u64 = 60_000;

#[derive(Clone)]
enum MobileChatWorkerEvent {
    Mutation(MobileChatMutationRecord),
    SenderResolution(MobileChatSenderResolutionRecord),
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
    outbound: NotifyingSender<MobileMeshOutboundFrameRecord>,
    completions: Arc<BridgeTransmitCompletions>,
}

impl Radio for BridgeRadio {
    type Error = BridgeRadioError;

    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(TxError::Io(BridgeRadioError::FrameTooLarge));
        }
        // The MAC skips CAD only for immediate acks (channel-access.md
        // § Immediate ACK Transmission); every other policy asks the
        // device to listen before talking.
        let nocca = matches!(options.cad, umsh_hal::CadPolicy::Skip);
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
                nocca,
            })
            .is_err()
        {
            let _ = self.completions.complete(id, false);
            return Err(TxError::Io(BridgeRadioError::Closed));
        }

        // Awaiting here is deliberate: Radio::transmit completes only after
        // the frame has actually left the radio PHY. Returning at
        // bridge-queue acceptance starts MAC ACK timers too early and causes
        // fragmented sends to retransmit frames that are still waiting in
        // the device queue. This is an async wait, not a thread block, so
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

/// Peer capacity of the phone's in-memory MAC. The embedded default (16) is
/// sized for microcontroller RAM; the app registers a peer per conversation
/// plus every checkpointed stream, which can plausibly exceed it, and phone
/// RAM is not the constraint.
const MOBILE_MAC_PEERS: usize = 64;

/// Channel capacity of the phone's in-memory MAC. The embedded default of 8
/// is sized for microcontroller RAM and already spends two slots on the
/// default `public` and `EMERGENCY` channels; per-channel replay state is a
/// few hundred bytes, which phone RAM does not need to ration.
const MOBILE_MAC_CHANNELS: usize = 32;

type MobileMac = Mac<
    MobilePlatform,
    { umsh_mac::DEFAULT_IDENTITIES },
    MOBILE_MAC_PEERS,
    MOBILE_MAC_CHANNELS,
>;
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
    peer_heard: Mutex<std_mpsc::Receiver<MobileMeshPeerHeardRecord>>,
    chat_events: Mutex<std_mpsc::Receiver<MobileChatWorkerEvent>>,
    pending_chat_events: Mutex<Option<PendingChatEventBatch>>,
    next_chat_batch_id: Mutex<u64>,
    next_operation_id: Mutex<u64>,
    wake: Arc<WakeSignal>,
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

    /// Solicit a specific peer's current node identity by sending a targeted
    /// MAC Identity Request (command 1). This resolves once the request has
    /// been handed to the transport; the peer's identity response arrives
    /// later as a `NodeIdentity` advertisement on the normal receive path
    /// (surfaced through `poll_update`'s advertisement events).
    pub async fn request_identity(&self, peer_address: String) -> Result<(), MobileMeshError> {
        let peer = decode_peer(&peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RequestIdentity { peer, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Solicit identities from nearby nodes with one zero-hop broadcast MAC
    /// Identity Request.
    ///
    /// The request goes out as a direct broadcast with no flood budget, so
    /// repeaters never carry it — the blast radius is exactly the nodes in
    /// radio range. It carries this phone's full source address, so a
    /// matching node can reply with a targeted unicast without any prior
    /// contact; replies arrive as ordinary `NodeIdentity` advertisements on
    /// the receive path. `role_code` and `capability_bits` narrow which
    /// nodes respond (AND-combined when both are given); `None` for both
    /// asks every node in range.
    pub async fn discover_identities(
        &self,
        role_code: Option<u8>,
        capability_bits: Option<u8>,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::DiscoverIdentities {
                role_code,
                capability_bits,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Ask a channel member who is known only by their claimed hint to send
    /// their identity.
    ///
    /// A group message carries a 3-byte hint and nothing else, so there is no
    /// address to unicast a request to. This goes out over the channel itself,
    /// filtered to that hint, and only the member it names answers — with a
    /// targeted unicast, since the request carries this phone's full address.
    ///
    /// The request is routed by what that member's own frames have shown:
    /// their observed trace route if one is known, otherwise a flood budget
    /// bounded by the hops their last message took rather than a default.
    pub async fn request_identity_by_hint(
        &self,
        conversation_address: String,
        hint: Vec<u8>,
    ) -> Result<(), MobileMeshError> {
        let hint: [u8; 3] = hint
            .try_into()
            .map_err(|_| MobileMeshError::UnknownConversation)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RequestIdentityByHint {
                conversation_address,
                hint: NodeHint(hint),
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Set whether this phone answers Identity Requests with its own
    /// identity — the passive counterpart of [`discover_identities`]:
    /// discoverable phones show up in other people's Discover sessions.
    ///
    /// `name` is the display name carried in replies (truncated to the
    /// 24-byte wire limit). The session starts discoverable with no name;
    /// the app pushes the stored preference and name right after install
    /// and again whenever either changes. Replies are targeted
    /// authenticated unicasts, never broadcasts.
    /// Set the name carried on this phone's own group messages.
    ///
    /// A multicast reaches members holding no identity for us, so a group
    /// message says who sent it or arrives anonymous. Direct messages never
    /// carry it: the recipient authenticated us by key. Empty clears it.
    pub async fn set_chat_display_name(&self, name: String) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::SetChatDisplayName { name, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    pub async fn set_discoverable(
        &self,
        enabled: bool,
        name: Option<String>,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::SetDiscoverable {
                enabled,
                name,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    /// Report the route the MAC will use for the next frame sent to `peer`.
    ///
    /// Read-only: an unregistered peer reads as `Unknown` rather than being
    /// registered as a side effect of being inspected.
    pub async fn peer_route(
        &self,
        peer_address: String,
    ) -> Result<MobileMeshRouteRecord, MobileMeshError> {
        let peer = decode_peer(&peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::PeerRoute { peer, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }

    /// Forget the route cached for `peer`, returning whether one was held.
    ///
    /// The peer, its keys, and its counters are untouched; only the learned
    /// path is discarded, so the next send starts over from flood delivery.
    pub async fn clear_peer_route(&self, peer_address: String) -> Result<bool, MobileMeshError> {
        let peer = decode_peer(&peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::ClearPeerRoute { peer, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)
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

    /// Remove peers from the live MAC. Idempotent: a peer that was never
    /// registered is already in the requested state, so it is not an error.
    /// A removed peer that transmits again may be auto-re-registered
    /// (unpinned) by the MAC — removal here tracks the app's stored peer
    /// list, it is not a block list.
    pub async fn remove_peers(&self, peer_addresses: Vec<String>) -> Result<(), MobileMeshError> {
        let peers = peer_addresses
            .iter()
            .map(|address| decode_peer(address).map_err(|_| MobileMeshError::InvalidPeer))
            .collect::<Result<Vec<_>, _>>()?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RemovePeers { peers, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Register channel keys with the live MAC so their traffic is accepted.
    ///
    /// Membership itself is persisted by the platform, which replays the whole
    /// joined set through this call when a session starts. Re-registering a
    /// channel already held is harmless.
    pub async fn register_channels(&self, keys: Vec<Vec<u8>>) -> Result<(), MobileMeshError> {
        let keys = decode_channel_keys(keys)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RegisterChannels { keys, response })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Drop channel keys from the live MAC, so its traffic is no longer
    /// decrypted. Idempotent, like [`Self::remove_peers`].
    pub async fn remove_channels(&self, keys: Vec<Vec<u8>>) -> Result<(), MobileMeshError> {
        let keys = decode_channel_keys(keys)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::RemoveChannels { keys, response })
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

    /// Report the actual physical radio result for an outbound
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

    /// Compose a message into a conversation, addressed either by a peer's
    /// address or by a channel's conversation address.
    pub async fn compose_text(
        &self,
        conversation_address: String,
        client_token: u32,
        body: String,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        self.compose_chat(
            conversation_address,
            client_token,
            ChatComposeRequest::Text { body },
        )
        .await
    }

    /// Compose an edit of a previously sent message. The original may come
    /// from an earlier app launch: its persisted `(wire_id, epoch)` is used
    /// when the facade session no longer holds a live handle, and the engine
    /// rejects it (`ChatComposeFailed`) if stream continuity was lost since.
    pub async fn compose_edit(
        &self,
        conversation_address: String,
        client_token: u32,
        original: MobileChatOriginalRef,
        body: String,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        self.compose_chat(
            conversation_address,
            client_token,
            ChatComposeRequest::Edit { original, body },
        )
        .await
    }

    /// Compose a deletion (empty edit on the wire) of a previously sent
    /// message. Same original-reference rules as [`Self::compose_edit`].
    pub async fn compose_delete(
        &self,
        conversation_address: String,
        client_token: u32,
        original: MobileChatOriginalRef,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        self.compose_chat(
            conversation_address,
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
            // Events that queued while this batch was outstanding could not
            // form a new batch; poke the listener so the platform drains
            // again now that the slot is free.
            self.wake.notify();
        }
        Ok(())
    }

    /// Fail every chat transmission currently owned by the mobile radio
    /// bridge. The platform calls this when ULCP-link delivery failed
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

    /// Register (or replace) the listener that is told when this session
    /// has new data for `poll_update`. If data is already pending, the
    /// listener fires immediately.
    pub fn set_wake_listener(&self, listener: Arc<dyn MobileMeshWakeListener>) {
        self.wake.set_listener(Some(listener));
    }

    pub fn clear_wake_listener(&self) {
        self.wake.set_listener(None);
    }

    pub fn poll_update(&self) -> MobileMeshSessionUpdateRecord {
        // Re-arm before draining: anything enqueued mid-drain triggers a
        // fresh notification rather than being silently swallowed.
        self.wake.drained();
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
        let mut peer_heard_events = Vec::new();
        if let Ok(receiver) = self.peer_heard.lock() {
            peer_heard_events.extend(receiver.try_iter());
        }
        let mut chat_mutations = Vec::new();
        let mut chat_deliveries = Vec::new();
        let mut chat_archive_lookups = Vec::new();
        let mut chat_sender_resolutions = Vec::new();
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
                        MobileChatWorkerEvent::SenderResolution(record) => {
                            chat_sender_resolutions.push(record);
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
            peer_heard_events,
            chat_batch_id,
            chat_mutations,
            chat_deliveries,
            chat_archive_lookups,
            chat_sender_resolutions,
            chat_diagnostics,
        }
    }
}

impl MobileMeshSession {
    async fn compose_chat(
        &self,
        conversation_address: String,
        client_token: u32,
        request: ChatComposeRequest,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        // Resolved on the worker, which owns the channel registry an address
        // may need to be interpreted against.
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::ComposeChat {
                conversation_address,
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
        let wake = Arc::new(WakeSignal::new());
        let (outbound_tx, outbound) = std_mpsc::channel();
        let (event_tx, events) = std_mpsc::channel();
        let (advertisement_tx, advertisements) = std_mpsc::channel();
        let (peer_heard_tx, peer_heard) = std_mpsc::channel();
        let (chat_event_tx, chat_events) = std_mpsc::channel();
        let outbound_tx = NotifyingSender {
            tx: outbound_tx,
            wake: wake.clone(),
        };
        let event_tx = NotifyingSender {
            tx: event_tx,
            wake: wake.clone(),
        };
        let advertisement_tx = NotifyingSender {
            tx: advertisement_tx,
            wake: wake.clone(),
        };
        let peer_heard_tx = NotifyingSender {
            tx: peer_heard_tx,
            wake: wake.clone(),
        };
        let chat_event_tx = NotifyingSender {
            tx: chat_event_tx,
            wake: wake.clone(),
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker_identity = identity.take_for_session()?;
        let transmit_completions = Arc::new(BridgeTransmitCompletions::new());
        let worker_transmit_completions = transmit_completions.clone();

        std::thread::Builder::new()
            .name("umsh-mobile-mesh".to_owned())
            // The whole 64-peer MAC lives inside the worker future, and the
            // future is polled (and moved during construction) on this
            // thread's stack. The platform default (512 KiB–2 MiB for
            // secondary threads) is not enough headroom for that.
            .stack_size(16 * 1024 * 1024)
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
                // Boxed so the future's state — which embeds the MAC and its
                // peer tables by value — lives on the heap rather than in
                // this thread's stack frame.
                local.block_on(
                    &runtime,
                    Box::pin(run_worker(
                        worker_identity,
                        SharedCounterStore(counter_store),
                        command_rx,
                        outbound_tx,
                        worker_transmit_completions,
                        event_tx,
                        advertisement_tx,
                        peer_heard_tx,
                        chat_event_tx,
                        ready_tx,
                    )),
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
            peer_heard: Mutex::new(peer_heard),
            chat_events: Mutex::new(chat_events),
            pending_chat_events: Mutex::new(None),
            next_chat_batch_id: Mutex::new(1),
            next_operation_id: Mutex::new(1),
            wake,
        }))
    }
}

impl Drop for MobileMeshSession {
    fn drop(&mut self) {
        self.transmit_completions.fail_all();
        let _ = self.commands.send(WorkerCommand::Shutdown);
    }
}

/// The identity profile the phone's Identity Request responder serves:
/// the same role Chat / Mobile + Text messages statement the signed
/// advertisement makes, with the display name truncated identically.
fn phone_identity_profile(public_key: PublicKey, name: Option<&str>) -> NodeIdentityProfile {
    let mut profile = NodeIdentityProfile::new(
        public_key,
        NodeRole::Chat,
        NodeCapabilities::MOBILE | NodeCapabilities::TEXT_MESSAGES,
    );
    profile.name = name
        .map(|name| {
            let mut end = name.len().min(24);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            name[..end].to_owned()
        })
        .filter(|name| !name.is_empty());
    profile
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
    outbound: NotifyingSender<MobileMeshOutboundFrameRecord>,
    transmit_completions: Arc<BridgeTransmitCompletions>,
    events: NotifyingSender<MobileMeshPingEventRecord>,
    advertisements: NotifyingSender<MobileMeshAdvertisementRecord>,
    peer_heard: NotifyingSender<MobileMeshPeerHeardRecord>,
    chat_events: NotifyingSender<MobileChatWorkerEvent>,
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
    // A stranger's authenticated unicast — an Identity Request reply, a
    // first contact — names its sender with a full 32-byte source key.
    // Auto-registration (unpinned, LRU-evictable) is what lets the MAC
    // verify such a frame at all; without it the reply to our own
    // Discover solicitation is dropped unheard. Device firmware runs
    // with the same setting.
    handle.set_auto_register_full_key_peers(true).await;

    let mut host = Host::new(handle);
    let node = host.add_node(identity_id);
    // The session starts discoverable with no name; the app pushes the
    // stored preference and display name via `set_discoverable` right
    // after install.
    node.enable_identity_responder_default(phone_identity_profile(local_key, None));
    // Held outside the chat state: rejecting a batch rebuilds the reducer,
    // and the channels the platform registered must outlive that.
    let channel_registry = Rc::new(RefCell::new(ChannelRegistry::default()));
    let mut chat = MobileChatState::new(local_key, channel_registry.clone());
    // Registered before every other receive handler: dispatch stops at the
    // first handler that claims a packet, and presence is true of packets
    // that something else goes on to claim. It never claims one itself.
    let peer_heard_events = peer_heard.clone();
    let peer_heard_subscription = node.on_receive(move |packet| {
        let _ = peer_heard_events.send(MobileMeshPeerHeardRecord {
            peer_address: packet.from_key().map(|peer| encode_peer_address(&peer)),
            node_hint: packet.from_hint().map(|hint| hint.0.to_vec()),
            source_authenticated: packet.source_authenticated(),
        });
        false
    });
    let inbound_text = Rc::new(RefCell::new(Vec::<InboundText>::new()));
    let inbound_text_callback = inbound_text.clone();
    let text_channels = channel_registry.clone();
    let echo_events = chat_events.clone();
    let text_subscription = node.on_receive(move |packet| {
        if packet.payload_type() != PayloadType::TextMessage {
            return false;
        }
        // Our own multicast, relayed back to us. Every group send carries our
        // full source address, so a repeater's copy arrives naming us — but
        // it is the message we already have, not a second one, and the
        // transcript must not show it twice.
        //
        // It is still evidence: something out there received our frame and
        // forwarded it, which is the only reachability signal a multicast
        // ever produces. Claim it so nothing else interprets it, and report
        // how far it travelled.
        if packet.from_key() == Some(local_key) {
            let hops = packet
                .flood_hops()
                .map(|hops| hops.accumulated())
                .unwrap_or(0);
            let _ = echo_events.send(MobileChatWorkerEvent::Diagnostic(format!(
                "own multicast relayed back after {hops} hop(s)"
            )));
            return true;
        }
        // A channel frame names its channel by the key that authenticated it,
        // so the tag is derived from that key rather than looked up by the
        // two-byte identifier the frame carried — distinct keys may share an
        // identifier, and only the key that decrypted the frame is the truth.
        let channel_tag = packet.channel().map(|channel| {
            (
                crate::channel_tag(channel.key()),
                text_channels.borrow().contains(&crate::channel_tag(channel.key())),
            )
        });
        // The same rule read from the receiving end: emergency traffic that is
        // not readable by every node in range, or that does not name its
        // sender outright, is not accepted at all. A frame that fails either
        // test is dropped rather than shown unmarked — a message the reader
        // would act on in an emergency must not arrive with its origin or its
        // reach in question.
        //
        // Both checks live here, at the chat layer, rather than under the MAC:
        // the requirement the spec states is about chat messages, and the MAC
        // is deliberately incurious about what it carries.
        if let Some((tag, _)) = channel_tag
            && tag == crate::emergency_channel_tag()
            && (packet.encrypted() || packet.from_key().is_none())
        {
            let reason = if packet.encrypted() {
                "encrypted"
            } else {
                "missing its full source key"
            };
            let _ = echo_events.send(MobileChatWorkerEvent::Diagnostic(format!(
                "dropped an emergency-channel text frame: {reason}"
            )));
            return false;
        }
        let source = match (packet.packet_family(), channel_tag) {
            (PacketFamily::Unicast, _) => match packet.from_key() {
                Some(peer) => InboundTextSource::Direct { peer },
                None => return false,
            },
            // Membership is what the channel MIC authenticates; the hint is
            // the only sender identity a multicast frame must carry.
            (PacketFamily::Multicast, Some((channel, true))) => match packet.from_hint() {
                Some(hint) => InboundTextSource::ChannelGroup {
                    channel,
                    hint,
                    full_key: packet.from_key(),
                },
                None => return false,
            },
            // Without a full key there is nobody to attribute the message to,
            // and nobody to answer a repair request to.
            (PacketFamily::BlindUnicast, Some((channel, true))) => match packet.from_key() {
                Some(peer) => InboundTextSource::ChannelDirect { channel, peer },
                None => return false,
            },
            _ => return false,
        };
        inbound_text_callback.borrow_mut().push(InboundText {
            source,
            payload: packet.payload().to_vec(),
            received_at_ms: packet.received_at_ms(),
            rx: MobileChatRxMetadataRecord {
                rssi_dbm: packet.rssi(),
                snr_centibels: packet.snr().map(|snr| snr.as_centibels()),
                lqi: packet.lqi().map(|lqi| lqi.get()),
                hop_count: packet.flood_hops().map(|hops| hops.accumulated()),
                route_hints: packet
                    .trace_route_hops()
                    .map(|hop| hop.0.to_vec())
                    .collect(),
                source_authenticated: packet.source_authenticated(),
            },
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
        let _ = advertisement_events.send(MobileMeshAdvertisementRecord {
            peer_address: encode_peer_address(&peer),
            payload: packet.payload().to_vec(),
            source_authenticated: packet.source_authenticated(),
        });
        true
    });
    let mut in_flight_chat = Vec::<InFlightChatTransmission>::new();
    // How each channel member was last reached, so an identity request can be
    // routed by evidence rather than flooded at the default budget.
    let mut member_routes = BTreeMap::<(ChannelTag, [u8; 3]), MemberRoute>::new();
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
        peer_heard_subscription,
        text_subscription,
        advertisement_subscription,
    );
    let _ = ready.send(Ok(()));
    let mut protocol_timeout_tick = tokio::time::interval(Duration::from_millis(50));
    protocol_timeout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The worker runs as two sibling loops polled by one outer select.
    //
    // `Radio::transmit` awaits the device's physical TX completion while
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
                        Some(WorkerCommand::RemovePeers { peers, response }) => {
                            for peer in peers {
                                // Not-found is success: the peer is absent
                                // either way.
                                let _ = node.remove_peer(&peer).await;
                            }
                            let _ = response.send(Ok(()));
                        }
                        Some(WorkerCommand::RegisterChannels { keys, response }) => {
                            let mut result = Ok(());
                            for key in keys {
                                // Named and private channels are the same
                                // thing here: the app already holds the
                                // derived key either way.
                                if node.join(&umsh_node::Channel::private(key, "")).await.is_err() {
                                    result = Err(MobileMeshError::ChannelCapacity);
                                    break;
                                }
                                channel_registry
                                    .borrow_mut()
                                    .register(crate::channel_tag(&key), key);
                            }
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::RemoveChannels { keys, response }) => {
                            for key in keys {
                                // Not-joined is success, as for peers.
                                let _ = node.leave(&umsh_node::Channel::private(key, "")).await;
                                channel_registry
                                    .borrow_mut()
                                    .remove(&crate::channel_tag(&key));
                            }
                            let _ = response.send(Ok(()));
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
                                            .with_trace_route()
                                            .with_mic_size(umsh_node::PING_MIC_SIZE),
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
                                    // Full source so the detached signature
                                    // is checkable; trace route so a listener
                                    // learns a path back to this phone from
                                    // the same frame.
                                    node.send_all(
                                        &frame,
                                        &SendOptions::default()
                                            .with_full_source()
                                            .with_trace_route(),
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
                        Some(WorkerCommand::RequestIdentity { peer, response }) => {
                            let result = match node.peer(peer).await {
                                Ok(connection) => connection
                                    .request_identity(
                                        &SendOptions::default()
                                            .with_flood_hops(5)
                                            .with_ack_requested(false),
                                    )
                                    .await
                                    .map(|_| ())
                                    .map_err(|_| MobileMeshError::SendFailed),
                                Err(_) => Err(MobileMeshError::SendFailed),
                            };
                            // A real authenticated send advances the frame counter;
                            // persist it before acknowledging, as the ping/advertise
                            // paths do.
                            if result.is_ok()
                                && handle.service_counter_persistence().await.is_err()
                            {
                                let _ = response.send(Err(MobileMeshError::SendFailed));
                                return;
                            }
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::RequestIdentityByHint {
                            conversation_address,
                            hint,
                            response,
                        }) => {
                            let channel = chat
                                .parse_conversation_address(&conversation_address)
                                .and_then(|conversation| match conversation {
                                    ConversationKey::ChannelGroup { channel } => Some(channel),
                                    _ => None,
                                });
                            let result = match channel {
                                Some(channel) => {
                                    let route = member_routes.get(&(channel, hint.0)).cloned();
                                    let mut nonce_bytes = [0u8; 4];
                                    handle.fill_random(&mut nonce_bytes).await;
                                    request_identity_over_channel(
                                        &node,
                                        &channel_registry,
                                        channel,
                                        hint,
                                        u32::from_be_bytes(nonce_bytes),
                                        route,
                                    )
                                    .await
                                }
                                None => Err(MobileMeshError::UnknownConversation),
                            };
                            if result.is_ok()
                                && handle.service_counter_persistence().await.is_err()
                            {
                                let _ = response.send(Err(MobileMeshError::SendFailed));
                                return;
                            }
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::SetChatDisplayName { name, response }) => {
                            chat.engine.set_local_handle(&name);
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::SetDiscoverable { enabled, name, response }) => {
                            if enabled {
                                node.enable_identity_responder_default(phone_identity_profile(
                                    local_key,
                                    name.as_deref(),
                                ));
                            } else {
                                node.disable_identity_responder();
                            }
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::DiscoverIdentities {
                            role_code,
                            capability_bits,
                            response,
                        }) => {
                            let result = async {
                                let mut builder = umsh_node::mac_command::IdentityRequestBuilder::new();
                                let mut nonce_bytes = [0u8; 4];
                                handle.fill_random(&mut nonce_bytes).await;
                                builder = builder
                                    .nonce(u32::from_be_bytes(nonce_bytes))
                                    .map_err(|_| MobileMeshError::SendFailed)?;
                                if let Some(role) = role_code {
                                    builder = builder
                                        .filter_role(NodeRole::from_byte(role))
                                        .map_err(|_| MobileMeshError::SendFailed)?;
                                }
                                // A broadcast request must carry at least one
                                // filter option. An unrestricted ask carries a
                                // zero-bit capability filter, which every node
                                // satisfies.
                                let capability_bits = capability_bits
                                    .or(if role_code.is_none() { Some(0) } else { None });
                                if let Some(bits) = capability_bits {
                                    builder = builder
                                        .filter_caps(NodeCapabilities::from_bits_truncate(bits))
                                        .map_err(|_| MobileMeshError::SendFailed)?;
                                }
                                let options_block = builder.build();
                                let cmd = umsh_node::MacCommand::IdentityRequest {
                                    options: &options_block,
                                };
                                let mut frame = [0u8; 128];
                                frame[0] = PayloadType::MacCommand as u8;
                                let length = umsh_node::mac_command::encode(&cmd, &mut frame[1..])
                                    .map_err(|_| MobileMeshError::SendFailed)?
                                    + 1;
                                // Zero-hop by design: no flood budget, so
                                // repeaters never carry the solicitation.
                                // Full source lets a stranger unicast back.
                                node.send_all(
                                    &frame[..length],
                                    &SendOptions::default().with_full_source().no_flood(),
                                )
                                .await
                                .map(|_| ())
                                .map_err(|_| MobileMeshError::SendFailed)
                            }
                            .await;
                            if result.is_ok()
                                && handle.service_counter_persistence().await.is_err()
                            {
                                let _ = response.send(Err(MobileMeshError::SendFailed));
                                return;
                            }
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::PeerRoute { peer, response }) => {
                            let _ = response.send(node.peer_route(&peer).await.into());
                        }
                        Some(WorkerCommand::ClearPeerRoute { peer, response }) => {
                            let _ = response.send(node.clear_peer_route(&peer).await);
                        }
                        Some(WorkerCommand::RestoreChat { checkpoints, response }) => {
                            chat.restore(&checkpoints, handle.now_ms().await);
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::ComposeChat {
                            conversation_address,
                            client_token,
                            request,
                            response,
                        }) => {
                            // Rejecting a persisted batch rebuilds the reducer from
                            // durable checkpoints. Keep that recovery operation
                            // unambiguous by allowing only one uncommitted compose.
                            let conversation =
                                chat.parse_conversation_address(&conversation_address);
                            let result = if !chat.pending_batches.is_empty() {
                                Err(MobileMeshError::OperationInProgress)
                            } else if let Some(conversation) = conversation {
                                let now_ms = handle.now_ms().await;
                                let composed = match &request {
                                    ChatComposeRequest::Text { body } => {
                                        chat.compose_text(conversation, client_token, body, now_ms)
                                    }
                                    ChatComposeRequest::Edit { original, body } => chat.compose_edit(
                                        conversation,
                                        client_token,
                                        original,
                                        body,
                                        now_ms,
                                    ),
                                    ChatComposeRequest::Delete { original } => chat.compose_delete(
                                        conversation,
                                        client_token,
                                        original,
                                        now_ms,
                                    ),
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
                                // Either the address is malformed, or it names
                                // a channel this session does not hold a key
                                // for — from here those are the same thing.
                                Err(MobileMeshError::UnknownConversation)
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
                                        &channel_registry,
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
                                    chat = MobileChatState::new(
                                        local_key,
                                        channel_registry.clone(),
                                    );
                                    for diagnostic in
                                        chat.restore(&checkpoints, handle.now_ms().await)
                                    {
                                        let _ = chat_events.send(
                                            MobileChatWorkerEvent::Diagnostic(diagnostic),
                                        );
                                    }
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
                                    &channel_registry,
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
                        // The envelope's sender is what the engine keys a
                        // stream by. A multicast member is always the claimed
                        // hint, with the full key passed alongside: naming the
                        // key here instead would split one member into two
                        // streams the moment a frame omitted it.
                        let (envelope, sender_full_key) = match text.source {
                            InboundTextSource::Direct { peer } => (
                                Envelope {
                                    path: DeliveryPath::Unicast,
                                    conversation: ConversationKey::Direct { peer },
                                    sender: SenderScope::Peer(peer),
                                },
                                Some(peer),
                            ),
                            InboundTextSource::ChannelGroup {
                                channel,
                                hint,
                                full_key,
                            } => {
                                if let Some(peer) = full_key {
                                    if let Some(resolution) =
                                        chat.resolve_member(channel, hint, peer)
                                    {
                                        let _ = chat_events.send(
                                            MobileChatWorkerEvent::SenderResolution(resolution),
                                        );
                                    }
                                }
                                remember_member_route(
                                    &mut member_routes,
                                    channel,
                                    hint,
                                    &text.rx,
                                );
                                (
                                    Envelope {
                                        path: DeliveryPath::Multicast,
                                        conversation: ConversationKey::ChannelGroup { channel },
                                        sender: SenderScope::ClaimedMember(hint),
                                    },
                                    full_key,
                                )
                            }
                            InboundTextSource::ChannelDirect { channel, peer } => (
                                Envelope {
                                    path: DeliveryPath::BlindUnicast,
                                    conversation: ConversationKey::ChannelDirect { channel, peer },
                                    sender: SenderScope::Peer(peer),
                                },
                                Some(peer),
                            ),
                        };
                        let _ = chat.engine.receive(
                            &envelope,
                            sender_full_key,
                            &text.payload,
                            received_at_ms,
                        );
                        let mut drain = chat.drain();
                        // This drain belongs to exactly one frame, so the
                        // records it produced are the ones that frame caused.
                        attach_rx_metadata(&mut drain.mutations, &text.rx);
                        let transmissions = drain.transmissions.clone();
                        publish_chat_drain(drain, &chat_events);
                        if !transmissions.is_empty() || !pending_chat_transmissions.is_empty() {
                            let sent = queue_chat_transmissions(
                                &node,
                                transmissions,
                                &mut pending_chat_transmissions,
                                &mut in_flight_chat,
                                &chat_pipeline_ready,
                                &channel_registry,
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
                        &chat_events,
                        pending_chat_transmissions.len(),
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
                            &channel_registry,
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
    channels: &Rc<RefCell<ChannelRegistry>>,
    chat: &mut MobileChatState,
    now_ms: u64,
) -> usize {
    pending.extend(transmissions);
    // Keep a bounded pipeline aligned with the device's target-selected
    // TX queue. The durable pending queue below handles messages larger than
    // this window without imposing the mobile RAM choice on embedded MACs.
    if in_flight.len() >= MOBILE_CHAT_TRANSMIT_WINDOW {
        return 0;
    }
    let mut queued = 0;
    while let Some(transmission) = pending.pop_front() {
        let gate_peer = match transmission.destination {
            Destination::Peer(peer) => Some(peer),
            // Multicast is unaddressed and blind unicast carries no ACK, so
            // neither has a peer whose pipeline could be confirmed.
            Destination::Channel(_) | Destination::ChannelPeer { .. } => None,
        };
        if let Some(peer) = gate_peer {
            if !pipeline_ready.contains(&peer.0)
                && in_flight
                    .iter()
                    .any(|entry| entry.gate_peer == Some(peer))
            {
                // First contact may require counter synchronization. Confirm
                // one authenticated frame before opening this peer's full
                // pipeline.
                pending.push_front(transmission);
                break;
            }
        }
        let mut payload = Vec::with_capacity(transmission.payload.len() + 1);
        payload.push(PayloadType::TextMessage as u8);
        payload.extend_from_slice(transmission.payload.as_slice());
        let sent = match transmission.destination {
            Destination::Peer(peer) => match node.peer(peer).await {
                Ok(connection) => {
                    connection
                        .send(&payload, &SendOptions::default().with_ack_requested(true))
                        .await
                }
                Err(_) => {
                    chat.engine.transmit_update(
                        transmission.transmission_id,
                        DeliveryState::Failed,
                        now_ms,
                    );
                    continue;
                }
            },
            Destination::Channel(channel) => {
                let Some(bound) = bound_channel(node, channels, &channel) else {
                    chat.engine.transmit_update(
                        transmission.transmission_id,
                        DeliveryState::Failed,
                        now_ms,
                    );
                    continue;
                };
                // Carry the full source address: a member who misses a
                // fragment can only ask us to resend it if our frames name
                // the key to address that request to.
                let mut options = SendOptions::default().with_full_source();
                // An emergency message that only channel members can read is
                // not an emergency message. The spec forbids encrypting chat
                // on `EMERGENCY` so anyone in range can act on it, whether or
                // not they hold the key; the full source key it already
                // carries is what keeps it attributable without it.
                if channel == crate::emergency_channel_tag() {
                    options = options.unencrypted();
                }
                bound.send_all(&payload, &options).await
            }
            Destination::ChannelPeer { channel, peer } => {
                let Some(bound) = bound_channel(node, channels, &channel) else {
                    chat.engine.transmit_update(
                        transmission.transmission_id,
                        DeliveryState::Failed,
                        now_ms,
                    );
                    continue;
                };
                // The MAC will only address a registered peer, and a channel
                // member is not one — nothing about being in a channel
                // together registers anybody. Register on the way out rather
                // than on sight: only the members we actually have to ask
                // something of spend a peer slot, and this is the only place
                // we ever ask.
                if node.peer(peer).await.is_err() {
                    chat.engine.transmit_update(
                        transmission.transmission_id,
                        DeliveryState::Failed,
                        now_ms,
                    );
                    continue;
                }
                // A repair request; the engine owns retrying it, so no ACK is
                // asked for here.
                let mut options = SendOptions::default().with_full_source();
                // Repairs carry the same message the multicast did, so they
                // are held to the same rule — and have to be, since the
                // receiving side refuses encrypted emergency text whatever
                // family it arrives in. It stays blind unicast even so: what
                // an unencrypted blind unicast still carries over a plain one
                // is the channel it names, which is what a repeater decides
                // to forward on.
                if channel == crate::emergency_channel_tag() {
                    options = options.unencrypted();
                }
                let r = bound.send(&peer, &payload, &options).await;
                r
            }
        };
        let ticket = match sent {
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
            gate_peer,
            ticket,
            sent_reported: false,
            non_ack: gate_peer.is_none(),
            queued_at_ms: now_ms,
            stall_reported: false,
        });
        queued += 1;
        if in_flight.len() >= MOBILE_CHAT_TRANSMIT_WINDOW {
            break;
        }
    }
    queued
}

/// Solicit one channel member's identity over the channel they were heard on.
///
/// The request is a multicast every member receives but only the filtered hint
/// answers. Routing follows the evidence that member's own frames left: their
/// trace route if one was observed, otherwise a flood budget no larger than
/// the distance they were last heard from.
async fn request_identity_over_channel<M: MacBackend>(
    node: &LocalNode<M>,
    channels: &Rc<RefCell<ChannelRegistry>>,
    channel: ChannelTag,
    hint: NodeHint,
    nonce: u32,
    route: Option<MemberRoute>,
) -> Result<(), MobileMeshError> {
    let Some(bound) = bound_channel(node, channels, &channel) else {
        return Err(MobileMeshError::UnknownConversation);
    };
    let options_block = umsh_node::mac_command::IdentityRequestBuilder::new()
        .nonce(nonce)
        .and_then(|builder| builder.filter_hint(&hint))
        .map_err(|_| MobileMeshError::SendFailed)?
        .build();
    let cmd = umsh_node::MacCommand::IdentityRequest {
        options: &options_block,
    };
    let mut frame = [0u8; 128];
    frame[0] = PayloadType::MacCommand as u8;
    let length = umsh_node::mac_command::encode(&cmd, &mut frame[1..])
        .map_err(|_| MobileMeshError::SendFailed)?
        + 1;
    // Full source so the member can answer with a targeted unicast rather
    // than another multicast.
    let mut options = SendOptions::default().with_full_source();
    match route.as_ref() {
        Some(route) if !route.route_hints.is_empty() => {
            let hops = route
                .route_hints
                .iter()
                .filter_map(|hint| <[u8; 2]>::try_from(hint.as_slice()).ok())
                .map(umsh_core::RouterHint)
                .collect::<Vec<_>>();
            // An over-long observed route is not a reason to fail the
            // request; fall back to flooding at the distance it implies.
            options = match options.try_with_source_route(&hops) {
                Ok(options) => options,
                Err(_) => SendOptions::default()
                    .with_full_source()
                    .with_flood_hops(route.hop_count.unwrap_or(5).max(1)),
            };
        }
        Some(MemberRoute {
            hop_count: Some(hops),
            ..
        }) => {
            options = options.with_flood_hops((*hops).max(1));
        }
        _ => {}
    }
    bound
        .send_all(&frame[..length], &options)
        .await
        .map(|_| ())
        .map_err(|_| MobileMeshError::SendFailed)
}

/// Bind the channel a transmission names, so it can be sent over.
fn bound_channel<M: MacBackend>(
    node: &LocalNode<M>,
    channels: &Rc<RefCell<ChannelRegistry>>,
    channel: &ChannelTag,
) -> Option<umsh_node::BoundChannel<M>> {
    let key = channels.borrow().key(channel)?;
    // Looked up per send rather than cached: leaving and rejoining a channel
    // invalidates the binding, and the registry is the one place that knows.
    node.bound_channel(&umsh_node::Channel::private(key, ""))
}

fn service_chat_tickets(
    chat: &mut MobileChatState,
    in_flight: &mut Vec<InFlightChatTransmission>,
    pipeline_ready: &mut BTreeSet<[u8; 32]>,
    events: &NotifyingSender<MobileChatWorkerEvent>,
    pending_depth: usize,
    now_ms: u64,
) {
    let occupied = in_flight.len();
    let mut index = 0;
    while index < in_flight.len() {
        let entry = &mut in_flight[index];
        // Checked before the state transitions below, so an entry that is
        // about to retire this pass is not accused on its way out.
        if !entry.stall_reported
            && !entry.ticket.was_transmitted()
            && now_ms.saturating_sub(entry.queued_at_ms) >= CHAT_TRANSMISSION_STALL_MS
        {
            entry.stall_reported = true;
            let waited = now_ms.saturating_sub(entry.queued_at_ms) / 1000;
            let transmission_id = entry.transmission_id;
            let _ = events.send(MobileChatWorkerEvent::Diagnostic(format!(
                "transmission {transmission_id} has not left the radio after {waited}s \
                 ({occupied}/{MOBILE_CHAT_TRANSMIT_WINDOW} window slots used, \
                 {pending_depth} more waiting)"
            )));
        }
        let entry = &mut in_flight[index];
        if entry.ticket.was_transmitted() && !entry.sent_reported {
            chat.engine
                .transmit_update(entry.transmission_id, DeliveryState::Sent, now_ms);
            entry.sent_reported = true;
        }
        if entry.non_ack && entry.sent_reported {
            // Nothing further can happen to this one: no acknowledgement is
            // coming, so transmission is where it ends. Retiring it here is
            // what keeps channel sends from accumulating in flight forever.
            in_flight.swap_remove(index);
        } else if entry.ticket.was_acked() {
            if let Some(peer) = entry.gate_peer {
                pipeline_ready.insert(peer.0);
            }
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
    events: &NotifyingSender<MobileChatWorkerEvent>,
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
    for resolution in drain.resolutions {
        let _ = events.send(MobileChatWorkerEvent::SenderResolution(resolution));
    }
    for diagnostic in drain.diagnostics {
        let _ = events.send(MobileChatWorkerEvent::Diagnostic(diagnostic));
    }
}

/// Attach a frame's radio metadata to the records it produced.
///
/// The engine is transport-agnostic, so this is the only place the two are
/// together. Only records describing received content carry it — an outbound
/// echo or a placeholder has no frame behind it.
fn attach_rx_metadata(
    mutations: &mut [MobileChatMutationRecord],
    rx: &MobileChatRxMetadataRecord,
) {
    for mutation in mutations {
        let describes_receipt = match mutation.kind {
            MobileChatMutationKind::Insert => {
                mutation.direction == Some(MobileChatDirection::Inbound)
                    && mutation.presence == MobileChatPresence::Present
            }
            MobileChatMutationKind::UpdateBody => true,
            MobileChatMutationKind::Edit | MobileChatMutationKind::Delete => false,
        };
        if describes_receipt {
            mutation.rx = Some(rx.clone());
        }
    }
}

/// Remember how a channel member was last reached, so a later request to them
/// can be routed by evidence instead of by a default flood budget.
fn remember_member_route(
    routes: &mut BTreeMap<(ChannelTag, [u8; 3]), MemberRoute>,
    channel: ChannelTag,
    hint: NodeHint,
    rx: &MobileChatRxMetadataRecord,
) {
    routes.insert(
        (channel, hint.0),
        MemberRoute {
            hop_count: rx.hop_count,
            route_hints: rx.route_hints.clone(),
        },
    );
}

/// What the last frame from a channel member showed about reaching them.
#[derive(Clone)]
struct MemberRoute {
    hop_count: Option<u8>,
    route_hints: Vec<Vec<u8>>,
}

fn decode_peer(address: &str) -> Result<PublicKey, MobileError> {
    let bytes = umsh_core::base58::decode(address.as_bytes())?;
    Ok(PublicKey(bytes))
}

fn decode_channel_keys(keys: Vec<Vec<u8>>) -> Result<Vec<ChannelKey>, MobileMeshError> {
    keys.into_iter()
        .map(|key| {
            <[u8; 32]>::try_from(key.as_slice())
                .map(ChannelKey)
                .map_err(|_| MobileMeshError::InvalidChannelKey)
        })
        .collect()
}

/// The canonical fixed-width Base58 rendering of a peer key, matching what
/// `decode_peer` accepts and what the platform stores as an address.
fn encode_peer_address(peer: &PublicKey) -> String {
    umsh_core::base58::encode(&peer.0)
        .into_iter()
        .map(char::from)
        .collect()
}

fn emit_ping_failure(events: &NotifyingSender<MobileMeshPingEventRecord>, operation_id: u64) {
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

    /// The 3-byte hint a node's multicast frames claim, which is the leading
    /// bytes of its public key.
    fn hint_of(identity: &MobileIdentity) -> Vec<u8> {
        decode_peer(&address(identity)).unwrap().0[..3].to_vec()
    }

    async fn channel_session(name: &str) -> Arc<MobileMeshSession> {
        let directory = tempfile::tempdir().unwrap();
        let store = MobileCounterStore::new(directory.path().join(name).display().to_string())
            .unwrap();
        // The temp directory must outlive the session's counter store.
        std::mem::forget(directory);
        MobileMeshSession::new(identity(31), store).await.unwrap()
    }

    #[tokio::test]
    async fn channel_registration_is_idempotent_and_reversible() {
        let session = channel_session("channels").await;
        let key = vec![0x5au8; 32];

        session.register_channels(vec![key.clone()]).await.unwrap();
        // Re-registering an already-joined channel restates the current
        // state, which is what a session-start replay does.
        session.register_channels(vec![key.clone()]).await.unwrap();
        session.remove_channels(vec![key.clone()]).await.unwrap();
        // Leaving a channel that is not joined is likewise not an error.
        session.remove_channels(vec![key.clone()]).await.unwrap();
        // And the key can come back afterwards.
        session.register_channels(vec![key]).await.unwrap();
    }

    #[tokio::test]
    async fn channel_keys_must_be_full_length() {
        let session = channel_session("shortkey").await;
        assert_eq!(
            session.register_channels(vec![vec![0x01; 31]]).await,
            Err(MobileMeshError::InvalidChannelKey)
        );
        assert_eq!(
            session.remove_channels(vec![Vec::new()]).await,
            Err(MobileMeshError::InvalidChannelKey)
        );
    }

    #[tokio::test]
    async fn the_phone_mac_holds_more_channels_than_the_embedded_default() {
        let session = channel_session("capacity").await;
        // Distinct keys, one per slot the phone advertises.
        let keys: Vec<Vec<u8>> = (0..MOBILE_MAC_CHANNELS)
            .map(|index| {
                let mut key = vec![0u8; 32];
                key[0] = index as u8;
                key[1] = 0xA5;
                key
            })
            .collect();
        assert!(keys.len() > umsh_mac::DEFAULT_CHANNELS);
        session.register_channels(keys).await.unwrap();

        let overflow = vec![vec![0xFFu8; 32]];
        assert_eq!(
            session.register_channels(overflow).await,
            Err(MobileMeshError::ChannelCapacity)
        );
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

    /// Drive one authenticated ping between the two sessions to completion,
    /// shuttling frames both ways.
    async fn complete_ping(alice: &MobileMeshSession, bob: &MobileMeshSession, target: String) {
        let operation = alice.ping(target, 2_000).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
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
                break;
            }
            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
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
    async fn removed_peer_re_registers_cleanly_and_traffic_still_flows() {
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
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();

        alice
            .register_peers(vec![address(&bob_identity)])
            .await
            .unwrap();
        bob.register_peers(vec![address(&alice_identity)])
            .await
            .unwrap();
        complete_ping(&alice, &bob, address(&bob_identity)).await;

        // Removal is idempotent — an unknown peer and a double removal are
        // both fine — and must not disturb the session.
        alice
            .remove_peers(vec![address(&bob_identity)])
            .await
            .unwrap();
        alice
            .remove_peers(vec![address(&bob_identity)])
            .await
            .unwrap();
        alice
            .remove_peers(vec![address(&alice_identity)])
            .await
            .unwrap();

        // Re-registering after removal starts from a clean slot; Bob's
        // replay state still accepts Alice because her TX counter is
        // identity-scoped and survived the peer-table churn.
        alice
            .register_peers(vec![address(&bob_identity)])
            .await
            .unwrap();
        complete_ping(&alice, &bob, address(&bob_identity)).await;
    }

    #[tokio::test]
    async fn discover_identities_emits_one_acceptable_zero_hop_broadcast() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(31);
        let bob_identity = identity(33);
        let alice_store =
            MobileCounterStore::new(directory.path().join("alice").display().to_string()).unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("bob").display().to_string()).unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();

        alice.discover_identities(None, Some(0x02)).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        let frames = loop {
            let update = alice.poll_update();
            if !update.outbound_frames.is_empty() {
                break update.outbound_frames;
            }
            assert!(Instant::now() < deadline, "solicitation never went out");
            std::thread::sleep(Duration::from_millis(5));
        };
        // One broadcast, no retries, no companions.
        assert_eq!(frames.len(), 1);
        let frame = frames.into_iter().next().unwrap();
        alice.complete_outbound_frame(frame.id, true).unwrap();
        let header = umsh_core::PacketHeader::parse(&frame.data).unwrap();
        assert_eq!(header.packet_type(), umsh_core::PacketType::Broadcast);
        // Zero-hop: no flood budget for repeaters to spend.
        assert!(header.flood_hops.is_none());
        // Full source, so a stranger can unicast its identity back.
        assert!(header.fcf.full_source());

        // A bystander session consumes the solicitation without error.
        // (Whether it answers is its responder's business — the full
        // reply loop is covered separately below.)
        bob.receive(MobileMeshRxRecord {
            data: frame.data,
            rssi_dbm: Some(-40),
            lqi: None,
            snr_cb: Some(100),
        })
        .unwrap();

        // An unrestricted ask still satisfies the rule that a broadcast
        // request carries at least one filter: it gets a zero-bit
        // capability filter, which every node matches.
        alice.discover_identities(None, None).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let frames = loop {
            let update = alice.poll_update();
            if !update.outbound_frames.is_empty() {
                break update.outbound_frames;
            }
            assert!(Instant::now() < deadline, "solicitation never went out");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(frames.len(), 1);
        let frame = frames.into_iter().next().unwrap();
        alice.complete_outbound_frame(frame.id, true).unwrap();
        let header = umsh_core::PacketHeader::parse(&frame.data).unwrap();
        let body = &frame.data[header.body_range.clone()];
        assert_eq!(body[0], umsh_core::PayloadType::MacCommand as u8);
        let umsh_node::MacCommand::IdentityRequest { options } =
            umsh_node::mac_command::parse(&body[1..]).unwrap()
        else {
            panic!("expected an identity request");
        };
        let has_vacuous_caps_filter = umsh_core::options::OptionDecoder::new(options)
            .filter_map(Result::ok)
            .any(|(number, value)| {
                number == umsh_node::mac_command::identity_filter::FILTER_NODE_CAPS && value == [0]
            });
        assert!(has_vacuous_caps_filter);
    }

    /// The whole discover loop between two strangers: Alice's zero-hop
    /// broadcast ask reaches Bob, Bob's default-on responder answers with
    /// a jittered authenticated unicast carrying his full source key, and
    /// Alice — who has never registered Bob — auto-registers him
    /// transiently, verifies the reply, and surfaces it as an
    /// advertisement event. This is the exact path the Discover sheet
    /// rides on hardware.
    #[tokio::test]
    async fn discover_solicitation_earns_a_stranger_reply_end_to_end() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(21);
        let bob_identity = identity(23);
        let alice_store =
            MobileCounterStore::new(directory.path().join("alice").display().to_string()).unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("bob").display().to_string()).unwrap();
        // Bob's reply is held for a random slice of the 30-second identity
        // response window. Virtual time collapses that wait whenever his
        // worker is otherwise idle, so the deadline below bounds the shuttle
        // loop rather than the protocol delay.
        let alice = MobileMeshSession::new_with_virtual_time(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new_with_virtual_time(bob_identity.clone(), bob_store)
            .await
            .unwrap();
        // Bob answers under a display name; Alice should hear it back.
        bob.set_discoverable(true, Some("Bob's phone".into()))
            .await
            .unwrap();

        alice.discover_identities(None, None).await.unwrap();

        // Shuttle frames both ways until Bob's identity lands at Alice.
        let bob_address = address(&bob_identity);
        let deadline = Instant::now() + Duration::from_secs(15);
        let event = 'outer: loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-40),
                    lqi: None,
                    snr_cb: Some(100),
                })
                .unwrap();
            }
            for event in alice_update.advertisement_events {
                if event.peer_address == bob_address {
                    break 'outer event;
                }
            }
            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
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
            assert!(Instant::now() < deadline, "no identity reply reached Alice");
            std::thread::sleep(Duration::from_millis(5));
        };
        // The reply is a MAC-authenticated unicast, not a broadcast the
        // platform still has to signature-check.
        assert!(event.source_authenticated);
        let payload = umsh_node::NodeIdentityPayload::from_bytes(&event.payload).unwrap();
        assert_eq!(payload.name.as_deref(), Some("Bob's phone"));

        // Opting out is honored: a fresh ask earns silence from Bob.
        bob.set_discoverable(false, None).await.unwrap();
        alice.discover_identities(None, None).await.unwrap();
        let quiet_until = Instant::now() + Duration::from_secs(6);
        while Instant::now() < quiet_until {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-40),
                    lqi: None,
                    snr_cb: Some(100),
                })
                .unwrap();
            }
            let bob_update = bob.poll_update();
            assert!(
                bob_update.outbound_frames.is_empty(),
                "Bob answered while not discoverable"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[tokio::test]
    async fn peer_route_is_visible_and_resettable() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(11);
        let bob_identity = identity(13);
        let alice_store =
            MobileCounterStore::new(directory.path().join("alice").display().to_string()).unwrap();
        let bob_store =
            MobileCounterStore::new(directory.path().join("bob").display().to_string()).unwrap();
        let alice = MobileMeshSession::new(alice_identity.clone(), alice_store)
            .await
            .unwrap();
        let bob = MobileMeshSession::new(bob_identity.clone(), bob_store)
            .await
            .unwrap();

        // A peer nobody has heard from has no route, and inspecting it must
        // not register the peer or invent one.
        assert_eq!(
            alice.peer_route(address(&bob_identity)).await.unwrap(),
            MobileMeshRouteRecord::unknown()
        );
        assert!(
            !alice
                .clear_peer_route(address(&bob_identity))
                .await
                .unwrap()
        );

        let operation = alice.ping(address(&bob_identity), 2_000).unwrap();
        let _ = bob.ping(address(&alice_identity), 2_000).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
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
                break;
            }

            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
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

        // The pong carried a trace route that accumulated no hints, because
        // there is no repeater between the two. That is a direct peer — not a
        // source route naming no routers, which would put an empty (and
        // meaningless) SourceRoute option on every packet alice sends back.
        let route = alice.peer_route(address(&bob_identity)).await.unwrap();
        assert_eq!(route.kind, MobileMeshRouteKind::Direct);
        assert!(route.hints.is_empty());
        assert_eq!(route.flood_hops, None);

        // Resetting reports that a route was held, and leaves the peer with
        // nothing cached. A second reset has nothing left to discard.
        assert!(
            alice
                .clear_peer_route(address(&bob_identity))
                .await
                .unwrap()
        );
        assert_eq!(
            alice.peer_route(address(&bob_identity)).await.unwrap(),
            MobileMeshRouteRecord::unknown()
        );
        assert!(
            !alice
                .clear_peer_route(address(&bob_identity))
                .await
                .unwrap()
        );

        // Clearing a route must not disturb the peer's crypto state: the next
        // ping still completes, and teaches the route again.
        let operation = alice.ping(address(&bob_identity), 2_000).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
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
                break;
            }

            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
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
            assert!(
                Instant::now() < deadline,
                "ping after reset did not complete"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            alice.peer_route(address(&bob_identity)).await.unwrap().kind,
            MobileMeshRouteKind::Direct
        );
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
        let bob = MobileMeshSession::new(bob_identity, bob_store)
            .await
            .unwrap();

        // The signed bundle used for QR/URI sharing verifies out of band.
        let bundle = alice
            .sign_identity_bundle(Some("Alice's Phone".to_owned()), Some(1_760_000_000))
            .await
            .unwrap();
        let record = crate::decode_node_identity(address(&alice_identity), bundle.clone()).unwrap();
        assert_eq!(record.signature, crate::IdentitySignatureState::Valid);
        assert_eq!(record.name.as_deref(), Some("Alice's Phone"));
        assert_eq!(record.role_label, "Chat");
        let uri = crate::node_uri_with_identity(address(&alice_identity), bundle).unwrap();
        assert!(
            crate::inspect_node_uri(uri)
                .unwrap()
                .identity_payload
                .is_some()
        );

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
            // Presence is reported for the same frame, independently of what
            // it carried: this is the only signal a payload-free beacon
            // produces, so it must not be conditional on a payload.
            let heard = bob_update.peer_heard_events;
            if let Some(event) = bob_update.advertisement_events.into_iter().next() {
                assert_eq!(
                    heard.iter().find_map(|record| record.peer_address.clone()),
                    Some(address(&alice_identity)),
                    "the frame that carried the advertisement also reported presence"
                );
                assert_eq!(event.peer_address, address(&alice_identity));
                // A broadcast has no MIC, so the platform is told the sender
                // was not authenticated and must fall back to the bundle's
                // own signature — which is why one is attached.
                assert!(!event.source_authenticated);
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

    struct TestWakeListener {
        signal: std_mpsc::Sender<()>,
    }

    impl MobileMeshWakeListener for TestWakeListener {
        fn on_update_pending(&self) {
            let _ = self.signal.send(());
        }
    }

    /// The wake listener replaces platform-side polling: it must fire when
    /// data becomes pending without any poll_update call, coalesce while
    /// pending, and re-arm after each drain.
    #[tokio::test]
    async fn wake_listener_fires_on_pending_data_and_rearms_after_drain() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(63);
        let silent_peer = identity(64);
        let store =
            MobileCounterStore::new(directory.path().join("wake").display().to_string()).unwrap();
        let session = MobileMeshSession::new(local_identity, store).await.unwrap();
        let (signal, wakes) = std_mpsc::channel();
        session.set_wake_listener(Arc::new(TestWakeListener { signal }));

        // The ping's outbound frame must announce itself with no polling.
        let operation = session.ping(address(&silent_peer), 100).unwrap();
        wakes
            .recv_timeout(Duration::from_secs(5))
            .expect("no wake for the outbound ping frame");

        let update = session.poll_update();
        assert!(
            !update.outbound_frames.is_empty(),
            "wake fired but nothing was pending"
        );
        for frame in update.outbound_frames {
            session.complete_outbound_frame(frame.id, true).unwrap();
        }

        // The drain re-armed the signal: the ping-timeout event a moment
        // later must produce a second wake.
        wakes
            .recv_timeout(Duration::from_secs(5))
            .expect("no wake for the ping timeout event");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let update = session.poll_update();
            if let Some(event) = update.ping_events.into_iter().next() {
                assert_eq!(event.operation_id, operation);
                assert_eq!(event.outcome, MobileMeshPingOutcome::TimedOut);
                break;
            }
            assert!(Instant::now() < deadline, "timeout event never surfaced");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A listener registered after data is already pending is told
    /// immediately instead of waiting for the next protocol event.
    #[tokio::test]
    async fn wake_listener_registered_late_fires_for_already_pending_data() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(65);
        let silent_peer = identity(66);
        let store =
            MobileCounterStore::new(directory.path().join("wake-late").display().to_string())
                .unwrap();
        let session = MobileMeshSession::new(local_identity, store).await.unwrap();

        session.ping(address(&silent_peer), 5_000).unwrap();
        // Give the worker time to enqueue the outbound frame first; even if
        // it loses this race, the enqueue itself fires the listener, so the
        // assertion below holds either way.
        std::thread::sleep(Duration::from_millis(200));

        let (signal, wakes) = std_mpsc::channel();
        session.set_wake_listener(Arc::new(TestWakeListener { signal }));
        wakes
            .recv_timeout(Duration::from_secs(5))
            .expect("late-registered listener never fired");
        assert!(!session.poll_update().outbound_frames.is_empty());
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
        assert_eq!(batch.checkpoint.conversation_address, address(&bob_identity));
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
    async fn ulcp_link_failure_terminates_pending_chat_delivery() {
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
                "link failure did not terminate chat delivery"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A ULCP-link failure declared while one fragment awaits physical
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

    /// A group message crosses two real sessions over a shared channel key.
    ///
    /// Multicast has no acknowledgement, so the sender's terminal state is
    /// `Sent`; the receiver attributes the message to a claimed hint and,
    /// because group sends carry the full source, resolves that hint to a
    /// real address it can name.
    #[tokio::test]
    async fn a_channel_group_message_crosses_two_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(61);
        let bob_identity = identity(62);
        let alice = MobileMeshSession::new(
            alice_identity.clone(),
            MobileCounterStore::new(directory.path().join("ch-alice").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();
        let bob = MobileMeshSession::new(
            bob_identity.clone(),
            MobileCounterStore::new(directory.path().join("ch-bob").display().to_string()).unwrap(),
        )
        .await
        .unwrap();

        let key = vec![0x5Cu8; 32];
        let conversation = crate::channel_conversation_address(key.clone()).unwrap();
        assert!(conversation.starts_with("ch:"));
        alice.register_channels(vec![key.clone()]).await.unwrap();
        bob.register_channels(vec![key]).await.unwrap();

        let batch = alice
            .compose_text(conversation.clone(), 1, "regroup at the ridge".to_owned())
            .await
            .unwrap();
        assert_eq!(batch.checkpoint.conversation_address, conversation);
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        let mut alice_states = Vec::new();
        let mut received: Option<MobileChatMutationRecord> = None;
        let mut resolution: Option<MobileChatSenderResolutionRecord> = None;
        // The sender's delivery state lands on a later protocol tick than the
        // receiver's transcript, so all three are waited for together.
        let deadline = Instant::now() + Duration::from_secs(10);
        while received.is_none()
            || resolution.is_none()
            || !alice_states.contains(&MobileChatDeliveryState::Sent)
        {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-70),
                    lqi: None,
                    snr_cb: Some(60),
                })
                .unwrap();
            }
            alice_states.extend(
                alice_update
                    .chat_deliveries
                    .iter()
                    .map(|delivery| delivery.state),
            );
            if let Some(batch_id) = alice_update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }

            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
                bob.complete_outbound_frame(frame.id, true).unwrap();
            }
            if let Some(record) = bob_update
                .chat_mutations
                .iter()
                .find(|mutation| mutation.body.as_deref() == Some("regroup at the ridge"))
            {
                received = Some(record.clone());
            }
            if let Some(record) = bob_update.chat_sender_resolutions.first() {
                resolution = Some(record.clone());
            }
            if let Some(batch_id) = bob_update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "group message incomplete (mutation: {}, resolution: {}, states: {alice_states:?})",
                received.is_some(),
                resolution.is_some()
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let received = received.unwrap();
        assert_eq!(received.conversation_address.as_deref(), Some(&conversation[..]));
        assert_eq!(received.direction, Some(MobileChatDirection::Inbound));
        // The hint is what the wire carried; the address is what the full
        // source let the facade resolve it to.
        assert_eq!(
            received.sender_hint.as_deref(),
            Some(&hint_of(&alice_identity)[..])
        );
        assert_eq!(
            received.sender_address.as_deref(),
            Some(&address(&alice_identity)[..])
        );
        let rx = received.rx.expect("a received frame carries radio metadata");
        assert_eq!(rx.rssi_dbm, Some(-70));
        assert_eq!(rx.snr_centibels, Some(60));
        // Heard directly off the air: no repeater carried it, so nothing
        // accumulated.
        assert_eq!(rx.hop_count, Some(0));

        let resolution = resolution.unwrap();
        assert_eq!(resolution.conversation_address, conversation);
        assert_eq!(resolution.sender_hint, hint_of(&alice_identity));
        assert_eq!(resolution.sender_address, address(&alice_identity));

        // Nothing acknowledges a multicast, so `Sent` is where it ends.
        assert!(alice_states.contains(&MobileChatDeliveryState::Sent));
        assert!(!alice_states.contains(&MobileChatDeliveryState::Acknowledged));
    }

    /// `EMERGENCY` chat goes out readable, and unreadable copies are ignored.
    ///
    /// The two halves are one rule seen from both ends, so they are proven
    /// together: what leaves carries no encryption, and a frame that arrives
    /// encrypted is refused however well it authenticates. The refused frame
    /// here is byte-for-byte the payload the accepted one carries, sealed
    /// under the same channel key by the same sender — encryption is the only
    /// difference between the message that is shown and the message that is
    /// not.
    #[tokio::test]
    async fn emergency_chat_is_sent_readable_and_encrypted_copies_are_refused() {
        use umsh_core::{MicSize, PacketBuilder, PacketHeader};
        use umsh_crypto::{
            CryptoEngine, PairwiseKeys,
            software::{SoftwareAes, SoftwareSha256},
        };

        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(71);
        let alice = MobileMeshSession::new(
            alice_identity.clone(),
            MobileCounterStore::new(directory.path().join("sos-alice").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();
        let bob = MobileMeshSession::new(
            identity(72),
            MobileCounterStore::new(directory.path().join("sos-bob").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();

        let key = crate::inspect_channel_name(crate::EMERGENCY_CHANNEL_NAME.to_owned())
            .unwrap()
            .key;
        let conversation = crate::channel_conversation_address(key.clone()).unwrap();
        alice.register_channels(vec![key.clone()]).await.unwrap();
        bob.register_channels(vec![key.clone()]).await.unwrap();

        let body = "tower down at mile 14";
        let batch = alice
            .compose_text(conversation.clone(), 1, body.to_owned())
            .await
            .unwrap();
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        // Collect what Alice puts on the air. A message this short is one
        // frame; anything else the session emits is not a multicast on this
        // channel and is filtered out below.
        let engine = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let channel_keys =
            engine.derive_channel_keys(&crate::channel_key_from_bytes(&key).unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut frame = None;
        while frame.is_none() {
            for outbound in alice.poll_update().outbound_frames {
                alice.complete_outbound_frame(outbound.id, true).unwrap();
                let header = match PacketHeader::parse(&outbound.data) {
                    Ok(header) => header,
                    Err(_) => continue,
                };
                if header.channel == Some(channel_keys.channel_id)
                    && header.packet_type() == umsh_core::PacketType::Multicast
                {
                    frame = Some((outbound.data, header));
                }
            }
            assert!(Instant::now() < deadline, "no emergency frame was sent");
            std::thread::sleep(Duration::from_millis(5));
        }
        let (frame, header) = frame.unwrap();

        // Half one: it left in the clear.
        let sec_info = header.sec_info.expect("a multicast frame carries SECINFO");
        assert!(
            !sec_info.scf.encrypted(),
            "emergency chat must be readable by any node in range"
        );
        assert!(
            matches!(header.source, umsh_core::SourceAddrRef::FullKeyAt { .. }),
            "emergency chat must name its sender outright"
        );

        // Half two: the same payload, from the same sender, under the same
        // channel key — encrypted. It authenticates perfectly and must still
        // be refused. An earlier frame counter keeps it ahead of the real
        // frame in the channel's replay window, so the genuine copy that
        // follows is judged on its own merits.
        let payload = {
            let mut opened = frame.clone();
            let range = engine
                .open_packet(
                    &mut opened,
                    &header,
                    &PairwiseKeys {
                        k_enc: channel_keys.k_enc,
                        k_mic: channel_keys.k_mic,
                    },
                )
                .unwrap();
            opened[range].to_vec()
        };
        assert!(
            sec_info.frame_counter > 0,
            "the forged copy needs a lower counter than the genuine one"
        );
        let alice_key = decode_peer(&address(&alice_identity)).unwrap();
        let mut buf = [0u8; 256];
        let mut forged = PacketBuilder::new(&mut buf)
            .multicast(channel_keys.channel_id)
            .source_full(&alice_key)
            .frame_counter(sec_info.frame_counter - 1)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(&payload)
            .build()
            .unwrap();
        engine
            .seal_packet(
                &mut forged,
                &PairwiseKeys {
                    k_enc: channel_keys.k_enc,
                    k_mic: channel_keys.k_mic,
                },
            )
            .unwrap();
        bob.receive(MobileMeshRxRecord {
            data: forged.as_bytes().to_vec(),
            rssi_dbm: Some(-70),
            lqi: None,
            snr_cb: Some(60),
        })
        .unwrap();

        let mut refusal = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while refusal.is_none() {
            let update = bob.poll_update();
            assert!(
                !update
                    .chat_mutations
                    .iter()
                    .any(|mutation| mutation.body.as_deref() == Some(body)),
                "an encrypted emergency frame reached the transcript"
            );
            refusal = update
                .chat_diagnostics
                .iter()
                .find(|line| line.contains("emergency-channel"))
                .cloned();
            if let Some(batch_id) = update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            assert!(Instant::now() < deadline, "the encrypted copy was not refused");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(refusal.unwrap().contains("encrypted"));

        // And the genuine one, differing only in that it is readable, lands.
        bob.receive(MobileMeshRxRecord {
            data: frame,
            rssi_dbm: Some(-70),
            lqi: None,
            snr_cb: Some(60),
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut received = false;
        while !received {
            let update = bob.poll_update();
            received = update
                .chat_mutations
                .iter()
                .any(|mutation| mutation.body.as_deref() == Some(body));
            if let Some(batch_id) = update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            assert!(Instant::now() < deadline, "the readable copy never arrived");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Repair still works once emergency traffic stops being encrypted.
    ///
    /// A resend request goes out channel-addressed and, on `EMERGENCY`, in
    /// the clear, so it is a frame the receiving gate now judges: were the
    /// two halves of the rule out of step, a dropped fragment there could
    /// never be recovered and a long emergency message would never assemble.
    ///
    /// It also covers group repair as such, which nothing else does: it is
    /// the only test where a member has to ask for a fragment and get it.
    /// Two separate faults used to stop that dead — the requester could not
    /// address a channel member it had never registered as a peer, and the
    /// sender refused to serve any frame still sitting in `in_flight`, which
    /// a multicast never left. Either one alone leaves this failing.
    ///
    /// Runs on the real clock, and takes the repair grace period in real
    /// seconds because of it. Virtual time is faster but not usable here:
    /// the runtime leaps to the next deadline whenever it is idle, and a
    /// test that drives it from outside idles constantly, so under load the
    /// reassembly can age out its whole 90-second lifetime between two
    /// polls.
    #[tokio::test]
    async fn a_dropped_emergency_fragment_is_repaired() {
        let directory = tempfile::tempdir().unwrap();
        let alice = MobileMeshSession::new(
            identity(73),
            MobileCounterStore::new(directory.path().join("sos-frag-a").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();
        let bob = MobileMeshSession::new(
            identity(74),
            MobileCounterStore::new(directory.path().join("sos-frag-b").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();

        let key = crate::inspect_channel_name(crate::EMERGENCY_CHANNEL_NAME.to_owned())
            .unwrap()
            .key;
        let conversation = crate::channel_conversation_address(key.clone()).unwrap();
        alice.register_channels(vec![key.clone()]).await.unwrap();
        bob.register_channels(vec![key]).await.unwrap();

        let body: String = (0..600).map(|index| char::from(b'a' + (index % 26) as u8)).collect();
        let batch = alice
            .compose_text(conversation.clone(), 1, body.clone())
            .await
            .unwrap();
        assert!(batch.mutations[0].fragment_count.unwrap() > 1);
        // Alice's own archive, as the platform would keep it: the only thing
        // she can answer a resend request out of.
        let archives: std::collections::HashMap<(u8, Option<u8>), Vec<u8>> = batch
            .archives
            .iter()
            .map(|archive| {
                (
                    (archive.message_id, archive.fragment_index),
                    archive.payload.clone(),
                )
            })
            .collect();
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        let mut sent = 0;
        let mut repairs = 0;
        let mut assembled: Option<String> = None;
        let deadline = Instant::now() + Duration::from_secs(40);
        while assembled.as_deref() != Some(body.as_str()) {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                sent += 1;
                // The radio eats the second fragment. Everything after it
                // gets through, so only a repair can complete the message.
                if sent == 2 {
                    continue;
                }
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-70),
                    lqi: None,
                    snr_cb: Some(60),
                })
                .unwrap();
            }
            for lookup in &alice_update.chat_archive_lookups {
                match archives.get(&(lookup.message_id, lookup.fragment_index)) {
                    Some(payload) => alice
                        .apply_chat_archive_result(
                            lookup.request_id,
                            MobileChatArchiveResultKind::Found,
                            payload.clone(),
                        )
                        .unwrap(),
                    None => alice
                        .apply_chat_archive_result(
                            lookup.request_id,
                            MobileChatArchiveResultKind::Unknown,
                            Vec::new(),
                        )
                        .unwrap(),
                }
            }
            if let Some(batch_id) = alice_update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }

            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
                bob.complete_outbound_frame(frame.id, true).unwrap();
                repairs += 1;
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-70),
                        lqi: None,
                        snr_cb: Some(60),
                    })
                    .unwrap();
            }
            for mutation in &bob_update.chat_mutations {
                if let Some(text) = mutation.body.as_deref() {
                    assembled = Some(text.to_owned());
                }
            }
            if let Some(batch_id) = bob_update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "a dropped emergency fragment was never repaired \
                 ({repairs} repair frame(s), assembled {:?})",
                assembled.as_ref().map(|text| text.len())
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(repairs > 0, "the message assembled without any repair");
    }

    /// A repeater's copy of our own group message is not a second message.
    ///
    /// Every multicast send carries our full source address so strangers can
    /// address repairs to us, which means a relayed copy comes back naming us
    /// as the sender. Feeding that to the transcript would show the user
    /// their own message twice — once as sent, once as received from
    /// themselves.
    #[tokio::test]
    async fn a_relayed_copy_of_our_own_group_message_is_not_transcribed() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity(67);
        let session = MobileMeshSession::new(
            identity.clone(),
            MobileCounterStore::new(directory.path().join("echo").display().to_string()).unwrap(),
        )
        .await
        .unwrap();

        let key = vec![0x3Eu8; 32];
        let conversation = crate::channel_conversation_address(key.clone()).unwrap();
        session.register_channels(vec![key]).await.unwrap();

        let batch = session
            .compose_text(conversation.clone(), 1, "anyone out there".to_owned())
            .await
            .unwrap();
        session.commit_chat_batch(batch.batch_id).await.unwrap();

        // Feed every frame the session emits straight back into it, which is
        // exactly what a repeater in range does.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut echoed = 0;
        let mut inbound = Vec::new();
        while echoed == 0 || Instant::now() < deadline.min(Instant::now() + Duration::from_millis(1))
        {
            let update = session.poll_update();
            for frame in update.outbound_frames {
                session.complete_outbound_frame(frame.id, true).unwrap();
                session
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-60),
                        lqi: None,
                        snr_cb: Some(70),
                    })
                    .unwrap();
                echoed += 1;
            }
            inbound.extend(
                update
                    .chat_mutations
                    .iter()
                    .filter(|mutation| mutation.direction == Some(MobileChatDirection::Inbound))
                    .cloned(),
            );
            if let Some(batch_id) = update.chat_batch_id {
                session.acknowledge_chat_batch(batch_id).unwrap();
            }
            if echoed > 0 && Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
            if echoed > 0 {
                // Give the echo every chance to be (wrongly) transcribed.
                for _ in 0..20 {
                    let update = session.poll_update();
                    inbound.extend(
                        update
                            .chat_mutations
                            .iter()
                            .filter(|mutation| {
                                mutation.direction == Some(MobileChatDirection::Inbound)
                            })
                            .cloned(),
                    );
                    if let Some(batch_id) = update.chat_batch_id {
                        session.acknowledge_chat_batch(batch_id).unwrap();
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                break;
            }
        }

        assert!(echoed > 0, "the session never transmitted the message");
        assert!(
            inbound.is_empty(),
            "our own relayed message was transcribed as inbound: {inbound:?}"
        );
    }

    /// Composing needs a channel this session actually holds: an address for
    /// an unregistered key, and an address for a channel that was left, are
    /// both refused rather than silently sent nowhere.
    #[tokio::test]
    async fn composing_to_an_unheld_channel_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let session = MobileMeshSession::new(
            identity(63),
            MobileCounterStore::new(directory.path().join("unheld").display().to_string()).unwrap(),
        )
        .await
        .unwrap();

        let key = vec![0x77u8; 32];
        let conversation = crate::channel_conversation_address(key.clone()).unwrap();
        assert_eq!(
            session
                .compose_text(conversation.clone(), 1, "hello".to_owned())
                .await,
            Err(MobileMeshError::UnknownConversation)
        );

        session.register_channels(vec![key.clone()]).await.unwrap();
        let batch = session
            .compose_text(conversation.clone(), 2, "hello".to_owned())
            .await
            .expect("a joined channel composes");
        // Rejected rather than committed: this test is about which addresses
        // resolve, and an uncommitted batch would block the next compose.
        session
            .reject_chat_batch(batch.batch_id, Vec::new())
            .await
            .unwrap();

        session.remove_channels(vec![key]).await.unwrap();
        assert_eq!(
            session.compose_text(conversation, 3, "hello".to_owned()).await,
            Err(MobileMeshError::UnknownConversation)
        );
    }

    /// A malformed conversation address is rejected the same way, rather than
    /// being taken for a peer address and failing somewhere less obvious.
    #[tokio::test]
    async fn a_malformed_conversation_address_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let session = MobileMeshSession::new(
            identity(64),
            MobileCounterStore::new(directory.path().join("malformed").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();
        for address in ["ch:not-hex", "ch:0011", "definitely not base58 !!"] {
            assert_eq!(
                session
                    .compose_text(address.to_owned(), 1, "hello".to_owned())
                    .await,
                Err(MobileMeshError::UnknownConversation),
                "{address} should not resolve to a conversation"
            );
        }
    }

    /// Direct chat keeps working, and now reports the radio metadata of the
    /// frame each inbound message arrived on.
    #[tokio::test]
    async fn direct_chat_still_delivers_and_now_carries_radio_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(65);
        let bob_identity = identity(66);
        let alice = MobileMeshSession::new(
            alice_identity.clone(),
            MobileCounterStore::new(directory.path().join("dm-alice").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();
        let bob = MobileMeshSession::new(
            bob_identity.clone(),
            MobileCounterStore::new(directory.path().join("dm-bob").display().to_string()).unwrap(),
        )
        .await
        .unwrap();
        let bob_address = address(&bob_identity);
        alice.register_peers(vec![bob_address.clone()]).await.unwrap();
        bob.register_peers(vec![address(&alice_identity)])
            .await
            .unwrap();

        let batch = alice
            .compose_text(bob_address.clone(), 1, "still here".to_owned())
            .await
            .unwrap();
        assert_eq!(batch.checkpoint.conversation_address, bob_address);
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        let received = loop {
            let alice_update = alice.poll_update();
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-55),
                    lqi: None,
                    snr_cb: Some(75),
                })
                .unwrap();
            }
            if let Some(batch_id) = alice_update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }
            let bob_update = bob.poll_update();
            for frame in bob_update.outbound_frames {
                bob.complete_outbound_frame(frame.id, true).unwrap();
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-55),
                        lqi: None,
                        snr_cb: Some(75),
                    })
                    .unwrap();
            }
            let found = bob_update
                .chat_mutations
                .iter()
                .find(|mutation| mutation.body.as_deref() == Some("still here"))
                .cloned();
            if let Some(batch_id) = bob_update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            if let Some(found) = found {
                break found;
            }
            assert!(Instant::now() < deadline, "the direct message never arrived");
            std::thread::sleep(Duration::from_millis(5));
        };

        assert_eq!(
            received.conversation_address.as_deref(),
            Some(&address(&alice_identity)[..])
        );
        // A direct sender is individually authenticated, so there is no hint
        // standing in for an identity.
        assert_eq!(received.sender_hint, None);
        assert_eq!(
            received.sender_address.as_deref(),
            Some(&address(&alice_identity)[..])
        );
        let rx = received.rx.expect("a received frame carries radio metadata");
        assert_eq!(rx.rssi_dbm, Some(-55));
        assert_eq!(rx.snr_centibels, Some(75));
        assert!(rx.source_authenticated);
    }

    /// A batch id is issued exactly when the batch has events in it, and never
    /// otherwise. The platform reads the id as its whole signal to apply and
    /// acknowledge, so a batch made of only one kind of event — a lone sender
    /// resolution, say — must still be announced. One batch left
    /// unacknowledged holds the slot for the rest of the session, and every
    /// delivery receipt behind it never arrives: messages transmit fine and
    /// stay on "Sending" forever, in every conversation at once.
    fn assert_batch_id_matches_events(update: &MobileMeshSessionUpdateRecord) {
        let has_events = !update.chat_mutations.is_empty()
            || !update.chat_deliveries.is_empty()
            || !update.chat_archive_lookups.is_empty()
            || !update.chat_sender_resolutions.is_empty()
            || !update.chat_diagnostics.is_empty();
        assert_eq!(
            update.chat_batch_id.is_some(),
            has_events,
            "batch id {:?} disagrees with the batch's contents",
            update.chat_batch_id
        );
    }

    /// A fragmented group message must arrive whole.
    ///
    /// Multicast is never acknowledged, so nothing downstream may treat an ack
    /// as the signal to release the next fragment: every fragment has to reach
    /// the air on transmission alone.
    #[tokio::test]
    async fn a_fragmented_channel_group_message_arrives_whole() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(71);
        let bob_identity = identity(72);
        let alice = MobileMeshSession::new(
            alice_identity.clone(),
            MobileCounterStore::new(directory.path().join("frag-alice").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();
        let bob = MobileMeshSession::new(
            bob_identity.clone(),
            MobileCounterStore::new(directory.path().join("frag-bob").display().to_string())
                .unwrap(),
        )
        .await
        .unwrap();

        let key = vec![0x9Au8; 32];
        let conversation = crate::channel_conversation_address(key.clone()).unwrap();
        alice.register_channels(vec![key.clone()]).await.unwrap();
        bob.register_channels(vec![key]).await.unwrap();

        // Comfortably past a single frame, so the engine must fragment.
        let body: String = (0..600).map(|index| char::from(b'a' + (index % 26) as u8)).collect();
        let batch = alice
            .compose_text(conversation.clone(), 1, body.clone())
            .await
            .unwrap();
        let fragments = batch.mutations[0].fragment_count.unwrap();
        assert!(fragments > 1, "the test body must fragment, got {fragments}");
        alice.commit_chat_batch(batch.batch_id).await.unwrap();

        let mut transmitted = 0;
        let mut repairs = 0;
        let mut assembled: Option<String> = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while assembled.as_deref() != Some(body.as_str()) {
            let alice_update = alice.poll_update();
            assert_batch_id_matches_events(&alice_update);
            for frame in alice_update.outbound_frames {
                alice.complete_outbound_frame(frame.id, true).unwrap();
                transmitted += 1;
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-70),
                    lqi: None,
                    snr_cb: Some(60),
                })
                .unwrap();
            }
            if let Some(batch_id) = alice_update.chat_batch_id {
                alice.acknowledge_chat_batch(batch_id).unwrap();
            }

            let bob_update = bob.poll_update();
            assert_batch_id_matches_events(&bob_update);
            for frame in bob_update.outbound_frames {
                bob.complete_outbound_frame(frame.id, true).unwrap();
                // Bob has nothing to say on his own account: anything he
                // transmits is a request to have a fragment resent.
                repairs += 1;
                alice
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-70),
                        lqi: None,
                        snr_cb: Some(60),
                    })
                    .unwrap();
            }
            for mutation in &bob_update.chat_mutations {
                if let Some(text) = mutation.body.as_deref() {
                    assembled = Some(text.to_owned());
                }
            }
            if let Some(batch_id) = bob_update.chat_batch_id {
                bob.acknowledge_chat_batch(batch_id).unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "fragmented group message never completed \
                 ({transmitted} frame(s) transmitted of {fragments}, \
                 assembled {:?})",
                assembled.as_ref().map(|text| text.len())
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        // Every fragment reached the air off the original send. Had the
        // sender stalled waiting for an acknowledgement that a multicast
        // never produces, the message could only have completed through
        // Bob asking for the rest — so a repair here would mean the
        // transmit path is ack-gated even though the transcript recovered.
        assert!(
            transmitted >= usize::from(fragments),
            "only {transmitted} of {fragments} fragment(s) were transmitted"
        );
        assert_eq!(repairs, 0, "the message needed {repairs} repair request(s)");
    }
}
