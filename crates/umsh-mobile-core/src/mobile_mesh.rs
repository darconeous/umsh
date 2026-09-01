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
use umsh_hal::{
    Clock, CounterStore, KeyValueStore, Radio, RxBuffered, RxInfo, RxOrigin, Snr, TxError,
    TxOptions,
};
use umsh_mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::{
    Host, LocalNode, MacBackend, NodeCapabilities, NodeIdentityPayload, NodeIdentityProfile,
    NodeRole, PacketFamily, SendProgressTicket, Transport,
    location::{MAX_PRECISION, NodeLocation},
};
use umsh_sync::AsyncRefCell;
use umsh_text::engine::{ArchiveResult, DeliveryState, Destination};
use umsh_text::model::{ConversationKey, SenderScope};
use umsh_text::validate::{DeliveryPath, Envelope};
use umsh_ulcp::{frame, ids::prop, items};

use crate::mobile_chat::{
    ChannelRegistry, MobileChatArchiveLookupRecord, MobileChatArchiveResultKind,
    MobileChatCheckpointRecord, MobileChatComposeBatchRecord, MobileChatDeliveryRecord,
    MobileChatDirection, MobileChatMutationKind, MobileChatMutationRecord, MobileChatOriginalRef,
    MobileChatPresence, MobileChatRegardingRef, MobileChatRxMetadataRecord,
    MobileChatSenderResolutionRecord, MobileChatState,
};
use crate::ulcp::{UlcpPropertyFrameRecord, UlcpSyncRecord};
use crate::{MobileCounterStore, MobileError, MobileIdentity};

const MAX_FRAME_SIZE: usize = 256;
const DEFAULT_FRAME_TIME_MS: u32 = 800;
/// Flood-hop budget on a beacon. A beacon exists to publish a path, so it
/// has to travel far enough for there to be a path worth publishing.
const BEACON_FLOOD_HOPS: u8 = 5;

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
    /// A shared location did not name a place: a non-finite or
    /// out-of-range coordinate, or a precision the cell code cannot
    /// carry.
    InvalidLocation,
    /// A management request does not fit one Node Management payload, or
    /// asked for nothing at all.
    InvalidRequest,
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
            Self::InvalidLocation => "MESH_INVALID_LOCATION",
            Self::InvalidRequest => "MESH_INVALID_REQUEST",
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
    /// Radio links the response crossed, counting the final one into this
    /// device: a direct response is one hop. Absent on a reply that was
    /// source-routed without a trace route — it crossed hops nobody recorded,
    /// so no count is claimed.
    pub hop_count: Option<u8>,
    /// Authenticated intermediate-router hints, in source-to-destination order.
    /// The two endpoints are not included.
    pub route_hints: Vec<Vec<u8>>,
    /// Signal measurements for the final radio hop into this device.
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
}

/// How a Node Management operation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileMeshManagementOutcome {
    /// Not an ending: the operation is still running. Emitted while a
    /// device works through an answer larger than one frame, or while a
    /// whole-device read crawls; `remaining_octets` is what the device
    /// says it is still holding back.
    Progress,
    /// The device answered, and `answers` is what it said.
    Replied,
    /// A reset-class command, which a device answers with nothing at all.
    /// The acknowledgment is the completion.
    Acknowledged,
    /// Nothing came back before the exchange gave up. Over LoRa this is
    /// the ordinary shape of "out of range", not a malfunction.
    TimedOut,
    /// The operation could not be carried: an unroutable target, another
    /// operation already outstanding, or an answer that could not be read.
    /// A device that is not listing this phone as an administrator answers
    /// with silence rather than a refusal, so it arrives as `TimedOut`.
    Failed,
}

/// What occupied one position of a management answer.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshManagementAnswerRecord {
    pub property_id: u32,
    /// What the device reports the property is worth. A write is echoed
    /// with the value the device actually kept, which is not always the
    /// one that was sent.
    pub value: Option<Vec<u8>>,
    /// The status that stood in place of a value: refused, absent, or out
    /// of an administrator's reach.
    pub status_code: Option<u32>,
}

/// One report from an operation started with a `begin_management_*` call.
///
/// Several may arrive for one `operation_id`: any number of `Progress`
/// reports, then exactly one ending.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshManagementEventRecord {
    pub operation_id: u64,
    /// Canonical Base58 address of the device being managed.
    pub peer_address: String,
    pub outcome: MobileMeshManagementOutcome,
    /// The answers, in the order they were asked for.
    pub answers: Vec<MobileMeshManagementAnswerRecord>,
    /// The status when the device answered the whole exchange with one —
    /// what a save or a whole-table write reports.
    pub status_code: Option<u32>,
    /// Octets the device has yet to return of the answer it is part-way
    /// through, as of the last frame it sent.
    pub remaining_octets: Option<u32>,
    /// Properties a read has yet to ask for. Only `begin_management_fetch`
    /// reports it, and only while it is running.
    pub properties_remaining: Option<u32>,
}

/// What a reset-class command puts back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileMeshResetScope {
    /// `CMD_RST`: protocol state, leaving configuration alone.
    Protocol,
    /// `CMD_RESTORE`: the saved snapshot, discarding unsaved changes.
    Restore,
    /// `CMD_REBOOT`: nothing. The device power-cycles and comes back as
    /// itself, with everything it had persisted. A device without
    /// `CAP_REBOOT` answers `STATUS_UNIMPLEMENTED` rather than silence,
    /// which is the one reply this scope can produce.
    Reboot,
    /// `CMD_FACTORY_RESET`: everything, including the device's identity.
    /// A device that has forgotten its identity is a different node, and
    /// no longer reachable at the address this operation was sent to.
    Factory,
}

/// One position of a multi-property write.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshPropertyWriteRecord {
    pub property_id: u32,
    pub value: Vec<u8>,
}

/// The writes that state a whole device configuration, ordered, for a
/// device being configured across the mesh.
///
/// A phone holding a device open writes a configuration through
/// `MobileUlcpSession::configure_device`, which owns the ordering — the
/// PHY goes down first and comes back up last — and closes with a save.
/// An administrator has no session to hand a record to, only the record
/// its read produced, so it asks for the same writes here and sends them
/// with [`MobileMeshSession::begin_management_set_many`]. The reduction is
/// literally the same code, which is the point: the two paths cannot
/// drift into configuring a device differently.
///
/// `reported` is the device as a completed read found it. Its
/// capabilities decide which fields must be present, and the properties
/// it would not report are left out — writing one of those fails, and a
/// device fails the write it is on rather than the ones after it.
#[uniffi::export]
pub fn ulcp_device_config_writes(
    configuration: crate::ulcp::UlcpDeviceConfigRecord,
    reported: UlcpSyncRecord,
) -> Result<Vec<MobileMeshPropertyWriteRecord>, MobileMeshError> {
    let values = crate::ulcp::device_config_writes(configuration, &reported)
        .map_err(|_| MobileMeshError::InvalidRequest)?;
    Ok(values
        .into_iter()
        .map(|(property_id, value)| MobileMeshPropertyWriteRecord { property_id, value })
        .collect())
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

/// One repeater a repeater told this phone about, from a Peer Repeaters
/// Response.
///
/// Everything past the hint is optional because the answering node reports
/// only what it has: an identity supplies the name, position, and regions; a
/// reception supplies the signal; neither supplies the other. A hop that has
/// only been heard is named by a two-byte router hint, which is all a trace
/// reveals about it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshPeerRepeaterRecord {
    /// Three bytes when an identity named the peer, two when only a
    /// reception did.
    pub hint: Vec<u8>,
    pub name: Option<String>,
    pub rssi_dbm: Option<i16>,
    /// Signal-to-noise ratio in quarter-decibel steps, as the wire carries
    /// it.
    pub snr_quarter_db: Option<i16>,
    /// Minutes since the answering node last heard from this peer.
    pub last_heard_minutes: Option<u16>,
    /// The peer's position as a raw location cell, decodable with the
    /// location helpers.
    pub location: Option<Vec<u8>>,
    /// The 2-octet flood-forwarding codes the peer advertised.
    pub region_codes: Vec<Vec<u8>>,
}

/// The position this phone is willing to put in its identity.
///
/// Precision is the disclosure decision: the wire format carries a cell,
/// not a point, and the coordinate is reduced to that cell before it goes
/// anywhere. The platform hands over its best reading and the chosen cell
/// size; the truncation happens here, on this side of every send.
#[derive(Clone, Copy, Debug, PartialEq, uniffi::Record)]
pub struct MobileMeshSharedLocationRecord {
    pub latitude_degrees: f64,
    pub longitude_degrees: f64,
    /// Cell-code precision in bytes, 1–7. `ulcp_location_cell_meters`
    /// names the cell size each buys.
    pub precision_bytes: u8,
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
    /// Reports from operations started with `begin_management_*` or
    /// `begin_remote_sync`, in the order they were produced.
    pub management_events: Vec<MobileMeshManagementEventRecord>,
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
    /// The frame was replayed from the radio's inbound queue rather than
    /// received live; the signal fields are still the measurements taken at
    /// the original reception.
    pub was_buffered: bool,
    /// The radio already acknowledged the frame on this host's behalf.
    pub was_acknowledged: bool,
    /// Seconds the frame spent queued before delivery; zero for a live
    /// reception.
    pub age_seconds: u32,
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
    Manage {
        operation_id: u64,
        peer: PublicKey,
        request: ManagementRequest,
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
        /// Whether this is the phone's own schedule speaking rather than
        /// someone tapping a button. A scheduled advertisement reaches
        /// only the neighbours that can hear the phone directly.
        scheduled: bool,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    Beacon {
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
        /// Leading bytes of the one node's hint that should answer; two of
        /// them is a router hint.
        node_hint: Option<Vec<u8>>,
        /// Routers to steer the request through, in send order; empty for a
        /// zero-hop ask of this node's own neighbors.
        source_route: Vec<Vec<u8>>,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    RequestIdentityByHint {
        conversation_address: String,
        hint: NodeHint,
        response: oneshot::Sender<Result<(), MobileMeshError>>,
    },
    PeerRepeaters {
        peer: PublicKey,
        response: oneshot::Sender<Result<Vec<MobileMeshPeerRepeaterRecord>, MobileMeshError>>,
    },
    SetDiscoverable {
        enabled: bool,
        name: Option<String>,
        response: oneshot::Sender<()>,
    },
    /// Already reduced to the disclosed cell; `None` stops sharing.
    SetAdvertisedLocation {
        location: Option<NodeLocation>,
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

/// What kind of answer a management request expects, which is what makes
/// the reply frame readable.
#[derive(Clone, Debug)]
enum ReplyShape {
    /// A `CMD_PROP_IS` for this property, or a status standing in for it.
    Property(u32),
    /// A `CMD_PROP_ARE` covering these properties, in order.
    Entries(Vec<u32>),
    /// A bare `PROP_LAST_STATUS`, which is what a save reports.
    Status,
    /// Nothing at all: a reset-class command is completed by the
    /// acknowledgment.
    Acknowledgment,
}

/// What the phone was asked to do to a device over the mesh.
enum ManagementRequest {
    /// One request frame, already encoded, and the shape of its answer.
    One { frame: Vec<u8>, shape: ReplyShape },
    /// Read a named set of properties, in as many exchanges as it takes.
    Fetch {
        property_ids: Vec<u32>,
        multi_hint: bool,
    },
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
    Reaction {
        target: MobileChatRegardingRef,
        body: String,
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
                    origin: RxOrigin::Air,
                    buffered: frame.record.was_buffered.then_some(RxBuffered {
                        age_s: frame.record.age_seconds,
                        acked: frame.record.was_acknowledged,
                    }),
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

type MobileMac =
    Mac<MobilePlatform, { umsh_mac::DEFAULT_IDENTITIES }, MOBILE_MAC_PEERS, MOBILE_MAC_CHANNELS>;
const MOBILE_CHAT_TRANSMIT_WINDOW: usize = 8;

/// Long-lived Rust protocol engine used by the mobile app.
///
/// `ping` is the only ping operation exposed to Swift. The existing Rust node
/// layer owns its nonce, authenticated echo request, counter reservation,
/// response matching, and timeout.
#[derive(uniffi::Object)]
pub struct MobileMeshSession {
    /// This phone's node public key. Held here rather than asked of the
    /// worker: it never changes for the life of a session, and it is what
    /// a device has to list before this phone may manage it.
    local_key: PublicKey,
    commands: mpsc::UnboundedSender<WorkerCommand>,
    outbound: Mutex<std_mpsc::Receiver<MobileMeshOutboundFrameRecord>>,
    transmit_completions: Arc<BridgeTransmitCompletions>,
    events: Mutex<std_mpsc::Receiver<MobileMeshPingEventRecord>>,
    management: Mutex<std_mpsc::Receiver<MobileMeshManagementEventRecord>>,
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
        let operation_id = self.next_operation_id()?;
        self.commands
            .send(WorkerCommand::Ping {
                operation_id,
                peer,
                timeout_ms,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        Ok(operation_id)
    }

    /// This phone's own node public key, which is what a device lists in
    /// `PROP_DEV_ADMINS` to let this phone manage it over the mesh.
    ///
    /// Handing this to a radio the phone is attached to —
    /// `MobileUlcpSession::insert_device_admin` — is the whole of making
    /// this phone an administrator of that radio. Nothing else is
    /// exchanged: the session both ends derive comes from their two
    /// identities.
    pub fn node_public_key(&self) -> Vec<u8> {
        self.local_key.0.to_vec()
    }

    /// Read one property from a device across the mesh.
    ///
    /// Every `begin_management_*` call returns immediately with an
    /// operation identifier, and reports through `poll_update` — the same
    /// shape as `ping`, because it is the same kind of thing: a
    /// round-trip over a network that promises nothing. One operation runs
    /// at a time; starting another while one is outstanding fails it.
    pub fn begin_management_get(
        &self,
        peer_address: String,
        property_id: u32,
    ) -> Result<u64, MobileMeshError> {
        let frame = encode_management(|buf| frame::prop_get(buf, 0, property_id))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Property(property_id),
            },
        )
    }

    /// Write one property on a device across the mesh.
    ///
    /// The answer echoes what the property is now worth, which is what the
    /// device kept rather than what was sent. The change is live and
    /// unsaved; `begin_management_save` is what makes it survive a reboot.
    pub fn begin_management_set(
        &self,
        peer_address: String,
        property_id: u32,
        value: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        let frame = encode_management(|buf| frame::prop_set(buf, 0, property_id, &value))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Property(property_id),
            },
        )
    }

    /// Add one item to a multiple-value property on a device across the
    /// mesh — a peer key, an administrator key, a channel key.
    pub fn begin_management_insert(
        &self,
        peer_address: String,
        property_id: u32,
        item: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        let frame = encode_management(|buf| frame::prop_insert(buf, 0, property_id, &item))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Property(property_id),
            },
        )
    }

    /// Take one item out of a multiple-value property on a device across
    /// the mesh.
    pub fn begin_management_remove(
        &self,
        peer_address: String,
        property_id: u32,
        selector: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        let frame = encode_management(|buf| frame::prop_remove(buf, 0, property_id, &selector))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Property(property_id),
            },
        )
    }

    /// Let one more node manage this device over the mesh, by adding its
    /// public key to `PROP_DEV_ADMINS`.
    ///
    /// Named rather than left to [`Self::begin_management_insert`] for the
    /// same reason `MobileUlcpSession::insert_device_admin` is: this is a
    /// decision about who may configure a node, and a caller should not
    /// have to name the property — or be able to reach a different one by
    /// naming it wrong. The device holds it live until a save.
    pub fn begin_management_insert_admin(
        &self,
        peer_address: String,
        public_key: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        if public_key.len() != items::PUBLIC_KEY_LEN {
            return Err(MobileMeshError::InvalidRequest);
        }
        self.begin_management_insert(peer_address, prop::DEV_ADMINS, public_key)
    }

    /// Take a node's authority to manage this device away again.
    ///
    /// A device that removes the administrator it is answering keeps
    /// answering this exchange — the reply is already authorized — and
    /// refuses the next one.
    pub fn begin_management_remove_admin(
        &self,
        peer_address: String,
        public_key: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        if public_key.len() != items::PUBLIC_KEY_LEN {
            return Err(MobileMeshError::InvalidRequest);
        }
        self.begin_management_remove(peer_address, prop::DEV_ADMINS, public_key)
    }

    /// Store one more peer public key on a device's identity
    /// (`PROP_DEV_PEERS`), so it can hold a secure session with that node
    /// on its own.
    ///
    /// Named for the same reason the administrator pair is: the caller is
    /// deciding who a device talks to, not writing to a numbered property.
    /// Live until a save.
    pub fn begin_management_insert_peer(
        &self,
        peer_address: String,
        public_key: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        if public_key.len() != items::PUBLIC_KEY_LEN {
            return Err(MobileMeshError::InvalidRequest);
        }
        self.begin_management_insert(peer_address, prop::DEV_PEERS, public_key)
    }

    /// Drop a peer public key from a device's identity.
    pub fn begin_management_remove_peer(
        &self,
        peer_address: String,
        public_key: Vec<u8>,
    ) -> Result<u64, MobileMeshError> {
        if public_key.len() != items::PUBLIC_KEY_LEN {
            return Err(MobileMeshError::InvalidRequest);
        }
        self.begin_management_remove(peer_address, prop::DEV_PEERS, public_key)
    }

    /// Tell a device to make itself conspicuous, or to stop
    /// (`PROP_ALERT`).
    ///
    /// Live state, never saved: an alert is a thing happening now, and one
    /// restored at boot would be a device that woke up beeping. The device
    /// ends it on its own deadline as well, so a search that outlasts that
    /// is kept alive by asking again — the same contract as the local link,
    /// with the round trip of the mesh in front of it.
    pub fn begin_management_set_alert(
        &self,
        peer_address: String,
        state: crate::ulcp::UlcpAlertState,
    ) -> Result<u64, MobileMeshError> {
        let value = crate::ulcp::encode_alert_state(state).map_err(|_| {
            // The encoding is total over the enum; a failure here would be
            // a bug in this crate rather than anything the caller did.
            MobileMeshError::InvalidRequest
        })?;
        self.begin_management_set(peer_address, prop::ALERT, value)
    }

    /// Read several properties in one exchange.
    ///
    /// A device answers as many as fit and stops; the answers that arrive
    /// are the ones it sent, and the rest are simply absent. Requires
    /// `CAP_CMD_MULTI` on the device — one that lacks it refuses the whole
    /// request rather than answering part of it.
    pub fn begin_management_get_many(
        &self,
        peer_address: String,
        property_ids: Vec<u32>,
    ) -> Result<u64, MobileMeshError> {
        if property_ids.is_empty() {
            return Err(MobileMeshError::InvalidRequest);
        }
        let frame = encode_management(|buf| frame::prop_multi_get(buf, 0, &property_ids))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Entries(property_ids),
            },
        )
    }

    /// Write several properties in one exchange, in order.
    ///
    /// A device applies them until the next answer would not fit and stops
    /// there, so a short answer means the remainder was never attempted.
    /// Each position echoes what that property is now worth.
    pub fn begin_management_set_many(
        &self,
        peer_address: String,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<u64, MobileMeshError> {
        if writes.is_empty() {
            return Err(MobileMeshError::InvalidRequest);
        }
        let property_ids: Vec<u32> = writes.iter().map(|write| write.property_id).collect();
        let entries: Vec<(u32, &[u8])> = writes
            .iter()
            .map(|write| (write.property_id, write.value.as_slice()))
            .collect();
        let frame = encode_management(|buf| frame::prop_multi_set(buf, 0, &entries))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Entries(property_ids),
            },
        )
    }

    /// Persist a device's live configuration across the mesh.
    pub fn begin_management_save(&self, peer_address: String) -> Result<u64, MobileMeshError> {
        let frame = encode_management(|buf| frame::save(buf, 0))?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Status,
            },
        )
    }

    /// Reset a device across the mesh.
    ///
    /// A device answers a reset with nothing — it is busy doing what was
    /// asked — so the operation ends `Acknowledged` on the MAC
    /// acknowledgment. `Restore` on a device holding no snapshot resets
    /// nothing and answers like any other command, which arrives as an
    /// ordinary `Replied` status.
    pub fn begin_management_reset(
        &self,
        peer_address: String,
        scope: MobileMeshResetScope,
    ) -> Result<u64, MobileMeshError> {
        let frame = encode_management(|buf| match scope {
            MobileMeshResetScope::Protocol => frame::reset(buf, 0),
            MobileMeshResetScope::Restore => frame::restore(buf, 0),
            MobileMeshResetScope::Reboot => frame::reboot(buf, 0),
            MobileMeshResetScope::Factory => frame::factory_reset(buf, 0),
        })?;
        self.begin_management(
            peer_address,
            ManagementRequest::One {
                frame,
                shape: ReplyShape::Acknowledgment,
            },
        )
    }

    /// Read a named set of properties across the mesh.
    ///
    /// The caller names what it wants, in as many exchanges as the
    /// answers need — a screenful of settings is normally one. Every
    /// property comes back answered, refusals included, so a caller can
    /// tell "the device would not say" from "nobody asked".
    ///
    /// `multi_hint` says whether to open with a batched request. A device
    /// that declines one is asked again a property at a time, so the hint
    /// costs a round trip when wrong rather than an answer. Pass what
    /// `CAP_CMD_MULTI` last said, or true before anything has.
    ///
    /// Every exchange is airtime over a link that may be several hops
    /// deep. Ask for what a screen needs and no more.
    pub fn begin_management_fetch(
        &self,
        peer_address: String,
        property_ids: Vec<u32>,
        multi_hint: bool,
    ) -> Result<u64, MobileMeshError> {
        self.begin_management(
            peer_address,
            ManagementRequest::Fetch {
                property_ids,
                multi_hint,
            },
        )
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
        self.send_advertisement(name, timestamp, false).await
    }

    /// The same advertisement, sent because the phone's own interval came
    /// round rather than because someone asked for it.
    ///
    /// Reaches only direct neighbours. A repeated statement of who this
    /// phone is does not need to cross the mesh every time; introducing
    /// it, which is what the manual send does, is the case that does.
    pub async fn advertise_identity_scheduled(
        &self,
        name: Option<String>,
        timestamp: Option<u32>,
    ) -> Result<(), MobileMeshError> {
        self.send_advertisement(name, timestamp, true).await
    }

    async fn send_advertisement(
        &self,
        name: Option<String>,
        timestamp: Option<u32>,
        scheduled: bool,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::Advertise {
                name,
                timestamp,
                scheduled,
                response,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        result
            .await
            .map_err(|_| MobileMeshError::SessionUnavailable)?
    }

    /// Broadcast an empty beacon: no payload, so what it publishes is the
    /// path back to this phone rather than who this phone is. Costs a
    /// fraction of an advertisement.
    pub async fn send_beacon(&self) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::Beacon { response })
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

    /// Solicit identities with one broadcast MAC Identity Request, either
    /// from this node's own neighbors or from a remote vantage point.
    ///
    /// With an empty `source_route` the request goes out as a direct
    /// broadcast with no flood budget, so repeaters never carry it — the
    /// blast radius is exactly the nodes in radio range. Given a route, the
    /// request is steered along it instead: each repeater consumes its hint,
    /// so the request arrives with an empty Route option in the neighborhood
    /// the route ends at, and the nodes *there* are the ones that answer. A
    /// steered request also carries a trace route, which is what gives the
    /// answering strangers a path back — without it their replies would have
    /// no route and no flood budget, and would die on their own transmitter.
    ///
    /// Either way it carries this phone's full source address, so a matching
    /// node can reply with a targeted unicast without any prior contact;
    /// replies arrive as ordinary `NodeIdentity` advertisements on the
    /// receive path. `role_code` and `capability_bits` narrow which nodes
    /// respond (AND-combined when both are given); `None` for all three
    /// filters asks every node the request reaches.
    ///
    /// `node_hint` narrows the ask to one node by the leading bytes of its
    /// node hint. Two bytes is a router hint, which is all a route reveals
    /// about the hops it crosses: pair it with a route ending at the hop
    /// *before* the one in question, since a repeater consumes its own hint
    /// only when forwarding and drops a request that still names it.
    ///
    /// Each entry of `source_route` is one 2-byte router hint in send order.
    pub async fn discover_identities(
        &self,
        role_code: Option<u8>,
        capability_bits: Option<u8>,
        node_hint: Option<Vec<u8>>,
        source_route: Vec<Vec<u8>>,
    ) -> Result<(), MobileMeshError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::DiscoverIdentities {
                role_code,
                capability_bits,
                node_hint,
                source_route,
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

    /// Ask one repeater which repeaters it knows of, and return the whole
    /// listing.
    ///
    /// Unlike `discover_identities`, which scatters a request and lets the
    /// answers arrive as events, this is one node's own account of its
    /// neighborhood: a single addressed exchange, paged when it does not fit
    /// one frame, so it resolves to a list rather than a stream. Pages are
    /// followed here; the caller sees only the finished listing.
    pub async fn request_peer_repeaters(
        &self,
        peer: Vec<u8>,
    ) -> Result<Vec<MobileMeshPeerRepeaterRecord>, MobileMeshError> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| MobileMeshError::InvalidPeer)?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::PeerRepeaters {
                peer: PublicKey(peer),
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

    /// Set the position this phone's identity carries, or `None` to stop
    /// sharing one.
    ///
    /// Reaches every *live* identity payload — advertisements, manual and
    /// scheduled, and Identity Request replies while discoverable — but
    /// never the shareable QR/URI bundle: that bundle is durable, and a
    /// position frozen into it would go stale and then travel wherever
    /// the QR is pasted. The coordinate is reduced to the cell named by
    /// `precision_bytes` before it is stored, so nothing finer ever sits
    /// in this session, whatever later reads it.
    pub async fn set_advertised_location(
        &self,
        location: Option<MobileMeshSharedLocationRecord>,
    ) -> Result<(), MobileMeshError> {
        let location = location.map(disclosed_cell).transpose()?;
        let (response, result) = oneshot::channel();
        self.commands
            .send(WorkerCommand::SetAdvertisedLocation { location, response })
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

    /// React to a message with a short emote body, or withdraw an earlier
    /// reaction by passing an empty body. A sender has at most one live
    /// reaction per message: sending another simply supersedes it, so there
    /// is nothing to edit or delete.
    ///
    /// Unlike an edit, the target may be a message the peer sent, and usually
    /// one persisted before this launch; the reference carries the direction
    /// and (for channel groups) the sender hint needed to name it.
    pub async fn compose_reaction(
        &self,
        conversation_address: String,
        client_token: u32,
        target: MobileChatRegardingRef,
        body: String,
    ) -> Result<MobileChatComposeBatchRecord, MobileMeshError> {
        self.compose_chat(
            conversation_address,
            client_token,
            ChatComposeRequest::Reaction { target, body },
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
        let mut management_events = Vec::new();
        if let Ok(receiver) = self.management.lock() {
            management_events.extend(receiver.try_iter());
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
            management_events,
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
    /// Allocate an operation identifier and hand the request to the
    /// worker, which owns the administrator engine.
    fn begin_management(
        &self,
        peer_address: String,
        request: ManagementRequest,
    ) -> Result<u64, MobileMeshError> {
        let peer = decode_peer(&peer_address).map_err(|_| MobileMeshError::InvalidPeer)?;
        let operation_id = self.next_operation_id()?;
        self.commands
            .send(WorkerCommand::Manage {
                operation_id,
                peer,
                request,
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        Ok(operation_id)
    }

    fn next_operation_id(&self) -> Result<u64, MobileMeshError> {
        let mut next = self
            .next_operation_id
            .lock()
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        let current = *next;
        *next = next.wrapping_add(1).max(1);
        Ok(current)
    }

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
        let (management_tx, management) = std_mpsc::channel();
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
        let management_tx = NotifyingSender {
            tx: management_tx,
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
        let local_key = *worker_identity.public_key();
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
                        management_tx,
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
            local_key,
            commands,
            outbound: Mutex::new(outbound),
            transmit_completions,
            events: Mutex::new(events),
            management: Mutex::new(management),
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

/// Reduce a platform reading to the cell it discloses.
///
/// The integer path (`from_e7`) rather than the float one: it is exact at
/// every precision the format carries, so the cell a listener decodes is
/// the cell that was chosen, not its floating-point neighbour.
fn disclosed_cell(record: MobileMeshSharedLocationRecord) -> Result<NodeLocation, MobileMeshError> {
    if !(1..=MAX_PRECISION).contains(&record.precision_bytes)
        || !record.latitude_degrees.is_finite()
        || record.latitude_degrees.abs() > 90.0
        || !record.longitude_degrees.is_finite()
        || record.longitude_degrees.abs() > 180.0
    {
        return Err(MobileMeshError::InvalidLocation);
    }
    Ok(NodeLocation::from_e7(
        (record.latitude_degrees * 1e7).round() as i32,
        (record.longitude_degrees * 1e7).round() as i32,
        record.precision_bytes,
    ))
}

/// The identity profile the phone's Identity Request responder serves:
/// the same role Chat / Mobile + Text messages statement the signed
/// advertisement makes, with the display name truncated identically and
/// the same disclosed location, so a node that asks and a node that
/// listens hear one description.
fn phone_identity_profile(
    public_key: PublicKey,
    name: Option<&str>,
    location: Option<NodeLocation>,
) -> NodeIdentityProfile {
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
    profile.location = location;
    profile
}

/// Build the signed standalone node-identity bundle for this phone: role
/// Chat, capabilities Mobile + Text messages, optional display name
/// (truncated to the 24-byte wire limit on a character boundary), and the
/// disclosed location when one is being shared. The result is ROLE
/// through the trailing 64-byte signature, without the payload-type byte.
async fn build_signed_identity_bundle(
    signer: &SoftwareIdentity,
    name: Option<&str>,
    timestamp: Option<u32>,
    location: Option<NodeLocation>,
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
        location,
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

/// Flood-hop budget on a management request. A device worth managing
/// remotely is one that is not in the room, so an unrouted first request
/// has to be able to travel.
const MANAGEMENT_FLOOD_HOPS: u8 = 5;

/// How many properties one batch of a whole-device read asks for.
///
/// Small enough that a device answers most batches in one frame, and that
/// a batch lost to a timeout is cheap to have lost; a batch whose answer
/// does overflow is continued by the binding's own cursors, so this is not
/// a correctness bound.
const SYNC_BATCH: usize = 8;

/// Encode a management request, which must fit one Node Management
/// payload. The frame's TID is ignored over this binding — the envelope
/// token is what correlates a response — so every request carries zero.
fn encode_management(
    build: impl FnOnce(&mut [u8]) -> Result<usize, umsh_ulcp::frame::WriteError>,
) -> Result<Vec<u8>, MobileMeshError> {
    let mut buf = vec![0u8; umsh_node_mgmt::REQUEST_MAX];
    let len = build(&mut buf).map_err(|_| MobileMeshError::InvalidRequest)?;
    buf.truncate(len);
    Ok(buf)
}

/// A read of a named set of properties, one batch at a time.
///
/// The caller says what to ask for, which is what keeps a screenful of
/// settings from costing a whole-device read. Everything out of an
/// administrator's reach is dropped before a single frame goes on the
/// air.
struct FetchCrawl {
    /// Whether the device answers multi-property requests. A hint from
    /// the caller, corrected by the device the moment it declines one.
    multi: bool,
    /// What the outstanding request asked for, in order.
    asked: Vec<u32>,
    /// What is still to be asked for.
    pending: VecDeque<u32>,
    /// Every answer so far, refusals included: a property the device
    /// would not report is a different thing from one nobody asked for,
    /// and only the caller can tell what that means for its screen.
    answers: Vec<MobileMeshManagementAnswerRecord>,
}

impl FetchCrawl {
    fn new(properties: Vec<u32>, multi_hint: bool) -> Self {
        let mut pending = properties;
        pending.dedup();
        Self {
            multi: multi_hint,
            asked: Vec::new(),
            pending: pending.into(),
            answers: Vec::new(),
        }
    }

    /// The next request, or `None` when there is nothing left to ask.
    fn next_request(&mut self) -> Result<Option<Vec<u8>>, MobileMeshError> {
        let batch = if self.multi { SYNC_BATCH } else { 1 };
        self.asked = self
            .pending
            .drain(..batch.min(self.pending.len()))
            .collect();
        match self.asked.as_slice() {
            [] => Ok(None),
            [key] => encode_management(|buf| frame::prop_get(buf, 0, *key)).map(Some),
            keys => encode_management(|buf| frame::prop_multi_get(buf, 0, keys)).map(Some),
        }
    }

    /// Take in one answer.
    fn receive(&mut self, reply: &[u8]) -> Result<(), MobileMeshError> {
        if let [key] = self.asked.as_slice() {
            let key = *key;
            match umsh_ulcp::reply::property(key, reply) {
                Ok(answer) => self.answers.push(answer_record(key, answer)),
                Err(_) => return Err(MobileMeshError::InvalidRequest),
            }
            return Ok(());
        }

        let asked = core::mem::take(&mut self.asked);
        let Ok(entries) = umsh_ulcp::reply::entries(&asked, reply) else {
            // The device declined the command rather than the properties,
            // which is what one without `CAP_CMD_MULTI` does. Ask again one
            // at a time; the hint said otherwise, but the device is the
            // authority on itself.
            self.multi = false;
            for key in asked.into_iter().rev() {
                self.pending.push_front(key);
            }
            return Ok(());
        };
        let mut answered = 0usize;
        for (key, answer) in entries.flatten() {
            answered += 1;
            self.answers.push(answer_record(key, answer));
        }
        // A device stops before its answer overflows rather than
        // truncating one, so whatever it did not reach is simply asked for
        // again. An answer that reached nothing would ask forever, so that
        // batch is broken up instead.
        if answered == 0 {
            self.multi = false;
        }
        for key in asked.into_iter().skip(answered).rev() {
            self.pending.push_front(key);
        }
        Ok(())
    }
}

/// What the phone is doing with one device, and how to read what comes
/// back.
enum ManagementPlan {
    One(ReplyShape),
    Fetch(FetchCrawl),
}

/// One outstanding management operation.
struct ManagementJob<M: MacBackend> {
    operation_id: u64,
    peer: PublicKey,
    manager: umsh_node_mgmt::NodeManager<M>,
    plan: ManagementPlan,
    /// The last REMAINING reported, so progress is emitted when the device
    /// says something new rather than on every service call.
    reported_remaining: Option<u32>,
}

impl<M: MacBackend> ManagementJob<M> {
    fn event(&self, outcome: MobileMeshManagementOutcome) -> MobileMeshManagementEventRecord {
        MobileMeshManagementEventRecord {
            operation_id: self.operation_id,
            peer_address: encode_peer_address(&self.peer),
            outcome,
            answers: Vec::new(),
            status_code: None,
            remaining_octets: self.manager.remaining(),
            properties_remaining: match &self.plan {
                ManagementPlan::Fetch(crawl) => Some(crawl.pending.len() as u32),
                ManagementPlan::One(_) => None,
            },
        }
    }

    /// A report of what the device is still holding back, the first time
    /// it says so and whenever the number changes.
    fn progress(&mut self) -> Option<MobileMeshManagementEventRecord> {
        let remaining = self.manager.remaining();
        if remaining.is_none() || remaining == self.reported_remaining {
            return None;
        }
        self.reported_remaining = remaining;
        Some(self.event(MobileMeshManagementOutcome::Progress))
    }

    /// Read a finished exchange. `None` means another exchange was begun
    /// and the operation continues.
    fn settle(
        &mut self,
        outcome: umsh_node_mgmt::Outcome,
        now_ms: u64,
    ) -> Option<MobileMeshManagementEventRecord> {
        match outcome {
            umsh_node_mgmt::Outcome::Failed(umsh_node_mgmt::Failure::TimedOut) => {
                return Some(self.event(MobileMeshManagementOutcome::TimedOut));
            }
            umsh_node_mgmt::Outcome::Failed(_) => {
                return Some(self.event(MobileMeshManagementOutcome::Failed));
            }
            umsh_node_mgmt::Outcome::NoResponse => {
                return Some(match self.plan {
                    // Only a reset-class command is answered by nothing.
                    ManagementPlan::One(ReplyShape::Acknowledgment) => {
                        self.event(MobileMeshManagementOutcome::Acknowledged)
                    }
                    _ => self.event(MobileMeshManagementOutcome::Failed),
                });
            }
            // The reply is the reassembly buffer, which the manager hands
            // out whole; its length is not needed separately.
            umsh_node_mgmt::Outcome::Replied { .. } => {}
        }

        match &mut self.plan {
            ManagementPlan::One(shape) => {
                let shape = shape.clone();
                Some(self.replied(&shape))
            }
            ManagementPlan::Fetch(crawl) => {
                if crawl.receive(self.manager.reply()).is_err() {
                    return Some(self.event(MobileMeshManagementOutcome::Failed));
                }
                match crawl.next_request() {
                    Ok(Some(request)) => match self.manager.begin(&request, now_ms) {
                        Ok(()) => {
                            self.reported_remaining = None;
                            None
                        }
                        Err(_) => Some(self.event(MobileMeshManagementOutcome::Failed)),
                    },
                    Ok(None) => Some(self.fetched()),
                    Err(_) => Some(self.event(MobileMeshManagementOutcome::Failed)),
                }
            }
        }
    }

    /// Report a single exchange's reply, read against the shape that was
    /// asked for.
    fn replied(&self, shape: &ReplyShape) -> MobileMeshManagementEventRecord {
        let reply = self.manager.reply();
        let mut event = self.event(MobileMeshManagementOutcome::Replied);
        match shape {
            ReplyShape::Property(key) => match umsh_ulcp::reply::property(*key, reply) {
                Ok(answer) => event.answers.push(answer_record(*key, answer)),
                Err(_) => return self.event(MobileMeshManagementOutcome::Failed),
            },
            ReplyShape::Entries(keys) => match umsh_ulcp::reply::entries(keys, reply) {
                Ok(entries) => {
                    for (key, answer) in entries.flatten() {
                        event.answers.push(answer_record(key, answer));
                    }
                }
                // A device without `CAP_CMD_MULTI` declines the command
                // itself, which is an answer about the request rather than
                // about any one property.
                Err(_) => event.status_code = umsh_ulcp::reply::status_of(reply).map(|s| s.0),
            },
            // A reset the device answered anyway — `CMD_RESTORE` with no
            // snapshot to restore — reports like any other status.
            ReplyShape::Status | ReplyShape::Acknowledgment => {
                match umsh_ulcp::reply::status_of(reply) {
                    Some(status) => event.status_code = Some(status.0),
                    None => return self.event(MobileMeshManagementOutcome::Failed),
                }
            }
        }
        event
    }

    /// Hand back everything a finished crawl collected.
    ///
    /// Undecoded on purpose: what these values mean is the caller's
    /// question, and it asked for a particular set of properties because
    /// it already knew what it wanted with them.
    fn fetched(&mut self) -> MobileMeshManagementEventRecord {
        let ManagementPlan::Fetch(crawl) = &mut self.plan else {
            return self.event(MobileMeshManagementOutcome::Failed);
        };
        let answers = core::mem::take(&mut crawl.answers);
        let mut event = self.event(MobileMeshManagementOutcome::Replied);
        event.answers = answers;
        event
    }
}

/// Present the answers to a management read as the property frames the
/// ULCP inspectors read.
///
/// A mesh answer and a GATT property frame carry the same thing — a
/// property and what the device said it is worth — so the decoders are
/// the same decoders. Refusals drop out here: they are answers *about* a
/// property rather than values of one, and the event still carries them
/// for a caller that needs to know which.
#[uniffi::export]
pub fn ulcp_records_from_answers(
    answers: Vec<MobileMeshManagementAnswerRecord>,
) -> Vec<UlcpPropertyFrameRecord> {
    answers
        .into_iter()
        .filter_map(|answer| {
            Some(crate::ulcp::ulcp_property_record(
                answer.property_id,
                answer.value?,
            ))
        })
        .collect()
}

fn answer_record(
    property_id: u32,
    answer: umsh_ulcp::reply::Answer<'_>,
) -> MobileMeshManagementAnswerRecord {
    MobileMeshManagementAnswerRecord {
        property_id,
        value: answer.value().map(<[u8]>::to_vec),
        status_code: answer.status().map(|status| status.0),
    }
}

/// Report an operation that never started.
fn emit_management_failure(
    events: &NotifyingSender<MobileMeshManagementEventRecord>,
    operation_id: u64,
    peer: &PublicKey,
) {
    let _ = events.send(MobileMeshManagementEventRecord {
        operation_id,
        peer_address: encode_peer_address(peer),
        outcome: MobileMeshManagementOutcome::Failed,
        answers: Vec::new(),
        status_code: None,
        remaining_octets: None,
        properties_remaining: None,
    });
}

/// Register the target and put the first request on the air.
async fn start_management<M: MacBackend>(
    node: &LocalNode<M>,
    operation_id: u64,
    peer: PublicKey,
    request: ManagementRequest,
    now_ms: u64,
    token_seed: u16,
) -> Option<ManagementJob<M>> {
    let connection = node.peer(peer).await.ok()?;
    let mut manager = umsh_node_mgmt::NodeManager::new(connection, token_seed);
    // An acknowledgment is what completes a reset and what turns an
    // unreachable device into an early answer; a flood budget and a trace
    // route are what get a first request to a device no route is known
    // for, and teach the MAC the way back.
    *manager.send_options_mut() = SendOptions::default()
        .with_ack_requested(true)
        .with_flood_hops(MANAGEMENT_FLOOD_HOPS)
        .with_trace_route();
    let (plan, request) = match request {
        ManagementRequest::One { frame, shape } => (ManagementPlan::One(shape), frame),
        ManagementRequest::Fetch {
            property_ids,
            multi_hint,
        } => {
            let mut crawl = FetchCrawl::new(property_ids, multi_hint);
            let request = crawl.next_request().ok()??;
            (ManagementPlan::Fetch(crawl), request)
        }
    };
    manager.begin(&request, now_ms).ok()?;
    Some(ManagementJob {
        operation_id,
        peer,
        manager,
        plan,
        reported_remaining: None,
    })
}

/// Carry the outstanding operation as far as it goes right now, clearing
/// it and reporting once it ends.
async fn service_management<M: MacBackend>(
    job: &mut Option<ManagementJob<M>>,
    now_ms: u64,
    events: &NotifyingSender<MobileMeshManagementEventRecord>,
    token: &mut u16,
) {
    let Some(active) = job.as_mut() else {
        return;
    };
    loop {
        let progress = active.manager.service(now_ms).await;
        // The service call may have advanced the token ledger, and the
        // next operation's manager is seeded from here — a token issued
        // twice is answered with the earlier exchange's retained
        // response instead of running.
        *token = active.manager.counter();
        match progress {
            Err(_) => {
                let _ = events.send(active.event(MobileMeshManagementOutcome::Failed));
                *job = None;
                return;
            }
            Ok(umsh_node_mgmt::Progress::Waiting { .. }) => {
                if let Some(progress) = active.progress() {
                    let _ = events.send(progress);
                }
                return;
            }
            Ok(umsh_node_mgmt::Progress::Done(outcome)) => match active.settle(outcome, now_ms) {
                Some(event) => {
                    let _ = events.send(event);
                    *job = None;
                    return;
                }
                None => {
                    // Another exchange of the same operation. A crawl says
                    // so at every batch boundary, which is the only sign
                    // of life a long read gives before it finishes.
                    let _ = events.send(active.event(MobileMeshManagementOutcome::Progress));
                    continue;
                }
            },
        }
    }
}

async fn run_worker(
    identity: SoftwareIdentity,
    counter_store: SharedCounterStore,
    mut commands: mpsc::UnboundedReceiver<WorkerCommand>,
    outbound: NotifyingSender<MobileMeshOutboundFrameRecord>,
    transmit_completions: Arc<BridgeTransmitCompletions>,
    events: NotifyingSender<MobileMeshPingEventRecord>,
    management_events: NotifyingSender<MobileMeshManagementEventRecord>,
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
    // What this phone currently says about itself. The session starts
    // discoverable with no name and no location; the app pushes the
    // stored preferences via `set_discoverable` and
    // `set_advertised_location` right after install. Held here because
    // the responder profile is rebuilt whole whenever any of it changes,
    // and the advertisement arms read the location at send time.
    let mut discoverable = true;
    let mut responder_name: Option<String> = None;
    let mut advertised_location: Option<NodeLocation> = None;
    node.enable_identity_responder_default(phone_identity_profile(
        local_key,
        responder_name.as_deref(),
        advertised_location,
    ));
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
        //
        // Scoped to multicast, because a directed frame naming us is not an
        // echo. A unicast reaches this handler only when it also named a
        // local identity as its destination, which makes it a message we
        // addressed to ourselves; that belongs in the transcript like any
        // other. It takes a neighbor willing to repeat it to arrive at all,
        // since a radio never hears its own transmission.
        if packet.packet_family() == PacketFamily::Multicast && packet.from_key() == Some(local_key)
        {
            let distance = match packet.hop_count() {
                Some(hops) => format!("after {hops} hop(s)"),
                None => "over a source route".to_string(),
            };
            let _ = echo_events.send(MobileChatWorkerEvent::Diagnostic(format!(
                "own multicast relayed back {distance}"
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
                text_channels
                    .borrow()
                    .contains(&crate::channel_tag(channel.key())),
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
                hop_count: packet.hop_count(),
                route_hints: packet
                    .trace_route_hops()
                    .map(|hop| hop.0.to_vec())
                    .collect(),
                source_authenticated: packet.source_authenticated(),
                buffered_age_seconds: packet.rx().buffered_age_s(),
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
    // One device at a time: an administrator has one exchange outstanding
    // with a device, and a phone has no reason to be managing two at once.
    let mut management: Option<ManagementJob<_>> = None;
    // One advancing token counter for every management exchange this
    // worker will ever run. An operation consumes as many tokens as it
    // has batches and continuations, and a device holds every answered
    // token against retransmission — a request reusing one is answered
    // with the old exchange's response and never runs. Seeded randomly
    // so a fresh session cannot land on tokens a device still retains
    // from the previous one.
    let mut management_token: u16 = rand::random();
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
                                        // Trace route for the path, trace
                                        // signal for what each hop of it
                                        // cost. A ping that reports only a
                                        // round-trip time says a link is bad
                                        // without saying where.
                                        &SendOptions::default()
                                            .with_flood_hops(5)
                                            .with_trace_route()
                                            .with_trace_signal()
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
                        Some(WorkerCommand::Manage { operation_id, peer, request }) => {
                            if management.is_some() {
                                emit_management_failure(&management_events, operation_id, &peer);
                                continue;
                            }
                            let now_ms = handle.now_ms().await;
                            management = start_management(
                                &node,
                                operation_id,
                                peer,
                                request,
                                now_ms,
                                management_token,
                            )
                            .await;
                            if management.is_none() {
                                emit_management_failure(&management_events, operation_id, &peer);
                                continue;
                            }
                            service_management(
                                &mut management,
                                now_ms,
                                &management_events,
                                &mut management_token,
                            )
                            .await;
                            if handle.service_counter_persistence().await.is_err() {
                                return;
                            }
                        }
                        Some(WorkerCommand::Advertise { name, timestamp, scheduled, response }) => {
                            let result = match build_signed_identity_bundle(
                                &signer,
                                name.as_deref(),
                                timestamp,
                                advertised_location,
                            )
                            .await
                            {
                                Ok(bundle) => {
                                    let mut frame = Vec::with_capacity(bundle.len() + 1);
                                    frame.push(PayloadType::NodeIdentity as u8);
                                    frame.extend_from_slice(&bundle);
                                    // Full source either way, so the detached
                                    // signature is checkable.
                                    let options = SendOptions::default().with_full_source();
                                    let options = if scheduled {
                                        // No flood budget and no trace: a
                                        // restatement on a timer belongs to
                                        // the neighbours who can hear it.
                                        options.no_flood()
                                    } else {
                                        // Trace route so a listener learns a
                                        // path back to this phone from the
                                        // same frame, and trace signal so it
                                        // learns what that path costs — the
                                        // two pair entry for entry.
                                        options.with_trace_route().with_trace_signal()
                                    };
                                    node.send_all(&frame, &options)
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
                        Some(WorkerCommand::Beacon { response }) => {
                            // Trace route to learn the path, trace signal to
                            // learn what that path costs.
                            let result = node
                                .send_all(
                                    &[],
                                    &SendOptions::default()
                                        .with_flood_hops(BEACON_FLOOD_HOPS)
                                        .with_trace_route()
                                        .with_trace_signal(),
                                )
                                .await
                                .map(|_| ())
                                .map_err(|_| MobileMeshError::SendFailed);
                            if result.is_ok()
                                && handle.service_counter_persistence().await.is_err()
                            {
                                let _ = response.send(Err(MobileMeshError::SendFailed));
                                return;
                            }
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::SignIdentityBundle { name, timestamp, response }) => {
                            // Never the location: this bundle outlives the
                            // moment — pasted into messages, printed as a
                            // QR — and a position frozen into it goes
                            // stale and then travels wherever it does.
                            let result = build_signed_identity_bundle(
                                &signer,
                                name.as_deref(),
                                timestamp,
                                None,
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
                        Some(WorkerCommand::PeerRepeaters { peer, mut response }) => {
                            let result = tokio::select! {
                                result = collect_peer_repeaters(&node, &handle, peer) => result,
                                // The asker let go of its half. The pages still
                                // outstanding are for nobody, and waiting out
                                // their timeouts would hold this loop against
                                // every command behind them.
                                _ = response.closed() => continue,
                            };
                            let _ = response.send(result);
                        }
                        Some(WorkerCommand::SetChatDisplayName { name, response }) => {
                            chat.engine.set_local_handle(&name);
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::SetDiscoverable { enabled, name, response }) => {
                            discoverable = enabled;
                            responder_name = name;
                            if discoverable {
                                node.enable_identity_responder_default(phone_identity_profile(
                                    local_key,
                                    responder_name.as_deref(),
                                    advertised_location,
                                ));
                            } else {
                                node.disable_identity_responder();
                            }
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::SetAdvertisedLocation { location, response }) => {
                            advertised_location = location;
                            // The installed profile is a copy, so a live
                            // responder is reinstalled to serve the new
                            // position. Not discoverable means not
                            // installed — nothing to refresh.
                            if discoverable {
                                node.enable_identity_responder_default(phone_identity_profile(
                                    local_key,
                                    responder_name.as_deref(),
                                    advertised_location,
                                ));
                            }
                            let _ = response.send(());
                        }
                        Some(WorkerCommand::DiscoverIdentities {
                            role_code,
                            capability_bits,
                            node_hint,
                            source_route,
                            response,
                        }) => {
                            let result = async {
                                let mut builder = umsh_node::mac_command::IdentityRequestBuilder::new();
                                let mut nonce_bytes = [0u8; 4];
                                handle.fill_random(&mut nonce_bytes).await;
                                builder = builder
                                    .nonce(u32::from_be_bytes(nonce_bytes))
                                    .map_err(|_| MobileMeshError::SendFailed)?;
                                // Options are emitted in ascending key order, so
                                // the hint filter goes between the nonce and
                                // the role.
                                if let Some(hint) = node_hint.as_deref() {
                                    builder = builder
                                        .filter_hint_prefix(hint)
                                        .map_err(|_| MobileMeshError::SendFailed)?;
                                }
                                if let Some(role) = role_code {
                                    builder = builder
                                        .filter_role(NodeRole::from_byte(role))
                                        .map_err(|_| MobileMeshError::SendFailed)?;
                                }
                                // A broadcast request must carry at least one
                                // filter option. An unrestricted ask carries a
                                // zero-bit capability filter, which every node
                                // satisfies — but a hint filter already narrows
                                // the ask, and padding it would only cost bytes.
                                let unfiltered = role_code.is_none() && node_hint.is_none();
                                let capability_bits =
                                    capability_bits.or(if unfiltered { Some(0) } else { None });
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
                                // Full source lets a stranger unicast back.
                                let mut options = SendOptions::default().with_full_source();
                                if !source_route.is_empty() {
                                    let hops = source_route
                                        .iter()
                                        .map(|hint| {
                                            <[u8; 2]>::try_from(hint.as_slice())
                                                .map(umsh_core::RouterHint)
                                                .map_err(|_| MobileMeshError::SendFailed)
                                        })
                                        .collect::<Result<Vec<_>, _>>()?;
                                    // Unlike a hint-filtered ask over a
                                    // channel, this one must never fall back to
                                    // flooding. A role- or capability-filtered
                                    // request is answered by every node it
                                    // reaches, and even a hint-filtered one is
                                    // aimed at a particular place rather than
                                    // at the mesh: a route we cannot express is
                                    // a failure, not a license to broadcast.
                                    options = options
                                        .try_with_source_route(&hops)
                                        .map_err(|_| MobileMeshError::SendFailed)?
                                        // The trace the request accumulates is
                                        // the answering strangers' only path
                                        // home: a broadcast teaches the MAC no
                                        // route, and the reply carries no flood
                                        // budget.
                                        .with_trace_route();
                                }
                                // Last, always: try_with_source_route back-fills
                                // a flood budget from the route length, and any
                                // FHOPS field at all makes the far end drop an
                                // unhinted solicitation. A hint filter would
                                // license a flood budget, but this ask is aimed
                                // and has no use for one.
                                let options = options.no_flood();
                                node.send_all(&frame[..length], &options)
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
                                    ChatComposeRequest::Reaction { target, body } => chat
                                        .compose_reaction(
                                            conversation,
                                            client_token,
                                            target,
                                            body,
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
                    if management.is_some() {
                        // Retries, cursor continuations, and the batches of
                        // a crawl all leave on this tick. Persistence is
                        // serviced alongside because each of those is a
                        // real authenticated send.
                        service_management(
                            &mut management,
                            now_ms,
                            &management_events,
                            &mut management_token,
                        )
                        .await;
                        if handle.service_counter_persistence().await.is_err() {
                            return;
                        }
                    }
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
                && in_flight.iter().any(|entry| entry.gate_peer == Some(peer))
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
                    .with_flood_hops(flood_budget(route.hop_count)),
            };
        }
        Some(MemberRoute {
            hop_count: Some(hops),
            ..
        }) => {
            options = options.with_flood_hops(flood_budget(Some(*hops)));
        }
        _ => {}
    }
    bound
        .send_all(&frame[..length], &options)
        .await
        .map(|_| ())
        .map_err(|_| MobileMeshError::SendFailed)
}

/// How long one page of a Peer Repeaters listing is waited for.
///
/// A repeater builds its answer from tables it already holds, so the wait is
/// the mesh crossing and the responder's own channel-access window, not any
/// work on its part.
const PEER_REPEATERS_PAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most pages one listing is followed across.
///
/// A responder's table is bounded, so an enumeration that keeps handing back
/// cursors is a responder that has lost its place; the ask ends rather than
/// following it forever.
const PEER_REPEATERS_MAX_PAGES: usize = 8;

/// The most time one listing is followed for, across all its pages.
///
/// The worker loop serves every command in turn, so a walk that kept waiting
/// out page timeouts back to back would hold the whole session hostage. Pages
/// from a live responder arrive in seconds; a walk this old is being dripped
/// at, and ends with what it has.
const PEER_REPEATERS_WALK_TIMEOUT: Duration = Duration::from_secs(60);

/// Ask one repeater for its peer-repeater listing, following cursors until
/// the answer is complete.
///
/// Each page carries its own nonce, so a late page from an abandoned ask
/// cannot be mistaken for the one being waited on.
async fn collect_peer_repeaters<M: MacBackend>(
    node: &LocalNode<M>,
    handle: &M,
    peer: PublicKey,
) -> Result<Vec<MobileMeshPeerRepeaterRecord>, MobileMeshError> {
    let connection = node
        .peer(peer)
        .await
        .map_err(|_| MobileMeshError::InvalidPeer)?;

    let pages: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
    let _subscription = {
        let pages = pages.clone();
        node.on_mac_command(move |from, command| {
            if from != peer {
                return;
            }
            if let umsh_node::OwnedMacCommand::PeerRepeatersResponse { body } = command {
                pages.borrow_mut().push(body.clone());
            }
        })
    };

    let mut listing = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    let walk_deadline = tokio::time::Instant::now() + PEER_REPEATERS_WALK_TIMEOUT;
    for _ in 0..PEER_REPEATERS_MAX_PAGES {
        let mut nonce_bytes = [0u8; 2];
        handle.fill_random(&mut nonce_bytes).await;
        let nonce = u16::from_be_bytes(nonce_bytes);
        pages.borrow_mut().clear();
        let sent = connection
            .request_peer_repeaters(nonce, cursor.as_deref(), &SendOptions::default())
            .await;
        if sent.is_err() {
            if listing.is_empty() {
                return Err(MobileMeshError::SendFailed);
            }
            // A follow-up ask that cannot leave ends the walk the same way
            // an unanswered one does: with the pages already in hand.
            break;
        }

        let deadline =
            (tokio::time::Instant::now() + PEER_REPEATERS_PAGE_TIMEOUT).min(walk_deadline);
        let page = loop {
            let matched = pages.borrow_mut().iter().position(|body| {
                umsh_node::mac_command::PeerRepeatersResponseView::new(body).nonce() == Some(nonce)
            });
            if let Some(index) = matched {
                break Some(pages.borrow_mut().remove(index));
            }
            if tokio::time::Instant::now() >= deadline {
                break None;
            }
            // The worker's pump runs as a sibling future, so yielding here is
            // what lets the answer arrive at all.
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let Some(page) = page else {
            // A listing that stopped part way is still what the repeater
            // said; the caller gets it rather than nothing.
            break;
        };

        let view = umsh_node::mac_command::PeerRepeatersResponseView::new(&page);
        listing.extend(view.entries().map(peer_repeater_record));
        match view.cursor() {
            Some(next) => cursor = Some(next.to_vec()),
            None => break,
        }
        if tokio::time::Instant::now() >= walk_deadline {
            // No answer to the next ask would be waited for, so it is not
            // worth the airtime.
            break;
        }
    }
    Ok(listing)
}

fn peer_repeater_record(
    entry: umsh_node::mac_command::PeerRepeaterEntryView<'_>,
) -> MobileMeshPeerRepeaterRecord {
    let signal = entry.rssi_snr();
    MobileMeshPeerRepeaterRecord {
        hint: entry.hint().map(Vec::from).unwrap_or_default(),
        name: entry.name().map(String::from),
        rssi_dbm: signal.map(|(rssi, _)| rssi),
        snr_quarter_db: signal.map(|(_, snr)| snr.as_quarter_db_steps()),
        last_heard_minutes: entry.last_heard_min(),
        location: entry
            .location()
            .filter(|location| !location.is_unspecified())
            .map(|location| location.as_bytes().to_vec()),
        region_codes: entry.regions().map(Vec::from).collect(),
    }
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
fn attach_rx_metadata(mutations: &mut [MobileChatMutationRecord], rx: &MobileChatRxMetadataRecord) {
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

/// The flood budget an observed hop count implies. A hop count includes the
/// final link into this device, which no repeater has to pay for, so the
/// budget is one less than the distance the frame was heard from — and at
/// least one, since a budget of zero forwards nowhere.
fn flood_budget(hop_count: Option<u8>) -> u8 {
    hop_count
        .map(|hops| hops.saturating_sub(1))
        .unwrap_or(5)
        .max(1)
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

    // ─── Reading a device whole, across the mesh ─────────────────────────

    fn is_reply(property: u32, value: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        let len = frame::prop_is(&mut buf, 0, property, value).unwrap();
        buf.truncate(len);
        buf
    }

    /// A `CMD_PROP_ARE` answering the first `answered` of `keys` with an
    /// empty value each, as a device that ran out of room would.
    fn are_reply(keys: &[u32]) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        let mut writer = frame::prop_are(&mut buf, 0).unwrap();
        for key in keys {
            writer.write_entry(*key, &[]).unwrap();
        }
        let len = writer.finish();
        buf.truncate(len);
        buf
    }

    /// Ask what the outstanding request was, without decoding the frame.
    fn asked(crawl: &FetchCrawl) -> Vec<u32> {
        crawl.asked.clone()
    }

    /// A list long enough to need more than one batch.
    fn long_list() -> Vec<u32> {
        vec![
            prop::PHY_ENABLED,
            prop::PHY_FREQ,
            prop::PHY_TX_POWER,
            prop::PHY_LORA_BW,
            prop::PHY_LORA_SF,
            prop::PHY_LORA_CR,
            prop::PHY_DUTY_NOW,
            prop::PHY_DUTY_LIMIT,
            prop::DEV_NAME,
            prop::DEV_DISCOVERABLE,
        ]
    }

    #[test]
    fn a_fetch_asks_for_what_it_was_given_and_nothing_else() {
        let mut crawl = FetchCrawl::new(long_list(), true);
        crawl.next_request().unwrap().unwrap();
        assert_eq!(asked(&crawl).len(), SYNC_BATCH);
        assert_eq!(asked(&crawl), long_list()[..SYNC_BATCH].to_vec());

        // An administrator reads everything: the host domain and session
        // state answer over the mesh like any other property, so a fetch
        // queues what it was given and lets each key fail on its own
        // terms.
        let unfiltered = FetchCrawl::new(
            vec![prop::DEV_NAME, prop::HOST_KEY, prop::MAC_PROMISCUOUS],
            true,
        );
        assert_eq!(
            unfiltered.pending,
            vec![prop::DEV_NAME, prop::HOST_KEY, prop::MAC_PROMISCUOUS]
        );
    }

    #[test]
    fn a_fetch_asks_again_for_what_a_short_answer_left_out() {
        let mut crawl = FetchCrawl::new(long_list(), true);
        crawl.next_request().unwrap().unwrap();
        let batch = asked(&crawl);
        assert!(batch.len() > 1);

        // The device stopped before its answer overflowed.
        crawl.receive(&are_reply(&batch[..2])).unwrap();
        assert_eq!(
            crawl
                .pending
                .iter()
                .take(batch.len() - 2)
                .copied()
                .collect::<Vec<_>>(),
            batch[2..].to_vec(),
            "the unanswered keys go back to the front of the queue"
        );
        assert_eq!(crawl.answers.len(), 2);
    }

    #[test]
    fn a_fetch_falls_back_to_one_property_at_a_time() {
        let mut crawl = FetchCrawl::new(long_list(), true);
        crawl.next_request().unwrap().unwrap();
        let batch = asked(&crawl);

        // A device that declines the command itself, whatever the hint
        // said.
        crawl
            .receive(&is_reply(
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::UNIMPLEMENTED.0 as u8],
            ))
            .unwrap();
        assert!(!crawl.multi);
        assert_eq!(
            crawl
                .pending
                .iter()
                .take(batch.len())
                .copied()
                .collect::<Vec<_>>(),
            batch
        );

        crawl.next_request().unwrap().unwrap();
        assert_eq!(asked(&crawl), vec![batch[0]]);

        // A property it will not report comes back as a refusal rather
        // than as nothing: the caller has a screen to draw either way,
        // and "would not say" is not "never asked".
        crawl
            .receive(&is_reply(
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::PROP_NOT_FOUND.0 as u8],
            ))
            .unwrap();
        assert_eq!(crawl.answers.len(), 1);
        assert_eq!(crawl.answers[0].property_id, batch[0]);
        assert!(crawl.answers[0].value.is_none());
        assert_eq!(
            crawl.answers[0].status_code,
            Some(umsh_ulcp::Status::PROP_NOT_FOUND.0)
        );
        assert!(!crawl.pending.contains(&batch[0]));
    }

    /// The identity card: capabilities, firmware version, name and model
    /// in a single exchange, which is what every later screen is planned
    /// against and what caching it saves on every reopen.
    #[test]
    fn the_identity_card_is_one_exchange() {
        let card = crate::ulcp::ulcp_card_properties();
        let mut crawl = FetchCrawl::new(card.clone(), true);
        crawl.next_request().unwrap().unwrap();
        assert_eq!(asked(&crawl), card);

        crawl.receive(&are_reply(&card)).unwrap();
        assert!(crawl.pending.is_empty(), "one exchange covered the card");
        assert_eq!(crawl.answers.len(), 4);
        assert!(crawl.next_request().unwrap().is_none());
    }

    #[tokio::test]
    async fn the_phones_node_key_is_what_a_device_lists() {
        let directory = tempfile::tempdir().unwrap();
        let phone_identity = identity(21);
        let store = MobileCounterStore::new(directory.path().display().to_string()).unwrap();
        let phone = MobileMeshSession::new(phone_identity.clone(), store)
            .await
            .unwrap();
        assert_eq!(
            phone.node_public_key(),
            decode_peer(&address(&phone_identity)).unwrap().0.to_vec()
        );
    }

    #[tokio::test]
    async fn one_device_is_managed_at_a_time() {
        let directory = tempfile::tempdir().unwrap();
        let phone_identity = identity(22);
        let device = address(&identity(23));
        let store = MobileCounterStore::new(directory.path().display().to_string()).unwrap();
        let phone = MobileMeshSession::new(phone_identity, store).await.unwrap();

        let first = phone
            .begin_management_get(device.clone(), prop::DEV_NAME)
            .unwrap();
        let second = phone
            .begin_management_fetch(device.clone(), vec![prop::CAPS], true)
            .unwrap();
        assert_ne!(first, second);

        // The first operation is on the air and will not be answered here;
        // the second is refused outright rather than queued behind it.
        let deadline = Instant::now() + Duration::from_secs(5);
        let refusal = loop {
            assert!(
                Instant::now() < deadline,
                "no report for the second operation"
            );
            if let Some(event) = phone
                .poll_update()
                .management_events
                .into_iter()
                .find(|event| event.operation_id == second)
            {
                break event;
            }
        };
        assert_eq!(refusal.outcome, MobileMeshManagementOutcome::Failed);
        assert_eq!(refusal.peer_address, device);
    }

    #[tokio::test]
    async fn a_request_larger_than_one_payload_is_refused_before_it_is_sent() {
        let directory = tempfile::tempdir().unwrap();
        let phone_identity = identity(24);
        let device = address(&identity(25));
        let store = MobileCounterStore::new(directory.path().display().to_string()).unwrap();
        let phone = MobileMeshSession::new(phone_identity, store).await.unwrap();

        assert_eq!(
            phone.begin_management_set(device.clone(), prop::DEV_NAME, vec![0x41; 400]),
            Err(MobileMeshError::InvalidRequest)
        );
        assert_eq!(
            phone.begin_management_get_many(device, Vec::new()),
            Err(MobileMeshError::InvalidRequest)
        );
    }

    /// The 3-byte hint a node's multicast frames claim, which is the leading
    /// bytes of its public key.
    fn hint_of(identity: &MobileIdentity) -> Vec<u8> {
        decode_peer(&address(identity)).unwrap().0[..3].to_vec()
    }

    async fn channel_session(name: &str) -> Arc<MobileMeshSession> {
        let directory = tempfile::tempdir().unwrap();
        let store =
            MobileCounterStore::new(directory.path().join(name).display().to_string()).unwrap();
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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

    /// The ask is addressed and authenticated: one repeater's own account of
    /// its neighborhood, not a question put to the mesh at large.
    #[tokio::test]
    async fn request_peer_repeaters_emits_a_unicast_addressed_to_the_peer() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(51);
        let bob_key = *SoftwareIdentity::from_secret_bytes(&[53; 32]).public_key();
        let alice_store =
            MobileCounterStore::new(directory.path().join("alice").display().to_string()).unwrap();
        let alice = MobileMeshSession::new(alice_identity, alice_store)
            .await
            .unwrap();

        // The listing never arrives — no repeater is listening — so the ask
        // runs beside a loop watching for what it put on the air, and is
        // dropped once that has been seen.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let frame = tokio::select! {
            _ = alice.request_peer_repeaters(bob_key.0.to_vec()) => {
                panic!("the listing cannot complete with nobody to answer")
            }
            frame = async {
                loop {
                    let update = alice.poll_update();
                    if let Some(frame) = update.outbound_frames.into_iter().next() {
                        break frame;
                    }
                    assert!(tokio::time::Instant::now() < deadline, "no request went out");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            } => frame,
        };

        // The payload is sealed to the peer, so the frame proves addressing
        // and nothing further from outside; that the body really is command
        // ten is what the two-node mesh test decrypts and answers.
        let header = umsh_core::PacketHeader::parse(&frame.data).unwrap();
        assert_eq!(header.packet_type(), umsh_core::PacketType::Unicast);
        assert_eq!(
            header.dst,
            Some(umsh_core::NodeHint::from_public_key(&bob_key))
        );
        alice.complete_outbound_frame(frame.id, true).unwrap();

        // An unparseable key is refused before anything is sent.
        assert_eq!(
            alice.request_peer_repeaters(vec![0x01, 0x02]).await,
            Err(MobileMeshError::InvalidPeer)
        );
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

        alice
            .discover_identities(None, Some(0x02), None, Vec::new())
            .await
            .unwrap();

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
            was_buffered: false,
            was_acknowledged: false,
            age_seconds: 0,
        })
        .unwrap();

        // An unrestricted ask still satisfies the rule that a broadcast
        // request carries at least one filter: it gets a zero-bit
        // capability filter, which every node matches.
        alice
            .discover_identities(None, None, None, Vec::new())
            .await
            .unwrap();
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

        // Steered at a remote vantage point and aimed at one router there by
        // its two-byte hint — the shape that identifies an intermediate hop.
        // The ask still goes out with no flood budget for a repeater to spend
        // on its own initiative.
        alice
            .discover_identities(
                None,
                None,
                Some(vec![0x5A, 0x5B]),
                vec![vec![0xAB, 0xCD], vec![0x12, 0x34]],
            )
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let frames = loop {
            let update = alice.poll_update();
            if !update.outbound_frames.is_empty() {
                break update.outbound_frames;
            }
            assert!(
                Instant::now() < deadline,
                "routed solicitation never went out"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(frames.len(), 1);
        let frame = frames.into_iter().next().unwrap();
        alice.complete_outbound_frame(frame.id, true).unwrap();
        let header = umsh_core::PacketHeader::parse(&frame.data).unwrap();
        assert_eq!(header.packet_type(), umsh_core::PacketType::Broadcast);
        // No FHOPS field, despite the route: try_with_source_route back-fills
        // a flood budget from the route length, and any budget at all makes
        // the far end drop an unhinted solicitation.
        assert!(header.flood_hops.is_none());
        assert!(header.fcf.full_source());
        let options =
            umsh_core::ParsedOptions::extract(&frame.data, header.options_range.clone()).unwrap();
        // The route we asked for, in send order.
        let route = options
            .source_route
            .clone()
            .map(|range| frame.data[range].to_vec())
            .expect("a steered request carries a Route option");
        assert_eq!(route, vec![0xAB, 0xCD, 0x12, 0x34]);
        // And an empty trace for the repeaters to fill, which is what gives
        // the answering strangers a path home.
        let trace = options
            .trace_route
            .clone()
            .map(|range| frame.data[range].to_vec())
            .expect("a steered request carries a trace route");
        assert!(trace.is_empty());

        // The hint filter rides as the two bytes given, and the vacuous caps
        // filter is dropped: the ask is already narrowed to one node.
        let body = &frame.data[header.body_range.clone()];
        let umsh_node::MacCommand::IdentityRequest { options } =
            umsh_node::mac_command::parse(&body[1..]).unwrap()
        else {
            panic!("expected an identity request");
        };
        let filters: Vec<_> = umsh_core::options::OptionDecoder::new(options)
            .filter_map(Result::ok)
            .map(|(number, value)| (number, value.to_vec()))
            .collect();
        assert!(filters.contains(&(
            umsh_node::mac_command::identity_filter::FILTER_NODE_HINT,
            vec![0x5A, 0x5B]
        )));
        assert!(
            !filters
                .iter()
                .any(|(number, _)| *number
                    == umsh_node::mac_command::identity_filter::FILTER_NODE_CAPS),
            "a hint-filtered ask needs no vacuous capability filter"
        );
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
        // And under a shared location: the responder serves the same
        // description an advertisement carries.
        bob.set_advertised_location(Some(MobileMeshSharedLocationRecord {
            latitude_degrees: 48.1173,
            longitude_degrees: 11.5167,
            precision_bytes: 5,
        }))
        .await
        .unwrap();

        alice
            .discover_identities(None, None, None, Vec::new())
            .await
            .unwrap();

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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
        let cell = payload
            .location
            .expect("the reply serves the shared location");
        assert_eq!(cell.precision(), 5);
        let (lat, lon) = cell.center();
        assert!((f64::from(lat) - 48.1173).abs() < 0.01);
        assert!((f64::from(lon) - 11.5167).abs() < 0.01);

        // Opting out is honored: a fresh ask earns silence from Bob.
        bob.set_discoverable(false, None).await.unwrap();
        alice
            .discover_identities(None, None, None, Vec::new())
            .await
            .unwrap();
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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

    /// The location policy in one pass: a shared cell rides every live
    /// advertisement, never the durable QR/URI bundle, and clearing it
    /// removes it from the next send rather than lingering.
    #[tokio::test]
    async fn a_shared_location_rides_adverts_but_never_the_durable_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let alice_identity = identity(51);
        let bob_identity = identity(53);
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

        alice
            .set_advertised_location(Some(MobileMeshSharedLocationRecord {
                latitude_degrees: 37.774_929,
                longitude_degrees: -122.419_416,
                precision_bytes: 5,
            }))
            .await
            .unwrap();

        // The durable bundle stays location-free while a location is live:
        // it outlives the moment and travels wherever the QR is pasted.
        let bundle = alice
            .sign_identity_bundle(Some("Alice's Phone".to_owned()), None)
            .await
            .unwrap();
        let record = crate::decode_node_identity(address(&alice_identity), bundle).unwrap();
        assert_eq!(record.signature, crate::IdentitySignatureState::Valid);
        assert!(
            record.latitude.is_none(),
            "a QR bundle never places its owner"
        );

        // One advertisement while sharing, one after clearing.
        let mut received = Vec::new();
        for share in [true, false] {
            if !share {
                alice.set_advertised_location(None).await.unwrap();
            }
            alice.advertise_identity(None, None).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            'advert: loop {
                for frame in alice.poll_update().outbound_frames {
                    alice.complete_outbound_frame(frame.id, true).unwrap();
                    bob.receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-50),
                        lqi: None,
                        snr_cb: None,
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
                    })
                    .unwrap();
                }
                for event in bob.poll_update().advertisement_events {
                    received.push(
                        crate::decode_node_identity(event.peer_address, event.payload).unwrap(),
                    );
                    break 'advert;
                }
                assert!(Instant::now() < deadline, "advertisement not received");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        let shared = &received[0];
        assert_eq!(shared.location_precision, Some(5));
        assert!((shared.latitude.unwrap() - 37.774_929).abs() < 0.01);
        assert!((shared.longitude.unwrap() + 122.419_416).abs() < 0.01);
        // Clearing is complete: the next advertisement places nobody.
        assert!(received[1].latitude.is_none());
    }

    /// The refusals: a coordinate that names no place, at either end of
    /// the record, never reaches the worker.
    #[test]
    fn a_location_that_names_no_place_is_refused() {
        let valid = MobileMeshSharedLocationRecord {
            latitude_degrees: 37.774_929,
            longitude_degrees: -122.419_416,
            precision_bytes: 5,
        };
        for broken in [
            // Precision zero encodes "unspecified", which the API spells
            // `None`; a record saying both is a confusion to reject.
            MobileMeshSharedLocationRecord {
                precision_bytes: 0,
                ..valid
            },
            MobileMeshSharedLocationRecord {
                precision_bytes: MAX_PRECISION + 1,
                ..valid
            },
            MobileMeshSharedLocationRecord {
                latitude_degrees: 90.1,
                ..valid
            },
            MobileMeshSharedLocationRecord {
                longitude_degrees: -180.1,
                ..valid
            },
            MobileMeshSharedLocationRecord {
                latitude_degrees: f64::NAN,
                ..valid
            },
        ] {
            assert!(matches!(
                disclosed_cell(broken),
                Err(MobileMeshError::InvalidLocation)
            ));
        }
        let cell = disclosed_cell(valid).unwrap();
        assert_eq!(cell.precision(), 5);
    }

    /// A beacon carries no payload at all, so what reaches a listener is
    /// presence and a trace — never an advertisement.
    #[tokio::test]
    async fn a_beacon_reports_presence_and_carries_nothing() {
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
        let bob = MobileMeshSession::new(bob_identity, bob_store)
            .await
            .unwrap();

        alice.send_beacon().await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            for frame in alice.poll_update().outbound_frames {
                let header = umsh_core::PacketHeader::parse(&frame.data).unwrap();
                assert!(header.is_beacon(), "a beacon carries no body");
                let options =
                    umsh_core::ParsedOptions::extract(&frame.data, header.options_range.clone())
                        .unwrap();
                assert!(options.trace_route.is_some());
                assert!(
                    options.trace_signal.is_some(),
                    "the pair is what makes the trace worth collecting"
                );
                alice.complete_outbound_frame(frame.id, true).unwrap();
                bob.receive(MobileMeshRxRecord {
                    data: frame.data,
                    rssi_dbm: Some(-50),
                    lqi: None,
                    snr_cb: None,
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
                })
                .unwrap();
            }
            let bob_update = bob.poll_update();
            assert!(
                bob_update.advertisement_events.is_empty(),
                "an empty beacon identifies nobody"
            );
            if let Some(heard) = bob_update.peer_heard_events.into_iter().next() {
                // Hint-only, not a full key: a beacon is the cheapest
                // thing this phone can say, and the 29 bytes a key costs
                // buy nothing a listener who already knows it needs.
                assert_eq!(heard.peer_address, None);
                assert_eq!(heard.node_hint, Some(hint_of(&alice_identity)));
                assert!(!heard.source_authenticated);
                break;
            }
            assert!(Instant::now() < deadline, "beacon not received");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The two advertisement paths differ only in reach: a manual one
    /// floods and traces so a stranger can find its way back, a scheduled
    /// one restates to whoever can already hear this phone.
    #[tokio::test]
    async fn a_scheduled_advertisement_stays_with_the_neighbours() {
        let directory = tempfile::tempdir().unwrap();
        let local_identity = identity(41);
        let store =
            MobileCounterStore::new(directory.path().join("local").display().to_string()).unwrap();
        let session = MobileMeshSession::new(local_identity, store).await.unwrap();

        session
            .advertise_identity_scheduled(Some("Phone".to_owned()), None)
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let frames = session.poll_update().outbound_frames;
            if let Some(frame) = frames.into_iter().next() {
                let header = umsh_core::PacketHeader::parse(&frame.data).unwrap();
                assert!(
                    header.flood_hops.is_none(),
                    "a scheduled advertisement is not flooded"
                );
                let options =
                    umsh_core::ParsedOptions::extract(&frame.data, header.options_range.clone())
                        .unwrap();
                assert!(options.trace_route.is_none());
                assert!(
                    header.fcf.full_source(),
                    "the detached signature is only checkable against the key"
                );
                session.complete_outbound_frame(frame.id, true).unwrap();
                break;
            }
            assert!(Instant::now() < deadline, "advertisement never queued");
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
        assert_eq!(
            batch.checkpoint.conversation_address,
            address(&bob_identity)
        );
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
        assert_eq!(
            received.conversation_address.as_deref(),
            Some(&conversation[..])
        );
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
        let rx = received
            .rx
            .expect("a received frame carries radio metadata");
        assert_eq!(rx.rssi_dbm, Some(-70));
        assert_eq!(rx.snr_centibels, Some(60));
        // Heard directly off the air: the link from the sender is the one
        // and only hop.
        assert_eq!(rx.hop_count, Some(1));

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
            was_buffered: false,
            was_acknowledged: false,
            age_seconds: 0,
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
            assert!(
                Instant::now() < deadline,
                "the encrypted copy was not refused"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(refusal.unwrap().contains("encrypted"));

        // And the genuine one, differing only in that it is readable, lands.
        bob.receive(MobileMeshRxRecord {
            data: frame,
            rssi_dbm: Some(-70),
            lqi: None,
            snr_cb: Some(60),
            was_buffered: false,
            was_acknowledged: false,
            age_seconds: 0,
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

        let body: String = (0..600)
            .map(|index| char::from(b'a' + (index % 26) as u8))
            .collect();
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
        while echoed == 0
            || Instant::now() < deadline.min(Instant::now() + Duration::from_millis(1))
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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

    /// A message addressed to our own key is a message, not an echo.
    ///
    /// The unicast goes out naming us as both sender and destination, so it
    /// arrives looking exactly like the relayed group copy above; only the
    /// packet family tells them apart. Nothing can carry it without a
    /// neighbor willing to repeat it, which is what the echo below stands in
    /// for.
    #[tokio::test]
    async fn a_message_addressed_to_ourselves_is_transcribed() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity(71);
        let session = MobileMeshSession::new(
            identity.clone(),
            MobileCounterStore::new(directory.path().join("self").display().to_string()).unwrap(),
        )
        .await
        .unwrap();

        let own_address = address(&identity);
        session
            .register_peers(vec![own_address.clone()])
            .await
            .unwrap();

        let body = "note to self".to_owned();
        let batch = session
            .compose_text(own_address, 7, body.clone())
            .await
            .unwrap();
        session.commit_chat_batch(batch.batch_id).await.unwrap();

        // Stand in for the repeater: every frame the session emits goes back
        // in, including the acknowledgment it composes for its own message.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut inbound = Vec::new();
        while Instant::now() < deadline {
            let update = session.poll_update();
            for frame in update.outbound_frames {
                session.complete_outbound_frame(frame.id, true).unwrap();
                session
                    .receive(MobileMeshRxRecord {
                        data: frame.data,
                        rssi_dbm: Some(-60),
                        lqi: None,
                        snr_cb: Some(70),
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
                    })
                    .unwrap();
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
            if !inbound.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(
            inbound
                .iter()
                .any(|mutation| mutation.body.as_deref() == Some(body.as_str())),
            "the message we sent ourselves never arrived: {inbound:?}"
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
            session
                .compose_text(conversation, 3, "hello".to_owned())
                .await,
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
        alice
            .register_peers(vec![bob_address.clone()])
            .await
            .unwrap();
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
            assert!(
                Instant::now() < deadline,
                "the direct message never arrived"
            );
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
        let rx = received
            .rx
            .expect("a received frame carries radio metadata");
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
        let body: String = (0..600)
            .map(|index| char::from(b'a' + (index % 26) as u8))
            .collect();
        let batch = alice
            .compose_text(conversation.clone(), 1, body.clone())
            .await
            .unwrap();
        let fragments = batch.mutations[0].fragment_count.unwrap();
        assert!(
            fragments > 1,
            "the test body must fragment, got {fragments}"
        );
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
                    was_buffered: false,
                    was_acknowledged: false,
                    age_seconds: 0,
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
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
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
