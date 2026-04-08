use core::num::NonZeroU8;
use heapless::Vec;
use umsh_core::{
    ChannelId, ChannelKey, FloodHops, MicSize, NodeHint, PacketHeader, PacketType, ParsedOptions,
    PayloadType, PublicKey, RouterHint, SecInfo,
};
use umsh_hal::Snr;

use crate::{CapacityError, LocalIdentityId, MAX_RESEND_FRAME_LEN, MAX_SOURCE_ROUTE_HOPS};

/// Opaque tracking token returned for ACK-requested transmissions.
///
/// When [`Mac::queue_unicast`](crate::Mac::queue_unicast) or
/// [`Mac::queue_blind_unicast`](crate::Mac::queue_blind_unicast) is called with
/// `options.ack_requested = true`, the coordinator allocates a `SendReceipt` from the
/// identity slot's internal sequence counter and returns it wrapped in `Some(...)`.
/// The application stores this token and watches for it to appear in a future MAC event
/// callback — either confirming delivery (MAC ACK received and verified) or reporting
/// failure (all retransmit attempts exhausted without a valid ACK).
///
/// Receipts are unique within the lifetime of an [`IdentitySlot`](crate::IdentitySlot)
/// (wrapping after ~4 billion sends). They are not meaningful across reboots or after
/// the identity slot is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SendReceipt(pub u32);

/// High-level transmission options passed to [`Mac`](crate::Mac) send helpers.
///
/// `SendOptions` expresses *what* the application wants from a send — the coordinator
/// translates these into packet-builder calls and enforces any
/// [`OperatingPolicy`](crate::OperatingPolicy) constraints before building the frame.
///
/// The default configuration (`SendOptions::default()`) is a reasonable starting point:
/// 16-byte MIC, encryption enabled, no ACK, 3-byte source hint, 5 flood hops, no trace
/// route, no salt.
///
/// `SendOptions` exposes a fluent builder API so applications can override only what they
/// care about:
///
/// ```rust
/// # use umsh_mac::SendOptions;
/// # use umsh_core::MicSize;
/// let opts = SendOptions::default()
///     .with_ack_requested(true)
///     .with_mic_size(MicSize::Mic8)
///     .no_flood()
///     .with_trace_route();
/// ```
///
/// ## Field notes
///
/// - **`mic_size`** — trading MIC length against frame overhead. 16-byte MIC is strongly
///   preferred for unicast; 4-byte may be acceptable for low-bandwidth broadcast beacons.
/// - **`flood_hops`** — `None` disables flood forwarding (point-to-point or source-routed
///   only). `Some(n)` sets the initial `FHOPS_REM` budget; repeaters decrement it and drop
///   at zero.
/// - **`full_source`** — include the full 32-byte public key instead of the 3-byte hint,
///   allowing the receiver to authenticate without a prior key exchange. Useful for first
///   contact or identity announcements; costs 29 extra bytes per frame.
/// - **`salt`** — append a random 2-byte salt to SECINFO, adding nonce diversity and
///   preventing correlation of frames sharing the same counter value across sessions.
/// - **`source_route`** — provide an explicit list of [`RouterHint`] values to route the
///   frame along a known path rather than relying on flood forwarding. Setting a source route
///   also constrains the flood-hop budget to the route length when `flood_hops` is unset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendOptions {
    /// Requested MIC size.
    pub mic_size: MicSize,
    /// Whether the payload should be encrypted when supported.
    pub encrypted: bool,
    /// Whether a transport ACK should be requested.
    pub ack_requested: bool,
    /// Whether to encode the full source public key.
    pub full_source: bool,
    /// Optional flood-hop budget.
    pub flood_hops: Option<u8>,
    /// Whether to include a trace-route option.
    pub trace_route: bool,
    /// Optional explicit source route.
    pub source_route: Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
    /// Optional region-code option.
    pub region_code: Option<[u8; 2]>,
    /// Whether to include a random salt in SECINFO.
    pub salt: bool,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            mic_size: MicSize::Mic16,
            encrypted: true,
            ack_requested: false,
            full_source: false,
            flood_hops: Some(5),
            trace_route: false,
            source_route: None,
            region_code: None,
            salt: false,
        }
    }
}

impl SendOptions {
    /// Override the MIC size.
    pub fn with_mic_size(mut self, mic_size: MicSize) -> Self {
        self.mic_size = mic_size;
        self
    }

    /// Set whether the send should request an ACK.
    pub fn with_ack_requested(mut self, value: bool) -> Self {
        self.ack_requested = value;
        self
    }

    /// Set the flood-hop budget.
    pub fn with_flood_hops(mut self, hops: u8) -> Self {
        self.flood_hops = Some(hops);
        self
    }

    /// Disable flood forwarding.
    pub fn no_flood(mut self) -> Self {
        self.flood_hops = None;
        self
    }

    /// Request that a trace-route option be added.
    pub fn with_trace_route(mut self) -> Self {
        self.trace_route = true;
        self
    }

    /// Copy a source route into fixed-capacity storage.
    pub fn try_with_source_route(mut self, route: &[RouterHint]) -> Result<Self, CapacityError> {
        let mut owned = Vec::new();
        for hop in route {
            owned.push(*hop).map_err(|_| CapacityError)?;
        }
        self.source_route = Some(owned);
        self.flood_hops
            .get_or_insert(route.len().min(u8::MAX as usize) as u8);
        Ok(self)
    }

    /// Request a random salt in SECINFO.
    pub fn with_salt(mut self) -> Self {
        self.salt = true;
        self
    }

    /// Force the source address to use the full public key.
    pub fn with_full_source(mut self) -> Self {
        self.full_source = true;
        self
    }

    /// Disable encryption for this send.
    pub fn unencrypted(mut self) -> Self {
        self.encrypted = false;
        self
    }

    /// Set the region-code option.
    pub fn with_region_code(mut self, code: [u8; 2]) -> Self {
        self.region_code = Some(code);
        self
    }
}

/// Tracks which phase of the two-stage ACK lifecycle a pending transmission is in.
///
/// UMSH ACK-requested sends go through up to two distinct waiting phases before the
/// coordinator either confirms delivery or gives up:
///
/// 1. **`AwaitingForward`** — immediately after sending, the coordinator listens to see if
///    the frame is re-broadcast by a repeater within `confirm_deadline_ms`. Because LoRa
///    links are half-duplex, the sender may not be in direct range of the destination but
///    *can* hear the repeater that retransmitted the frame, providing an early, cheap
///    confirmation that the packet made it to the next hop. If no forwarding echo is heard
///    before the deadline, the frame is retransmitted (up to [`MAX_FORWARD_RETRIES`]
///    attempts). On success, the state advances to `AwaitingAck`.
///
/// 2. **`AwaitingAck`** — the coordinator waits for the destination to return a MAC ACK
///    packet containing the correct ACK tag (a CMAC-derived value only the destination can
///    compute after successfully decrypting the original frame). The absolute deadline is
///    `PendingAck::ack_deadline_ms`; expiry means the send failed.
///
/// Nodes in direct radio range of the destination skip `AwaitingForward` entirely and are
/// placed directly into `AwaitingAck` via [`PendingAck::direct`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckState {
    /// Waiting to overhear forwarding confirmation from the next hop.
    AwaitingForward { confirm_deadline_ms: u64 },
    /// Waiting for the final destination's transport ACK.
    AwaitingAck,
}

/// Sealed frame bytes and optional source route retained for retransmission.
///
/// When the coordinator sends an ACK-requested packet, it must keep a verbatim copy of the
/// already-sealed frame for potential retransmission — not just the plaintext — because
/// re-building and re-sealing would produce a different ciphertext and a different ACK tag,
/// which the destination would not recognize.
///
/// `ResendRecord` stores up to `FRAME` bytes of the original sealed frame alongside any
/// source route that may need to be re-injected into the frame header on retransmit. Records
/// are created via [`ResendRecord::try_new`] and embedded inside [`PendingAck`]. The `FRAME`
/// const generic must be at least as large as the largest unicast frame the application will
/// send; oversized frames are rejected at queue time with [`crate::CapacityError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResendRecord<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    /// Exact sealed frame bytes.
    pub frame: Vec<u8, FRAME>,
    /// Optional source route retained for retransmission.
    pub source_route: Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
}

impl<const FRAME: usize> ResendRecord<FRAME> {
    /// Copy frame bytes and an optional route into fixed-capacity storage.
    pub fn try_new(
        frame: &[u8],
        source_route: Option<&[RouterHint]>,
    ) -> Result<Self, CapacityError> {
        let mut stored_frame = Vec::new();
        for byte in frame {
            stored_frame.push(*byte).map_err(|_| CapacityError)?;
        }

        let stored_route = match source_route {
            Some(route) => {
                let mut owned = Vec::new();
                for hop in route {
                    owned.push(*hop).map_err(|_| CapacityError)?;
                }
                Some(owned)
            }
            None => None,
        };

        Ok(Self {
            frame: stored_frame,
            source_route: stored_route,
        })
    }
}

/// Complete tracking state for one in-flight ACK-requested transmission.
///
/// The coordinator's [`IdentitySlot`](crate::IdentitySlot) maintains a `LinearMap` of
/// `PendingAck` records keyed by [`SendReceipt`], one per active ACK-requested send. The
/// record holds everything needed to detect completion, detect timeout, and retransmit:
///
/// - **`ack_tag`** — the 8-byte CMAC-derived value that will appear in the destination's
///   MAC ACK packet. Only a node that received and successfully decrypted the original frame
///   can produce the correct tag, so a matching `ack_tag` is cryptographic proof of delivery.
/// - **`peer`** — the destination's full public key, used to look up the correct pending
///   entry when matching an inbound MAC ACK against the pending table.
/// - **`resend`** — a verbatim copy of the sealed frame for retransmission. See
///   [`ResendRecord`].
/// - **`sent_ms`** — the monotonic millisecond timestamp at which the frame was first
///   transmitted; useful for latency measurement.
/// - **`ack_deadline_ms`** — absolute deadline for the final ACK. Expiry means failure and
///   the entry is removed.
/// - **`retries`** — the number of retransmissions already attempted; capped at
///   [`MAX_FORWARD_RETRIES`](crate::MAX_FORWARD_RETRIES).
/// - **`state`** — current position in the [`AckState`] lifecycle (forwarding confirmation
///   wait or final-ACK wait).
///
/// Use [`PendingAck::direct`] for sends to nodes in direct radio range, or
/// [`PendingAck::forwarded`] when routing through a repeater.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAck<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    /// Internal ACK tag used for inbound matching.
    pub ack_tag: [u8; 8],
    /// Final destination peer.
    pub peer: PublicKey,
    /// Retransmission data.
    pub resend: ResendRecord<FRAME>,
    /// Initial send timestamp in milliseconds.
    pub sent_ms: u64,
    /// Absolute deadline for the final ACK.
    pub ack_deadline_ms: u64,
    /// Number of retries already attempted.
    pub retries: u8,
    /// Current state in the ACK lifecycle.
    pub state: AckState,
}

impl<const FRAME: usize> PendingAck<FRAME> {
    /// Create pending-ACK state for a direct send.
    pub fn direct(
        ack_tag: [u8; 8],
        peer: PublicKey,
        resend: ResendRecord<FRAME>,
        sent_ms: u64,
        ack_deadline_ms: u64,
    ) -> Self {
        Self {
            ack_tag,
            peer,
            resend,
            sent_ms,
            ack_deadline_ms,
            retries: 0,
            state: AckState::AwaitingAck,
        }
    }

    /// Create pending-ACK state for a forwarded send.
    pub fn forwarded(
        ack_tag: [u8; 8],
        peer: PublicKey,
        resend: ResendRecord<FRAME>,
        sent_ms: u64,
        ack_deadline_ms: u64,
        confirm_deadline_ms: u64,
    ) -> Self {
        Self {
            ack_tag,
            peer,
            resend,
            sent_ms,
            ack_deadline_ms,
            retries: 0,
            state: AckState::AwaitingForward {
                confirm_deadline_ms,
            },
        }
    }
}

/// Errors returned when recording pending-ACK state in an identity slot.
///
/// Returned by [`IdentitySlot::try_insert_pending_ack`](crate::IdentitySlot::try_insert_pending_ack)
/// when the coordinator attempts to register a new in-flight ACK-requested send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingAckError {
    /// The [`LocalIdentityId`](crate::LocalIdentityId) supplied does not correspond to an
    /// occupied slot — the identity was removed while the send was being set up.
    IdentityMissing,
    /// The pending-ACK `LinearMap` inside the identity slot has reached its `ACKS` capacity.
    /// Wait for an in-flight send to complete or time out before issuing another ACK-requested
    /// send on this identity.
    TableFull,
}

/// Priority class assigned to entries in the [`TxQueue`].
///
/// The transmit queue services entries in priority order (lowest rank first) so that
/// time-sensitive control traffic is never delayed by a backlog of application sends.
/// Within the same priority class, entries are served in FIFO order by sequence number.
///
/// Priority levels from highest to lowest:
///
/// - **`ImmediateAck`** (rank 0) — MAC ACK frames generated in response to a received
///   unicast or blind-unicast with ACK-requested. Must be sent as quickly as possible so
///   the original sender's retransmit timer does not expire.
/// - **`Forward`** (rank 1) — frames being forwarded by the repeater. Prompt forwarding
///   feeds the sender's forwarding-confirmation window, so delays here can trigger
///   unnecessary retransmissions at the source.
/// - **`Retry`** (rank 2) — retransmissions of unacknowledged ACK-requested sends. These
///   have already been delayed by a full forwarding-confirmation window and need to get out
///   before the final ACK deadline expires.
/// - **`Application`** (rank 3) — new application-originated frames (`queue_broadcast`,
///   `queue_unicast`, `queue_multicast`, etc.). Lowest priority; yields to all control traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPriority {
    /// Immediate transport ACK.
    ImmediateAck,
    /// Receive-triggered forwarding.
    Forward,
    /// Retransmission after missed confirmation.
    Retry,
    /// Application-originated send.
    Application,
}

impl TxPriority {
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::ImmediateAck => 0,
            Self::Forward => 1,
            Self::Retry => 2,
            Self::Application => 3,
        }
    }
}

/// One entry in the [`TxQueue`] waiting to be transmitted by the [`Mac`](crate::Mac) coordinator.
///
/// Each `QueuedTx` holds a complete, already-sealed frame ready to hand directly to the
/// radio driver. The coordinator does not re-seal on retransmit; the frame bytes are the
/// authoritative on-the-wire representation.
///
/// - **`priority`** — determines service order within the queue. See [`TxPriority`].
/// - **`frame`** — the sealed frame bytes, at most `FRAME` bytes. The coordinator calls
///   `radio.transmit(&entry.frame, tx_options).await` when this entry reaches the head of
///   the queue and its `not_before_ms` has elapsed.
/// - **`receipt`** — for ACK-requested sends, the associated [`SendReceipt`] so the
///   coordinator can update the [`PendingAck`] state after a successful transmit.
/// - **`sequence`** — a monotonic counter assigned at enqueue time, used to preserve
///   FIFO ordering among entries sharing the same priority.
/// - **`not_before_ms`** — earliest acceptable transmit time in monotonic milliseconds.
///   Entries with a future `not_before_ms` are skipped until the clock advances past it.
///   Used to introduce per-node forwarding delay jitter that reduces collision probability.
///   Zero means transmit immediately.
/// - **`cad_attempts`** — number of channel-activity-detection retries already consumed
///   on this entry; compared against [`MAX_CAD_ATTEMPTS`](crate::MAX_CAD_ATTEMPTS) to bound
///   medium contention retries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedTx<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    /// Priority class.
    pub priority: TxPriority,
    /// Stored frame bytes.
    pub frame: Vec<u8, FRAME>,
    /// Optional receipt associated with the frame.
    pub receipt: Option<SendReceipt>,
    /// Identity that owns this send; set for identity-originated sends, `None` for
    /// internally generated frames (MAC ACKs, forwarded frames).
    pub identity_id: Option<LocalIdentityId>,
    /// Monotonic sequence number for stable ordering.
    pub sequence: u32,
    /// Earliest transmission timestamp.
    pub not_before_ms: u64,
    /// Number of CAD attempts already consumed.
    pub cad_attempts: u8,
}

impl<const FRAME: usize> QueuedTx<FRAME> {
    /// Create a queue entry ready to send immediately.
    pub fn try_new(
        priority: TxPriority,
        frame: &[u8],
        receipt: Option<SendReceipt>,
        identity_id: Option<LocalIdentityId>,
        sequence: u32,
    ) -> Result<Self, CapacityError> {
        Self::try_new_with_state(priority, frame, receipt, identity_id, sequence, 0, 0)
    }

    /// Create a queue entry with explicit timer and CAD state.
    pub fn try_new_with_state(
        priority: TxPriority,
        frame: &[u8],
        receipt: Option<SendReceipt>,
        identity_id: Option<LocalIdentityId>,
        sequence: u32,
        not_before_ms: u64,
        cad_attempts: u8,
    ) -> Result<Self, CapacityError> {
        let mut stored_frame = Vec::new();
        for byte in frame {
            stored_frame.push(*byte).map_err(|_| CapacityError)?;
        }

        Ok(Self {
            priority,
            frame: stored_frame,
            receipt,
            identity_id,
            sequence,
            not_before_ms,
            cad_attempts,
        })
    }
}

/// Fixed-capacity, priority-ordered transmit queue owned by the [`Mac`](crate::Mac) coordinator.
///
/// The `TxQueue` serializes all outgoing frames — MAC ACKs, forwarded frames, retransmissions,
/// and application sends — into a single ordered sequence for delivery to the radio one at a
/// time. Entries are serviced in [`TxPriority`] order, with FIFO ordering within each class.
///
/// The queue capacity `N` is a compile-time constant (default [`DEFAULT_TX`](crate::DEFAULT_TX)).
/// Attempts to enqueue beyond capacity fail with [`crate::CapacityError`], propagated as
/// [`SendError::QueueFull`](crate::SendError::QueueFull) or
/// [`MacError::QueueFull`](crate::MacError::QueueFull). Choose `N` large enough to absorb
/// the worst-case burst: a forwarded frame, its MAC ACK, plus any application sends already
/// queued, plus the retransmit backlog.
///
/// Internally the queue is an unsorted `heapless::Vec<QueuedTx, N>`. The `dequeue` operation
/// does a linear scan for the highest-priority, lowest-sequence entry whose `not_before_ms`
/// has elapsed, which is O(N) — acceptable for the small N typical in embedded deployments.
#[derive(Clone, Debug)]
pub struct TxQueue<const N: usize = 16, const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    entries: Vec<QueuedTx<FRAME>, N>,
    next_sequence: u32,
}

impl<const N: usize, const FRAME: usize> Default for TxQueue<N, FRAME> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const FRAME: usize> TxQueue<N, FRAME> {
    /// Create an empty transmission queue.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Return the number of queued transmissions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether no transmissions are queued.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Enqueue a frame and return its internal sequence number.
    pub fn enqueue(
        &mut self,
        priority: TxPriority,
        frame: &[u8],
        receipt: Option<SendReceipt>,
        identity_id: Option<LocalIdentityId>,
    ) -> Result<u32, CapacityError> {
        let sequence = self.next_sequence;
        let entry = QueuedTx::try_new(priority, frame, receipt, identity_id, sequence)?;
        self.entries.push(entry).map_err(|_| CapacityError)?;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(sequence)
    }

    /// Enqueue a frame with explicit timer and CAD state.
    pub fn enqueue_with_state(
        &mut self,
        priority: TxPriority,
        frame: &[u8],
        receipt: Option<SendReceipt>,
        identity_id: Option<LocalIdentityId>,
        not_before_ms: u64,
        cad_attempts: u8,
    ) -> Result<u32, CapacityError> {
        let sequence = self.next_sequence;
        let entry = QueuedTx::try_new_with_state(
            priority,
            frame,
            receipt,
            identity_id,
            sequence,
            not_before_ms,
            cad_attempts,
        )?;
        self.entries.push(entry).map_err(|_| CapacityError)?;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(sequence)
    }

    /// Remove and return the highest-priority queued frame.
    pub fn pop_next(&mut self) -> Option<QueuedTx<FRAME>> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| (entry.priority.rank(), entry.sequence))
            .map(|(index, _)| index)?;
        Some(self.entries.swap_remove(index))
    }

    /// Return the earliest `not_before_ms` across all entries, if any are deferred.
    pub fn earliest_not_before_ms(&self) -> Option<u64> {
        self.entries
            .iter()
            .filter(|entry| entry.not_before_ms > 0)
            .map(|entry| entry.not_before_ms)
            .min()
    }

    /// Return whether the queue contains any entry that is ready to send now.
    pub fn has_ready(&self, now_ms: u64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.not_before_ms <= now_ms)
    }

    /// Remove and return the first queued frame matching `predicate`.
    pub fn remove_first_matching(
        &mut self,
        mut predicate: impl FnMut(&QueuedTx<FRAME>) -> bool,
    ) -> Option<QueuedTx<FRAME>> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .find_map(|(index, entry)| predicate(entry).then_some(index))?;
        Some(self.entries.swap_remove(index))
    }
}

/// Borrowing view of an inbound MAC event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelInfoRef<'a> {
    pub id: ChannelId,
    pub key: &'a ChannelKey,
}

impl<'a> ChannelInfoRef<'a> {
    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn key(&self) -> &'a ChannelKey {
        self.key
    }
}

/// Coarser grouping of on-wire packet types.
///
/// This is useful for applications that care about "unicast-like" or
/// "blind-unicast-like" traffic without matching both ACK and non-ACK packet
/// variants individually.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketFamily {
    Broadcast,
    MacAck,
    Unicast,
    Multicast,
    BlindUnicast,
    Reserved,
}

impl PacketFamily {
    pub fn includes(self, packet_type: PacketType) -> bool {
        match self {
            Self::Broadcast => packet_type == PacketType::Broadcast,
            Self::MacAck => packet_type == PacketType::MacAck,
            Self::Unicast => matches!(packet_type, PacketType::Unicast | PacketType::UnicastAckReq),
            Self::Multicast => packet_type == PacketType::Multicast,
            Self::BlindUnicast => {
                matches!(
                    packet_type,
                    PacketType::BlindUnicast | PacketType::BlindUnicastAckReq
                )
            }
            Self::Reserved => packet_type == PacketType::Reserved5,
        }
    }
}

/// Iterator over packed two-byte route hops from a source-route or trace-route option.
#[derive(Clone, Copy, Debug)]
pub struct RouteHops<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

/// Local physical-layer observations captured when a frame was received.
///
/// SNR is represented in centibels (0.1 dB units). This is finer than whole
/// decibels, but still compact and integer-friendly. Some common LoRa radios
/// report packet SNR in quarter-dB steps; converting those readings into
/// centibels may therefore introduce a small rounding error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxMetadata {
    rssi: Option<i16>,
    snr: Option<Snr>,
    lqi: Option<NonZeroU8>,
    received_at_ms: Option<u64>,
}

impl RxMetadata {
    pub fn new(
        rssi: Option<i16>,
        snr: Option<Snr>,
        lqi: Option<NonZeroU8>,
        received_at_ms: Option<u64>,
    ) -> Self {
        Self {
            rssi,
            snr,
            lqi,
            received_at_ms,
        }
    }

    pub fn rssi(&self) -> Option<i16> {
        self.rssi
    }

    pub fn snr(&self) -> Option<Snr> {
        self.snr
    }

    pub fn lqi(&self) -> Option<NonZeroU8> {
        self.lqi
    }

    pub fn received_at_ms(&self) -> Option<u64> {
        self.received_at_ms
    }
}

impl<'a> RouteHops<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
}

impl Iterator for RouteHops<'_> {
    type Item = RouterHint;

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = self.bytes.get(self.cursor..self.cursor + 2)?;
        self.cursor += 2;
        Some(RouterHint([chunk[0], chunk[1]]))
    }
}

/// Borrowed view of one accepted inbound packet together with parsed on-wire metadata.
///
/// `ReceivedPacketRef` is meant to stay close to the original packet rather than eagerly
/// translating it into application-level events. It includes the accepted wire bytes, the
/// decrypted/usable payload slice, parsed header and option metadata, resolved sender and
/// channel information, and security details such as frame counter, salt, MIC bytes, and
/// authentication status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedPacketRef<'a> {
    wire: &'a [u8],
    payload_bytes: &'a [u8],
    payload_type: PayloadType,
    payload: &'a [u8],
    header: PacketHeader,
    options: ParsedOptions,
    from_key: Option<PublicKey>,
    from_hint: Option<NodeHint>,
    source_authenticated: bool,
    channel: Option<ChannelInfoRef<'a>>,
    rx: RxMetadata,
}

impl<'a> ReceivedPacketRef<'a> {
    pub fn new(
        wire: &'a [u8],
        payload_bytes: &'a [u8],
        header: PacketHeader,
        options: ParsedOptions,
        from_key: Option<PublicKey>,
        from_hint: Option<NodeHint>,
        source_authenticated: bool,
        channel: Option<ChannelInfoRef<'a>>,
        rx: RxMetadata,
    ) -> Self {
        let (payload_type, payload) = if payload_bytes.is_empty() {
            (PayloadType::Empty, &[][..])
        } else if let Some(payload_type) = PayloadType::from_byte(payload_bytes[0]) {
            (payload_type, &payload_bytes[1..])
        } else {
            (PayloadType::Empty, payload_bytes)
        };
        Self {
            wire,
            payload_bytes,
            payload_type,
            payload,
            header,
            options,
            from_key,
            from_hint,
            source_authenticated,
            channel,
            rx,
        }
    }

    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type()
    }

    /// Return the coarse packet family for this frame.
    pub fn packet_family(&self) -> PacketFamily {
        match self.packet_type() {
            PacketType::Broadcast => PacketFamily::Broadcast,
            PacketType::MacAck => PacketFamily::MacAck,
            PacketType::Unicast | PacketType::UnicastAckReq => PacketFamily::Unicast,
            PacketType::Multicast => PacketFamily::Multicast,
            PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => PacketFamily::BlindUnicast,
            PacketType::Reserved5 => PacketFamily::Reserved,
        }
    }

    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    pub fn options(&self) -> &ParsedOptions {
        &self.options
    }

    pub fn wire_bytes(&self) -> &'a [u8] {
        self.wire
    }

    /// Return the payload bytes after any successful decryption/authentication work.
    ///
    /// This is the application payload body only; it does not include the leading
    /// typed-payload byte. Use [`Self::payload_type`] or [`Self::payload_bytes`]
    /// to inspect the application envelope.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Return the application payload type carried by this frame.
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    /// Return the exact application payload bytes including the leading
    /// typed-payload byte when present.
    pub fn payload_bytes(&self) -> &'a [u8] {
        self.payload_bytes
    }

    /// Return the exact on-wire body region before higher-layer payload parsing.
    pub fn wire_body(&self) -> &'a [u8] {
        self.wire
            .get(self.header.body_range.clone())
            .unwrap_or_default()
    }

    pub fn is_beacon(&self) -> bool {
        self.header.is_beacon()
    }

    pub fn from_key(&self) -> Option<PublicKey> {
        self.from_key
    }

    pub fn from_hint(&self) -> Option<NodeHint> {
        self.from_hint
    }

    pub fn source_authenticated(&self) -> bool {
        self.source_authenticated
    }

    /// Local radio observations captured when this frame was received.
    pub fn rx(&self) -> &RxMetadata {
        &self.rx
    }

    pub fn rssi(&self) -> Option<i16> {
        self.rx.rssi()
    }

    pub fn snr(&self) -> Option<Snr> {
        self.rx.snr()
    }

    pub fn lqi(&self) -> Option<NonZeroU8> {
        self.rx.lqi()
    }

    pub fn received_at_ms(&self) -> Option<u64> {
        self.rx.received_at_ms()
    }

    /// True when the source address in the accepted frame used the full public key form.
    pub fn has_full_source(&self) -> bool {
        self.header.fcf.full_source()
    }

    /// Resolved channel metadata, when this packet was accepted via a known private channel.
    pub fn channel(&self) -> Option<ChannelInfoRef<'a>> {
        self.channel
    }

    pub fn ack_requested(&self) -> bool {
        self.packet_type().ack_requested()
    }

    /// Whether the accepted frame carried a valid SECINFO block.
    pub fn is_secure(&self) -> bool {
        self.packet_type().is_secure()
    }

    pub fn sec_info(&self) -> Option<SecInfo> {
        self.header.sec_info
    }

    pub fn encrypted(&self) -> bool {
        self.sec_info()
            .map(|sec| sec.scf.encrypted())
            .unwrap_or(false)
    }

    pub fn frame_counter(&self) -> Option<u32> {
        self.sec_info().map(|sec| sec.frame_counter)
    }

    pub fn salt(&self) -> Option<u16> {
        self.sec_info().and_then(|sec| sec.salt)
    }

    pub fn mic_size(&self) -> Option<MicSize> {
        self.sec_info().and_then(|sec| sec.scf.mic_size().ok())
    }

    /// Return the authenticated MIC bytes from the original wire frame.
    pub fn mic(&self) -> &'a [u8] {
        self.wire
            .get(self.header.mic_range.clone())
            .unwrap_or_default()
    }

    pub fn mic_len(&self) -> usize {
        self.mic().len()
    }

    pub fn flood_hops(&self) -> Option<FloodHops> {
        self.header.flood_hops
    }

    pub fn region_code(&self) -> Option<[u8; 2]> {
        self.options.region_code
    }

    pub fn min_rssi(&self) -> Option<i16> {
        self.options.min_rssi
    }

    pub fn min_snr(&self) -> Option<i8> {
        self.options.min_snr
    }

    pub fn has_unknown_critical_options(&self) -> bool {
        self.options.has_unknown_critical
    }

    pub fn source_route(&self) -> Option<&'a [u8]> {
        self.options
            .source_route
            .as_ref()
            .and_then(|range| self.wire.get(range.clone()))
    }

    /// Iterate decoded source-route hops from the packed option bytes.
    pub fn source_route_hops(&self) -> RouteHops<'a> {
        RouteHops::new(self.source_route().unwrap_or(&[]))
    }

    pub fn trace_route(&self) -> Option<&'a [u8]> {
        self.options
            .trace_route
            .as_ref()
            .and_then(|range| self.wire.get(range.clone()))
    }

    /// Iterate decoded trace-route hops from the packed option bytes.
    pub fn trace_route_hops(&self) -> RouteHops<'a> {
        RouteHops::new(self.trace_route().unwrap_or(&[]))
    }

    pub fn source_route_hop_count(&self) -> usize {
        self.source_route()
            .map(|route| route.len() / 2)
            .unwrap_or(0)
    }

    pub fn trace_route_hop_count(&self) -> usize {
        self.trace_route().map(|route| route.len() / 2).unwrap_or(0)
    }
}

/// Borrowing view of an inbound MAC event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacEventRef<'a> {
    /// Accepted inbound packet with parsed metadata and resolved sender/channel information.
    Received(ReceivedPacketRef<'a>),
    /// Matching transport ACK received.
    AckReceived {
        peer: PublicKey,
        receipt: SendReceipt,
    },
    /// Pending ACK timed out.
    AckTimeout {
        peer: PublicKey,
        receipt: SendReceipt,
    },
    /// Frame was successfully handed to the radio transmitter.
    ///
    /// `identity_id` + `receipt` together form the identity-scoped send token.
    /// `receipt` is `Some` only for ACK-requested sends.
    Transmitted {
        identity_id: LocalIdentityId,
        receipt: Option<SendReceipt>,
    },
    /// A repeater was overheard forwarding this frame
    /// (AwaitingForward → AwaitingAck transition).
    Forwarded {
        identity_id: LocalIdentityId,
        receipt: SendReceipt,
        hint: Option<RouterHint>,
    },
}
