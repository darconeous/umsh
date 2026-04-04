use heapless::Vec;
use umsh_core::{ChannelId, MicSize, NodeHint, PublicKey, RouterHint};

use crate::{CapacityError, MAX_RESEND_FRAME_LEN, MAX_SOURCE_ROUTE_HOPS};

/// Opaque receipt returned for ACK-requested transmissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SendReceipt(pub u32);

/// High-level transmission options passed to MAC send helpers.
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
        self
            .flood_hops
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

/// State of a pending ACK-requested transmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckState {
    /// Waiting to overhear forwarding confirmation from the next hop.
    AwaitingForward { confirm_deadline_ms: u64 },
    /// Waiting for the final destination's transport ACK.
    AwaitingAck,
}

/// Stored frame data used for retransmission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResendRecord<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    /// Exact sealed frame bytes.
    pub frame: Vec<u8, FRAME>,
    /// Optional source route retained for retransmission.
    pub source_route: Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
}

impl<const FRAME: usize> ResendRecord<FRAME> {
    /// Copy frame bytes and an optional route into fixed-capacity storage.
    pub fn try_new(frame: &[u8], source_route: Option<&[RouterHint]>) -> Result<Self, CapacityError> {
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

/// Tracking record for one ACK-requested transmission.
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

/// Errors returned while recording pending-ACK state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingAckError {
    /// The referenced local identity was missing.
    IdentityMissing,
    /// The pending-ACK table was full.
    TableFull,
}

/// Priority class used by the transmit queue.
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

/// One queued transmission entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedTx<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    /// Priority class.
    pub priority: TxPriority,
    /// Stored frame bytes.
    pub frame: Vec<u8, FRAME>,
    /// Optional receipt associated with the frame.
    pub receipt: Option<SendReceipt>,
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
        sequence: u32,
    ) -> Result<Self, CapacityError> {
        Self::try_new_with_state(priority, frame, receipt, sequence, 0, 0)
    }

    /// Create a queue entry with explicit timer and CAD state.
    pub fn try_new_with_state(
        priority: TxPriority,
        frame: &[u8],
        receipt: Option<SendReceipt>,
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
            sequence,
            not_before_ms,
            cad_attempts,
        })
    }
}

/// Fixed-capacity transmission queue owned by the MAC coordinator.
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
    ) -> Result<u32, CapacityError> {
        let sequence = self.next_sequence;
        let entry = QueuedTx::try_new(priority, frame, receipt, sequence)?;
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
        not_before_ms: u64,
        cad_attempts: u8,
    ) -> Result<u32, CapacityError> {
        let sequence = self.next_sequence;
        let entry = QueuedTx::try_new_with_state(
            priority,
            frame,
            receipt,
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
        self.entries.iter().any(|entry| entry.not_before_ms <= now_ms)
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
pub enum MacEventRef<'a> {
    /// Accepted unicast payload.
    Unicast {
        from: PublicKey,
        payload: &'a [u8],
        ack_requested: bool,
    },
    /// Accepted multicast payload.
    Multicast {
        from: PublicKey,
        channel_id: ChannelId,
        payload: &'a [u8],
    },
    /// Accepted blind-unicast payload.
    BlindUnicast {
        from: PublicKey,
        channel_id: ChannelId,
        payload: &'a [u8],
        ack_requested: bool,
    },
    /// Accepted broadcast payload or beacon.
    Broadcast {
        from_hint: NodeHint,
        from_key: Option<PublicKey>,
        payload: &'a [u8],
    },
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
}