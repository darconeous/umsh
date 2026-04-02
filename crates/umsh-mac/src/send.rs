use heapless::Vec;
use umsh_core::{ChannelId, MicSize, NodeHint, PublicKey, RouterHint};

use crate::{CapacityError, MAX_RESEND_FRAME_LEN, MAX_SOURCE_ROUTE_HOPS};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SendReceipt(pub u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendOptions {
    pub mic_size: MicSize,
    pub encrypted: bool,
    pub ack_requested: bool,
    pub full_source: bool,
    pub flood_hops: Option<u8>,
    pub trace_route: bool,
    pub source_route: Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
    pub region_code: Option<[u8; 2]>,
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
    pub fn with_mic_size(mut self, mic_size: MicSize) -> Self {
        self.mic_size = mic_size;
        self
    }

    pub fn with_ack_requested(mut self, value: bool) -> Self {
        self.ack_requested = value;
        self
    }

    pub fn with_flood_hops(mut self, hops: u8) -> Self {
        self.flood_hops = Some(hops);
        self
    }

    pub fn no_flood(mut self) -> Self {
        self.flood_hops = None;
        self
    }

    pub fn with_trace_route(mut self) -> Self {
        self.trace_route = true;
        self
    }

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

    pub fn with_salt(mut self) -> Self {
        self.salt = true;
        self
    }

    pub fn with_full_source(mut self) -> Self {
        self.full_source = true;
        self
    }

    pub fn unencrypted(mut self) -> Self {
        self.encrypted = false;
        self
    }

    pub fn with_region_code(mut self, code: [u8; 2]) -> Self {
        self.region_code = Some(code);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckState {
    AwaitingForward { confirm_deadline_ms: u64 },
    AwaitingAck,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResendRecord<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    pub frame: Vec<u8, FRAME>,
    pub source_route: Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
}

impl<const FRAME: usize> ResendRecord<FRAME> {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAck<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    pub ack_tag: [u8; 8],
    pub peer: PublicKey,
    pub resend: ResendRecord<FRAME>,
    pub sent_ms: u64,
    pub ack_deadline_ms: u64,
    pub retries: u8,
    pub state: AckState,
}

impl<const FRAME: usize> PendingAck<FRAME> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingAckError {
    IdentityMissing,
    TableFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPriority {
    ImmediateAck,
    Forward,
    Retry,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedTx<const FRAME: usize = MAX_RESEND_FRAME_LEN> {
    pub priority: TxPriority,
    pub frame: Vec<u8, FRAME>,
    pub receipt: Option<SendReceipt>,
    pub sequence: u32,
    pub not_before_ms: u64,
    pub cad_attempts: u8,
}

impl<const FRAME: usize> QueuedTx<FRAME> {
    pub fn try_new(
        priority: TxPriority,
        frame: &[u8],
        receipt: Option<SendReceipt>,
        sequence: u32,
    ) -> Result<Self, CapacityError> {
        Self::try_new_with_state(priority, frame, receipt, sequence, 0, 0)
    }

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
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

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

    pub fn pop_next(&mut self) -> Option<QueuedTx<FRAME>> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| (entry.priority.rank(), entry.sequence))
            .map(|(index, _)| index)?;
        Some(self.entries.swap_remove(index))
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacEventRef<'a> {
    Unicast {
        from: PublicKey,
        payload: &'a [u8],
        ack_requested: bool,
    },
    Multicast {
        from: PublicKey,
        channel_id: ChannelId,
        payload: &'a [u8],
    },
    BlindUnicast {
        from: PublicKey,
        channel_id: ChannelId,
        payload: &'a [u8],
        ack_requested: bool,
    },
    Broadcast {
        from_hint: NodeHint,
        from_key: Option<PublicKey>,
        payload: &'a [u8],
    },
    AckReceived {
        peer: PublicKey,
        receipt: SendReceipt,
    },
    AckTimeout {
        peer: PublicKey,
        receipt: SendReceipt,
    },
}