//! Per-stream sequence state: serial-number arithmetic, duplicate windows,
//! and wire-ID-to-handle mappings.
//!
//! Sequence IDs are scoped to `(conversation, sender)`. Each stream keeps a
//! windowed bitmap of recently seen IDs (half-range window of 128) plus a
//! bounded ring mapping recent wire IDs to stable application handles.

use umsh_core::PublicKey;

use crate::model::{ConversationKey, SenderScope};

/// Serial-number delta from `last` to `id`, modulo 256.
///
/// Deltas 1–127 are newer; 128–255 are old or ambiguous.
pub fn serial_delta(last: u8, id: u8) -> u8 {
    id.wrapping_sub(last)
}

/// Classification of a received ID relative to a stream baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialClass {
    /// Equal to the baseline.
    Baseline,
    /// Newer by the contained forward delta (1–127).
    Newer(u8),
    /// Older by the contained backward distance (1–127).
    Older(u8),
    /// Exactly half the range away: old or ambiguous.
    Ambiguous,
}

pub fn classify(last: u8, id: u8) -> SerialClass {
    match serial_delta(last, id) {
        0 => SerialClass::Baseline,
        delta @ 1..=127 => SerialClass::Newer(delta),
        128 => SerialClass::Ambiguous,
        delta => SerialClass::Older(delta.wrapping_neg()),
    }
}

/// Stable application identity of a transcript message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageHandle(pub u32);

/// Bounded ring mapping recent wire IDs to message handles within one
/// stream epoch. When an ID is reused or evicted, the old mapping retires.
#[derive(Clone, Debug, Default)]
pub struct RefRing {
    entries: heapless::Vec<(u8, MessageHandle), 16>,
}

impl RefRing {
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Record `id -> handle`, retiring any previous mapping of `id` and the
    /// oldest entry when full.
    pub fn record(&mut self, id: u8, handle: MessageHandle) {
        self.entries.retain(|(entry_id, _)| *entry_id != id);
        if self.entries.is_full() {
            self.entries.remove(0);
        }
        let _ = self.entries.push((id, handle));
    }

    pub fn lookup(&self, id: u8) -> Option<MessageHandle> {
        self.entries
            .iter()
            .find(|(entry_id, _)| *entry_id == id)
            .map(|(_, handle)| *handle)
    }

    pub fn lookup_handle(&self, handle: MessageHandle) -> Option<u8> {
        self.entries
            .iter()
            .find(|(_, entry)| *entry == handle)
            .map(|(id, _)| *id)
    }

    /// Retire the mapping for `id`, if present.
    pub fn retire(&mut self, id: u8) {
        self.entries.retain(|(entry_id, _)| *entry_id != id);
    }
}

/// 256-bit seen-ID bitmap with half-range window semantics.
#[derive(Clone, Debug, Default)]
pub struct SeenWindow {
    bits: [u32; 8],
}

impl SeenWindow {
    pub fn clear(&mut self) {
        self.bits = [0; 8];
    }

    pub fn contains(&self, id: u8) -> bool {
        self.bits[(id >> 5) as usize] & (1 << (id & 31)) != 0
    }

    pub fn insert(&mut self, id: u8) {
        self.bits[(id >> 5) as usize] |= 1 << (id & 31);
    }

    fn remove(&mut self, id: u8) {
        self.bits[(id >> 5) as usize] &= !(1 << (id & 31));
    }

    /// Advance the baseline from `last` by `delta`, clearing stale bits for
    /// the IDs entering the window so quarter-old duplicates never alias
    /// wrapped IDs.
    pub fn advance(&mut self, last: u8, delta: u8) {
        for step in 1..=delta {
            self.remove(last.wrapping_add(step));
        }
    }
}

/// A pending automatic repair request for one missing frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRepair {
    pub message_id: u8,
    /// Missing fragment index, or `None` for the whole-message 1-byte form.
    pub fragment: Option<u8>,
    /// Earliest time the request may be transmitted (grace plus jitter).
    pub deadline_ms: u64,
    pub attempts: u8,
}

/// Inbound stream state for one `(conversation, sender)` pair.
#[derive(Clone, Debug)]
pub struct InboundStream {
    /// Local epoch counter; bumped on reset so stale cached state can never
    /// merge across a reset.
    pub epoch: u16,
    /// Most recent (serial-order) accepted ID.
    pub baseline: Option<u8>,
    pub seen: SeenWindow,
    pub refs: RefRing,
    pub pending: heapless::Vec<PendingRepair, 8>,
    /// Resolved full key of a claimed multicast member, when known. Needed to
    /// address group repair requests.
    pub sender_key: Option<PublicKey>,
    /// Two known peer keys collide on this stream's hint; automatic repair is
    /// suppressed and references resolve only when unambiguous.
    pub collided: bool,
    pub last_request_ms: u64,
    pub last_active_ms: u64,
}

impl InboundStream {
    pub fn new(now_ms: u64) -> Self {
        Self {
            epoch: 0,
            baseline: None,
            seen: SeenWindow::default(),
            refs: RefRing::default(),
            pending: heapless::Vec::new(),
            sender_key: None,
            collided: false,
            last_request_ms: 0,
            last_active_ms: now_ms,
        }
    }

    /// Start a new epoch, discarding cached wire mappings and repair state
    /// but not transcript history.
    pub fn reset_epoch(&mut self, new_baseline: Option<u8>) {
        self.epoch = self.epoch.wrapping_add(1);
        self.baseline = new_baseline;
        self.seen.clear();
        self.refs.clear();
        self.pending.clear();
        if let Some(id) = new_baseline {
            self.seen.insert(id);
        }
    }

    /// Cancel pending repairs satisfied by an arrival: a whole-message
    /// arrival (`fragment == None`) satisfies everything for that ID, while a
    /// fragment arrival satisfies its own request and any whole-message
    /// request (which fragment zero or reassembly tracking supersedes).
    pub fn cancel_pending(&mut self, message_id: u8, fragment: Option<u8>) {
        self.pending.retain(|pending| {
            if pending.message_id != message_id {
                return true;
            }
            match (fragment, pending.fragment) {
                (None, _) | (Some(_), None) => false,
                (Some(arrived), Some(wanted)) => wanted != arrived,
            }
        });
    }
}

/// Outbound stream state for the local sender in one conversation.
#[derive(Clone, Debug)]
pub struct OutboundStream {
    pub next_id: u8,
    pub epoch: u16,
    /// Include Sequence Reset on the next message sent in this conversation.
    pub announce_reset: bool,
    pub refs: RefRing,
    pub last_active_ms: u64,
}

impl OutboundStream {
    pub fn fresh(now_ms: u64) -> Self {
        Self {
            next_id: 0,
            epoch: 0,
            announce_reset: true,
            refs: RefRing::default(),
            last_active_ms: now_ms,
        }
    }

    /// Allocate the next wire ID, retiring any wrapped mapping.
    pub fn allocate(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.refs.retire(id);
        id
    }
}

/// Key of an inbound stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub conversation: ConversationKey,
    pub sender: SenderScope,
}
