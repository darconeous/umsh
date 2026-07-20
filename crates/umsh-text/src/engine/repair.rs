//! Resend-service bookkeeping: pending archive lookups, response coalescing,
//! and deterministic jitter.

use umsh_core::PublicKey;

use crate::model::{ConversationKey, MessageSequence};

/// An archive lookup the platform has been asked to perform.
#[derive(Clone, Copy, Debug)]
pub struct PendingLookup {
    pub request_id: u32,
    /// The stream the request selects (the original conversation).
    pub conversation: ConversationKey,
    /// The authenticated requester (used only for diagnostics; responses are
    /// addressed by the conversation's delivery mode).
    pub requester: PublicKey,
    pub sequence: MessageSequence,
}

/// Ring of recently transmitted or answered frames, for coalescing resend
/// requests: duplicate requests from multiple group members, and requests
/// for a frame whose original transmission just left this node (a slow
/// serialized link can deliver frames later than the requester's patience).
#[derive(Clone, Debug, Default)]
pub struct CoalesceRing {
    entries: heapless::Vec<(ConversationKey, u8, Option<u8>, u64), 16>,
}

impl CoalesceRing {
    /// True when an equivalent request was answered within `window_ms`.
    pub fn recently_answered(
        &self,
        conversation: &ConversationKey,
        sequence: &MessageSequence,
        now_ms: u64,
        window_ms: u64,
    ) -> bool {
        let fragment = sequence.fragment.map(|fragment| fragment.index);
        self.entries.iter().any(|(conv, id, frag, at)| {
            conv == conversation
                && *id == sequence.message_id
                && *frag == fragment
                && now_ms.saturating_sub(*at) < window_ms
        })
    }

    pub fn record(
        &mut self,
        conversation: ConversationKey,
        sequence: &MessageSequence,
        now_ms: u64,
    ) {
        let fragment = sequence.fragment.map(|fragment| fragment.index);
        self.record_frame(conversation, sequence.message_id, fragment, now_ms);
    }

    /// Record one frame by its archive coordinates, refreshing any existing
    /// entry for the same frame.
    pub fn record_frame(
        &mut self,
        conversation: ConversationKey,
        message_id: u8,
        fragment: Option<u8>,
        now_ms: u64,
    ) {
        self.entries.retain(|(conv, id, frag, _)| {
            !(*conv == conversation && *id == message_id && *frag == fragment)
        });
        if self.entries.is_full() {
            self.entries.remove(0);
        }
        let _ = self
            .entries
            .push((conversation, message_id, fragment, now_ms));
    }
}

/// SplitMix64: deterministic scheduling jitter.
///
/// This is scheduling randomness only — it desynchronizes group repair
/// requests — and is never used as security material. Supplying the seed at
/// construction keeps the reducer deterministic under test.
#[derive(Clone, Debug)]
pub struct JitterSource {
    state: u64,
}

impl JitterSource {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// Uniform-ish value in `0..bound_ms` (0 when the bound is 0).
    pub fn jitter_ms(&mut self, bound_ms: u64) -> u64 {
        if bound_ms == 0 {
            0
        } else {
            self.next_u64() % bound_ms
        }
    }
}
