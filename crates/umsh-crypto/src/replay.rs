//! Replay detection for secure traffic, as specified in the protocol's
//! Security chapter (§Replay Detection, §Duplicate Acknowledgement
//! Window).
//!
//! A [`ReplayWindow`] tracks one sender's frame counters at a final
//! destination: a monotonic baseline, a small backward bitmap for
//! out-of-order delivery, and a bounded cache of recently accepted MICs
//! used both to reject backward-window replays and to recognize
//! duplicates eligible for an idempotent re-acknowledgement. It is used
//! by the host MAC per peer and per identity, and by the device
//! per provisioned host peer for detached acknowledgement delegation.

use heapless::Deque;

/// Retained accepted-MIC entries per window (backward window + 1).
pub const RECENT_MIC_CAPACITY: usize = 9;
/// Backward-window size in counter slots (spec suggested default).
pub const REPLAY_BACKTRACK_SLOTS: u32 = 8;
/// Out-of-order acceptance time bound (spec: 5 minutes).
pub const REPLAY_STALE_MS: u64 = 5 * 60 * 1000;

/// Recently accepted MIC tracked for backward-window replay handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentMic {
    /// Accepted frame counter.
    pub counter: u32,
    /// Normalized MIC bytes.
    pub mic: [u8; 16],
    /// Number of valid bytes in [`mic`](Self::mic).
    pub mic_len: u8,
    /// Acceptance timestamp in milliseconds.
    pub accepted_ms: u64,
}

/// Replay-detection window for secure traffic from one sender.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// Highest accepted frame counter.
    pub last_accepted: u32,
    /// Timestamp of the highest accepted frame.
    pub last_accepted_time_ms: u64,
    /// Occupancy bitmap for the backward counter window.
    pub backward_bitmap: u8,
    /// Accepted MICs retained for duplicate late-arrival checks.
    pub recent_mics: Deque<RecentMic, RECENT_MIC_CAPACITY>,
    /// Counter of the last duplicate re-acknowledged, paired with
    /// [`last_dup_ack_ms`](Self::last_dup_ack_ms).
    ///
    /// One pair for the whole window, not a stamp per retained MIC:
    /// duplicate re-acks pace one packet's copies, and windows are
    /// replicated widely enough (per channel, per tracked sender) that
    /// per-entry state is real RAM on the embedded targets — spent, for
    /// channel traffic, on packets that are never acknowledged at all.
    pub last_dup_ack_counter: u32,
    /// When the duplicate carrying
    /// [`last_dup_ack_counter`](Self::last_dup_ack_counter) was last
    /// re-acknowledged, in milliseconds.
    pub last_dup_ack_ms: u64,
}

/// Result of checking a packet against a replay window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// The packet is acceptable.
    Accept,
    /// The exact counter/MIC pair was already accepted.
    Replay,
    /// The counter is too far behind the tracked window.
    OutOfWindow,
    /// The replay state is too stale to safely accept backward-window traffic.
    Stale,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Create a fresh replay window.
    pub fn new() -> Self {
        Self {
            last_accepted: 0,
            last_accepted_time_ms: 0,
            backward_bitmap: 0,
            recent_mics: Deque::new(),
            last_dup_ack_counter: 0,
            last_dup_ack_ms: 0,
        }
    }

    /// Evaluate whether `counter` and `mic` are acceptable at `now_ms`.
    pub fn check(&self, counter: u32, mic: &[u8], now_ms: u64) -> ReplayVerdict {
        if self.last_accepted_time_ms == 0 && self.recent_mics.is_empty() {
            return ReplayVerdict::Accept;
        }

        if counter > self.last_accepted {
            return ReplayVerdict::Accept;
        }

        if now_ms.saturating_sub(self.last_accepted_time_ms) > REPLAY_STALE_MS {
            return ReplayVerdict::Stale;
        }

        let delta = self.last_accepted - counter;
        if delta > REPLAY_BACKTRACK_SLOTS {
            return ReplayVerdict::OutOfWindow;
        }

        let slot_occupied = if delta == 0 {
            true
        } else {
            self.backward_bitmap & (1u8 << (delta - 1)) != 0
        };

        if !slot_occupied {
            return ReplayVerdict::Accept;
        }

        let _ = self.has_matching_recent_mic(counter, mic, now_ms);
        ReplayVerdict::Replay
    }

    /// Return whether this is an exact, recently accepted packet eligible for
    /// an idempotent duplicate acknowledgement, and record the
    /// acknowledgement when it is.
    ///
    /// This deliberately requires both the bounded counter distance and a
    /// matching retained MIC. Merely reusing an occupied counter does not prove
    /// that the receiver previously accepted this logical packet.
    ///
    /// A duplicate is re-acknowledged at most once per `holdoff_ms`. The
    /// duplicate-acknowledgement window exists so a sender whose ack was
    /// lost can recover by retransmitting — but most duplicates are not
    /// retransmissions, they are flood copies of a single transmission
    /// arriving over different paths, and each already-sent ack covers
    /// all of them. A sender cannot retransmit before its confirmation
    /// window lapses, so a duplicate arriving inside that window proves
    /// nothing was lost yet and earns no fresh ack. Callers pass their
    /// forwarding-confirmation window (or the closest equivalent their
    /// radio timing offers) as `holdoff_ms`.
    ///
    /// Two clocks pace this. Copies of the *accepted* transmission are
    /// caught by the entry's acceptance time — the acceptance already
    /// queued their ack. Copies of a *retransmission* are caught by the
    /// re-ack stamp the first copy leaves behind. A `true` return
    /// stamps: the caller is expected to queue the acknowledgement it
    /// just asked about.
    pub fn note_acknowledgeable_duplicate(
        &mut self,
        counter: u32,
        mic: &[u8],
        now_ms: u64,
        holdoff_ms: u64,
    ) -> bool {
        if self.last_accepted_time_ms == 0 && self.recent_mics.is_empty() {
            return false;
        }

        let ack_distance = self.last_accepted.wrapping_sub(counter);
        if ack_distance > REPLAY_BACKTRACK_SLOTS {
            return false;
        }
        let Some(entry) = self.find_recent_mic(counter, mic, now_ms) else {
            return false;
        };
        if now_ms.saturating_sub(entry.accepted_ms) < holdoff_ms {
            return false;
        }
        if self.last_dup_ack_counter == counter
            && now_ms.saturating_sub(self.last_dup_ack_ms) < holdoff_ms
        {
            return false;
        }
        self.last_dup_ack_counter = counter;
        self.last_dup_ack_ms = now_ms;
        true
    }

    /// Record an accepted `counter` and `mic` at `now_ms`.
    pub fn accept(&mut self, counter: u32, mic: &[u8], now_ms: u64) {
        self.prune_recent_mics(now_ms);

        if self.last_accepted_time_ms == 0 && self.recent_mics.is_empty() {
            self.last_accepted = counter;
            self.last_accepted_time_ms = now_ms;
        } else if counter > self.last_accepted {
            let shift = (counter - self.last_accepted) as usize;
            self.backward_bitmap = if shift > REPLAY_BACKTRACK_SLOTS as usize {
                0
            } else {
                let shifted = if shift >= u8::BITS as usize {
                    0
                } else {
                    self.backward_bitmap << shift
                };
                shifted | (1u8 << (shift - 1))
            };
            self.last_accepted = counter;
            self.last_accepted_time_ms = now_ms;
        } else if counter < self.last_accepted {
            let delta = self.last_accepted - counter;
            if (1..=REPLAY_BACKTRACK_SLOTS).contains(&delta) {
                self.backward_bitmap |= 1u8 << (delta - 1);
            }
        } else {
            self.last_accepted_time_ms = now_ms;
        }

        if let Some((normalized_mic, mic_len)) = normalize_mic(mic) {
            if self.recent_mics.is_full() {
                let _ = self.recent_mics.pop_front();
            }
            let _ = self.recent_mics.push_back(RecentMic {
                counter,
                mic: normalized_mic,
                mic_len,
                accepted_ms: now_ms,
            });
        }
    }

    /// Reset the replay window to a known baseline.
    pub fn reset(&mut self, baseline: u32, now_ms: u64) {
        self.last_accepted = baseline;
        self.last_accepted_time_ms = now_ms;
        self.backward_bitmap = 0;
        self.recent_mics.clear();
        self.last_dup_ack_counter = 0;
        self.last_dup_ack_ms = 0;
    }

    fn has_matching_recent_mic(&self, counter: u32, mic: &[u8], now_ms: u64) -> bool {
        let Some((normalized_mic, mic_len)) = normalize_mic(mic) else {
            return false;
        };

        self.recent_mics.iter().any(|entry| {
            entry.counter == counter
                && now_ms.saturating_sub(entry.accepted_ms) <= REPLAY_STALE_MS
                && entry.mic_len == mic_len
                && entry.mic[..mic_len as usize] == normalized_mic[..mic_len as usize]
        })
    }

    fn find_recent_mic(&self, counter: u32, mic: &[u8], now_ms: u64) -> Option<&RecentMic> {
        let (normalized_mic, mic_len) = normalize_mic(mic)?;

        self.recent_mics.iter().find(|entry| {
            entry.counter == counter
                && now_ms.saturating_sub(entry.accepted_ms) <= REPLAY_STALE_MS
                && entry.mic_len == mic_len
                && entry.mic[..mic_len as usize] == normalized_mic[..mic_len as usize]
        })
    }

    fn prune_recent_mics(&mut self, now_ms: u64) {
        while let Some(front) = self.recent_mics.front() {
            if now_ms.saturating_sub(front.accepted_ms) <= REPLAY_STALE_MS {
                break;
            }
            let _ = self.recent_mics.pop_front();
        }
    }
}

fn normalize_mic(mic: &[u8]) -> Option<([u8; 16], u8)> {
    if mic.len() > 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out[..mic.len()].copy_from_slice(mic);
    Some((out, mic.len() as u8))
}
