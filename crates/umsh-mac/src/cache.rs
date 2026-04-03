use heapless::Deque;

use crate::{RECENT_MIC_CAPACITY, REPLAY_BACKTRACK_SLOTS, REPLAY_STALE_MS};

/// Duplicate-suppression key derived from an accepted packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DupCacheKey {
    /// Authenticated packet keyed by its MIC bytes.
    Mic { bytes: [u8; 16], len: u8 },
    /// Unauthenticated packet keyed by a local hash.
    Hash32(u32),
}

/// Fixed-capacity cache of recently observed duplicate keys.
#[derive(Clone, Debug)]
pub struct DuplicateCache<const N: usize = 64> {
    entries: Deque<(DupCacheKey, u64), N>,
}

impl<const N: usize> Default for DuplicateCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DuplicateCache<N> {
    /// Create an empty duplicate cache.
    pub fn new() -> Self {
        Self {
            entries: Deque::new(),
        }
    }

    /// Return whether `key` is already present.
    pub fn contains(&self, key: &DupCacheKey) -> bool {
        self.entries.iter().any(|(entry, _)| entry == key)
    }

    /// Insert `key`, evicting the oldest entry if necessary.
    pub fn insert(&mut self, key: DupCacheKey, now_ms: u64) {
        if self.contains(&key) {
            return;
        }
        if self.entries.is_full() {
            let _ = self.entries.pop_front();
        }
        let _ = self.entries.push_back((key, now_ms));
    }

    /// Return the number of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

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