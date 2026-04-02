use heapless::Deque;

use crate::{RECENT_MIC_CAPACITY, REPLAY_BACKTRACK_SLOTS, REPLAY_STALE_MS};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DupCacheKey {
    Mic { bytes: [u8; 16], len: u8 },
    Hash32(u32),
}

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
    pub fn new() -> Self {
        Self {
            entries: Deque::new(),
        }
    }

    pub fn contains(&self, key: &DupCacheKey) -> bool {
        self.entries.iter().any(|(entry, _)| entry == key)
    }

    pub fn insert(&mut self, key: DupCacheKey, now_ms: u64) {
        if self.contains(&key) {
            return;
        }
        if self.entries.is_full() {
            let _ = self.entries.pop_front();
        }
        let _ = self.entries.push_back((key, now_ms));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentMic {
    pub counter: u32,
    pub mic: [u8; 16],
    pub mic_len: u8,
    pub accepted_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ReplayWindow {
    pub last_accepted: u32,
    pub last_accepted_time_ms: u64,
    pub backward_bitmap: u8,
    pub recent_mics: Deque<RecentMic, RECENT_MIC_CAPACITY>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayVerdict {
    Accept,
    Replay,
    OutOfWindow,
    Stale,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last_accepted: 0,
            last_accepted_time_ms: 0,
            backward_bitmap: 0,
            recent_mics: Deque::new(),
        }
    }

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

        if self.has_matching_recent_mic(counter, mic, now_ms) {
            ReplayVerdict::Replay
        } else {
            ReplayVerdict::Accept
        }
    }

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