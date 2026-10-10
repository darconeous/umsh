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
// ACK offsets reserve zero for "not queued" and cover the retention window.
const _: () = assert!(REPLAY_STALE_MS < u32::MAX as u64);

/// Recently accepted MIC tracked for backward-window replay handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentMic {
    /// Accepted frame counter.
    pub counter: u32,
    /// Normalized MIC bytes.
    pub mic: [u8; 16],
    /// Number of valid bytes in [`mic`](Self::mic).
    pub mic_len: u8,
    /// Monotonic acceptance time in wrapping u32 seconds, rounded down.
    /// Retention may end up to 999 ms early, but never extends beyond the
    /// five-minute limit.
    pub accepted_secs: u32,
    /// Milliseconds from the beginning of `accepted_secs` when an ACK was
    /// queued, plus one; zero means no ACK was queued. This preserves exact
    /// ACK timing even though the acceptance timestamp is rounded down.
    ack_queued_offset: u32,
}

impl RecentMic {
    fn age_ms(&self, now_ms: u64) -> u64 {
        let now_secs = (now_ms / 1000) as u32;
        // Subtract in the wrapping seconds domain before widening. Include
        // the current fractional second so ACK offsets retain ms precision.
        u64::from(now_secs.wrapping_sub(self.accepted_secs)) * 1000 + now_ms % 1000
    }

    fn is_recent(&self, now_ms: u64) -> bool {
        self.age_ms(now_ms) <= REPLAY_STALE_MS
    }
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

        if now_ms.wrapping_sub(self.last_accepted_time_ms) > REPLAY_STALE_MS {
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

    /// Whether an exact retained duplicate may be acknowledged. An accepted
    /// payload may not yet have had an ACK-eligible copy (e.g. an overheard
    /// source route), or enqueue may have failed. Only a successfully queued
    /// ACK starts the per-packet holdoff. This never changes replay state.
    pub fn can_acknowledge_duplicate(
        &self,
        counter: u32,
        mic: &[u8],
        now_ms: u64,
        holdoff_ms: u64,
    ) -> bool {
        if self.last_accepted.wrapping_sub(counter) > REPLAY_BACKTRACK_SLOTS {
            return false;
        }
        let Some(entry) = self.find_recent_mic(counter, mic, now_ms) else {
            return false;
        };
        let offset = entry.ack_queued_offset;
        offset == 0 || entry.age_ms(now_ms).wrapping_sub(u64::from(offset - 1)) >= holdoff_ms
    }

    /// How long ago the copy this one duplicates was accepted, when it is an
    /// exact retained duplicate—same counter, same MIC.
    ///
    /// A copy of one transmission still propagating through the mesh
    /// arrives within seconds of the first; the age is what separates it
    /// from the same frame replayed minutes later. Acceptance times are
    /// rounded down to the second, so the age can read up to 999 ms long.
    pub fn duplicate_age_ms(&self, counter: u32, mic: &[u8], now_ms: u64) -> Option<u64> {
        self.find_recent_mic(counter, mic, now_ms)
            .map(|entry| entry.age_ms(now_ms))
    }

    /// Record a successful ACK enqueue, without refreshing acceptance or the
    /// replay baseline. Failed enqueue attempts must not call this method.
    pub fn mark_ack_queued(&mut self, counter: u32, mic: &[u8], now_ms: u64) {
        let Some((normalized_mic, mic_len)) = normalize_mic(mic) else {
            return;
        };
        if let Some(entry) = self.recent_mics.iter_mut().find(|entry| {
            entry.counter == counter
                && entry.mic_len == mic_len
                && entry.mic[..mic_len as usize] == normalized_mic[..mic_len as usize]
                && entry.is_recent(now_ms)
        }) {
            entry.ack_queued_offset = (entry.age_ms(now_ms) + 1) as u32;
        }
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
                accepted_secs: (now_ms / 1000) as u32,
                ack_queued_offset: 0,
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
                && entry.is_recent(now_ms)
                && entry.mic_len == mic_len
                && entry.mic[..mic_len as usize] == normalized_mic[..mic_len as usize]
        })
    }

    fn find_recent_mic(&self, counter: u32, mic: &[u8], now_ms: u64) -> Option<&RecentMic> {
        let (normalized_mic, mic_len) = normalize_mic(mic)?;

        self.recent_mics.iter().find(|entry| {
            entry.counter == counter
                && entry.is_recent(now_ms)
                && entry.mic_len == mic_len
                && entry.mic[..mic_len as usize] == normalized_mic[..mic_len as usize]
        })
    }

    fn prune_recent_mics(&mut self, now_ms: u64) {
        while let Some(front) = self.recent_mics.front() {
            if front.is_recent(now_ms) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_tracking_stays_within_replay_storage_budget() {
        assert!(core::mem::size_of::<RecentMic>() <= 32);
        assert!(core::mem::size_of::<ReplayWindow>() <= 384);
    }

    #[test]
    fn rounded_acceptance_preserves_millisecond_ack_pacing() {
        for base_ms in [
            0,
            1_000_000,
            u64::from(u32::MAX) * 1000,
            (u64::from(u32::MAX) + 1) * 1000,
            (u64::from(u32::MAX) + 2) * 1000,
        ] {
            for fraction_ms in [0, 1, 999] {
                for ack_delay_ms in [0, 1, 1_205] {
                    let accepted_ms = base_ms + fraction_ms;
                    let queued_ms = accepted_ms + ack_delay_ms;
                    let mut window = ReplayWindow::new();
                    window.accept(10, &[7; 8], accepted_ms);
                    assert!(window.can_acknowledge_duplicate(10, &[7; 8], queued_ms, 100));
                    window.mark_ack_queued(10, &[7; 8], queued_ms);
                    assert!(!window.can_acknowledge_duplicate(10, &[7; 8], queued_ms + 99, 100));
                    assert!(window.can_acknowledge_duplicate(10, &[7; 8], queued_ms + 100, 100));
                    assert_eq!(window.last_accepted_time_ms, accepted_ms);
                    assert_eq!(
                        window.check(10, &[7; 8], queued_ms + 100),
                        ReplayVerdict::Replay
                    );
                }
            }
        }
    }

    #[test]
    fn rounded_acceptance_expires_conservatively_without_changing_replay_baseline() {
        for base_ms in [
            1_000_000,
            u64::from(u32::MAX) * 1000,
            (u64::from(u32::MAX) + 1) * 1000,
        ] {
            for fraction_ms in [0, 1, 999] {
                let mut window = ReplayWindow::new();
                let accepted_ms = base_ms + fraction_ms;
                let last_retained_ms = base_ms + REPLAY_STALE_MS;
                window.accept(10, &[7; 8], accepted_ms);
                assert!(window.can_acknowledge_duplicate(10, &[7; 8], last_retained_ms, 0));
                window.mark_ack_queued(10, &[7; 8], last_retained_ms);
                let last_offset = window.recent_mics.front().unwrap().ack_queued_offset;
                assert!(!window.can_acknowledge_duplicate(10, &[7; 8], last_retained_ms + 1, 0));
                window.mark_ack_queued(10, &[7; 8], last_retained_ms + 1);
                assert_eq!(
                    window.recent_mics.front().unwrap().ack_queued_offset,
                    last_offset
                );
                // Per-entry expiry can be early; the baseline still has exact timing.
                assert_eq!(
                    window.check(10, &[7; 8], accepted_ms + REPLAY_STALE_MS),
                    ReplayVerdict::Replay
                );
                assert_eq!(
                    window.check(10, &[7; 8], accepted_ms + REPLAY_STALE_MS + 1),
                    ReplayVerdict::Stale
                );
                window.accept(11, &[8; 8], last_retained_ms + 1);
                assert_eq!(window.recent_mics.len(), 1);
                assert_eq!(window.recent_mics.front().unwrap().counter, 11);
            }
        }
    }

    #[test]
    fn seconds_rollover_preserves_entries_ack_pacing_and_expiry() {
        let mut window = ReplayWindow::new();
        let rollover_ms = (u64::from(u32::MAX) + 1) * 1000;
        window.accept(10, &[7; 8], rollover_ms - 20);
        window.mark_ack_queued(10, &[7; 8], rollover_ms - 15);
        window.accept(11, &[8; 8], rollover_ms + 10);
        assert_eq!(window.recent_mics.len(), 2);
        assert_eq!(window.recent_mics.front().unwrap().accepted_secs, u32::MAX);
        assert_eq!(window.recent_mics.back().unwrap().accepted_secs, 0);
        assert!(!window.can_acknowledge_duplicate(10, &[7; 8], rollover_ms + 84, 100));
        assert!(window.can_acknowledge_duplicate(10, &[7; 8], rollover_ms + 85, 100));
        assert!(window.can_acknowledge_duplicate(11, &[8; 8], rollover_ms + 85, 100));
        window.mark_ack_queued(11, &[8; 8], rollover_ms + 85);
        assert!(!window.can_acknowledge_duplicate(11, &[8; 8], rollover_ms + 184, 100));
        assert!(window.can_acknowledge_duplicate(11, &[8; 8], rollover_ms + 185, 100));
        assert_eq!(
            window.check(10, &[7; 8], rollover_ms + 185),
            ReplayVerdict::Replay
        );
        assert_eq!(window.last_accepted_time_ms, rollover_ms + 10);

        // Prune the pre-wrap entry while retaining the post-wrap entry.
        let expired_ms = rollover_ms - 1000 + REPLAY_STALE_MS + 1;
        assert!(!window.can_acknowledge_duplicate(10, &[7; 8], expired_ms, 0));
        assert!(window.can_acknowledge_duplicate(11, &[8; 8], expired_ms, 0));
        window.accept(12, &[9; 8], expired_ms);
        assert_eq!(window.recent_mics.len(), 2);
        assert_eq!(window.recent_mics.front().unwrap().counter, 11);
    }

    #[test]
    fn ack_offset_covers_the_entire_retention_window() {
        // Exercise offsets beyond u16, including the last retained millisecond.
        let mut window = ReplayWindow::new();
        window.accept(10, &[7; 8], 1_000_000);
        let last_ms = 1_000_000 + REPLAY_STALE_MS;
        window.mark_ack_queued(10, &[7; 8], last_ms - 1);
        assert!(!window.can_acknowledge_duplicate(10, &[7; 8], last_ms, 2));
        assert!(window.can_acknowledge_duplicate(10, &[7; 8], last_ms, 1));
        window.mark_ack_queued(10, &[7; 8], last_ms);
        assert!(!window.can_acknowledge_duplicate(10, &[7; 8], last_ms, 1));
        assert!(!window.can_acknowledge_duplicate(10, &[7; 8], last_ms + 1, 0));
    }

    #[test]
    fn first_ack_waits_for_enqueue_not_payload_acceptance() {
        let mut window = ReplayWindow::new();
        window.accept(10, &[7; 8], 0);
        assert!(window.can_acknowledge_duplicate(10, &[7; 8], 1, 100));
        // A failed enqueue leaves the next copy immediately eligible.
        assert!(window.can_acknowledge_duplicate(10, &[7; 8], 2, 100));
        window.mark_ack_queued(10, &[7; 8], 2);
        assert!(!window.can_acknowledge_duplicate(10, &[7; 8], 101, 100));
        assert!(window.can_acknowledge_duplicate(10, &[7; 8], 102, 100));
        assert_eq!(window.check(10, &[7; 8], 102), ReplayVerdict::Replay);
        assert_eq!(window.last_accepted_time_ms, 0);
    }

    #[test]
    fn interleaved_acks_are_paced_per_mic_and_do_not_refresh_expiry() {
        let mut window = ReplayWindow::new();
        for counter in 1..=2 {
            window.accept(counter, &[counter as u8; 8], 1);
            window.mark_ack_queued(counter, &[counter as u8; 8], 20);
        }
        assert!(!window.can_acknowledge_duplicate(1, &[1; 8], 100, 100));
        assert!(!window.can_acknowledge_duplicate(1, &[9; 8], 120, 100));
        window.mark_ack_queued(1, &[1; 8], REPLAY_STALE_MS);
        assert!(!window.can_acknowledge_duplicate(1, &[1; 8], REPLAY_STALE_MS + 2, 0));
        assert_eq!(window.last_accepted_time_ms, 1);
        window.reset(2, REPLAY_STALE_MS + 2);
        assert!(!window.can_acknowledge_duplicate(1, &[1; 8], REPLAY_STALE_MS + 3, 0));
    }
}
