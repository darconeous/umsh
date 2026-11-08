use heapless::{Deque, Vec};

// Replay detection is a Security-chapter concept and lives in
// umsh-crypto so the device can share it without depending on
// the MAC; re-exported here so this crate's public API is unchanged.
pub use umsh_crypto::replay::{RecentMic, ReplayVerdict, ReplayWindow, RxAcceptance};

/// Duplicate-suppression key derived from an accepted packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DupCacheKey {
    /// Authenticated routable packet keyed by its MIC bytes.
    Mic {
        bytes: [u8; 16],
        len: u8,
        route_retry: bool,
    },
    /// MIC-less routable packet keyed by a stable local hash over non-dynamic
    /// fields.
    Hash32(u32),
    /// MAC ack keyed the same way as [`Hash32`](Self::Hash32), carried as its
    /// own variant because acks age out of the cache on a much shorter clock
    ///—see [`ACK_DUP_CACHE_TTL_MS`].
    AckHash32(u32),
}

/// How long a duplicate key stays suppressed.
///
/// Capacity alone is not an expiry policy. A packet whose identity is
/// derived from its contents rather than a MIC—a beacon, whose body is
/// empty and whose non-dynamic options never change—hashes to the same key
/// on every repetition, so a quiet mesh that never pushes 64 further keys
/// through the ring would suppress that node's beacons forever. An hour is
/// long enough that a burst of retransmissions of one packet is still
/// collapsed, and short enough that a node re-announcing itself is heard
/// again well within the time anyone would wait for it.
pub const DUP_CACHE_TTL_MS: u64 = 60 * 60 * 1000;

/// How long a MAC-ack duplicate key stays suppressed.
///
/// An identical re-acknowledgement is the one duplicate a *correct* node
/// emits on purpose: the duplicate-acknowledgement window exists so a
/// destination can re-ack when the sender retransmits, and that re-ack
/// only helps if repeaters carry it. An ack held under the general
/// hour-long TTL would be forwarded once and then silently absorbed for
/// the rest of the hour, killing the recovery path at the first hop.
/// Ten seconds still collapses the burst of copies from a single
/// exchange—flood copies and retransmission ladders both play out
/// within a few confirmation windows—while a re-ack provoked by a
/// sender's route retry, arriving tens of seconds later, is carried.
pub const ACK_DUP_CACHE_TTL_MS: u64 = 10 * 1000;

/// Fixed-capacity cache of recently observed duplicate keys.
///
/// Entries leave either by age ([`DUP_CACHE_TTL_MS`]) or by eviction of the
/// oldest when the ring is full, whichever comes first.
#[derive(Clone, Debug)]
pub struct DuplicateCache<const N: usize = 64> {
    /// Insertion-ordered, so the oldest entry is always at the front and
    /// expiry can be pruned from that end without a scan.
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

    /// Return whether `key` is present and has not aged out.
    pub fn contains(&self, key: &DupCacheKey, now_ms: u64) -> bool {
        self.entries.iter().any(|(entry, inserted_ms)| {
            entry == key && !Self::is_expired(entry, *inserted_ms, now_ms)
        })
    }

    /// Insert `key`, dropping aged-out entries and evicting the oldest
    /// survivor if the ring is still full.
    ///
    /// A repeat of a key already held does not refresh its timestamp: the
    /// entry ages from when the packet was *first* seen, so a node repeating
    /// itself inside the window cannot hold its own suppression open.
    pub fn insert(&mut self, key: DupCacheKey, now_ms: u64) {
        self.expire(now_ms);
        if self.contains(&key, now_ms) {
            return;
        }
        if self.entries.is_full() {
            let _ = self.entries.pop_front();
        }
        let _ = self.entries.push_back((key, now_ms));
    }

    /// Forget `key`, so the next copy of its packet counts as new.
    pub fn remove(&mut self, key: &DupCacheKey) {
        if !self.entries.iter().any(|(entry, _)| entry == key) {
            return;
        }
        let mut kept = Deque::new();
        while let Some(entry) = self.entries.pop_front() {
            if &entry.0 != key {
                // Capacity is unchanged and only entries are dropped, so
                // every survivor fits.
                let _ = kept.push_back(entry);
            }
        }
        self.entries = kept;
    }

    /// Drop aged-out entries from the front of the ring.
    ///
    /// Insertion order only bounds age from one side, and TTLs differ by
    /// key kind, so an expired short-TTL entry can sit behind a live
    /// long-TTL one; it stops answering [`contains`](Self::contains)
    /// immediately and is reclaimed when it reaches the front.
    pub fn expire(&mut self, now_ms: u64) {
        while let Some((entry, inserted_ms)) = self.entries.front() {
            if !Self::is_expired(entry, *inserted_ms, now_ms) {
                return;
            }
            let _ = self.entries.pop_front();
        }
    }

    /// A clock that has gone backwards (a resynchronized monotonic source)
    /// leaves the entry looking younger than it is, never older, so
    /// suppression can only be held slightly too long—never released early.
    fn is_expired(key: &DupCacheKey, inserted_ms: u64, now_ms: u64) -> bool {
        let ttl_ms = match key {
            DupCacheKey::AckHash32(_) => ACK_DUP_CACHE_TTL_MS,
            DupCacheKey::Mic { .. } | DupCacheKey::Hash32(_) => DUP_CACHE_TTL_MS,
        };
        now_ms.saturating_sub(inserted_ms) >= ttl_ms
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

/// Signed frames on `EMERGENCY` remembered at once.
pub const EMERGENCY_DIGESTS: usize = 8;
/// How long a signed frame on `EMERGENCY` is remembered.
pub const EMERGENCY_DIGEST_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// What a signed frame is remembered by: the first bytes of its
/// signature, which no other frame shares.
pub type FrameDigest = [u8; 8];

/// Signed frames accepted on `EMERGENCY`, remembered past their signers'
/// receive windows.
///
/// A stranger's window can be given up, and its next frame is then first
/// contact, so a replay of a real alert would raise it again. This record
/// is what refuses that replay. New frames never displace what it holds:
/// entries leave only by age, and a full record takes nothing more until
/// one does. A burst of frames from freshly minted keys can therefore keep
/// later frames out, but never release one already held.
#[derive(Clone, Debug)]
pub struct EmergencyDigests<const N: usize = EMERGENCY_DIGESTS> {
    entries: Vec<(FrameDigest, u64), N>,
}

impl<const N: usize> Default for EmergencyDigests<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> EmergencyDigests<N> {
    /// An empty record.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Whether `digest` is held and has not aged out.
    pub fn contains(&self, digest: &FrameDigest, now_ms: u64) -> bool {
        self.entries
            .iter()
            .any(|(held, at_ms)| held == digest && !Self::is_expired(*at_ms, now_ms))
    }

    /// Remember `digest`, dropping aged-out entries first. Returns `false`
    /// when every entry is still live, and so nothing was recorded.
    pub fn insert(&mut self, digest: FrameDigest, now_ms: u64) -> bool {
        self.entries
            .retain(|(_, at_ms)| !Self::is_expired(*at_ms, now_ms));
        if self.contains(&digest, now_ms) {
            return true;
        }
        self.entries.push((digest, now_ms)).is_ok()
    }

    /// As for [`DuplicateCache`], a clock that went backwards holds an
    /// entry longer, never shorter.
    fn is_expired(at_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(at_ms) >= EMERGENCY_DIGEST_TTL_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full record refuses new digests rather than give up a held one,
    /// and makes room only as entries age out.
    #[test]
    fn emergency_digests_are_never_displaced_by_new_ones() {
        let mut digests = EmergencyDigests::<2>::new();
        assert!(digests.insert([1; 8], 0));
        assert!(digests.insert([2; 8], 10));
        assert!(!digests.insert([3; 8], 20));
        assert!(digests.contains(&[1; 8], 20));
        assert!(digests.contains(&[2; 8], 20));
        assert!(!digests.contains(&[3; 8], 20));

        assert!(digests.insert([3; 8], EMERGENCY_DIGEST_TTL_MS));
        assert!(!digests.contains(&[1; 8], EMERGENCY_DIGEST_TTL_MS));
        assert!(digests.contains(&[2; 8], EMERGENCY_DIGEST_TTL_MS));
        assert!(digests.contains(&[3; 8], EMERGENCY_DIGEST_TTL_MS));
    }
}
