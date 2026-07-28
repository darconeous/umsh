use heapless::Deque;

// Replay detection is a Security-chapter concept and lives in
// umsh-crypto so the device can share it without depending on
// the MAC; re-exported here so this crate's public API is unchanged.
pub use umsh_crypto::replay::{RecentMic, ReplayVerdict, ReplayWindow};

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
}

/// How long a duplicate key stays suppressed.
///
/// Capacity alone is not an expiry policy. A packet whose identity is
/// derived from its contents rather than a MIC — a beacon, whose body is
/// empty and whose non-dynamic options never change — hashes to the same key
/// on every repetition, so a quiet mesh that never pushes 64 further keys
/// through the ring would suppress that node's beacons forever. An hour is
/// long enough that a burst of retransmissions of one packet is still
/// collapsed, and short enough that a node re-announcing itself is heard
/// again well within the time anyone would wait for it.
pub const DUP_CACHE_TTL_MS: u64 = 60 * 60 * 1000;

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
        self.entries
            .iter()
            .any(|(entry, inserted_ms)| entry == key && !Self::is_expired(*inserted_ms, now_ms))
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

    /// Drop every entry older than [`DUP_CACHE_TTL_MS`].
    pub fn expire(&mut self, now_ms: u64) {
        while let Some((_, inserted_ms)) = self.entries.front() {
            if !Self::is_expired(*inserted_ms, now_ms) {
                return;
            }
            let _ = self.entries.pop_front();
        }
    }

    /// A clock that has gone backwards (a resynchronized monotonic source)
    /// leaves the entry looking younger than it is, never older, so
    /// suppression can only be held slightly too long — never released early.
    fn is_expired(inserted_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(inserted_ms) >= DUP_CACHE_TTL_MS
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
