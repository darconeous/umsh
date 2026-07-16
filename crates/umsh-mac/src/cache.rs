use heapless::Deque;

// Replay detection is a Security-chapter concept and lives in
// umsh-crypto so the companion NCP can share it without depending on
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
