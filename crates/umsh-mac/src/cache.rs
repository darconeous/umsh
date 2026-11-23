use heapless::Deque;

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
    /// fields, and whether it carries Route Retry, as a MIC-keyed packet is.
    Hash32 { hash: u32, route_retry: bool },
    /// MAC ack keyed the same way as [`Hash32`](Self::Hash32), carried as its
    /// own variant because acks age out of the cache on a much shorter clock
    ///—see [`DuplicateCache::set_ack_ttl_ms`].
    AckHash32 { hash: u32, route_retry: bool },
}

/// How long a forwarding-cache key stays suppressed.
///
/// Capacity alone is not an expiry policy. A packet whose identity is
/// derived from its contents rather than a MIC—a beacon, whose body is
/// empty and whose non-dynamic options never change—hashes to the same key
/// on every repetition, so a quiet mesh that never pushes 64 further keys
/// through the ring would suppress that node's beacons forever. The entry
/// only has to outlast the copies of one flood and the forwards and retries
/// that carry it, which arrive within a minute or two even at slow
/// settings. A repeater cannot verify a MIC, so a longer lifetime buys no
/// defense against a replay, while it does hold back a node's repeated
/// identical packets beyond its direct neighbors.
pub const DUP_CACHE_TTL_MS: u64 = 10 * 60 * 1000;

/// How long the MAC's first-copy acceptance cache remembers a frame that no
/// replay window judges (an unsigned multicast, or a signed frame with no
/// window), so that delivery never sees a duplicate of it.
///
/// This is not a forwarding cache: it keeps a late copy of a frame from
/// reaching the application a second time, so it holds an entry much longer
/// than [`DUP_CACHE_TTL_MS`].
pub const FIRST_COPY_CACHE_TTL_MS: u64 = 60 * 60 * 1000;

/// How long a MAC-ack duplicate key stays suppressed until the MAC sets a
/// lifetime from its channel timing ([`DuplicateCache::set_ack_ttl_ms`]).
///
/// An ack's entry only has to outlive the copies of one exchange: late
/// flood copies and a routed ack's single retry. A re-acknowledgment that
/// answers a Route Retry carries the option itself, so it is a different
/// key and is carried whatever this lifetime is.
pub const ACK_DUP_CACHE_TTL_MS: u64 = 10 * 1000;

/// Fixed-capacity cache of recently observed duplicate keys.
///
/// Entries leave either by age ([`DUP_CACHE_TTL_MS`] unless the cache was
/// made [`with_ttl_ms`](Self::with_ttl_ms)) or by eviction of the oldest when
/// the ring is full, whichever comes first.
#[derive(Clone, Debug)]
pub struct DuplicateCache<const N: usize = 64> {
    /// Each key with the time it expires. Insertion-ordered, so the oldest
    /// entry is always at the front and expiry can be pruned from that end
    /// without a scan.
    entries: Deque<(DupCacheKey, u64), N>,
    /// Lifetime of a MIC- or hash-keyed entry.
    ttl_ms: u64,
    /// Lifetime of a MAC ack's entry.
    ack_ttl_ms: u64,
}

impl<const N: usize> Default for DuplicateCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DuplicateCache<N> {
    /// Create an empty duplicate cache whose MIC- and hash-keyed entries
    /// live [`DUP_CACHE_TTL_MS`].
    pub fn new() -> Self {
        Self::with_ttl_ms(DUP_CACHE_TTL_MS)
    }

    /// Create an empty duplicate cache whose MIC- and hash-keyed entries
    /// live `ttl_ms`.
    pub fn with_ttl_ms(ttl_ms: u64) -> Self {
        Self {
            entries: Deque::new(),
            ttl_ms,
            ack_ttl_ms: ACK_DUP_CACHE_TTL_MS,
        }
    }

    /// Set the lifetime of MAC-ack entries inserted from now on.
    pub fn set_ack_ttl_ms(&mut self, ttl_ms: u64) {
        self.ack_ttl_ms = ttl_ms;
    }

    /// Return whether `key` is present and has not aged out.
    pub fn contains(&self, key: &DupCacheKey, now_ms: u64) -> bool {
        self.entries
            .iter()
            .any(|(entry, expires_ms)| entry == key && now_ms < *expires_ms)
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
        let ttl_ms = match key {
            DupCacheKey::AckHash32 { .. } => self.ack_ttl_ms,
            DupCacheKey::Mic { .. } | DupCacheKey::Hash32 { .. } => self.ttl_ms,
        };
        let _ = self.entries.push_back((key, now_ms.saturating_add(ttl_ms)));
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
    ///
    /// A clock that has gone backwards (a resynchronized monotonic source)
    /// leaves an entry looking younger than it is, never older, so
    /// suppression can only be held slightly too long—never released early.
    pub fn expire(&mut self, now_ms: u64) {
        while let Some((_, expires_ms)) = self.entries.front() {
            if now_ms < *expires_ms {
                return;
            }
            let _ = self.entries.pop_front();
        }
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
