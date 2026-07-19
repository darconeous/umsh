//! The device node's persisted frame-counter map (device-node plan
//! increment 4).
//!
//! The MAC's `CounterStore` contract is per-context `store` calls
//! followed by one `flush` per persistence cycle, already batched to
//! one write per `COUNTER_PERSIST_BLOCK_SIZE` (128) secured frames.
//! This map is the RAM image behind that contract: `store` upserts
//! here, and `flush` serializes the *whole* map into a single
//! `proto_store` record in the counter journal (`COUNTER_PAGE0`).
//! Whole-map records keep the journal machinery identical to the other
//! journals — newest generation wins, one committed record is the
//! entire persisted state — at a size (≤ ~600 bytes) far under the
//! record payload bound.
//!
//! Contexts are the MAC's own key formats: the raw 32-byte identity
//! public key for TX boundaries and `mac.rx:` + public key (39 bytes)
//! for per-peer RX boundaries. The map stores them opaquely.

/// Longest stored context: `mac.rx:` (7) + 32-byte key, with headroom.
pub const MAX_KEY_LEN: usize = 40;

/// One TX boundary for the device identity plus RX boundaries for
/// `MAX_DEV_PEERS` (8) peers, with slack for a stale generation of
/// entries surviving until the next journal clear (identity
/// provisioning and CMD_CLEAR both clear the journal).
pub const MAX_ENTRIES: usize = 12;

/// Upper bound of [`CounterMap::encode`]'s output.
pub const ENCODED_MAX: usize = MAX_ENTRIES * (1 + MAX_KEY_LEN + 4);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    key: heapless::Vec<u8, MAX_KEY_LEN>,
    value: u32,
}

/// The map was full and the context could not be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapFull;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CounterMap {
    entries: heapless::Vec<Entry, MAX_ENTRIES>,
}

impl CounterMap {
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// The stored value for `key`, if any.
    pub fn get(&self, key: &[u8]) -> Option<u32> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.value)
    }

    /// Upsert `key` to `value`. Returns whether the map changed (an
    /// equal-value overwrite is a no-op, so callers can skip a flush).
    pub fn set(&mut self, key: &[u8], value: u32) -> Result<bool, MapFull> {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.key == key) {
            if entry.value == value {
                return Ok(false);
            }
            entry.value = value;
            return Ok(true);
        }
        let key = heapless::Vec::from_slice(key).map_err(|_| MapFull)?;
        self.entries
            .push(Entry { key, value })
            .map_err(|_| MapFull)?;
        Ok(true)
    }

    /// Drop every entry (factory clear).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drop TX-boundary entries belonging to any identity other than
    /// `keep` and report whether anything was removed. TX contexts are
    /// the MAC's raw 32-byte identity public key; every other context
    /// format (the 39-byte `mac.rx:` form) is left alone.
    pub fn prune_tx_except(&mut self, keep: &[u8; 32]) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|entry| entry.key.len() != 32 || entry.key == keep);
        before != self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Serialize into `out` (sized [`ENCODED_MAX`] or larger); returns
    /// the encoded length. Layout per entry: key length (1 byte), key,
    /// little-endian u32 value.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        for entry in self.entries.iter() {
            let needed = 1 + entry.key.len() + 4;
            if out.len() - at < needed {
                return None;
            }
            out[at] = entry.key.len() as u8;
            out[at + 1..at + 1 + entry.key.len()].copy_from_slice(&entry.key);
            out[at + 1 + entry.key.len()..at + needed].copy_from_slice(&entry.value.to_le_bytes());
            at += needed;
        }
        Some(at)
    }

    /// Parse a persisted payload. Anything malformed — truncated
    /// entries, oversized keys, more entries than capacity — yields
    /// `None`, and the mount treats the journal as empty (counters
    /// reseed, which is the safe direction for TX boundaries).
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut map = Self::new();
        let mut at = 0;
        while at < payload.len() {
            let key_len = usize::from(payload[at]);
            if key_len == 0 || key_len > MAX_KEY_LEN {
                return None;
            }
            let end = at + 1 + key_len + 4;
            if end > payload.len() {
                return None;
            }
            let key = heapless::Vec::from_slice(&payload[at + 1..at + 1 + key_len]).ok()?;
            let value = u32::from_le_bytes(payload[at + 1 + key_len..end].try_into().ok()?);
            map.entries.push(Entry { key, value }).ok()?;
            at = end;
        }
        Some(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_upserts() {
        let mut map = CounterMap::new();
        let tx_key = [0xAA; 32];
        let mut rx_key = [0u8; 39];
        rx_key[..7].copy_from_slice(b"mac.rx:");
        rx_key[7..].fill(0xBB);

        assert_eq!(map.set(&tx_key, 128), Ok(true));
        assert_eq!(map.set(&rx_key, 256), Ok(true));
        // Equal-value overwrite reports "unchanged".
        assert_eq!(map.set(&tx_key, 128), Ok(false));
        assert_eq!(map.set(&tx_key, 384), Ok(true));
        assert_eq!(map.get(&tx_key), Some(384));
        assert_eq!(map.get(&rx_key), Some(256));
        assert_eq!(map.get(&[0x01; 32]), None);

        let mut buf = [0u8; ENCODED_MAX];
        let len = map.encode(&mut buf).unwrap();
        let decoded = CounterMap::decode(&buf[..len]).unwrap();
        assert_eq!(decoded, map);

        // Empty map round-trips to an empty payload.
        assert_eq!(CounterMap::new().encode(&mut buf), Some(0));
        assert_eq!(CounterMap::decode(&[]), Some(CounterMap::new()));
    }

    #[test]
    fn capacity_and_malformed_payloads() {
        let mut map = CounterMap::new();
        for index in 0..MAX_ENTRIES {
            let key = [index as u8; 32];
            assert_eq!(map.set(&key, index as u32), Ok(true));
        }
        // Full: a new context is refused, existing ones still update.
        assert_eq!(map.set(&[0xFF; 32], 1), Err(MapFull));
        assert_eq!(map.set(&[0x00; 32], 7), Ok(true));

        // Truncated entry, zero-length key, oversized key, trailing
        // garbage after a valid entry.
        assert_eq!(CounterMap::decode(&[5, 1, 2]), None);
        assert_eq!(CounterMap::decode(&[0, 0, 0, 0, 0]), None);
        let mut oversized = [0u8; 1 + MAX_KEY_LEN + 1 + 4];
        oversized[0] = MAX_KEY_LEN as u8 + 1;
        assert_eq!(CounterMap::decode(&oversized), None);
        let mut valid = [0u8; ENCODED_MAX];
        let mut one = CounterMap::new();
        one.set(&[1; 32], 9).unwrap();
        let len = one.encode(&mut valid).unwrap();
        valid[len] = 3; // claims a 3-byte key with no data behind it
        assert_eq!(CounterMap::decode(&valid[..len + 1]), None);

        // clear() empties the map.
        map.clear();
        assert_eq!(map.len(), 0);
        assert_eq!(map.get(&[0x00; 32]), None);
    }

    #[test]
    fn prune_drops_only_foreign_tx_entries() {
        let mut map = CounterMap::new();
        let old_pk = [0x0A; 32];
        let new_pk = [0x0B; 32];
        let mut rx_key = [0u8; 39];
        rx_key[..7].copy_from_slice(b"mac.rx:");
        map.set(&old_pk, 128).unwrap();
        map.set(&rx_key, 256).unwrap();

        assert!(map.prune_tx_except(&new_pk));
        assert_eq!(map.get(&old_pk), None);
        assert_eq!(map.get(&rx_key), Some(256));

        // Idempotent, and the surviving identity's own entry stays.
        assert!(!map.prune_tx_except(&new_pk));
        map.set(&new_pk, 384).unwrap();
        assert!(!map.prune_tx_except(&new_pk));
        assert_eq!(map.get(&new_pk), Some(384));
    }
}
