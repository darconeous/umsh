//! The device node's persisted frame-counter map (device-node plan
//! increment 4).
//!
//! The MAC's `CounterStore` contract is per-context `store` calls
//! followed by one `flush` per persistence cycle, already batched: a TX
//! boundary per 128 secured frames sent, an RX boundary per
//! `RX_COUNTER_PERSIST_INTERVAL` (16) frames accepted from one peer.
//! This map is the RAM image behind that contract: `store` upserts
//! here, and `flush` serializes the *whole* map into a single
//! [`proto`](crate::proto) record in the firmware's counter journal.
//! Whole-map records keep the journal machinery identical to the other
//! journals—newest generation wins, one committed record is the
//! entire persisted state—at a size under the record payload bound.
//!
//! Contexts are the MAC's own key formats: the raw 32-byte identity
//! public key for TX boundaries and `mac.rx:` + public key (39 bytes)
//! for per-peer RX boundaries. The map keeps which of the two a context
//! is and the first [`TAG_LEN`] octets of its key, which is what lets
//! one record hold boundaries for every peer a chat device registers.

use crate::proto::MAX_PAYLOAD;

/// How much of a context's public key tells it from the others. Keys
/// are not chosen to collide, and two that did would share a boundary.
const TAG_LEN: usize = 8;

/// What the MAC puts before a peer's public key in an RX context.
const RX_PREFIX: &[u8] = b"mac.rx:";

/// One TX boundary for the device identity plus RX boundaries for the
/// 24 peers a node holds, with slack for a stale generation of entries
/// surviving until the next journal clear (identity provisioning and
/// CMD_CLEAR both clear the journal).
#[cfg(not(feature = "chat-peers"))]
pub const MAX_ENTRIES: usize = 30;

/// One TX boundary plus RX boundaries for the 80 peers a chat device's
/// node holds, with the slack one record has left over.
#[cfg(feature = "chat-peers")]
pub const MAX_ENTRIES: usize = 150;

/// What leads a record of entries: an octet no record of whole contexts,
/// which starts with a key length, can start with.
const FORMAT: u8 = 0;
const KIND_TX: u8 = 1;
const KIND_RX: u8 = 2;
const ENTRY_LEN: usize = 1 + TAG_LEN + 4;

/// The longest context a record of whole contexts holds.
const WHOLE_KEY_MAX: usize = 40;

/// Upper bound of [`CounterMap::encode`]'s output.
pub const ENCODED_MAX: usize = 1 + MAX_ENTRIES * ENTRY_LEN;
const _: () = assert!(ENCODED_MAX <= MAX_PAYLOAD);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tag {
    kind: u8,
    key: [u8; TAG_LEN],
}

impl Tag {
    /// What names `context`, if it is one of the MAC's.
    fn of(context: &[u8]) -> Option<Self> {
        let (kind, key) = match context.strip_prefix(RX_PREFIX) {
            Some(key) => (KIND_RX, key),
            None => (KIND_TX, context),
        };
        if key.len() != 32 {
            return None;
        }
        Some(Self {
            kind,
            key: key[..TAG_LEN].try_into().ok()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    tag: Tag,
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
        let tag = Tag::of(key)?;
        self.entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }

    /// Upsert `key` to `value`. Returns whether the map changed (an
    /// equal-value overwrite is a no-op, so callers can skip a flush).
    /// Nothing the map could hold is also refused as [`MapFull`].
    pub fn set(&mut self, key: &[u8], value: u32) -> Result<bool, MapFull> {
        let tag = Tag::of(key).ok_or(MapFull)?;
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.tag == tag) {
            if entry.value == value {
                return Ok(false);
            }
            entry.value = value;
            return Ok(true);
        }
        self.entries
            .push(Entry { tag, value })
            .map_err(|_| MapFull)?;
        Ok(true)
    }

    /// Drop every entry (factory clear).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drop TX-boundary entries belonging to any identity other than
    /// `keep` and report whether anything was removed. RX boundaries are
    /// left alone.
    pub fn prune_tx_except(&mut self, keep: &[u8; 32]) -> bool {
        let before = self.entries.len();
        let keep = Tag::of(keep);
        self.entries
            .retain(|entry| entry.tag.kind != KIND_TX || Some(entry.tag) == keep);
        before != self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize into `out` (sized [`ENCODED_MAX`] or larger); returns
    /// the encoded length. Layout: [`FORMAT`], then per entry its kind
    /// (1 byte), tag, little-endian u32 value.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        *out.first_mut()? = FORMAT;
        let mut at = 1;
        for entry in self.entries.iter() {
            let slot = out.get_mut(at..at + ENTRY_LEN)?;
            slot[0] = entry.tag.kind;
            slot[1..1 + TAG_LEN].copy_from_slice(&entry.tag.key);
            slot[1 + TAG_LEN..].copy_from_slice(&entry.value.to_le_bytes());
            at += ENTRY_LEN;
        }
        Some(at)
    }

    /// Parse a persisted payload. Anything malformed—truncated
    /// entries, oversized keys, more entries than capacity—yields
    /// `None`, and the mount treats the journal as empty (counters
    /// reseed, which is the safe direction for TX boundaries).
    pub fn decode(payload: &[u8]) -> Option<Self> {
        match payload.split_first() {
            Some((&FORMAT, entries)) => Self::decode_entries(entries),
            _ => Self::decode_whole_contexts(payload),
        }
    }

    fn decode_entries(entries: &[u8]) -> Option<Self> {
        let mut map = Self::new();
        let (records, remainder) = entries.as_chunks::<ENTRY_LEN>();
        for record in records {
            let kind = record[0];
            if kind != KIND_TX && kind != KIND_RX {
                return None;
            }
            let entry = Entry {
                tag: Tag {
                    kind,
                    key: record[1..1 + TAG_LEN].try_into().ok()?,
                },
                value: u32::from_le_bytes(record[1 + TAG_LEN..].try_into().ok()?),
            };
            map.entries.push(entry).ok()?;
        }
        remainder.is_empty().then_some(map)
    }

    /// A record from before entries were tagged, so that a device keeps
    /// its boundaries across the update. Per entry: key length (1 byte),
    /// key, little-endian u32 value.
    fn decode_whole_contexts(payload: &[u8]) -> Option<Self> {
        let mut map = Self::new();
        let mut at = 0;
        while at < payload.len() {
            let key_len = usize::from(payload[at]);
            if key_len == 0 || key_len > WHOLE_KEY_MAX {
                return None;
            }
            let end = at + 1 + key_len + 4;
            if end > payload.len() {
                return None;
            }
            let tag = Tag::of(&payload[at + 1..at + 1 + key_len])?;
            let value = u32::from_le_bytes(payload[at + 1 + key_len..end].try_into().ok()?);
            map.entries.push(Entry { tag, value }).ok()?;
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
        assert_eq!(CounterMap::new().encode(&mut buf), Some(1));
        assert_eq!(CounterMap::decode(&buf[..1]), Some(CounterMap::new()));
        assert_eq!(CounterMap::decode(&[]), Some(CounterMap::new()));
    }

    /// A device updated in the field still has what it wrote before.
    #[test]
    fn reads_a_record_of_whole_contexts() {
        let tx_key = [0xAA; 32];
        let mut rx_key = [0u8; 39];
        rx_key[..7].copy_from_slice(b"mac.rx:");
        rx_key[7..].fill(0xBB);
        let mut record = whole_context(&tx_key, 128);
        record
            .extend_from_slice(&whole_context(&rx_key, 256))
            .unwrap();

        let map = CounterMap::decode(&record).unwrap();
        assert_eq!(map.get(&tx_key), Some(128));
        assert_eq!(map.get(&rx_key), Some(256));
    }

    fn whole_context(key: &[u8], value: u32) -> heapless::Vec<u8, 128> {
        let mut record = heapless::Vec::new();
        record.push(key.len() as u8).unwrap();
        record.extend_from_slice(key).unwrap();
        record.extend_from_slice(&value.to_le_bytes()).unwrap();
        record
    }

    /// A TX context and an RX context on the same key stay apart.
    #[test]
    fn the_two_kinds_of_context_do_not_collide() {
        let mut map = CounterMap::new();
        let key = [0x11; 32];
        let mut rx_key = [0u8; 39];
        rx_key[..7].copy_from_slice(b"mac.rx:");
        rx_key[7..].copy_from_slice(&key);
        map.set(&key, 1).unwrap();
        map.set(&rx_key, 2).unwrap();
        assert_eq!(map.get(&key), Some(1));
        assert_eq!(map.get(&rx_key), Some(2));
        assert_eq!(map.set(&[0; 16], 3), Err(MapFull));
    }

    #[test]
    fn a_full_map_fits_a_record() {
        let mut map = CounterMap::new();
        for index in 0..MAX_ENTRIES {
            let mut key = [0u8; 32];
            key[0] = index as u8;
            map.set(&key, index as u32).unwrap();
        }
        let mut buf = [0u8; ENCODED_MAX];
        let len = map.encode(&mut buf).unwrap();
        assert!(len <= MAX_PAYLOAD);
        assert_eq!(CounterMap::decode(&buf[..len]).unwrap(), map);
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
        let mut oversized = [0u8; 1 + WHOLE_KEY_MAX + 1 + 4];
        oversized[0] = WHOLE_KEY_MAX as u8 + 1;
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
