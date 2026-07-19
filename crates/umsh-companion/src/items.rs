//! Item codecs for the full protocol's multi-value properties.
//!
//! Each multi-value property defines an **item form** (what the host
//! writes) and a **digest form** (what the NCP reports). The two differ
//! exactly where the item form carries symmetric key material: digest
//! forms never contain secrets. See "Multi-Value Properties" in the full
//! companion-radio spec.
//!
//! Whole-table values concatenate items: fixed-size items back to back
//! (see [`fixed_items`]), or PUI-length-prefixed items for properties
//! documented with an item length prefix (see [`prefixed_items`] /
//! [`encode_prefixed_item`]). Single items carried by
//! `CMD_PROP_INSERT`/`CMD_PROP_REMOVE` are never length-prefixed; the
//! framing layer bounds them.

use crate::pui;

/// Length of an Ed25519 public key (peer entries, `PROP_HOST_KEY`,
/// `PROP_DEV_KEY`).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a channel key item (`PROP_HOST_CHANNEL_KEYS`,
/// `PROP_DEV_CHANNEL_KEYS`).
pub const CHANNEL_KEY_LEN: usize = 32;
/// Length of a derived channel identifier (the digest form of a channel
/// key).
pub const CHANNEL_ID_LEN: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemError {
    /// The input ended before the item was complete.
    Truncated,
    /// The item's length does not match its type.
    BadLength,
    /// A filter entry carried an unrecognized `FILTER_TYPE`.
    UnknownFilterType,
    /// The output buffer cannot hold the encoded item.
    BufferTooSmall,
    /// An item length prefix was malformed.
    BadPrefix,
}

/// One `PROP_HOST_PEER_KEYS` entry in item form: the peer's public key
/// and the pairwise keys derived by the host. **Secret-bearing** — the
/// digest form is [`Self::public_key`] alone.
///
/// Inserting an entry whose public key matches an existing entry
/// replaces that entry's key material (the spec's exception to the
/// `STATUS_ALREADY` duplicate rule).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerKeyEntry {
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub k_enc: [u8; 16],
    pub k_mic: [u8; 16],
}

impl PeerKeyEntry {
    pub const WIRE_LEN: usize = 64;

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ItemError> {
        if out.len() < Self::WIRE_LEN {
            return Err(ItemError::BufferTooSmall);
        }
        out[..32].copy_from_slice(&self.public_key);
        out[32..48].copy_from_slice(&self.k_enc);
        out[48..64].copy_from_slice(&self.k_mic);
        Ok(Self::WIRE_LEN)
    }

    /// Decode an item occupying the whole input.
    pub fn decode(input: &[u8]) -> Result<Self, ItemError> {
        if input.len() != Self::WIRE_LEN {
            return Err(ItemError::BadLength);
        }
        let mut entry = Self {
            public_key: [0; PUBLIC_KEY_LEN],
            k_enc: [0; 16],
            k_mic: [0; 16],
        };
        entry.public_key.copy_from_slice(&input[..32]);
        entry.k_enc.copy_from_slice(&input[32..48]);
        entry.k_mic.copy_from_slice(&input[48..64]);
        Ok(entry)
    }

    /// The entry's digest form (and remove selector): the public key,
    /// never the pairwise keys.
    pub fn digest(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }
}

/// Debug intentionally omits `k_enc`/`k_mic`: entries must never leak
/// key material into logs or panic messages.
impl core::fmt::Debug for PeerKeyEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PeerKeyEntry")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// `FILTER_TYPE` for a 3-octet destination-hint filter.
pub const FILTER_DEST_HINT: u8 = 0;
/// `FILTER_TYPE` for a 2-octet channel-identifier filter.
pub const FILTER_CHANNEL_ID: u8 = 1;
/// `FILTER_TYPE` for a 1-octet FCF packet-type filter.
pub const FILTER_PKT_TYPE: u8 = 2;

/// One `PROP_HOST_RX_FILTERS` entry. Item and digest forms are
/// identical; the remove selector is the full item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Frames whose destination hint equals the value.
    DestHint([u8; 3]),
    /// Channel-addressed frames whose channel identifier equals the
    /// value.
    ChannelId([u8; CHANNEL_ID_LEN]),
    /// Frames whose FCF packet-type field equals the value.
    PktType(u8),
}

impl Filter {
    /// Largest encoded filter entry (type octet + 3-octet value).
    pub const MAX_WIRE_LEN: usize = 4;

    pub const fn wire_len(&self) -> usize {
        match self {
            Self::DestHint(_) => 4,
            Self::ChannelId(_) => 3,
            Self::PktType(_) => 2,
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ItemError> {
        let len = self.wire_len();
        if out.len() < len {
            return Err(ItemError::BufferTooSmall);
        }
        match self {
            Self::DestHint(hint) => {
                out[0] = FILTER_DEST_HINT;
                out[1..4].copy_from_slice(hint);
            }
            Self::ChannelId(id) => {
                out[0] = FILTER_CHANNEL_ID;
                out[1..3].copy_from_slice(id);
            }
            Self::PktType(pkt_type) => {
                out[0] = FILTER_PKT_TYPE;
                out[1] = *pkt_type;
            }
        }
        Ok(len)
    }

    /// Decode a filter entry occupying the whole input.
    ///
    /// Per the spec, an unrecognized `FILTER_TYPE` or a value length
    /// that does not match the type is invalid
    /// (`STATUS_INVALID_ARGUMENT`).
    pub fn decode(input: &[u8]) -> Result<Self, ItemError> {
        let [filter_type, value @ ..] = input else {
            return Err(ItemError::Truncated);
        };
        match (*filter_type, value) {
            (FILTER_DEST_HINT, &[a, b, c]) => Ok(Self::DestHint([a, b, c])),
            (FILTER_CHANNEL_ID, &[a, b]) => Ok(Self::ChannelId([a, b])),
            (FILTER_PKT_TYPE, &[pkt_type]) => Ok(Self::PktType(pkt_type)),
            (FILTER_DEST_HINT | FILTER_CHANNEL_ID | FILTER_PKT_TYPE, _) => {
                Err(ItemError::BadLength)
            }
            _ => Err(ItemError::UnknownFilterType),
        }
    }
}

/// Iterate the fixed-size items of a whole-table value with no item
/// length prefix (channel keys, peer public keys, peer key entries).
///
/// Fails up front unless the value is an exact multiple of `N`, so
/// callers can validate before mutating.
pub fn fixed_items<const N: usize>(
    value: &[u8],
) -> Result<impl ExactSizeIterator<Item = &[u8; N]> + Clone, ItemError> {
    const { assert!(N > 0) };
    if value.len() % N != 0 {
        return Err(ItemError::BadLength);
    }
    Ok(value
        .chunks_exact(N)
        .map(|chunk| chunk.try_into().expect("chunks_exact yields N-byte chunks")))
}

/// Iterate the PUI-length-prefixed items of a whole-table value
/// (properties documented with an item length prefix, such as
/// `PROP_HOST_RX_FILTERS`).
///
/// Yields an error item for a malformed prefix or truncated body and
/// then ends; validate the whole table before applying any of it.
pub fn prefixed_items(value: &[u8]) -> PrefixedItems<'_> {
    PrefixedItems { rest: value }
}

#[derive(Clone)]
pub struct PrefixedItems<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for PrefixedItems<'a> {
    type Item = Result<&'a [u8], ItemError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let (len, consumed) = match pui::decode(self.rest) {
            Ok(decoded) => decoded,
            Err(_) => {
                self.rest = &[];
                return Some(Err(ItemError::BadPrefix));
            }
        };
        let body = &self.rest[consumed..];
        let Ok(len) = usize::try_from(len) else {
            self.rest = &[];
            return Some(Err(ItemError::BadPrefix));
        };
        if body.len() < len {
            self.rest = &[];
            return Some(Err(ItemError::Truncated));
        }
        let (item, rest) = body.split_at(len);
        self.rest = rest;
        Some(Ok(item))
    }
}

/// Append one PUI-length-prefixed item to `out`, returning the number
/// of bytes written.
pub fn encode_prefixed_item(item: &[u8], out: &mut [u8]) -> Result<usize, ItemError> {
    let len = u32::try_from(item.len()).map_err(|_| ItemError::BadLength)?;
    let prefix = pui::encode(len, out).map_err(|error| match error {
        pui::Error::BufferTooSmall => ItemError::BufferTooSmall,
        _ => ItemError::BadLength,
    })?;
    let end = prefix + item.len();
    if out.len() < end {
        return Err(ItemError::BufferTooSmall);
    }
    out[prefix..end].copy_from_slice(item);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_key_entry_round_trip_and_digest_is_secret_free() {
        let entry = PeerKeyEntry {
            public_key: [0x11; 32],
            k_enc: [0x22; 16],
            k_mic: [0x33; 16],
        };
        let mut buf = [0u8; PeerKeyEntry::WIRE_LEN];
        assert_eq!(entry.encode(&mut buf).unwrap(), PeerKeyEntry::WIRE_LEN);
        assert_eq!(PeerKeyEntry::decode(&buf).unwrap(), entry);

        // The digest form and remove selector carry only the public key.
        assert_eq!(entry.digest(), &[0x11; 32]);
        // Debug output must not leak key material.
        let debug = std::format!("{entry:?}");
        assert!(
            !debug.contains("k_enc") && !debug.contains("k_mic"),
            "{debug}"
        );
    }

    #[test]
    fn peer_key_entry_rejects_wrong_lengths() {
        assert_eq!(PeerKeyEntry::decode(&[0; 63]), Err(ItemError::BadLength));
        assert_eq!(PeerKeyEntry::decode(&[0; 65]), Err(ItemError::BadLength));
        assert_eq!(PeerKeyEntry::decode(&[]), Err(ItemError::BadLength));
    }

    #[test]
    fn filter_round_trip_every_type() {
        let filters = [
            Filter::DestHint([0xAA, 0xBB, 0xCC]),
            Filter::ChannelId([0x12, 0x34]),
            Filter::PktType(0),
        ];
        for filter in filters {
            let mut buf = [0u8; Filter::MAX_WIRE_LEN];
            let len = filter.encode(&mut buf).unwrap();
            assert_eq!(len, filter.wire_len());
            assert_eq!(Filter::decode(&buf[..len]).unwrap(), filter);
        }
    }

    #[test]
    fn filter_rejects_malformed_entries() {
        assert_eq!(Filter::decode(&[]), Err(ItemError::Truncated));
        // Wrong value lengths for each known type.
        assert_eq!(
            Filter::decode(&[FILTER_DEST_HINT, 1, 2]),
            Err(ItemError::BadLength)
        );
        assert_eq!(
            Filter::decode(&[FILTER_CHANNEL_ID, 1, 2, 3]),
            Err(ItemError::BadLength)
        );
        assert_eq!(
            Filter::decode(&[FILTER_PKT_TYPE]),
            Err(ItemError::BadLength)
        );
        // Unknown filter type.
        assert_eq!(Filter::decode(&[3, 0]), Err(ItemError::UnknownFilterType));
    }

    #[test]
    fn fixed_items_iterates_and_validates_alignment() {
        let value = [1u8, 1, 2, 2, 3, 3];
        let items: Vec<[u8; 2]> = fixed_items::<2>(&value).unwrap().copied().collect();
        assert_eq!(items, [[1, 1], [2, 2], [3, 3]]);

        assert!(fixed_items::<2>(&[0; 5]).is_err());
        assert_eq!(fixed_items::<32>(&[]).unwrap().len(), 0);
    }

    #[test]
    fn prefixed_items_round_trip() {
        let mut table = [0u8; 32];
        let mut len = 0;
        let items: [&[u8]; 3] = [&[0xAA, 0xBB], &[], &[0xCC; 5]];
        for item in items {
            len += encode_prefixed_item(item, &mut table[len..]).unwrap();
        }
        let decoded: Vec<&[u8]> = prefixed_items(&table[..len])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(decoded, items);
        assert_eq!(prefixed_items(&[]).count(), 0);
    }

    #[test]
    fn prefixed_items_reports_truncation_and_stops() {
        // Prefix claims 4 bytes, only 2 present.
        let mut iterator = prefixed_items(&[4, 0xAA, 0xBB]);
        assert_eq!(iterator.next(), Some(Err(ItemError::Truncated)));
        assert_eq!(iterator.next(), None);

        // A malformed (over-long) PUI prefix.
        let mut iterator = prefixed_items(&[0x80, 0x80, 0x80, 0x80]);
        assert_eq!(iterator.next(), Some(Err(ItemError::BadPrefix)));
        assert_eq!(iterator.next(), None);
    }

    #[test]
    fn encode_prefixed_item_reports_overflow() {
        let mut small = [0u8; 3];
        assert_eq!(
            encode_prefixed_item(&[0; 8], &mut small),
            Err(ItemError::BufferTooSmall)
        );
    }
}
