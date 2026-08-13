//! Routing identity of a packet as seen by a forwarder.
//!
//! This is the identity that duplicate suppression and forwarding
//! confirmation both key on, and it is intentionally not the
//! destination's logical delivery identity:
//!
//! - delivery identity is governed by replay windows / frame counters at
//!   the destination
//! - routing identity must remain stable across repeater rewrites of
//!   dynamic routing metadata
//! - forwarding-confirmation identity matches routing identity so a node
//!   can recognize "the same packet, forwarded onward"
//!
//! It lives outside the coordinator because it is an interop surface,
//! not private state: any forwarder that participates in the same mesh —
//! including an [internet bridge], whose two radios must agree on which
//! frames are the same packet — has to compute it bit-for-bit
//! identically.
//!
//! [internet bridge]: https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html

use umsh_core::{OptionNumber, PacketHeader, PacketType, ParsedOptions};

use crate::cache::DupCacheKey;

/// Routing identity of an already-parsed frame.
///
/// `None` when the frame carries a MIC this cache cannot key on (absent,
/// or wider than the 16 bytes the key holds), or when its options do not
/// parse.
pub fn forwarding_dup_key_parsed(header: &PacketHeader, frame: &[u8]) -> Option<DupCacheKey> {
    if !header.packet_type().is_secure() {
        let hash = normalized_routable_hash32(header, frame);
        // Acks carry the same hash under their own variant so the cache
        // can age them out fast enough for deliberate re-acknowledgements
        // (spec §Duplicate Acknowledgement Window) to be carried onward.
        return Some(if header.packet_type() == PacketType::MacAck {
            DupCacheKey::AckHash32(hash)
        } else {
            DupCacheKey::Hash32(hash)
        });
    }
    let options = ParsedOptions::extract(frame, header.options_range.clone()).ok()?;
    let mic = frame.get(header.mic_range.clone())?;
    if mic.is_empty() || mic.len() > 16 {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes[..mic.len()].copy_from_slice(mic);
    Some(DupCacheKey::Mic {
        bytes,
        len: mic.len() as u8,
        route_retry: options.route_retry,
    })
}

/// Routing identity of a frame, parsing its header first.
///
/// `None` when the frame does not parse, or for the reasons
/// [`forwarding_dup_key_parsed`] gives.
pub fn forwarding_dup_key(frame: &[u8]) -> Option<DupCacheKey> {
    let header = PacketHeader::parse(frame).ok()?;
    forwarding_dup_key_parsed(&header, frame)
}

/// FNV-1a over the fields a repeater may not rewrite, for packets that
/// carry no MIC to key on.
fn normalized_routable_hash32(header: &PacketHeader, frame: &[u8]) -> u32 {
    let mut hash = 0x811C_9DC5u32;

    hash_u8(&mut hash, header.packet_type() as u8);
    hash_u8(&mut hash, header.fcf.full_source() as u8);

    if !header.options_range.is_empty() {
        for entry in umsh_core::iter_options(frame, header.options_range.clone()) {
            let Ok((number, value)) = entry else {
                continue;
            };
            let option = OptionNumber::from(number);
            if option.is_dynamic() {
                continue;
            }
            hash_u16(&mut hash, number);
            hash_u16(&mut hash, value.len() as u16);
            hash_bytes(&mut hash, value);
        }
    }

    match header.packet_type() {
        PacketType::Broadcast => {
            match header.source {
                umsh_core::SourceAddrRef::Hint(hint) => hash_bytes(&mut hash, &hint.0),
                umsh_core::SourceAddrRef::FullKeyAt { offset } => {
                    if let Some(key) = frame.get(offset..offset + 32) {
                        hash_bytes(&mut hash, key);
                    }
                }
                umsh_core::SourceAddrRef::Encrypted { offset, len } => {
                    if let Some(src) = frame.get(offset..offset + len) {
                        hash_bytes(&mut hash, src);
                    }
                }
                umsh_core::SourceAddrRef::None => {}
            }
            if let Some(payload) = frame.get(header.body_range.clone()) {
                hash_bytes(&mut hash, payload);
            }
        }
        PacketType::MacAck => {
            // The ack trailer (`ack_mic || ack_tag`) uniquely identifies
            // the acknowledged exchange; the ack carries no other
            // distinguishing fields.
            if let Some(trailer) = frame.get(header.mic_range.clone()) {
                hash_bytes(&mut hash, trailer);
            }
        }
        _ => {
            if let Some(bytes) = frame.get(header.body_range.clone()) {
                hash_bytes(&mut hash, bytes);
            }
        }
    }
    hash
}

fn hash_u8(hash: &mut u32, value: u8) {
    *hash ^= u32::from(value);
    *hash = hash.wrapping_mul(0x0100_0193);
}

fn hash_u16(hash: &mut u32, value: u16) {
    hash_bytes(hash, &value.to_be_bytes());
}

fn hash_bytes(hash: &mut u32, bytes: &[u8]) {
    for byte in bytes {
        hash_u8(hash, *byte);
    }
}
