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
//! not private state: any forwarder that participates in the same mesh—
//! including an [internet bridge], whose two radios must agree on which
//! frames are the same packet—has to compute it bit-for-bit
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

/// Whether `heard` is `sent` as some forwarder may have passed it on: the
/// two agree on every byte a forwarder may not rewrite.
///
/// Sharing a routing identity is not enough to say so. The key is a MIC, or
/// a 32-bit hash for frames without one, and a frame that carries ours over
/// different contents is not our packet, however it came to match.
pub(crate) fn same_packet(sent: &[u8], heard: &[u8]) -> bool {
    let (Ok(sent_header), Ok(heard_header)) =
        (PacketHeader::parse(sent), PacketHeader::parse(heard))
    else {
        return false;
    };
    match (
        static_bytes(&sent_header, sent),
        static_bytes(&heard_header, heard),
    ) {
        (Some(sent), Some(heard)) => sent.eq(heard),
        _ => false,
    }
}

/// A 64-bit digest of the bytes of `frame` a forwarder may not rewrite, for
/// telling a forward of `frame` apart from a frame that merely shares its
/// routing identity without keeping the whole frame.
///
/// FNV-1a, not a cryptographic hash: anyone able to forge a collision could
/// as easily send the frame itself, which would be a genuine forward.
pub(crate) fn static_fingerprint(header: &PacketHeader, frame: &[u8]) -> Option<u64> {
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    for byte in static_bytes(header, frame)? {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    Some(hash)
}

/// The bytes of `frame` no forwarder may rewrite, in order: the FCF without
/// its flood-hops-present bit, everything else outside the option block
/// except the flood-hop byte, and each static option as its number, length
/// and value. `None` when the options do not decode.
fn static_bytes<'a>(
    header: &PacketHeader,
    frame: &'a [u8],
) -> Option<impl Iterator<Item = u8> + 'a> {
    let options = header.options_range.clone();
    let fixed_start = if header.fcf.flood_hops_present() {
        2
    } else {
        1
    };
    let fixed = frame.get(fixed_start..options.start)?;
    let trailing = frame.get(options.end..)?;
    if umsh_core::iter_options(frame, options.clone()).any(|entry| entry.is_err()) {
        return None;
    }
    let static_options = umsh_core::iter_options(frame, options)
        .filter_map(Result::ok)
        .filter(|(number, _)| !OptionNumber::from(*number).is_dynamic())
        .flat_map(|(number, value)| {
            number
                .to_be_bytes()
                .into_iter()
                .chain((value.len() as u16).to_be_bytes())
                .chain(value.iter().copied())
        });
    Some(
        core::iter::once(header.fcf.aad_byte())
            .chain(fixed.iter().copied())
            .chain(static_options)
            .chain(trailing.iter().copied()),
    )
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
