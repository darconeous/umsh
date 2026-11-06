//! Getting a mutated frame past the MIC with no bypass in product code.
//!
//! A selector picks a party whose keys the harness knows. The frame is
//! treated as plaintext: its addresses are stamped to match that party, and
//! it is signed and sealed through the public API exactly as a sender would.
//! Anything that does not parse goes out as it came, and so does anything
//! under [`RAW`].

use std::sync::OnceLock;

use umsh_core::{
    BlindAddr, ChannelKey, PacketHeader, PacketType, PublicKey, SIGNATURE_INPUT_MAX, SourceAddrRef,
    UnsealedPacket, signature_input,
};
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_crypto::{CryptoEngine, DerivedChannelKeys, NodeIdentity, PairwiseKeys};

use crate::block_on;

/// The selector that leaves a frame exactly as it is.
pub const RAW: u8 = 0xFF;

/// Parties the fixup can seal for.
pub const PARTIES: usize = 4;
/// The parties registered as pinned peers. The rest are strangers.
pub const PINNED_PARTIES: usize = 2;

pub type Engine = CryptoEngine<SoftwareAes, SoftwareSha256>;

pub fn engine() -> Engine {
    CryptoEngine::new(SoftwareAes, SoftwareSha256)
}

/// A sender whose secrets the harness holds.
pub struct Party {
    pub secret: [u8; 32],
    pub identity: SoftwareIdentity,
    pub key: PublicKey,
    /// Keys shared with the local node.
    pub keys: PairwiseKeys,
}

/// Everyone a script can involve.
pub struct Cast {
    pub local_secret: [u8; 32],
    pub local_key: PublicKey,
    pub parties: [Party; PARTIES],
    /// A pinned peer the fixup has no business sealing for: traffic from it
    /// at the end of a script proves the rest of the script did not cost an
    /// honest peer its service.
    pub canary: Party,
    pub channel_key: ChannelKey,
    pub channel: DerivedChannelKeys,
}

fn party(engine: &Engine, local: &SoftwareIdentity, seed: u8) -> Party {
    let secret = [seed; 32];
    let identity = SoftwareIdentity::from_secret_bytes(&secret);
    let key = *identity.public_key();
    let shared = block_on::ready(local.agree(&key)).expect("distinct valid keys");
    let keys = engine.derive_pairwise_keys(&shared, local.public_key(), &key);
    Party {
        secret,
        identity,
        key,
        keys,
    }
}

/// The cast, built once: key agreement is the costliest thing a run does.
pub fn cast() -> &'static Cast {
    static CAST: OnceLock<Cast> = OnceLock::new();
    CAST.get_or_init(|| {
        let engine = engine();
        let local_secret = [0x4C; 32];
        let local = SoftwareIdentity::from_secret_bytes(&local_secret);
        let channel_key = ChannelKey([0x5A; 32]);
        Cast {
            local_secret,
            local_key: *local.public_key(),
            parties: [0x11, 0x22, 0x33, 0x44].map(|seed| party(&engine, &local, seed)),
            canary: party(&engine, &local, 0xCA),
            channel: engine.derive_channel_keys(&channel_key),
            channel_key,
        }
    })
}

fn write_source(buf: &mut [u8], header: &PacketHeader, key: &PublicKey, at: Option<usize>) {
    match (header.source, at) {
        (SourceAddrRef::FullKeyAt { offset }, _) => {
            buf[offset..offset + 32].copy_from_slice(&key.0);
        }
        (SourceAddrRef::Encrypted { offset, len: 32 }, _) => {
            buf[offset..offset + 32].copy_from_slice(&key.0);
        }
        (SourceAddrRef::Encrypted { offset, .. }, _) => {
            buf[offset..offset + 3].copy_from_slice(&key.hint().0);
        }
        (SourceAddrRef::Hint(_), Some(at)) => {
            buf[at..at + 3].copy_from_slice(&key.hint().0);
        }
        _ => {}
    }
}

/// Offset just past the frame control and any flood hops.
fn address_start(header: &PacketHeader) -> usize {
    1 + usize::from(header.flood_hops.is_some())
}

/// Stamp `frame` for `party`, so that a key this harness holds is the one a
/// receiver would look up.
fn stamp(buf: &mut [u8], header: &PacketHeader, party: &Party, cast: &Cast) {
    let start = address_start(header);
    match header.packet_type() {
        PacketType::Broadcast => write_source(buf, header, &party.key, Some(start)),
        PacketType::Unicast | PacketType::UnicastAckReq => {
            buf[start..start + 3].copy_from_slice(&cast.local_key.hint().0);
            write_source(buf, header, &party.key, Some(start + 3));
        }
        PacketType::Multicast => {
            buf[start..start + 2].copy_from_slice(&cast.channel.channel_id.0);
            let source = match header.source {
                SourceAddrRef::Hint(_) => Some(header.body_range.start - 3),
                _ => None,
            };
            write_source(buf, header, &party.key, source);
        }
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
            buf[start..start + 2].copy_from_slice(&cast.channel.channel_id.0);
            if let Some(range) = header.blind_addr_range() {
                let block = &mut buf[range];
                block[..3].copy_from_slice(&cast.local_key.hint().0);
                match block.len() {
                    35 => block[3..].copy_from_slice(&party.key.0),
                    6 => block[3..].copy_from_slice(&party.key.hint().0),
                    _ => {}
                }
            }
        }
        PacketType::MacAck | PacketType::Reserved5 => {}
    }
}

fn sign(buf: &mut [u8], header: &PacketHeader, party: &Party, blind: Option<&BlindAddr>) {
    let Some(signature) = header.signature.as_ref() else {
        return;
    };
    let commitment = header.channel.map(|_| cast().channel.commitment);
    let mut input = [0u8; SIGNATURE_INPUT_MAX];
    let Ok(len) = signature_input(header, buf, blind, commitment.as_ref(), &mut input) else {
        return;
    };
    let signed = block_on::ready(party.identity.sign(&input[..len])).expect("software signing");
    buf[signature.range.clone()].copy_from_slice(&signed);
}

fn unsealed<'a>(buf: &'a mut [u8], header: &PacketHeader) -> Option<UnsealedPacket<'a>> {
    let sec_info = header.sec_info?;
    let start = header.options_range.start;
    let sec_info_range = start.checked_sub(sec_info.wire_len())?..start;
    Some(UnsealedPacket::new(
        buf,
        header.total_len,
        header.body_range.clone(),
        header.blind_addr_range(),
        header.signature.as_ref().map(|s| s.range.clone()),
        header.mic_range.clone(),
        sec_info_range,
        header.options_range.clone(),
    ))
}

/// The keys a frame of this type seals under for `party`.
fn channel_keys(cast: &Cast) -> PairwiseKeys {
    PairwiseKeys {
        k_enc: cast.channel.k_enc,
        k_mic: cast.channel.k_mic,
    }
}

/// The keys a blind unicast from `party` seals under.
pub fn blind_keys(party: &Party) -> PairwiseKeys {
    engine().derive_blind_keys(&party.keys, &cast().channel)
}

/// Apply a selector to a frame.
pub fn apply(frame: &[u8], selector: u8) -> Vec<u8> {
    let mut buf = frame.to_vec();
    if selector == RAW {
        return buf;
    }
    let Ok(parsed) = PacketHeader::parse(frame) else {
        return buf;
    };
    if parsed.total_len != frame.len() {
        return buf;
    }
    let cast = cast();
    let party = &cast.parties[usize::from(selector) % PARTIES];
    stamp(&mut buf, &parsed, party, cast);
    let Ok(header) = PacketHeader::parse(&buf) else {
        return frame.to_vec();
    };

    let engine = engine();
    let blind = header
        .blind_addr_range()
        .and_then(|range| BlindAddr::from_plaintext(&buf[range]));
    sign(&mut buf, &header, party, blind.as_ref());

    match header.packet_type() {
        PacketType::Broadcast | PacketType::MacAck | PacketType::Reserved5 => {}
        PacketType::Unicast | PacketType::UnicastAckReq => {
            if let Some(mut packet) = unsealed(&mut buf, &header) {
                let _ = engine.seal_packet(&mut packet, &party.keys);
            }
        }
        PacketType::Multicast => {
            if let Some(mut packet) = unsealed(&mut buf, &header) {
                let _ = engine.seal_packet(&mut packet, &channel_keys(cast));
            }
        }
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
            if let Some(mut packet) = unsealed(&mut buf, &header) {
                let _ = engine.seal_blind_packet(&mut packet, &blind_keys(party), &cast.channel);
            }
        }
    }
    buf
}
