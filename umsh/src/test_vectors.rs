//! Canonical rendering for the phase-1 protocol appendix.
//!
//! This module exists so the checked-in specification appendix and the
//! implementation can be compared directly in tests.

use std::fmt::Write;

use crate::prelude::*;

/// Render the canonical phase-1 test-vector appendix as Markdown.
///
/// The output is expected to match `docs/protocol/src/test-vectors.md`
/// byte-for-byte.
pub fn render_phase1_test_vectors_markdown() -> String {
    let vectors = generate_phase1_vectors();
    let mut out = String::new();

    writeln!(&mut out, "# Test Vectors").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "This appendix contains byte-level packet examples. All values are hexadecimal, and multi-byte numeric fields are big-endian."
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "## Conventions").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "The generated examples use fixed Ed25519 private keys so the appendix covers the full path from private key to public key to X25519 ECDH to packet bytes."
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "- Node A private key: `{}`",
        hex_words(&vectors.node_a_private)
    )
    .unwrap();
    writeln!(
        &mut out,
        "- Node A public key: `{}`",
        hex_words(&vectors.node_a_public.0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - Source hint: `{}`",
        hex_spaced(&vectors.node_a_public.hint().0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "- Node B private key: `{}`",
        hex_words(&vectors.node_b_private)
    )
    .unwrap();
    writeln!(
        &mut out,
        "- Node B public key: `{}`",
        hex_words(&vectors.node_b_public.0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - Destination hint: `{}`",
        hex_spaced(&vectors.node_b_public.hint().0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "- Pairwise shared secret: `{}`",
        hex_words(&vectors.shared_secret.0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - Derived from the two private keys via the implementation's Ed25519-to-X25519 conversion and X25519 ECDH."
    )
    .unwrap();

    let unicast_encrypted_header = parse_header(&vectors.unicast_encrypted);
    let unicast_ackreq_header = parse_header(&vectors.unicast_ackreq_fullsrc);
    let multicast_encrypted_header = parse_header(&vectors.multicast_encrypted);
    let multicast_authenticated_header = parse_header(&vectors.multicast_authenticated);
    let unicast_with_options_header = parse_header(&vectors.unicast_with_options);
    let blind_unicast_header = parse_header(&vectors.blind_unicast);
    writeln!(
        &mut out,
        "- Channel key: `{}`",
        hex_words(&vectors.channel_key.0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "- Derived channel identifier: `{}`",
        hex_spaced(&vectors.channel.channel_id.0)
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "### FCF Bit Layout Reference").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "```text").unwrap();
    writeln!(&mut out, "  7   6   5   4   3   2   1   0").unwrap();
    writeln!(&mut out, "+-------+-----------+---+---+---+").unwrap();
    writeln!(&mut out, "| VER   | PKT TYPE  | S | O | H |").unwrap();
    writeln!(&mut out, "+-------+-----------+---+---+---+").unwrap();
    writeln!(&mut out, "```").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "### SCF Bit Layout Reference").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "```text").unwrap();
    writeln!(&mut out, "  7   6   5   4   3   2   1   0").unwrap();
    writeln!(&mut out, "+---+-------+---+---------------+").unwrap();
    writeln!(&mut out, "| E |  MIC  | S |   RESERVED    |").unwrap();
    writeln!(&mut out, "+---+-------+---+---------------+").unwrap();
    writeln!(&mut out, "```").unwrap();

    render_example(
        &mut out,
        "Example 1: Broadcast Beacon (S=0)",
        "A minimal beacon with a 3-byte source hint and no payload.",
        &[
            (
                "FCF",
                "VER=3, TYPE=0 (broadcast), S=0, O=0, H=0",
                "C0".into(),
            ),
            (
                "SRC",
                "Node A hint",
                hex_spaced(&vectors.node_a_public.hint().0),
            ),
        ],
        &vectors.broadcast_hint,
    );

    render_example(
        &mut out,
        "Example 2: Broadcast Beacon (S=1)",
        "A first-contact beacon carrying the sender's full 32-byte public key.",
        &[
            (
                "FCF",
                "VER=3, TYPE=0 (broadcast), S=1, O=0, H=0",
                "C4".into(),
            ),
            (
                "SRC",
                "Node A full key",
                hex_spaced(&vectors.node_a_public.0),
            ),
        ],
        &vectors.broadcast_full,
    );

    render_example(
        &mut out,
        "Example 3: Encrypted Unicast (S=0)",
        "An encrypted unicast from Node A to Node B using source hints and frame counter 42.",
        &[
            ("FCF", "VER=3, TYPE=2 (unicast), S=0, O=0, H=0", "D0".into()),
            (
                "DST",
                "Node B hint",
                hex_spaced(&vectors.node_b_public.hint().0),
            ),
            (
                "SRC",
                "Node A hint",
                hex_spaced(&vectors.node_a_public.hint().0),
            ),
            ("SCF", "E=1, MIC=3 (16-byte), S=0", "E0".into()),
            ("Frame Counter", "42", hex_spaced(&42u32.to_be_bytes())),
            (
                "Payload",
                "Encrypted `48 65 6C 6C 6F` (`\"Hello\"`)",
                hex_spaced(&vectors.unicast_encrypted[unicast_encrypted_header.body_range.clone()]),
            ),
            (
                "MIC",
                "16 bytes",
                hex_spaced(&vectors.unicast_encrypted[unicast_encrypted_header.mic_range.clone()]),
            ),
        ],
        &vectors.unicast_encrypted,
    );

    render_example(
        &mut out,
        "Example 4: Encrypted Unicast with Ack Requested (S=1)",
        "A first-contact encrypted unicast from Node A to Node B requesting a MAC acknowledgement. The full 32-byte source key is included.",
        &[
            ("FCF", "VER=3, TYPE=3 (unicast ack-req), S=1, O=0, H=0", "DC".into()),
            ("DST", "Node B hint", hex_spaced(&vectors.node_b_public.hint().0)),
            ("SRC", "Node A full key", hex_spaced(&vectors.node_a_public.0)),
            ("SCF", "E=1, MIC=3 (16-byte), S=0", "E0".into()),
            ("Frame Counter", "1", hex_spaced(&1u32.to_be_bytes())),
            (
                "Payload",
                "Encrypted `68 65 79` (`\"hey\"`)",
                hex_spaced(&vectors.unicast_ackreq_fullsrc[unicast_ackreq_header.body_range.clone()]),
            ),
            (
                "MIC",
                "16 bytes",
                hex_spaced(&vectors.unicast_ackreq_fullsrc[unicast_ackreq_header.mic_range.clone()]),
            ),
        ],
        &vectors.unicast_ackreq_fullsrc,
    );

    render_example(
        &mut out,
        "Example 5: Encrypted Multicast (E=1)",
        "An encrypted multicast from Node A on channel `B08D`. The encrypted body contains the source hint followed by the plaintext payload.",
        &[
            ("FCF", "VER=3, TYPE=4 (multicast), S=0, O=0, H=0", "E0".into()),
            ("CHANNEL", "Derived channel identifier", hex_spaced(&vectors.channel.channel_id.0)),
            ("SCF", "E=1, MIC=3 (16-byte), S=0", "E0".into()),
            ("Frame Counter", "5", hex_spaced(&5u32.to_be_bytes())),
            (
                "Encrypted data",
                "ENCRYPT(`SRC || \"Hello\"`)",
                hex_spaced(&vectors.multicast_encrypted[multicast_encrypted_header.body_range.clone()]),
            ),
            (
                "MIC",
                "16 bytes",
                hex_spaced(&vectors.multicast_encrypted[multicast_encrypted_header.mic_range.clone()]),
            ),
        ],
        &vectors.multicast_encrypted,
    );

    render_example(
        &mut out,
        "Example 6: Authenticated Multicast (E=0)",
        "An authenticated but unencrypted multicast from Node A carrying payload type `03` followed by `\"Hello\"`.",
        &[
            ("FCF", "VER=3, TYPE=4 (multicast), S=0, O=0, H=0", "E0".into()),
            ("CHANNEL", "Derived channel identifier", hex_spaced(&vectors.channel.channel_id.0)),
            ("SCF", "E=0, MIC=3 (16-byte), S=0", "60".into()),
            ("Frame Counter", "3", hex_spaced(&3u32.to_be_bytes())),
            ("SRC", "Node A hint", hex_spaced(&vectors.node_a_public.hint().0)),
            (
                "Payload",
                "`03 || \"Hello\"`",
                hex_spaced(&vectors.multicast_authenticated[multicast_authenticated_header.body_range.clone()]),
            ),
            (
                "MIC",
                "16 bytes",
                hex_spaced(&vectors.multicast_authenticated[multicast_authenticated_header.mic_range.clone()]),
            ),
        ],
        &vectors.multicast_authenticated,
    );

    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "## Example 7: Encrypted Unicast with Options and Flood Hops"
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "An encrypted unicast with a region code option, an empty trace-route option, and flood hop limit 4.").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "**Options encoding:**").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "| Option | Number | Delta | Length | Encoding |").unwrap();
    writeln!(&mut out, "|---|---:|---:|---:|---|").unwrap();
    writeln!(
        &mut out,
        "| Region Code | 1 | 1 | 2 | `12` then value `78 53` |"
    )
    .unwrap();
    writeln!(&mut out, "| Trace Route | 2 | 1 | 0 | `10` |").unwrap();
    writeln!(&mut out, "| End marker | — | — | — | `FF` |").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "| Field | Value | Hex |").unwrap();
    writeln!(&mut out, "|---|---|---|").unwrap();
    writeln!(
        &mut out,
        "| FCF | VER=3, TYPE=2 (unicast), S=0, O=1, H=1 | `D3` |"
    )
    .unwrap();
    writeln!(
        &mut out,
        "| Options | Region code + trace route + end marker | `12 78 53 10 FF` |"
    )
    .unwrap();
    writeln!(&mut out, "| FHOPS | FHOPS_REM=4, FHOPS_ACC=0 | `40` |").unwrap();
    writeln!(
        &mut out,
        "| DST | Node B hint | `{}` |",
        hex_spaced(&vectors.node_b_public.hint().0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "| SRC | Node A hint | `{}` |",
        hex_spaced(&vectors.node_a_public.hint().0)
    )
    .unwrap();
    writeln!(&mut out, "| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |").unwrap();
    writeln!(&mut out, "| Frame Counter | 10 | `00 00 00 0A` |").unwrap();
    writeln!(
        &mut out,
        "| Payload | Encrypted `68 65 79` (`\"hey\"`) | `{}` |",
        hex_spaced(&vectors.unicast_with_options[unicast_with_options_header.body_range.clone()])
    )
    .unwrap();
    writeln!(
        &mut out,
        "| MIC | 16 bytes | `{}` |",
        hex_spaced(&vectors.unicast_with_options[unicast_with_options_header.mic_range.clone()])
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "```text").unwrap();
    writeln!(
        &mut out,
        "{}",
        wrap_hex_lines(&vectors.unicast_with_options, 16)
    )
    .unwrap();
    writeln!(&mut out, "```").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "Total: {} bytes.",
        vectors.unicast_with_options.len()
    )
    .unwrap();

    render_example(
        &mut out,
        "Example 8: Blind Unicast (S=0)",
        "A blind unicast on channel `B08D`. The destination hint and source hint are encrypted together in `ENC_DST_SRC`, while the payload is encrypted with the blind-unicast payload keys.",
        &[
            ("FCF", "VER=3, TYPE=6 (blind unicast), S=0, O=0, H=0", "F0".into()),
            ("CHANNEL", "Derived channel identifier", hex_spaced(&vectors.channel.channel_id.0)),
            ("SCF", "E=1, MIC=3 (16-byte), S=0", "E0".into()),
            ("Frame Counter", "7", hex_spaced(&7u32.to_be_bytes())),
            (
                "ENC_DST_SRC",
                "ENCRYPT(`DST || SRC`)",
                hex_spaced(&vectors.blind_unicast[8..blind_unicast_header.body_range.start]),
            ),
            (
                "ENC_PAYLOAD",
                "ENCRYPT(`\"Hello\"`)",
                hex_spaced(&vectors.blind_unicast[blind_unicast_header.body_range.clone()]),
            ),
            (
                "MIC",
                "16 bytes",
                hex_spaced(&vectors.blind_unicast[blind_unicast_header.mic_range.clone()]),
            ),
        ],
        &vectors.blind_unicast,
    );

    out
}

struct Phase1Vectors {
    node_a_private: [u8; 32],
    node_b_private: [u8; 32],
    node_a_public: PublicKey,
    node_b_public: PublicKey,
    shared_secret: SharedSecret,
    channel_key: ChannelKey,
    channel: DerivedChannelKeys,
    broadcast_hint: Vec<u8>,
    broadcast_full: Vec<u8>,
    unicast_encrypted: Vec<u8>,
    unicast_ackreq_fullsrc: Vec<u8>,
    multicast_encrypted: Vec<u8>,
    multicast_authenticated: Vec<u8>,
    unicast_with_options: Vec<u8>,
    blind_unicast: Vec<u8>,
}

fn generate_phase1_vectors() -> Phase1Vectors {
    let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);

    let node_a_private = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30,
    ];
    let node_b_private = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F, 0x50,
    ];
    let node_a_identity = SoftwareIdentity::from_secret_bytes(&node_a_private);
    let node_b_identity = SoftwareIdentity::from_secret_bytes(&node_b_private);
    let node_a_public = *node_a_identity.public_key();
    let node_b_public = *node_b_identity.public_key();
    let shared_secret = node_a_identity.shared_secret_with(&node_b_public).unwrap();
    let pairwise = engine.derive_pairwise_keys(&shared_secret);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel = engine.derive_channel_keys(&channel_key);
    let blind_keys = engine.derive_blind_keys(&pairwise, &channel);

    Phase1Vectors {
        node_a_private,
        node_b_private,
        node_a_public,
        node_b_public,
        shared_secret,
        channel_key,
        broadcast_hint: build_broadcast_hint(&node_a_public),
        broadcast_full: build_broadcast_full(&node_a_public),
        unicast_encrypted: build_unicast_encrypted(
            &engine,
            &pairwise,
            &node_a_public,
            node_b_public.hint(),
        ),
        unicast_ackreq_fullsrc: build_unicast_ackreq_fullsrc(
            &engine,
            &pairwise,
            &node_a_public,
            node_b_public.hint(),
        ),
        multicast_encrypted: build_multicast_encrypted(&engine, &channel, &node_a_public),
        multicast_authenticated: build_multicast_authenticated(&engine, &channel, &node_a_public),
        unicast_with_options: build_unicast_with_options(
            &engine,
            &pairwise,
            &node_a_public,
            node_b_public.hint(),
        ),
        blind_unicast: build_blind_unicast(
            &engine,
            &blind_keys,
            &channel,
            &node_a_public,
            node_b_public.hint(),
        ),
        channel,
    }
}

fn build_broadcast_hint(node_a: &PublicKey) -> Vec<u8> {
    let mut buf = [0u8; 64];
    PacketBuilder::new(&mut buf)
        .broadcast()
        .source_hint(node_a.hint())
        .build()
        .unwrap()
        .to_vec()
}

fn build_broadcast_full(node_a: &PublicKey) -> Vec<u8> {
    let mut buf = [0u8; 64];
    PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(node_a)
        .build()
        .unwrap()
        .to_vec()
}

fn build_unicast_encrypted(
    engine: &SoftwareCryptoEngine,
    pairwise: &PairwiseKeys,
    node_a: &PublicKey,
    dst: NodeHint,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_hint(node_a.hint())
        .frame_counter(42)
        .encrypted()
        .mic_size(MicSize::Mic16)
        .payload(b"Hello")
        .build()
        .unwrap();
    engine.seal_packet(&mut packet, pairwise).unwrap();
    packet.as_bytes().to_vec()
}

fn build_unicast_ackreq_fullsrc(
    engine: &SoftwareCryptoEngine,
    pairwise: &PairwiseKeys,
    node_a: &PublicKey,
    dst: NodeHint,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_full(node_a)
        .frame_counter(1)
        .ack_requested()
        .encrypted()
        .mic_size(MicSize::Mic16)
        .payload(b"hey")
        .build()
        .unwrap();
    engine.seal_packet(&mut packet, pairwise).unwrap();
    packet.as_bytes().to_vec()
}

fn build_multicast_encrypted(
    engine: &SoftwareCryptoEngine,
    channel: &DerivedChannelKeys,
    node_a: &PublicKey,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut packet = PacketBuilder::new(&mut buf)
        .multicast(channel.channel_id)
        .source_hint(node_a.hint())
        .frame_counter(5)
        .encrypted()
        .mic_size(MicSize::Mic16)
        .payload(b"Hello")
        .build()
        .unwrap();
    let keys = PairwiseKeys {
        k_enc: channel.k_enc,
        k_mic: channel.k_mic,
    };
    engine.seal_packet(&mut packet, &keys).unwrap();
    packet.as_bytes().to_vec()
}

fn build_multicast_authenticated(
    engine: &SoftwareCryptoEngine,
    channel: &DerivedChannelKeys,
    node_a: &PublicKey,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut packet = PacketBuilder::new(&mut buf)
        .multicast(channel.channel_id)
        .source_hint(node_a.hint())
        .frame_counter(3)
        .mic_size(MicSize::Mic16)
        .payload(b"\x03Hello")
        .build()
        .unwrap();
    let keys = PairwiseKeys {
        k_enc: channel.k_enc,
        k_mic: channel.k_mic,
    };
    engine.seal_packet(&mut packet, &keys).unwrap();
    packet.as_bytes().to_vec()
}

fn build_unicast_with_options(
    engine: &SoftwareCryptoEngine,
    pairwise: &PairwiseKeys,
    node_a: &PublicKey,
    dst: NodeHint,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_hint(node_a.hint())
        .frame_counter(10)
        .encrypted()
        .flood_hops(4)
        .region_code([0x78, 0x53])
        .trace_route()
        .payload(b"hey")
        .build()
        .unwrap();
    engine.seal_packet(&mut packet, pairwise).unwrap();
    packet.as_bytes().to_vec()
}

fn build_blind_unicast(
    engine: &SoftwareCryptoEngine,
    blind_keys: &PairwiseKeys,
    channel: &DerivedChannelKeys,
    node_a: &PublicKey,
    dst: NodeHint,
) -> Vec<u8> {
    let mut buf = [0u8; 160];
    let mut packet = PacketBuilder::new(&mut buf)
        .blind_unicast(channel.channel_id, dst)
        .source_hint(node_a.hint())
        .frame_counter(7)
        .mic_size(MicSize::Mic16)
        .payload(b"Hello")
        .build()
        .unwrap();
    engine
        .seal_blind_packet(&mut packet, blind_keys, channel)
        .unwrap();
    packet.as_bytes().to_vec()
}

fn render_example(
    out: &mut String,
    title: &str,
    description: &str,
    fields: &[(&str, &str, String)],
    bytes: &[u8],
) {
    writeln!(out).unwrap();
    writeln!(out, "## {}", title).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "{}", description).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| Field | Value | Hex |").unwrap();
    writeln!(out, "|---|---|---|").unwrap();
    for (field, value, hex) in fields {
        writeln!(out, "| {} | {} | `{}` |", field, value, hex).unwrap();
    }
    writeln!(out).unwrap();
    writeln!(out, "```text").unwrap();
    writeln!(out, "{}", wrap_hex_lines(bytes, 16)).unwrap();
    writeln!(out, "```").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "Total: {} bytes.", bytes.len()).unwrap();
}

fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex_words(bytes: &[u8]) -> String {
    bytes
        .chunks(2)
        .map(|chunk| {
            chunk
                .iter()
                .map(|byte| format!("{:02X}", byte))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn wrap_hex_lines(bytes: &[u8], line_width: usize) -> String {
    bytes
        .chunks(line_width)
        .map(hex_spaced)
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_header(bytes: &[u8]) -> PacketHeader {
    PacketHeader::parse(bytes).expect("parse generated vector")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::render_phase1_test_vectors_markdown;

    #[test]
    fn phase1_vectors_match_protocol_appendix() {
        let expected = render_phase1_test_vectors_markdown();
        let actual = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/protocol/src/test-vectors.md"
        ))
        .expect("read protocol test vectors");
        assert_eq!(actual, expected);
    }
}
