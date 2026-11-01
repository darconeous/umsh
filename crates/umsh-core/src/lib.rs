#![cfg_attr(not(feature = "std"), no_std)]

//! Core wire-format types and packet construction/parsing utilities for UMSH.
//!
//! > Note: This reference implementation is a work in progress and was developed
//! > with the assistance of an LLM. It should be considered experimental.
//!
//! This crate stays focused on byte layout, typed header fields, and zero-copy
//! parsing. It does not perform any cryptographic operations or I/O.
//!
//! The main entry points are:
//!
//! - [`PacketHeader::parse`] to inspect a received frame.
//! - [`PacketBuilder`] to construct outbound frames with typestate guards.
//! - [`feed_aad`] to stream canonical authenticated data into a MAC state.
//! - [`options::OptionEncoder`] and [`options::OptionDecoder`] for CoAP-style
//!   option blocks used throughout the protocol.
//!
//! # Example
//!
//! ```rust
//! use umsh_core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PublicKey};
//!
//! let mut buf = [0u8; 128];
//! let src = PublicKey([0x11; 32]);
//! let dst = NodeHint([0xAA, 0xBB, 0xCC]);
//!
//! let packet = PacketBuilder::new(&mut buf)
//!     .unicast(dst)
//!     .source_full(&src)
//!     .frame_counter(7)
//!     .encrypted()
//!     .mic_size(MicSize::Mic16)
//!     .payload(b"hello")
//!     .build()
//!     .unwrap();
//!
//! let header = PacketHeader::parse(packet.as_bytes()).unwrap();
//! assert_eq!(header.dst, Some(dst));
//! assert_eq!(header.body_range.len(), 5);
//! ```

pub mod base58;
mod builder;
mod error;
pub mod hint_filter;
pub mod options;
mod packet;
#[cfg(feature = "region-codec")]
mod region;
mod route_slack;

pub use builder::{
    BlindUnicastBuilder, BroadcastBuilder, MacAckBuilder, MulticastBuilder, PacketBuilder,
    UnicastBuilder, state,
};
pub use error::{AddressParseError, BuildError, EncodeError, HintInputError, ParseError};
pub use packet::{
    BlindAddr, ChannelId, ChannelKey, ChannelTag, Fcf, FloodHops, MicSize, NodeHint, OptionNumber,
    PacketHeader, PacketType, ParsedOptions, PayloadType, PublicKey, RouterHint,
    RouterHintCandidates, Scf, SecInfo, SourceAddr, SourceAddrRef, UMSH_VERSION, UnsealedPacket,
    feed_aad, iter_options,
};
#[cfg(feature = "region-codec")]
pub use region::{REGION_NAME_MAX_LEN, RegionCode, RegionCodeError};
pub use route_slack::{
    ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS, RouteEvidence, STRONG_DIRECT_RSSI_DBM,
    WEAK_LAST_HOP_RSSI_DBM, established_route_slack,
};

#[cfg(test)]
mod tests {
    use crate::{
        Fcf, MicSize, NodeHint, OptionNumber, PacketBuilder, PacketHeader, PacketType, PublicKey,
        Scf, SecInfo, SourceAddrRef, feed_aad,
        options::{OptionDecoder, OptionEncoder},
    };

    #[test]
    fn option_codec_round_trip() {
        let mut buf = [0u8; 32];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(1, &[0x78, 0x53]).unwrap();
        enc.put(2, &[]).unwrap();
        enc.end_marker().unwrap();
        let len = enc.finish();

        let mut decoder = OptionDecoder::new(&buf[..len]);
        assert_eq!(decoder.next().unwrap().unwrap(), (1, &[0x78, 0x53][..]));
        assert_eq!(decoder.next().unwrap().unwrap(), (2, &[][..]));
        assert!(decoder.next().is_none());
    }

    #[test]
    fn secinfo_round_trip() {
        let sec = SecInfo {
            scf: Scf::new(true, MicSize::Mic16, true),
            frame_counter: 42,
            salt: Some(0x1234),
        };
        let mut buf = [0u8; 7];
        let len = sec.encode(&mut buf).unwrap();
        assert_eq!(len, 7);
        assert_eq!(SecInfo::decode(&buf).unwrap(), sec);
    }

    #[test]
    fn parse_broadcast_beacon() {
        let bytes = [0xC0, 0xA1, 0xB2, 0x03];
        let header = PacketHeader::parse(&bytes).unwrap();
        assert_eq!(header.packet_type(), PacketType::Broadcast);
        assert!(header.is_beacon());
    }

    #[test]
    fn empty_payload_emits_no_end_of_options_marker() {
        // A beacon is a broadcast with an empty payload. Nothing follows the
        // options block, so the `0xFF` marker must not be emitted—it would
        // be a wasted byte on every beacon.
        let mut buf = [0u8; 64];
        let beacon = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([0x8B, 0x60, 0xF5]))
            .flood_hops(5)
            .payload(&[])
            .build()
            .unwrap();
        assert_eq!(beacon, &[0xC1, 0x50, 0x8B, 0x60, 0xF5]);
        let header = PacketHeader::parse(beacon).unwrap();
        assert!(header.is_beacon());

        // The marker returns as soon as there is a payload to delimit.
        let mut buf = [0u8; 64];
        let with_payload = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([0x8B, 0x60, 0xF5]))
            .payload(b"hi")
            .build()
            .unwrap();
        assert_eq!(with_payload, &[0xC0, 0x8B, 0x60, 0xF5, 0xFF, b'h', b'i']);

        // The same holds for a secured type whose body is empty.
        let mut buf = [0u8; 128];
        let unicast = PacketBuilder::new(&mut buf)
            .unicast(NodeHint([0xC3, 0xD4, 0x25]))
            .source_hint(NodeHint([0xA1, 0xB2, 0x03]))
            .frame_counter(7)
            .encrypted()
            .mic_size(MicSize::Mic8)
            .payload(&[])
            .build()
            .unwrap();
        // FCF | DST(3) | SRC(3) | SECINFO(5) | no options, no marker | MIC(8)
        let bytes = unicast.as_bytes();
        assert_eq!(
            bytes,
            &[
                0xD0, 0xC3, 0xD4, 0x25, 0xA1, 0xB2, 0x03, 0xA0, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        let header = PacketHeader::parse(bytes).unwrap();
        assert!(header.options_range.is_empty());
        assert!(header.body_range.is_empty());
        assert_eq!(header.mic_range.len(), 8);
    }

    #[test]
    fn builder_and_parser_for_unicast_match() {
        let mut buf = [0u8; 128];
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let packet = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_full(&src)
            .frame_counter(42)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();

        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        assert_eq!(header.packet_type(), PacketType::Unicast);
        assert_eq!(header.dst, Some(dst));
        assert_eq!(header.body_range.len(), 5);
    }

    #[test]
    fn blind_unicast_builder_and_parser_match() {
        let mut buf = [0u8; 128];
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let channel = crate::ChannelId([0x7E, 0x5F]);
        let packet = PacketBuilder::new(&mut buf)
            .blind_unicast(channel, dst)
            .source_full(&src)
            .frame_counter(5)
            .payload(b"hello")
            .build()
            .unwrap();

        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        assert_eq!(header.packet_type(), PacketType::BlindUnicast);
        assert_eq!(header.channel, Some(channel));
        assert_eq!(packet.blind_addr().unwrap().len(), 35);
        assert_eq!(header.body_range.len(), 5);
    }

    #[test]
    fn unencrypted_blind_unicast_builder_and_parser_match() {
        let mut buf = [0u8; 128];
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let channel = crate::ChannelId([0x7E, 0x5F]);
        let packet = PacketBuilder::new(&mut buf)
            .blind_unicast(channel, dst)
            .source_full(&src)
            .frame_counter(5)
            .unencrypted()
            .payload(b"hello")
            .build()
            .unwrap();

        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        assert_eq!(header.packet_type(), PacketType::BlindUnicast);
        assert_eq!(header.channel, Some(channel));
        assert_eq!(header.dst, Some(dst));
        assert_eq!(
            header.source,
            SourceAddrRef::FullKeyAt {
                offset: header.body_range.start - 32
            }
        );
        assert!(!header.sec_info.unwrap().scf.encrypted());
        assert_eq!(header.body_range.len(), 5);
    }

    #[test]
    fn builder_encodes_incremental_options_with_correct_deltas() {
        let mut buf = [0u8; 128];
        let src = NodeHint([0xA1, 0xB2, 0x03]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let packet = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_hint(src)
            .frame_counter(10)
            .encrypted()
            .trace()
            .region_code([0x78, 0x53])
            .payload(b"hey")
            .build()
            .unwrap();

        // New layout: FCF DST(3) SRC(3) SECINFO(5) OPTIONS...
        // Options start at byte 12: trace(0x70) + region_code(0x42,0x78,0x53) + 0xFF
        assert_eq!(&packet.as_bytes()[12..17], &[0x70, 0x42, 0x78, 0x53, 0xFF]);
    }

    #[test]
    fn aad_excludes_dynamic_options() {
        // New layout for unicast with hint source, encrypted, MIC8, no fhops:
        // FCF | DST(3) | SRC(3) | SECINFO(5) | OPTIONS(5) | 0xFF | payload(3) | MIC(8)
        // Total = 1 + 3 + 3 + 5 + 4 + 1 + 3 + 8 = 28 bytes
        // Options: trace (7, len 0) + region code (11, len 2)—both dynamic, excluded from AAD
        let mut bytes = [0u8; 64];
        bytes[0] = Fcf::new(PacketType::Unicast, false, false).0;
        bytes[1..4].copy_from_slice(&[0xC3, 0xD4, 0x25]); // DST
        bytes[4..7].copy_from_slice(&[0xA1, 0xB2, 0x03]); // SRC hint
        bytes[7] = Scf::new(true, MicSize::Mic8, false).0; // SCF
        bytes[8..12].copy_from_slice(&42u32.to_be_bytes()); // frame counter
        bytes[12] = 0x70; // trace: delta=7, len=0
        bytes[13] = 0x42; // region code: delta=4, len=2
        bytes[14] = 0x78;
        bytes[15] = 0x53;
        bytes[16] = 0xFF; // end marker
        bytes[17..20].copy_from_slice(b"hey"); // payload
        bytes[20..28].fill(0x11); // MIC
        let header = PacketHeader::parse(&bytes[..28]).unwrap();
        let mut aad = [0u8; 20];
        let mut aad_len = 0usize;
        feed_aad(&header, &bytes[..28], None, |chunk| {
            let next_len = aad_len + chunk.len();
            aad[aad_len..next_len].copy_from_slice(chunk);
            aad_len = next_len;
        })
        .unwrap();
        assert_eq!(
            &aad[..aad_len],
            &[
                bytes[0],
                0xC3,
                0xD4,
                0x25,
                0xA1,
                0xB2,
                0x03,
                Scf::new(true, MicSize::Mic8, false).0,
                0x00,
                0x00,
                0x00,
                0x2A,
                0xFF,
                0xFF,
            ]
        );
    }

    #[test]
    fn aad_encodes_static_option_tl_as_u16_be_pairs() {
        let mut buf = [0u8; 96];
        let packet = PacketBuilder::new(&mut buf)
            .unicast(NodeHint([0xC3, 0xD4, 0x25]))
            .source_hint(NodeHint([0xA1, 0xB2, 0x03]))
            .frame_counter(42)
            .encrypted()
            .option(OptionNumber::Unknown(300), &[0xAA])
            .payload(b"hey")
            .build()
            .unwrap();
        let bytes = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&bytes).unwrap();
        let mut aad = [0u8; 32];
        let mut aad_len = 0usize;

        feed_aad(&header, &bytes, None, |chunk| {
            let next_len = aad_len + chunk.len();
            aad[aad_len..next_len].copy_from_slice(chunk);
            aad_len = next_len;
        })
        .unwrap();

        // FCF ‖ DST ‖ SRC ‖ SECINFO occupy the first 12 bytes; the static
        // option record and the terminator follow.
        assert_eq!(
            &aad[12..aad_len],
            &[0x01, 0x2C, 0x00, 0x01, 0xAA, 0xFF, 0xFF]
        );
    }

    #[test]
    fn parse_blind_unicast_tracks_secinfo_range() {
        // New layout: FCF | CHANNEL(2) | SECINFO(5) | 0xFF | ENC_DST_SRC(6) | payload(5) | MIC(4)
        // 0xFF is required because body follows options
        let bytes = [
            0xF0, 0x7E, 0x5F, 0x80, 0x00, 0x00, 0x00, 0x05, 0xFF, 0xC3, 0xD4, 0x25, 0xA1, 0xB2,
            0x03, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x11, 0x22, 0x33, 0x44,
        ];
        let header = PacketHeader::parse(&bytes).unwrap();
        assert_eq!(header.sec_info.unwrap().wire_len(), 5);
    }

    /// Every range a successful parse reports must lie inside the frame, and
    /// fields that follow the options must end before the MIC.
    fn assert_ranges_sane(header: &PacketHeader, len: usize) {
        for range in [&header.options_range, &header.body_range, &header.mic_range] {
            assert!(range.start <= range.end, "inverted range {range:?}");
            assert!(range.end <= len, "range {range:?} past frame of {len}");
        }
        assert!(header.total_len <= len);
        let trailer = header.mic_range.start;
        match header.source {
            SourceAddrRef::FullKeyAt { offset } => assert!(offset + 32 <= trailer),
            SourceAddrRef::Encrypted { offset, len } => assert!(offset + len <= trailer),
            SourceAddrRef::Hint(_) | SourceAddrRef::None => {}
        }
    }

    fn sample_frames() -> Vec<Vec<u8>> {
        let src = PublicKey([0xA1; 32]);
        let hint = NodeHint([0xA1, 0xB2, 0x03]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let channel = crate::ChannelId([0x7E, 0x5F]);
        let mut frames = Vec::new();

        let mut buf = [0u8; 255];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(hint)
            .region_code([0x12, 0x34])
            .payload(b"hello")
            .build()
            .unwrap();
        frames.push(frame.to_vec());

        let mut buf = [0u8; 255];
        let frame = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_hint(hint)
            .frame_counter(9)
            .region_code([0x12, 0x34])
            .encrypted()
            .mic_size(MicSize::Mic8)
            .payload(b"hello")
            .build()
            .unwrap();
        frames.push(frame.as_bytes().to_vec());

        for encrypted in [false, true] {
            for full in [false, true] {
                let mut buf = [0u8; 255];
                let builder = PacketBuilder::new(&mut buf).multicast(channel);
                let builder = if full {
                    builder.source_full(&src)
                } else {
                    builder.source_hint(hint)
                };
                let mut builder = builder.frame_counter(3).mic_size(MicSize::Mic4);
                if encrypted {
                    builder = builder.encrypted();
                }
                let frame = builder.payload(b"hi").build().unwrap();
                frames.push(frame.as_bytes().to_vec());

                let mut buf = [0u8; 255];
                let builder = PacketBuilder::new(&mut buf).blind_unicast(channel, dst);
                let builder = if full {
                    builder.source_full(&src)
                } else {
                    builder.source_hint(hint)
                };
                let mut builder = builder.frame_counter(3);
                if !encrypted {
                    builder = builder.unencrypted();
                }
                let frame = builder.payload(b"hi").build().unwrap();
                frames.push(frame.as_bytes().to_vec());
            }
        }

        let mut buf = [0u8; 255];
        let frame = PacketBuilder::new(&mut buf)
            .mac_ack([1, 2, 3, 4, 5, 6, 7, 8])
            .region_code([0x12, 0x34])
            .build()
            .unwrap();
        frames.push(frame.to_vec());
        frames
    }

    #[test]
    fn truncated_and_corrupted_frames_never_yield_out_of_range_fields() {
        for frame in sample_frames() {
            assert_ranges_sane(&PacketHeader::parse(&frame).unwrap(), frame.len());
            for cut in 0..frame.len() {
                if let Ok(header) = PacketHeader::parse(&frame[..cut]) {
                    assert_ranges_sane(&header, cut);
                }
            }
            for at in 0..frame.len() {
                for value in [0x00, 0x0F, 0xD0, 0xE0, 0xEE, 0xFF] {
                    let mut corrupted = frame.clone();
                    corrupted[at] = value;
                    if let Ok(header) = PacketHeader::parse(&corrupted) {
                        assert_ranges_sane(&header, corrupted.len());
                    }
                }
            }
        }
    }

    #[test]
    fn source_after_options_must_end_before_the_mic() {
        // FCF | CHANNEL | SECINFO (unencrypted, 4-byte MIC) | MIC: no options
        // and no end-of-options marker. A parser that bounded SRC by the
        // buffer instead of the MIC read the hint out of the MIC and reported
        // an inverted body range.
        let fcf = Fcf::new(PacketType::Multicast, false, false).0;
        for encrypted in [false, true] {
            let scf = Scf::new(encrypted, MicSize::Mic4, false).0;
            let frame = [fcf, 0x7E, 0x5F, scf, 0, 0, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD];
            assert_eq!(
                PacketHeader::parse(&frame),
                Err(crate::ParseError::Truncated)
            );
        }
        let fcf = Fcf::new(PacketType::BlindUnicast, false, false).0;
        for encrypted in [false, true] {
            let scf = Scf::new(encrypted, MicSize::Mic4, false).0;
            let frame = [
                fcf, 0x7E, 0x5F, scf, 0, 0, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22,
            ];
            assert_eq!(
                PacketHeader::parse(&frame),
                Err(crate::ParseError::Truncated)
            );
        }
    }

    #[test]
    fn option_numbers_past_0xffff_are_malformed() {
        // An extended delta of 0xFFFF + 269 does not fit sixteen bits.
        let single = [0xE0, 0xFF, 0xFF];
        // Two in-range deltas whose running sum passes 0xFFFF.
        let first = 0xFF00u16 - 269;
        let second = 0x0200u16 - 269;
        let summed = [
            0xE0,
            (first >> 8) as u8,
            first as u8,
            0xE0,
            (second >> 8) as u8,
            second as u8,
        ];
        for options in [&single[..], &summed[..]] {
            let decoded: Result<Vec<_>, _> = OptionDecoder::new(options).collect();
            assert_eq!(decoded, Err(crate::ParseError::MalformedOption));

            let mut frame = vec![
                Fcf::new(PacketType::Broadcast, false, false).0,
                0x8B,
                0x60,
                0xF5,
            ];
            frame.extend_from_slice(options);
            assert_eq!(
                PacketHeader::parse(&frame),
                Err(crate::ParseError::MalformedOption)
            );
        }
    }

    fn aad_of(frame: &[u8], blind: Option<&crate::BlindAddr>) -> Vec<u8> {
        let header = PacketHeader::parse(frame).unwrap();
        let mut aad = Vec::new();
        feed_aad(&header, frame, blind, |chunk| aad.extend_from_slice(chunk)).unwrap();
        aad
    }

    #[test]
    fn aad_always_ends_with_the_terminator() {
        let mut buf = [0u8; 64];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([0x8B, 0x60, 0xF5]))
            .payload(b"hi")
            .build()
            .unwrap()
            .to_vec();
        assert_eq!(
            aad_of(&frame, None),
            [frame[0], 0x8B, 0x60, 0xF5, 0xFF, 0xFF]
        );
    }

    /// Two headers that the earlier layout mapped to identical AAD bytes: an
    /// unencrypted, salted multicast with no static options whose SRC hint
    /// stood in the AAD, and an encrypted, unsalted multicast carrying one
    /// static option. Fields in wire order with a terminator keep them apart.
    #[test]
    fn colliding_headers_from_the_old_layout_have_distinct_aads() {
        let fcf_free_scf = Scf::new(false, MicSize::Mic4, true).0;
        let enc_scf = Scf::new(true, MicSize::Mic4, false).0;
        let mut buf = [0u8; 64];
        let a = PacketBuilder::new(&mut buf)
            .multicast(crate::ChannelId([0x00, 0x14]))
            .source_hint(NodeHint([0x00, 0x01, 0x5A]))
            .frame_counter(u32::from_be_bytes([0x33, enc_scf, 0x00, 0x00]))
            .salt(0x0007)
            .mic_size(MicSize::Mic4)
            .payload(b"x")
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut buf = [0u8; 64];
        let b = PacketBuilder::new(&mut buf)
            .multicast(crate::ChannelId([fcf_free_scf, 0x33]))
            .source_hint(NodeHint([0x00, 0x01, 0x5A]))
            .frame_counter(0x0000_0007)
            .option(OptionNumber::Unknown(20), &[0x5A])
            .encrypted()
            .mic_size(MicSize::Mic4)
            .payload(b"x")
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        assert_ne!(aad_of(&a, None), aad_of(&b, None));
    }

    #[test]
    fn multicast_aad_depends_on_e_only_through_the_scf() {
        let src = PublicKey([0xA1; 32]);
        let build = |encrypted: bool| {
            let mut buf = [0u8; 128];
            let builder = PacketBuilder::new(&mut buf)
                .multicast(crate::ChannelId([0x7E, 0x5F]))
                .source_full(&src)
                .frame_counter(9)
                .region_code([0x12, 0x34])
                .mic_size(MicSize::Mic8);
            let builder = if encrypted {
                builder.encrypted()
            } else {
                builder
            };
            builder
                .payload(b"hello")
                .build()
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        let (plain, sealed) = (build(false), build(true));
        let (aad_plain, aad_sealed) = (aad_of(&plain, None), aad_of(&sealed, None));
        assert_eq!(aad_plain.len(), aad_sealed.len());
        let differing: Vec<_> = (0..aad_plain.len())
            .filter(|&i| aad_plain[i] != aad_sealed[i])
            .collect();
        assert_eq!(differing, [3], "only the SCF byte may differ");
        for frame in [&plain, &sealed] {
            let header = PacketHeader::parse(frame).unwrap();
            let protected = header.protected_range();
            assert_eq!(&frame[protected.start..protected.start + 32], &src.0);
            assert_eq!(protected.end, header.mic_range.start);
        }
    }

    #[test]
    fn blind_unicast_aad_covers_plaintext_addresses_for_either_e() {
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let mut addr = [0u8; 35];
        addr[..3].copy_from_slice(&dst.0);
        addr[3..].copy_from_slice(&src.0);
        let addr = crate::BlindAddr::from_plaintext(&addr).unwrap();
        let build = |encrypted: bool| {
            let mut buf = [0u8; 128];
            let builder = PacketBuilder::new(&mut buf)
                .blind_unicast(crate::ChannelId([0x7E, 0x5F]), dst)
                .source_full(&src)
                .frame_counter(5);
            let builder = if encrypted {
                builder
            } else {
                builder.unencrypted()
            };
            builder
                .payload(b"hello")
                .build()
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        let (plain, sealed) = (build(false), build(true));
        let (aad_plain, aad_sealed) = (aad_of(&plain, Some(&addr)), aad_of(&sealed, Some(&addr)));
        assert!(aad_plain.ends_with(addr.as_bytes()));
        let differing: Vec<_> = (0..aad_plain.len())
            .filter(|&i| aad_plain[i] != aad_sealed[i])
            .collect();
        assert_eq!(differing, [3], "only the SCF byte may differ");

        let header = PacketHeader::parse(&plain).unwrap();
        assert_eq!(
            feed_aad(&header, &plain, None, |_| {}),
            Err(crate::ParseError::MissingAddressBlock)
        );
        assert_eq!(&plain[header.blind_addr_range().unwrap()], addr.as_bytes());
    }
}
