#![cfg_attr(not(feature = "std"), no_std)]

mod builder;
mod error;
pub mod options;
mod packet;

pub use builder::{
    state, BlindUnicastBuilder, BroadcastBuilder, MacAckBuilder, MulticastBuilder, PacketBuilder,
    UnicastBuilder,
};
pub use error::{BuildError, EncodeError, ParseError};
pub use packet::{
    feed_aad, iter_options, ChannelId, ChannelKey, Fcf, FloodHops, MicSize, NodeHint, OptionNumber,
    PacketHeader, PacketType, ParsedOptions, PublicKey, RouterHint, Scf, SecInfo, SourceAddr,
    SourceAddrRef, UnsealedPacket, UMSH_VERSION,
};

#[cfg(test)]
mod tests {
    use crate::{
        feed_aad,
        options::{OptionDecoder, OptionEncoder},
        Fcf, MicSize, NodeHint, OptionNumber, PacketBuilder, PacketHeader, PacketType, PublicKey, Scf, SecInfo,
        SourceAddrRef,
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
        let len = sec.encode(&mut buf);
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
        assert_eq!(header.source, SourceAddrRef::FullKeyAt { offset: header.body_range.start - 32 });
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
            .region_code([0x78, 0x53])
            .trace_route()
            .payload(b"hey")
            .build()
            .unwrap();

        assert_eq!(&packet.as_bytes()[1..6], &[0x12, 0x78, 0x53, 0x10, 0xFF]);
    }

    #[test]
    fn aad_excludes_dynamic_options() {
        let mut bytes = [0u8; 64];
        bytes[0] = Fcf::new(PacketType::Unicast, false, true, false).0;
        bytes[1] = 0x12;
        bytes[2] = 0x78;
        bytes[3] = 0x53;
        bytes[4] = 0x10;
        bytes[5] = 0xFF;
        bytes[6..9].copy_from_slice(&[0xC3, 0xD4, 0x25]);
        bytes[9..12].copy_from_slice(&[0xA1, 0xB2, 0x03]);
        bytes[12] = Scf::new(true, MicSize::Mic8, false).0;
        bytes[13..17].copy_from_slice(&42u32.to_be_bytes());
        bytes[17..20].copy_from_slice(b"hey");
        bytes[20..28].fill(0x11);
        let header = PacketHeader::parse(&bytes[..28]).unwrap();
        let mut aad = [0u8; 18];
        let mut aad_len = 0usize;
        feed_aad(&header, &bytes[..28], |chunk| {
            let next_len = aad_len + chunk.len();
            aad[aad_len..next_len].copy_from_slice(chunk);
            aad_len = next_len;
        });
        assert_eq!(
            &aad[..aad_len],
            &[
                bytes[0],
                0,
                1,
                0,
                2,
                0x78,
                0x53,
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

        feed_aad(&header, &bytes, |chunk| {
            let next_len = aad_len + chunk.len();
            aad[aad_len..next_len].copy_from_slice(chunk);
            aad_len = next_len;
        });

        assert_eq!(&aad[1..6], &[0x01, 0x2C, 0x00, 0x01, 0xAA]);
    }

    #[test]
    fn parse_blind_unicast_tracks_secinfo_range() {
        let bytes = [
            0xF0, 0x7E, 0x5F, 0x80, 0x00, 0x00, 0x00, 0x05, 0xC3, 0xD4, 0x25, 0xA1, 0xB2, 0x03,
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x11, 0x22, 0x33, 0x44,
        ];
        let header = PacketHeader::parse(&bytes).unwrap();
        assert_eq!(header.sec_info.unwrap().wire_len(), 5);
    }
}
