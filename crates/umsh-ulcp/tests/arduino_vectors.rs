//! The ULCP cases of the Arduino library's vector file: what this crate
//! encodes and decodes must be what the vectors say, so that the library,
//! which is checked against the same file, agrees with the device.

use std::collections::HashMap;

use umsh_ulcp::frame::{Cmd, Frame, StreamPayload, TID_UNSOLICITED};
use umsh_ulcp::hdlc;
use umsh_ulcp::ids::stream;
use umsh_ulcp::node_msg::{self, Kind, RecvMeta, SendMeta, Source};
use umsh_ulcp::pui;

const VECTORS: &str = include_str!("../../../packages/umsh-arduino/test/vectors.txt");

/// Each case of `kind`: its fields by name, with `-` for absent.
fn cases(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    let found: Vec<_> = VECTORS
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(kind)).then(|| {
                words
                    .map(|word| word.split_once('=').expect("key=value"))
                    .collect()
            })
        })
        .collect();
    assert!(!found.is_empty(), "no {kind} cases");
    found
}

fn hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn optional<T: std::str::FromStr>(text: &str) -> Option<T>
where
    T::Err: std::fmt::Debug,
{
    (text != "-").then(|| text.parse().unwrap())
}

fn array<const N: usize>(text: &str) -> Option<[u8; N]> {
    (text != "-").then(|| hex(text).try_into().unwrap())
}

#[test]
fn packed_unsigned_integers() {
    for case in cases("pui") {
        let value: u32 = case["value"].parse().unwrap();
        let mut out = [0u8; 4];
        let len = pui::encode(value, &mut out).unwrap();
        assert_eq!(out[..len], hex(case["hex"]), "{value}");
        assert_eq!(pui::decode(&out[..len]), Ok((value, len)));
    }
}

#[test]
fn hdlc_frames() {
    for case in cases("hdlc") {
        let frame = hex(case["frame"]);
        let mut wire = [0u8; 64];
        let len = hdlc::encode_frame(&frame, &mut wire).unwrap();
        assert_eq!(wire[..len], hex(case["wire"]), "{}", case["frame"]);
        let mut decoder = hdlc::Decoder::<64>::new();
        let decoded: Vec<_> = wire[..len]
            .iter()
            .filter_map(|&octet| decoder.push(octet).map(|frame| frame.unwrap().to_vec()))
            .collect();
        assert_eq!(decoded, [frame]);
    }
}

#[test]
fn node_message_sends() {
    for case in cases("send") {
        let kind = Kind::from_code(case["kind"].parse().unwrap()).unwrap();
        let flags: u8 = case["flags"].parse().unwrap();
        let route = hex(case["route"]);
        let mut meta = SendMeta::new(kind);
        meta.ack = flags & 0x01 != 0;
        meta.full_source = flags & 0x02 != 0;
        meta.signed = flags & 0x04 != 0;
        meta.channel = array(case["channel"]);
        meta.peer = array(case["peer"]);
        meta.flood_hops = optional(case["hops"]);
        meta.source_route = (!route.is_empty()).then_some(route.as_slice());
        meta.tx_power = optional(case["power"]);
        let mut buf = [0u8; 300];
        let tid = case["tid"].parse().unwrap();
        let len = node_msg::send_frame(&mut buf, tid, &hex(case["data"]), &meta).unwrap();
        assert_eq!(buf[..len], hex(case["frame"]), "{}", case["frame"]);

        // And what the device makes of it.
        let frame = Frame::parse(&buf[..len]).unwrap();
        let payload = StreamPayload::parse(frame.payload).unwrap();
        assert_eq!(SendMeta::parse(payload.metadata), Ok(meta));
    }
}

#[test]
fn node_message_receives() {
    for case in cases("recv") {
        let bytes = hex(case["frame"]);
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!(
            (frame.command(), frame.header.tid()),
            (Some(Cmd::StrRecv), TID_UNSOLICITED)
        );
        let payload = StreamPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.stream, stream::NODE_MSG);
        assert_eq!(payload.data, hex(case["data"]));
        let meta = RecvMeta::parse(payload.metadata).unwrap();
        let flags: u8 = case["flags"].parse().unwrap();
        assert_eq!(meta.kind.code(), case["kind"].parse::<u8>().unwrap());
        assert_eq!(meta.flags(), flags, "{}", case["frame"]);
        assert_eq!(meta.channel, array(case["channel"]));
        let source = match meta.source {
            Source::Key(key) => key.to_vec(),
            Source::Hint(hint) => hint.to_vec(),
        };
        assert_eq!(source, hex(case["src"]));
        assert_eq!(meta.rssi_dbm, optional(case["rssi"]));
        assert_eq!(meta.snr_cb, optional(case["snr"]));
        assert_eq!(meta.trace.map(<[u8]>::to_vec), array_vec(case["trace"]));
    }
}

fn array_vec(text: &str) -> Option<Vec<u8>> {
    (text != "-").then(|| hex(text))
}
