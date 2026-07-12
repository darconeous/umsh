//! End-to-end wire round-trips: companion frame inside HDLC-Lite.

use umsh_companion::frame::{self, Cmd, Frame, PropPayload, StreamPayload};
use umsh_companion::hdlc;
use umsh_companion::ids::{prop, stream};
use umsh_companion::meta::RxMeta;
use umsh_companion::{Status, TxMeta};

/// Push `wire` through a fresh decoder and return the single frame.
fn decode_one(wire: &[u8]) -> Vec<u8> {
    let mut decoder = hdlc::Decoder::<512>::new();
    let mut frames = Vec::new();
    for &byte in wire {
        if let Some(outcome) = decoder.push(byte) {
            frames.push(outcome.expect("valid frame").to_vec());
        }
    }
    assert_eq!(frames.len(), 1, "expected exactly one frame");
    frames.pop().unwrap()
}

#[test]
fn prop_get_over_hdlc() {
    let mut frame_buf = [0u8; 8];
    let frame_len = frame::prop_get(&mut frame_buf, 1, prop::PROTOCOL_VERSION).unwrap();

    let mut wire = [0u8; hdlc::max_encoded_len(8)];
    let wire_len = hdlc::encode_frame(&frame_buf[..frame_len], &mut wire).unwrap();

    let decoded = decode_one(&wire[..wire_len]);
    let parsed = Frame::parse(&decoded).unwrap();
    assert_eq!(parsed.header.tid(), 1);
    assert_eq!(parsed.command(), Some(Cmd::PropGet));
    let payload = PropPayload::parse(parsed.payload).unwrap();
    assert_eq!(payload.key, prop::PROTOCOL_VERSION);
}

#[test]
fn raw_frame_tx_and_rx_over_hdlc() {
    // Host -> NCP: transmit request with TX metadata.
    let packet: Vec<u8> = (0u8..64).collect();
    let mut meta_buf = [0u8; TxMeta::WIRE_LEN];
    let tx_meta = TxMeta {
        power: 22,
        flags: 0,
    };
    tx_meta.encode(&mut meta_buf).unwrap();

    let mut frame_buf = [0u8; 128];
    let frame_len =
        frame::str_send(&mut frame_buf, 2, stream::PHY_RAW, &packet, &meta_buf).unwrap();
    let mut wire = [0u8; hdlc::max_encoded_len(128)];
    let wire_len = hdlc::encode_frame(&frame_buf[..frame_len], &mut wire).unwrap();

    let decoded = decode_one(&wire[..wire_len]);
    let parsed = Frame::parse(&decoded).unwrap();
    assert_eq!(parsed.command(), Some(Cmd::StrSend));
    let payload = StreamPayload::parse(parsed.payload).unwrap();
    assert_eq!(payload.stream, stream::PHY_RAW);
    assert_eq!(payload.data, packet.as_slice());
    assert_eq!(TxMeta::decode(payload.metadata).unwrap(), tx_meta);

    // NCP -> Host: completion notification.
    let mut status_buf = [0u8; 8];
    let status_len = frame::last_status(&mut status_buf, 2, Status::OK).unwrap();
    let status_wire_len = hdlc::encode_frame(&status_buf[..status_len], &mut wire).unwrap();
    let decoded = decode_one(&wire[..status_wire_len]);
    let parsed = Frame::parse(&decoded).unwrap();
    assert_eq!(parsed.header.tid(), 2);
    assert_eq!(parsed.command(), Some(Cmd::PropIs));

    // NCP -> Host: received packet with RX metadata.
    let rx_meta = RxMeta {
        rssi_dbm: Some(-103),
        lqi: None,
        snr_cb: Some(-78),
    };
    let mut rx_meta_buf = [0u8; RxMeta::WIRE_LEN];
    rx_meta.encode(&mut rx_meta_buf).unwrap();
    let frame_len =
        frame::str_recv(&mut frame_buf, stream::PHY_RAW, &packet, &rx_meta_buf).unwrap();
    let wire_len = hdlc::encode_frame(&frame_buf[..frame_len], &mut wire).unwrap();

    let decoded = decode_one(&wire[..wire_len]);
    let parsed = Frame::parse(&decoded).unwrap();
    assert_eq!(parsed.header.tid(), frame::TID_UNSOLICITED);
    assert_eq!(parsed.command(), Some(Cmd::StrRecv));
    let payload = StreamPayload::parse(parsed.payload).unwrap();
    assert_eq!(payload.data, packet.as_slice());
    assert_eq!(RxMeta::decode(payload.metadata).unwrap(), rx_meta);
}
