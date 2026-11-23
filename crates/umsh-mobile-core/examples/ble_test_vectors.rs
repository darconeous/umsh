//! Golden vectors for `tools/ble-test-peripheral`: what this crate's GATT
//! segmentation, GATT reassembly and HDLC-Lite codecs make of a fixed set of
//! inputs, and what the firmware advertises for a few names. The
//! peripheral's Python is tested against them.
//!
//! `make ble-test-vectors` writes them to
//! `tools/ble-test-peripheral/tests/vectors.json`; the test
//! `ble_test_vectors_match` fails when the committed file drifts from what
//! this prints.

use umsh_mobile_core::{
    MobileGattReassembler, MobileHdlcDecoder, ulcp_gatt_segments, ulcp_hdlc_encode,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn quoted(bytes: &[u8]) -> String {
    format!("\"{}\"", hex(bytes))
}

fn list(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(", "))
}

/// A frame of `len` octets counting up from `start`, wrapping.
fn counting(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

/// Every octet HDLC-Lite escapes, among plain ones.
fn escapes() -> Vec<u8> {
    vec![0x01, 0x7e, 0x02, 0x7d, 0x11, 0x13, 0x03, 0x23, 0xff, 0x20]
}

pub fn vectors_json() -> String {
    let mut out = String::from("{\n");

    // Segmentation: frame lengths around each boundary of two ATT sizes
    // (the 23-octet default, and the nRF radios' 255), plus the largest frame.
    let mut sar = Vec::new();
    for (max_value_length, lengths) in [
        (20u16, vec![0usize, 1, 18, 19, 20, 38, 39, 57]),
        (252, vec![1, 250, 251, 252, 502, 503, 512]),
    ] {
        for len in lengths {
            let frame = counting(len as u8, len);
            let values = ulcp_gatt_segments(frame.clone(), max_value_length)
                .expect("segmentable")
                .into_iter()
                .map(|segment| quoted(&segment.value));
            sar.push(format!(
                "    {{\"frame\": {}, \"max_value_length\": {max_value_length}, \"values\": {}}}",
                quoted(&frame),
                list(values)
            ));
        }
    }
    out += &format!("  \"sar\": [\n{}\n  ],\n", sar.join(",\n"));

    // Reassembly: sequences of ATT values and what each push returns.
    let sequences: Vec<Vec<Vec<u8>>> = vec![
        vec![vec![0x00, 1, 2, 3]],
        vec![vec![0x00]],
        vec![vec![0x40, 1], vec![0x80], vec![0xc0, 2]],
        vec![vec![0x40, 1], vec![0x40, 2], vec![0xc0, 3]],
        vec![vec![0x01, 2]],
        vec![vec![0x80, 2]],
        vec![vec![0xc0]],
        vec![vec![]],
        vec![vec![0x40, 1], vec![], vec![0xc0, 2]],
        {
            let mut values = vec![[vec![0x40], counting(0, 300)].concat()];
            values.push([vec![0x80], counting(44, 300)].concat());
            values.push(vec![0xc0, 9]);
            values.push(vec![0x00, 7]);
            values
        },
    ];
    let mut reassembly = Vec::new();
    for values in sequences {
        let reassembler = MobileGattReassembler::new();
        let results = values
            .iter()
            .map(|value| match reassembler.push(value.clone()) {
                Ok(Some(frame)) => quoted(&frame),
                Ok(None) => "null".to_owned(),
                Err(_) => "\"error\"".to_owned(),
            });
        let results = list(results);
        reassembly.push(format!(
            "    {{\"values\": {}, \"results\": {results}}}",
            list(values.iter().map(|value| quoted(value)))
        ));
    }
    out += &format!("  \"reassembly\": [\n{}\n  ],\n", reassembly.join(",\n"));

    // HDLC-Lite framing.
    let frames = vec![
        vec![],
        vec![0x80, 0x01],
        escapes(),
        counting(0, 64),
        counting(200, 512),
    ];
    let mut hdlc = Vec::new();
    for frame in &frames {
        let wire = ulcp_hdlc_encode(frame.clone()).expect("encodable");
        hdlc.push(format!(
            "    {{\"frame\": {}, \"wire\": {}}}",
            quoted(frame),
            quoted(&wire)
        ));
    }
    out += &format!("  \"hdlc_encode\": [\n{}\n  ],\n", hdlc.join(",\n"));

    // HDLC-Lite decoding of whole streams: frames, idle flags, marked text,
    // fill, flow control, a corrupt FCS, an aborted escape, and an
    // oversized frame, each followed by a good one.
    let good = ulcp_hdlc_encode(vec![0x80, 0x02, 0x7e]).unwrap();
    let other = ulcp_hdlc_encode(escapes()).unwrap();
    let mut corrupt = ulcp_hdlc_encode(vec![0x80, 0x03, 0x04]).unwrap();
    let at = corrupt.len() - 2;
    corrupt[at] ^= 0x01;
    let oversized = ulcp_hdlc_encode(counting(0, 512)).unwrap();
    let mut oversized = oversized[..oversized.len() - 1].to_vec();
    oversized.extend(counting(1, 8));
    oversized.push(0x7e);
    let streams: Vec<Vec<u8>> = vec![
        [good.clone(), other.clone()].concat(),
        [vec![0x7e, 0x7e], good.clone(), vec![0x7e]].concat(),
        [b"\x7e#text line \x7e".to_vec(), good.clone()].concat(),
        [vec![0x7e, 0xff, 0xff, 0xff, 0x7e], good.clone()].concat(),
        [
            vec![0x11],
            good[..3].to_vec(),
            vec![0x13],
            good[3..].to_vec(),
        ]
        .concat(),
        [corrupt, good.clone()].concat(),
        [vec![0x7e, 0x80, 0x7d, 0x7e], good.clone()].concat(),
        [vec![0x7e, 0x80, 0x7e], good.clone()].concat(),
        [oversized, good.clone()].concat(),
    ];
    let mut decode = Vec::new();
    for stream in streams {
        let decoder = MobileHdlcDecoder::new();
        let frames = decoder
            .push(stream.clone())
            .into_iter()
            .map(|frame| quoted(&frame));
        decode.push(format!(
            "    {{\"stream\": {}, \"frames\": {}}}",
            quoted(&stream),
            list(frames)
        ));
    }
    out += &format!("  \"hdlc_decode\": [\n{}\n  ],\n", decode.join(",\n"));

    // Advertising: the primary packet and scan response the firmware makes,
    // outside and inside its pairing window. The name is cut to fit between
    // grapheme clusters: a combining accent, a skin tone, a joined emoji
    // sequence and a flag each stay whole.
    let service = umsh_ulcp::gatt::SERVICE_UUID.to_le_bytes();
    let names = [
        "T1000-E 4F2A",
        "abcdefghijklmnopqrstuvwxyzABC",
        "abcdefghijklmnopqrstuvwxyzABCD",
        "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
        "abcdefghijklmnopqrstuvwxyz1e\u{301}",
        "Radio camp 12 \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",
        "xxxxxxxxxxxxxxxxxxxxxxx\u{1F44D}\u{1F3FD}",
        "yyyyyyyyyyyyyyyyyyyyyy\u{1F1EB}\u{1F1F7}",
    ];
    let mut advertising = Vec::new();
    for (index, name) in names.iter().enumerate() {
        for pairing in [false, true] {
            if !pairing && index > 0 {
                continue;
            }
            let data = umsh_ulcp_runtime::ble_privacy::advertisement(
                service,
                name.as_bytes(),
                2,
                pairing,
                60_000,
            );
            advertising.push(format!(
                "    {{\"name\": {}, \"pairing\": {pairing}, \"model_id\": 2, \"advertising\": {}, \"scan_response\": {}}}",
                quoted(name.as_bytes()),
                quoted(&data.advertising[..data.advertising_len]),
                quoted(&data.scan_response[..data.scan_response_len])
            ));
        }
    }
    out += &format!("  \"advertising\": [\n{}\n  ]\n", advertising.join(",\n"));

    out += "}\n";
    out
}

#[allow(dead_code)]
fn main() {
    print!("{}", vectors_json());
}
