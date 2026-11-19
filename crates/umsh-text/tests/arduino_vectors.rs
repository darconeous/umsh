//! The text cases of the Arduino library's vector file: what this codec
//! encodes and decodes must be what the vectors say, so that the library,
//! which is checked against the same file, agrees with every other client.

use std::collections::HashMap;

use umsh_core::NodeHint;
use umsh_text::codec::{encode, parse};
use umsh_text::{Fragment, model::ExtensionOptions};
use umsh_text::{MessageSequence, MessageType, Regarding, TextMessage};

const VECTORS: &str = include_str!("../../../packages/umsh-arduino/test/vectors.txt");

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

/// The fields a case names, as the codec's message.
fn expected<'a>(case: &HashMap<&str, &str>, handle: &'a [u8], body: &'a [u8]) -> TextMessage<'a> {
    let mut message = TextMessage::basic("");
    message.message_type = MessageType::from_byte(case["type"].parse().unwrap());
    message.sender_handle = (!handle.is_empty()).then(|| std::str::from_utf8(handle).unwrap());
    message.sequence = match hex(case["seq"]).as_slice() {
        [] => None,
        [id] => Some(MessageSequence::unfragmented(*id)),
        [id, index, count] => Some(MessageSequence {
            message_id: *id,
            fragment: Some(Fragment {
                index: *index,
                count: *count,
            }),
        }),
        other => panic!("sequence {other:?}"),
    };
    message.sequence_reset = case["reset"] == "1";
    message.regarding = match hex(case["regarding"]).as_slice() {
        [] => None,
        [id] => Some(Regarding::Unicast { message_id: *id }),
        [id, 0] => Some(Regarding::Own { message_id: *id }),
        [id, a, b, c] => Some(Regarding::Multicast {
            message_id: *id,
            source_prefix: NodeHint([*a, *b, *c]),
        }),
        other => panic!("regarding {other:?}"),
    };
    message.editing = (case["editing"] != "-").then(|| case["editing"].parse().unwrap());
    message.body = body;
    message
}

/// The fields the library offers; colors and extensions it does not.
fn offered(mut message: TextMessage<'_>) -> TextMessage<'_> {
    message.bg_color = None;
    message.text_color = None;
    message.channel_group_resend = false;
    message.extensions = ExtensionOptions::empty();
    message
}

#[test]
fn text_payloads_encode_and_decode() {
    for case in cases("text") {
        let data = hex(case["data"]);
        let handle = hex(case["handle"]);
        let body = hex(case["body"]);
        let message = expected(&case, &handle, &body);
        let mut buf = [0u8; 256];
        let len = encode(&message, &mut buf).unwrap();
        assert_eq!(buf[..len], data, "{}", case["data"]);
        assert_eq!(parse(&data).unwrap(), message, "{}", case["data"]);
    }
}

#[test]
fn text_payloads_decode_as_a_receiver_reads_them() {
    for case in cases("textin") {
        let data = hex(case["data"]);
        if case["ok"] == "0" {
            assert!(parse(&data).is_err(), "{}", case["data"]);
            continue;
        }
        let handle = hex(case["handle"]);
        let body = hex(case["body"]);
        let message = expected(&case, &handle, &body);
        assert_eq!(offered(parse(&data).unwrap()), message, "{}", case["data"]);
    }
}
