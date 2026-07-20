//! Canonical byte vectors for the text-message codec and semantic
//! validation, shared with the protocol specification.

#![cfg(feature = "std")]

use umsh_core::{ChannelId, NodeHint, PublicKey};
use umsh_text::codec::{encode, parse, parse_with_info};
use umsh_text::model::option;
use umsh_text::validate::{
    DeliveryPath, DirectChannelProfile, Envelope, ValidateError, Validated, validate,
};
use umsh_text::{
    ConversationKey, Fragment, MessageSequence, MessageType, ParseError, Regarding, SenderScope,
    TextMessage,
};

fn round_trip(bytes: &[u8]) -> Vec<u8> {
    let message = parse(bytes).expect("canonical vector must parse");
    let mut buffer = [0u8; 512];
    let len = encode(&message, &mut buffer).expect("canonical vector must re-encode");
    buffer[..len].to_vec()
}

#[track_caller]
fn assert_canonical(bytes: &[u8]) {
    assert_eq!(
        round_trip(bytes),
        bytes,
        "vector must round-trip byte-exact"
    );
}

// ---------------------------------------------------------------------
// Canonical vectors: one per message type and option form
// ---------------------------------------------------------------------

#[test]
fn vector_basic_text() {
    let bytes = b"\xFFhello";
    let message = parse(bytes).unwrap();
    assert_eq!(message.message_type, MessageType::Basic);
    assert_eq!(message.body, b"hello");
    assert_canonical(bytes);
}

#[test]
fn vector_empty_body_has_no_end_marker() {
    // Message type Status with an empty body: options only, no 0xFF marker.
    let bytes = [0x01, 0x01];
    let message = parse(&bytes).unwrap();
    assert_eq!(message.message_type, MessageType::Status);
    assert_eq!(message.body, b"");
    assert_canonical(&bytes);
}

#[test]
fn vector_status_with_handle_sequence_and_colors() {
    let bytes = [
        0x01, 0x01, // Message Type = 1 (status)
        0x12, b'a', b'l', // Sender Handle "al"
        0x11, 0x2A, // Message Sequence, 1-byte form, ID 42
        0x10, // Sequence Reset flag
        0x21, 0x07, // Editing = 7 (delta 2 from option 3)
        0x13, 0x10, 0x20, 0x30, // Background Color
        0x13, 0x40, 0x50, 0x60, // Text Color
        0xFF, b'h', b'i',
    ];
    let (message, info) = parse_with_info(&bytes).unwrap();
    assert_eq!(message.message_type, MessageType::Status);
    assert_eq!(message.sender_handle, Some("al"));
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(42)));
    assert!(message.sequence_reset);
    assert_eq!(message.editing, Some(7));
    assert_eq!(message.bg_color, Some([0x10, 0x20, 0x30]));
    assert_eq!(message.text_color, Some([0x40, 0x50, 0x60]));
    assert_eq!(message.body, b"hi");
    assert_eq!(info.repeated_presentation_mask, 0);
    assert_canonical(&bytes);
}

#[test]
fn vector_fragment_sequence() {
    let bytes = [0x23, 0x05, 0x01, 0x03, 0xFF, 0x80, 0x81];
    let message = parse(&bytes).unwrap();
    assert_eq!(
        message.sequence,
        Some(MessageSequence {
            message_id: 5,
            fragment: Some(Fragment { index: 1, count: 3 }),
        })
    );
    // Fragment bodies are raw bytes and need not be valid UTF-8.
    assert_eq!(message.body, &[0x80, 0x81]);
    assert!(message.body_str().is_err());
    assert_canonical(&bytes);
}

#[test]
fn vector_regarding_unicast_and_multicast() {
    let unicast = [0x41, 0x09, 0xFF, b'r'];
    let message = parse(&unicast).unwrap();
    assert_eq!(
        message.regarding,
        Some(Regarding::Unicast { message_id: 9 })
    );
    assert_canonical(&unicast);

    let multicast = [0x44, 0x09, 0xAA, 0xBB, 0xCC, 0xFF, b'r'];
    let message = parse(&multicast).unwrap();
    assert_eq!(
        message.regarding,
        Some(Regarding::Multicast {
            message_id: 9,
            source_prefix: NodeHint([0xAA, 0xBB, 0xCC]),
        })
    );
    assert_canonical(&multicast);
}

#[test]
fn vector_resend_request_with_channel_group_flag() {
    // Type 2, sequence ID 17, Channel Group Resend flag, empty body.
    let bytes = [0x01, 0x02, 0x21, 0x11, 0x60];
    let message = parse(&bytes).unwrap();
    assert_eq!(message.message_type, MessageType::ResendRequest);
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(17)));
    assert!(message.channel_group_resend);
    assert!(message.body.is_empty());
    assert_canonical(&bytes);
}

#[test]
fn vector_message_unavailable_fragment_form() {
    let bytes = [0x01, 0x03, 0x23, 0x11, 0x02, 0x04];
    let message = parse(&bytes).unwrap();
    assert_eq!(message.message_type, MessageType::MessageUnavailable);
    assert_eq!(
        message.sequence,
        Some(MessageSequence {
            message_id: 0x11,
            fragment: Some(Fragment { index: 2, count: 4 }),
        })
    );
    assert_canonical(&bytes);
}

#[test]
fn vector_extension_options_are_retained() {
    // Room-style extensions: option 12 (Timestamp Received, 4 bytes) and
    // option 13 (Sender Sequence, 1 byte) after base option 2.
    let bytes = [
        0x21, 0x2A, // Message Sequence ID 42
        0xA4, 0x01, 0x02, 0x03, 0x04, // option 12 (delta 10), 4 bytes
        0x11, 0x2A, // option 13 (delta 1), 1 byte
        0xFF, b'x',
    ];
    let message = parse(&bytes).unwrap();
    let extensions: Vec<(u16, Vec<u8>)> = message
        .extensions
        .iter()
        .map(|item| {
            let (number, value) = item.unwrap();
            (number, value.to_vec())
        })
        .collect();
    assert_eq!(extensions, vec![(12, vec![1, 2, 3, 4]), (13, vec![0x2A])],);
    assert_canonical(&bytes);
}

#[test]
fn vector_unknown_extension_message_type_is_preserved() {
    let bytes = [0x01, 0x20, 0xFF, b'j', b'o', b'i', b'n'];
    let message = parse(&bytes).unwrap();
    assert_eq!(message.message_type, MessageType::Extension(32));
    assert_canonical(&bytes);
}

// ---------------------------------------------------------------------
// Invalid combinations
// ---------------------------------------------------------------------

#[test]
fn invalid_duplicate_identity_options_are_fatal() {
    // Two Message Type options (identical values still fatal).
    let bytes = [0x01, 0x01, 0x01, 0x01];
    assert_eq!(parse(&bytes), Err(ParseError::DuplicateOption(0)));

    // Two Message Sequence options.
    let bytes = [0x21, 0x05, 0x01, 0x06];
    assert_eq!(parse(&bytes), Err(ParseError::DuplicateOption(2)));

    // Two Regarding options.
    let bytes = [0x41, 0x05, 0x01, 0x06];
    assert_eq!(parse(&bytes), Err(ParseError::DuplicateOption(4)));

    // Two Editing options.
    let bytes = [0x51, 0x05, 0x01, 0x06];
    assert_eq!(parse(&bytes), Err(ParseError::DuplicateOption(5)));
}

#[test]
fn repeated_presentation_options_keep_first_and_note() {
    // Sender Handle twice: "aa" then "bb".
    let bytes = [0x12, b'a', b'a', 0x02, b'b', b'b', 0xFF, b'x'];
    let (message, info) = parse_with_info(&bytes).unwrap();
    assert_eq!(message.sender_handle, Some("aa"));
    assert_eq!(info.repeated_presentation_mask, 1 << option::SENDER_HANDLE);
}

#[test]
fn repeated_flags_are_idempotent() {
    // Sequence Reset twice (delta 3, then delta 0), zero-length both times.
    let bytes = [0x30, 0x00];
    let message = parse(&bytes).unwrap();
    assert!(message.sequence_reset);
}

#[test]
fn invalid_option_widths() {
    // Message Type longer than 1 byte.
    assert_eq!(
        parse(&[0x02, 0x00, 0x01]),
        Err(ParseError::InvalidOptionValue)
    );
    // Sequence of 2 bytes.
    assert_eq!(
        parse(&[0x22, 0x05, 0x01]),
        Err(ParseError::InvalidOptionValue)
    );
    // Fragment count below 2.
    assert_eq!(
        parse(&[0x23, 0x05, 0x00, 0x01]),
        Err(ParseError::InvalidOptionValue)
    );
    // Fragment index not below count.
    assert_eq!(
        parse(&[0x23, 0x05, 0x03, 0x03]),
        Err(ParseError::InvalidOptionValue)
    );
    // Regarding of 2 bytes.
    assert_eq!(
        parse(&[0x42, 0x05, 0x06]),
        Err(ParseError::InvalidOptionValue)
    );
    // Editing of 2 bytes.
    assert_eq!(
        parse(&[0x52, 0x05, 0x06]),
        Err(ParseError::InvalidOptionValue)
    );
    // Color of 2 bytes.
    assert_eq!(
        parse(&[0x62, 0x05, 0x06]),
        Err(ParseError::InvalidOptionValue)
    );
    // Channel Group Resend with a non-zero length.
    assert_eq!(parse(&[0x81, 0x00]), Err(ParseError::InvalidOptionValue));
    // Sequence Reset with a non-zero length.
    assert_eq!(parse(&[0x31, 0x00]), Err(ParseError::InvalidOptionValue));
    // Non-UTF-8 sender handle.
    assert_eq!(parse(&[0x11, 0x80]), Err(ParseError::InvalidUtf8));
}

#[test]
fn parser_never_panics_on_arbitrary_bytes() {
    // Cheap deterministic fuzz: structured splatter over 2-byte seeds.
    let mut buffer = [0u8; 24];
    for seed in 0u32..40_000 {
        let mut state = seed.wrapping_mul(0x9E37_79B9).wrapping_add(1);
        let len = (state % 24) as usize;
        for byte in buffer.iter_mut().take(len) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let _ = parse_with_info(&buffer[..len]);
    }
}

// ---------------------------------------------------------------------
// Semantic validation
// ---------------------------------------------------------------------

fn peer() -> PublicKey {
    PublicKey([0x11; 32])
}

fn direct_envelope() -> Envelope {
    Envelope {
        path: DeliveryPath::Unicast,
        conversation: ConversationKey::Direct { peer: peer() },
        sender: SenderScope::Peer(peer()),
    }
}

fn group_envelope() -> Envelope {
    Envelope {
        path: DeliveryPath::Multicast,
        conversation: ConversationKey::ChannelGroup {
            channel: ChannelId([1, 2]),
        },
        sender: SenderScope::ClaimedMember(NodeHint([0xAA, 0xBB, 0xCC])),
    }
}

fn validate_bytes(envelope: &Envelope, bytes: &[u8]) -> Result<Validated<'static>, ValidateError> {
    let leaked: &'static [u8] = Box::leak(bytes.to_vec().into_boxed_slice());
    let (message, info) = parse_with_info(leaked).map_err(ValidateError::Parse)?;
    validate(&DirectChannelProfile, envelope, &message, &info).map(|(validated, _)| validated)
}

#[test]
fn resend_request_dropped_on_multicast() {
    let bytes = [0x01, 0x02, 0x21, 0x11];
    assert_eq!(
        validate_bytes(&group_envelope(), &bytes),
        Err(ValidateError::ResendRequestPath)
    );
    assert!(matches!(
        validate_bytes(&direct_envelope(), &bytes),
        Ok(Validated::ResendRequest {
            channel_group: false,
            ..
        })
    ));
}

#[test]
fn channel_group_flag_requires_blind_unicast() {
    let bytes = [0x01, 0x02, 0x21, 0x11, 0x60];
    assert_eq!(
        validate_bytes(&direct_envelope(), &bytes),
        Err(ValidateError::ChannelGroupResendPath)
    );
    let blind = Envelope {
        path: DeliveryPath::BlindUnicast,
        conversation: ConversationKey::ChannelDirect {
            channel: ChannelId([1, 2]),
            peer: peer(),
        },
        sender: SenderScope::Peer(peer()),
    };
    assert!(matches!(
        validate_bytes(&blind, &bytes),
        Ok(Validated::ResendRequest {
            channel_group: true,
            ..
        })
    ));
}

#[test]
fn resend_request_ignores_extras_but_requires_sequence() {
    // Extra Sender Handle and a body: ignored after validation.
    let bytes = [
        0x01, 0x02, 0x12, b'h', b'i', 0x11, 0x2A, 0xFF, b'j', b'u', b'n', b'k',
    ];
    assert!(matches!(
        validate_bytes(&direct_envelope(), &bytes),
        Ok(Validated::ResendRequest { sequence, .. })
            if sequence == MessageSequence::unfragmented(42)
    ));
    // Missing Message Sequence: invalid.
    let bytes = [0x01, 0x02];
    assert_eq!(
        validate_bytes(&direct_envelope(), &bytes),
        Err(ValidateError::ResendRequestMissingSequence)
    );
}

#[test]
fn regarding_width_must_match_conversation() {
    // 4-byte form in a direct conversation: invalid.
    let bytes = [0x44, 0x09, 0xAA, 0xBB, 0xCC, 0xFF, b'r'];
    assert_eq!(
        validate_bytes(&direct_envelope(), &bytes),
        Err(ValidateError::RegardingWidth)
    );
    // 1-byte form in a channel-group conversation: invalid.
    let bytes = [0x41, 0x09, 0xFF, b'r'];
    assert_eq!(
        validate_bytes(&group_envelope(), &bytes),
        Err(ValidateError::RegardingWidth)
    );
}

#[test]
fn unrecognized_message_type_rejected_by_base_profile() {
    let bytes = [0x01, 0x20, 0xFF, b'x'];
    assert_eq!(
        validate_bytes(&direct_envelope(), &bytes),
        Err(ValidateError::UnrecognizedMessageType(32))
    );
}

#[test]
fn continuation_fragment_metadata_is_stripped() {
    // Fragment index 1 carrying a handle and colors.
    let bytes = [
        0x12, b'h', b'i', // Sender Handle
        0x13, 0x07, 0x01, 0x03, // sequence: id 7, index 1 of 3
        0xFF, b'x',
    ];
    let leaked: &'static [u8] = Box::leak(bytes.to_vec().into_boxed_slice());
    let (message, info) = parse_with_info(leaked).unwrap();
    let (validated, notes) =
        validate(&DirectChannelProfile, &direct_envelope(), &message, &info).unwrap();
    let Validated::Content(content) = validated else {
        panic!("expected content");
    };
    assert_eq!(content.sender_handle, None);
    assert!(notes.ignored_continuation_metadata);
}

#[test]
fn unfragmented_body_must_be_utf8() {
    let bytes = [0xFF, 0x80, 0x81];
    assert_eq!(
        validate_bytes(&direct_envelope(), &bytes),
        Err(ValidateError::Parse(ParseError::InvalidUtf8))
    );
}

#[test]
fn owned_round_trip_preserves_extensions() {
    let bytes = [
        0x21, 0x2A, 0xA4, 0x01, 0x02, 0x03, 0x04, 0x11, 0x2A, 0xFF, b'x',
    ];
    let message = parse(&bytes).unwrap();
    let owned = umsh_text::OwnedTextMessage::from(message);
    let mut buffer = [0u8; 64];
    let len = encode(&owned.as_borrowed(), &mut buffer).unwrap();
    assert_eq!(&buffer[..len], &bytes[..]);
}
