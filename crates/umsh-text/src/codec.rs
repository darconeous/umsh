//! Wire codec for text messages: exact bytes only.
//!
//! The codec decodes base options into typed fields, retains extension
//! options verbatim, and records the occurrence information that semantic
//! validation needs. It performs no conversation-context checks.

use umsh_core::options::{OptionDecoder, OptionEncoder};

use crate::model::{
    ExtensionOptions, FRAGMENT_COUNT_MAX, Fragment, MessageSequence, MessageType, Regarding,
    TextMessage, option,
};
use crate::{EncodeError, ParseError};

/// Occurrence information recorded while decoding, for semantic validation
/// and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParseInfo {
    /// Bitmask of base option numbers (0–8) present at least once.
    pub seen_mask: u16,
    /// Bitmask of presentation options (Sender Handle, colors) that appeared
    /// more than once; the first occurrence was kept.
    pub repeated_presentation_mask: u16,
    /// Bitmask of base options whose value could not be decoded. Each was
    /// dropped; validation decides what its absence means for the message.
    pub undecodable_mask: u16,
}

impl ParseInfo {
    pub fn saw(&self, number: u16) -> bool {
        number < 16 && self.seen_mask & (1 << number) != 0
    }

    pub fn undecodable(&self, number: u16) -> bool {
        number < 16 && self.undecodable_mask & (1 << number) != 0
    }
}

/// Decode a text-message payload (after the payload-type byte).
pub fn parse(payload: &[u8]) -> Result<TextMessage<'_>, ParseError> {
    parse_with_info(payload).map(|(message, _)| message)
}

/// Decode a text-message payload, also returning option occurrence
/// information for semantic validation.
pub fn parse_with_info(payload: &[u8]) -> Result<(TextMessage<'_>, ParseInfo), ParseError> {
    let mut decoder = OptionDecoder::new(payload);
    let mut message = TextMessage::basic("");
    let mut info = ParseInfo::default();
    let mut ext_range: Option<(usize, u16, usize)> = None; // start, base number, end

    loop {
        let snapshot_pos = decoder.position();
        let snapshot_number = decoder.last_number();
        let Some(item) = decoder.next() else {
            if let Some((_, _, end)) = ext_range.as_mut() {
                *end = snapshot_pos;
            }
            break;
        };
        let (number, value) = item?;

        if number >= option::EXTENSION_BASE {
            if ext_range.is_none() {
                ext_range = Some((snapshot_pos, snapshot_number, snapshot_pos));
            }
            continue;
        }

        let bit = 1u16 << number;
        if info.seen_mask & bit != 0 {
            match number {
                // Identity, sequencing, and reference options: duplication is
                // unresolvable ambiguity, even with identical values, so
                // none of the occurrences can be trusted. The message stays
                // readable without them, which validation sorts out.
                option::MESSAGE_TYPE => {
                    message.message_type = MessageType::Basic;
                    info.undecodable_mask |= bit;
                    continue;
                }
                option::MESSAGE_SEQUENCE => {
                    message.sequence = None;
                    info.undecodable_mask |= bit;
                    continue;
                }
                option::REGARDING => {
                    message.regarding = None;
                    info.undecodable_mask |= bit;
                    continue;
                }
                option::EDITING => {
                    message.editing = None;
                    info.undecodable_mask |= bit;
                    continue;
                }
                // Zero-length flags are idempotent, but a value on any
                // occurrence means this is not the flag we know.
                option::SEQUENCE_RESET => {
                    if !value.is_empty() {
                        message.sequence_reset = false;
                        info.undecodable_mask |= bit;
                    }
                    continue;
                }
                option::CHANNEL_GROUP_RESEND => {
                    if !value.is_empty() {
                        message.channel_group_resend = false;
                        info.undecodable_mask |= bit;
                    }
                    continue;
                }
                // Presentation options: first occurrence wins.
                _ => {
                    info.repeated_presentation_mask |= bit;
                    continue;
                }
            }
        }
        info.seen_mask |= bit;

        // Options are non-critical: a value this receiver cannot decode is
        // dropped and noted, never a reason to reject a message whose body
        // can still be read.
        match number {
            option::MESSAGE_TYPE => match value {
                [] => message.message_type = MessageType::Basic,
                [byte] => message.message_type = MessageType::from_byte(*byte),
                _ => info.undecodable_mask |= bit,
            },
            option::SENDER_HANDLE => match core::str::from_utf8(value) {
                Ok(handle) => message.sender_handle = Some(handle),
                Err(_) => info.undecodable_mask |= bit,
            },
            option::MESSAGE_SEQUENCE => match value {
                [message_id] => {
                    message.sequence = Some(MessageSequence {
                        message_id: *message_id,
                        fragment: None,
                    })
                }
                [message_id, index, count] if *count >= 2 && *index < *count => {
                    message.sequence = Some(MessageSequence {
                        message_id: *message_id,
                        fragment: Some(Fragment {
                            index: *index,
                            count: *count,
                        }),
                    })
                }
                _ => info.undecodable_mask |= bit,
            },
            option::SEQUENCE_RESET => {
                if value.is_empty() {
                    message.sequence_reset = true;
                } else {
                    info.undecodable_mask |= bit;
                }
            }
            option::REGARDING => match value {
                [message_id] => {
                    message.regarding = Some(Regarding::Unicast {
                        message_id: *message_id,
                    })
                }
                [message_id, 0x00] => {
                    message.regarding = Some(Regarding::Own {
                        message_id: *message_id,
                    })
                }
                [message_id, a, b, c] => {
                    message.regarding = Some(Regarding::Multicast {
                        message_id: *message_id,
                        source_prefix: umsh_core::NodeHint([*a, *b, *c]),
                    })
                }
                _ => info.undecodable_mask |= bit,
            },
            option::EDITING => match value {
                [message_id] => message.editing = Some(*message_id),
                _ => info.undecodable_mask |= bit,
            },
            option::BACKGROUND_COLOR => match value {
                [r, g, b] => message.bg_color = Some([*r, *g, *b]),
                _ => info.undecodable_mask |= bit,
            },
            option::TEXT_COLOR => match value {
                [r, g, b] => message.text_color = Some([*r, *g, *b]),
                _ => info.undecodable_mask |= bit,
            },
            option::CHANNEL_GROUP_RESEND => {
                if value.is_empty() {
                    message.channel_group_resend = true;
                } else {
                    info.undecodable_mask |= bit;
                }
            }
            _ => unreachable!(),
        }
    }

    if let Some((start, base_number, end)) = ext_range {
        message.extensions = ExtensionOptions {
            base_number,
            data: &payload[start..end],
        };
    }
    message.body = decoder.remainder();
    Ok((message, info))
}

/// Encode a text message into a caller-provided buffer, returning the number
/// of bytes written.
pub fn encode(msg: &TextMessage<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut encoder = OptionEncoder::new(buf);

    if msg.message_type != MessageType::Basic {
        encoder.put(option::MESSAGE_TYPE, &[msg.message_type.to_byte()])?;
    }
    if let Some(handle) = msg.sender_handle {
        encoder.put(option::SENDER_HANDLE, handle.as_bytes())?;
    }
    if let Some(sequence) = msg.sequence {
        let mut seq_buf = [0u8; 3];
        let seq_len = if let Some(fragment) = sequence.fragment {
            if fragment.count < 2
                || fragment.index >= fragment.count
                || fragment.count > FRAGMENT_COUNT_MAX
            {
                return Err(EncodeError::InvalidField);
            }
            seq_buf = [sequence.message_id, fragment.index, fragment.count];
            3
        } else {
            seq_buf[0] = sequence.message_id;
            1
        };
        encoder.put(option::MESSAGE_SEQUENCE, &seq_buf[..seq_len])?;
    }
    if msg.sequence_reset {
        encoder.put(option::SEQUENCE_RESET, &[])?;
    }
    if let Some(regarding) = msg.regarding {
        let mut regarding_buf = [0u8; 4];
        let regarding_len = match regarding {
            Regarding::Unicast { message_id } => {
                regarding_buf[0] = message_id;
                1
            }
            Regarding::Own { message_id } => {
                regarding_buf[0] = message_id;
                2
            }
            Regarding::Multicast {
                message_id,
                source_prefix,
            } => {
                regarding_buf = [
                    message_id,
                    source_prefix.0[0],
                    source_prefix.0[1],
                    source_prefix.0[2],
                ];
                4
            }
        };
        encoder.put(option::REGARDING, &regarding_buf[..regarding_len])?;
    }
    if let Some(editing) = msg.editing {
        encoder.put(option::EDITING, &[editing])?;
    }
    if let Some(color) = msg.bg_color {
        encoder.put(option::BACKGROUND_COLOR, &color)?;
    }
    if let Some(color) = msg.text_color {
        encoder.put(option::TEXT_COLOR, &color)?;
    }
    if msg.channel_group_resend {
        encoder.put(option::CHANNEL_GROUP_RESEND, &[])?;
    }
    let mut last_ext = option::CHANNEL_GROUP_RESEND;
    for item in msg.extensions.iter() {
        let (number, value) = item.map_err(|_| EncodeError::InvalidField)?;
        if number < option::EXTENSION_BASE || number < last_ext {
            return Err(EncodeError::InvalidField);
        }
        last_ext = number;
        encoder.put(number, value)?;
    }

    if !msg.body.is_empty() {
        encoder.end_marker()?;
    }
    let prefix_len = encoder.finish();
    if buf.len().saturating_sub(prefix_len) < msg.body.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[prefix_len..prefix_len + msg.body.len()].copy_from_slice(msg.body);
    Ok(prefix_len + msg.body.len())
}

/// The vectors of UEP-0020 Appendix A: each payload decodes to its message
/// and its message encodes to the same payload.
#[cfg(test)]
mod spec_vectors {
    use umsh_core::NodeHint;

    use super::{encode, parse};
    use crate::model::{Fragment, MessageSequence, MessageType, Regarding, TextMessage};

    fn check(payload: &[u8], message: TextMessage<'_>) {
        assert_eq!(parse(payload).unwrap(), message, "{payload:02X?}");
        let mut buf = [0u8; 64];
        let len = encode(&message, &mut buf).unwrap();
        assert_eq!(&buf[..len], payload);
    }

    fn sequence(id: u8) -> Option<MessageSequence> {
        Some(MessageSequence::unfragmented(id))
    }

    #[test]
    fn the_appendix_vectors_round_trip() {
        let hi = TextMessage {
            sender_handle: Some("Ann"),
            sequence: sequence(5),
            ..TextMessage::basic("hi")
        };
        check(&[0x13, 0x41, 0x6E, 0x6E, 0x11, 0x05, 0xFF, 0x68, 0x69], hi);

        let ok = TextMessage::basic("ok");
        check(
            &[0x21, 0x06, 0x21, 0x03, 0xFF, 0x6F, 0x6B],
            TextMessage {
                sequence: sequence(6),
                regarding: Some(Regarding::Unicast { message_id: 3 }),
                ..ok
            },
        );
        check(
            &[0x01, 0x01, 0x21, 0x07, 0x21, 0x03, 0xFF, 0x2B, 0x31],
            TextMessage {
                message_type: MessageType::Status,
                sequence: sequence(7),
                regarding: Some(Regarding::Unicast { message_id: 3 }),
                ..TextMessage::basic("+1")
            },
        );
        for (index, body, payload) in [
            (0, "ab", [0x23, 0x09, 0x00, 0x02, 0xFF, 0x61, 0x62]),
            (1, "cd", [0x23, 0x09, 0x01, 0x02, 0xFF, 0x63, 0x64]),
        ] {
            check(
                &payload,
                TextMessage {
                    sequence: Some(MessageSequence {
                        message_id: 9,
                        fragment: Some(Fragment { index, count: 2 }),
                    }),
                    ..TextMessage::basic(body)
                },
            );
        }
        check(
            &[0x44, 0x03, 0xED, 0x54, 0xA5, 0xFF, 0x6F, 0x6B],
            TextMessage {
                regarding: Some(Regarding::Multicast {
                    message_id: 3,
                    source_prefix: NodeHint([0xED, 0x54, 0xA5]),
                }),
                ..ok
            },
        );
        check(
            &[0x21, 0x08, 0x31, 0x03, 0xFF, 0x6F, 0x6B],
            TextMessage {
                sequence: sequence(8),
                editing: Some(3),
                ..ok
            },
        );
        check(
            &[0x21, 0x01, 0x10, 0xFF, 0x78],
            TextMessage {
                sequence: sequence(1),
                sequence_reset: true,
                ..TextMessage::basic("x")
            },
        );
        check(&[0xFF, 0x68, 0x69], TextMessage::basic("hi"));
        // The repair messages of the same appendix.
        let repair = |message_type, sequence, group| TextMessage {
            message_type,
            sequence: Some(sequence),
            channel_group_resend: group,
            ..TextMessage::basic("")
        };
        let five = MessageSequence::unfragmented(5);
        check(
            &[0x01, 0x02, 0x21, 0x05],
            repair(MessageType::ResendRequest, five, false),
        );
        check(
            &[0x01, 0x02, 0x21, 0x05, 0x60],
            repair(MessageType::ResendRequest, five, true),
        );
        check(
            &[0x01, 0x03, 0x21, 0x05],
            repair(MessageType::MessageUnavailable, five, false),
        );
        check(
            &[0x01, 0x02, 0x23, 0x05, 0x01, 0x03],
            repair(
                MessageType::ResendRequest,
                MessageSequence {
                    message_id: 5,
                    fragment: Some(Fragment { index: 1, count: 3 }),
                },
                false,
            ),
        );
        check(
            &[0x21, 0x09, 0x31, 0x03],
            TextMessage {
                sequence: sequence(9),
                editing: Some(3),
                ..TextMessage::basic("")
            },
        );
    }
}
