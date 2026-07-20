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
}

impl ParseInfo {
    pub fn saw(&self, number: u16) -> bool {
        number < 16 && self.seen_mask & (1 << number) != 0
    }
}

fn parse_utf8(input: &[u8]) -> Result<&str, ParseError> {
    core::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)
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
                // unresolvable ambiguity, even with identical values.
                option::MESSAGE_TYPE
                | option::MESSAGE_SEQUENCE
                | option::REGARDING
                | option::EDITING => return Err(ParseError::DuplicateOption(number)),
                // Zero-length flags are idempotent, but each occurrence must
                // still be syntactically valid.
                option::SEQUENCE_RESET | option::CHANNEL_GROUP_RESEND => {
                    if !value.is_empty() {
                        return Err(ParseError::InvalidOptionValue);
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

        match number {
            option::MESSAGE_TYPE => {
                message.message_type = if value.is_empty() {
                    MessageType::Basic
                } else if value.len() == 1 {
                    MessageType::from_byte(value[0])
                } else {
                    return Err(ParseError::InvalidOptionValue);
                };
            }
            option::SENDER_HANDLE => message.sender_handle = Some(parse_utf8(value)?),
            option::MESSAGE_SEQUENCE => {
                message.sequence = Some(match value {
                    [message_id] => MessageSequence {
                        message_id: *message_id,
                        fragment: None,
                    },
                    [message_id, index, count] if *count >= 2 && *index < *count => {
                        MessageSequence {
                            message_id: *message_id,
                            fragment: Some(Fragment {
                                index: *index,
                                count: *count,
                            }),
                        }
                    }
                    _ => return Err(ParseError::InvalidOptionValue),
                });
            }
            option::SEQUENCE_RESET => {
                if !value.is_empty() {
                    return Err(ParseError::InvalidOptionValue);
                }
                message.sequence_reset = true;
            }
            option::REGARDING => {
                message.regarding = Some(match value {
                    [message_id] => Regarding::Unicast {
                        message_id: *message_id,
                    },
                    [message_id, a, b, c] => Regarding::Multicast {
                        message_id: *message_id,
                        source_prefix: umsh_core::NodeHint([*a, *b, *c]),
                    },
                    _ => return Err(ParseError::InvalidOptionValue),
                });
            }
            option::EDITING => {
                message.editing = match value {
                    [message_id] => Some(*message_id),
                    _ => return Err(ParseError::InvalidOptionValue),
                };
            }
            option::BACKGROUND_COLOR => {
                message.bg_color = match value {
                    [r, g, b] => Some([*r, *g, *b]),
                    _ => return Err(ParseError::InvalidOptionValue),
                };
            }
            option::TEXT_COLOR => {
                message.text_color = match value {
                    [r, g, b] => Some([*r, *g, *b]),
                    _ => return Err(ParseError::InvalidOptionValue),
                };
            }
            option::CHANNEL_GROUP_RESEND => {
                if !value.is_empty() {
                    return Err(ParseError::InvalidOptionValue);
                }
                message.channel_group_resend = true;
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
