use alloc::string::String;

use umsh_core::{NodeHint, options::OptionDecoder, options::OptionEncoder};

use crate::{EncodeError, ParseError};

fn parse_utf8(input: &[u8]) -> Result<&str, ParseError> {
    core::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)
}

/// Text-message rendering type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Basic = 0,
    Status = 1,
    ResendRequest = 2,
}

impl MessageType {
    fn from_byte(value: u8) -> Result<Self, ParseError> {
        match value {
            0 => Ok(Self::Basic),
            1 => Ok(Self::Status),
            2 => Ok(Self::ResendRequest),
            _ => Err(ParseError::InvalidMessageType(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub index: u8,
    pub count: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageSequence {
    pub message_id: u8,
    pub fragment: Option<Fragment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regarding {
    Unicast {
        message_id: u8,
    },
    Multicast {
        message_id: u8,
        source_prefix: NodeHint,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextMessage<'a> {
    pub message_type: MessageType,
    pub sender_handle: Option<&'a str>,
    pub sequence: Option<MessageSequence>,
    pub sequence_reset: bool,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub body: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedTextMessage {
    pub message_type: MessageType,
    pub sender_handle: Option<String>,
    pub sequence: Option<MessageSequence>,
    pub sequence_reset: bool,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub body: String,
}

impl OwnedTextMessage {
    pub fn as_borrowed(&self) -> TextMessage<'_> {
        TextMessage {
            message_type: self.message_type,
            sender_handle: self.sender_handle.as_deref(),
            sequence: self.sequence,
            sequence_reset: self.sequence_reset,
            regarding: self.regarding,
            editing: self.editing,
            bg_color: self.bg_color,
            text_color: self.text_color,
            body: &self.body,
        }
    }
}

impl From<TextMessage<'_>> for OwnedTextMessage {
    fn from(value: TextMessage<'_>) -> Self {
        Self {
            message_type: value.message_type,
            sender_handle: value.sender_handle.map(String::from),
            sequence: value.sequence,
            sequence_reset: value.sequence_reset,
            regarding: value.regarding,
            editing: value.editing,
            bg_color: value.bg_color,
            text_color: value.text_color,
            body: String::from(value.body),
        }
    }
}

pub fn parse(payload: &[u8]) -> Result<TextMessage<'_>, ParseError> {
    let mut decoder = OptionDecoder::new(payload);
    let mut message_type = MessageType::Basic;
    let mut sender_handle = None;
    let mut sequence = None;
    let mut sequence_reset = false;
    let mut regarding = None;
    let mut editing = None;
    let mut bg_color = None;
    let mut text_color = None;

    while let Some(item) = decoder.next() {
        let (number, value) = item?;
        match number {
            0 => {
                message_type = if value.is_empty() {
                    MessageType::Basic
                } else if value.len() == 1 {
                    MessageType::from_byte(value[0])?
                } else {
                    return Err(ParseError::InvalidOptionValue);
                };
            }
            1 => sender_handle = Some(parse_utf8(value)?),
            2 => {
                sequence = Some(match value {
                    [message_id] => MessageSequence {
                        message_id: *message_id,
                        fragment: None,
                    },
                    [message_id, index, count] if *count >= 2 => MessageSequence {
                        message_id: *message_id,
                        fragment: Some(Fragment {
                            index: *index,
                            count: *count,
                        }),
                    },
                    _ => return Err(ParseError::InvalidOptionValue),
                });
            }
            3 => {
                if !value.is_empty() {
                    return Err(ParseError::InvalidOptionValue);
                }
                sequence_reset = true;
            }
            4 => {
                regarding = Some(match value {
                    [message_id] => Regarding::Unicast {
                        message_id: *message_id,
                    },
                    [message_id, a, b, c] => Regarding::Multicast {
                        message_id: *message_id,
                        source_prefix: NodeHint([*a, *b, *c]),
                    },
                    _ => return Err(ParseError::InvalidOptionValue),
                });
            }
            5 => {
                editing = match value {
                    [message_id] => Some(*message_id),
                    _ => return Err(ParseError::InvalidOptionValue),
                };
            }
            6 => {
                bg_color = match value {
                    [r, g, b] => Some([*r, *g, *b]),
                    _ => return Err(ParseError::InvalidOptionValue),
                };
            }
            7 => {
                text_color = match value {
                    [r, g, b] => Some([*r, *g, *b]),
                    _ => return Err(ParseError::InvalidOptionValue),
                };
            }
            _ => {}
        }
    }

    let body = parse_utf8(decoder.remainder())?;
    Ok(TextMessage {
        message_type,
        sender_handle,
        sequence,
        sequence_reset,
        regarding,
        editing,
        bg_color,
        text_color,
        body,
    })
}

pub fn encode(msg: &TextMessage<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut encoder = OptionEncoder::new(buf);

    if msg.message_type != MessageType::Basic {
        encoder.put(0, &[msg.message_type as u8])?;
    }
    if let Some(handle) = msg.sender_handle {
        encoder.put(1, handle.as_bytes())?;
    }
    if let Some(sequence) = msg.sequence {
        let mut seq_buf = [0u8; 3];
        let seq_len = if let Some(fragment) = sequence.fragment {
            if fragment.count < 2 {
                return Err(EncodeError::InvalidField);
            }
            seq_buf = [sequence.message_id, fragment.index, fragment.count];
            3
        } else {
            seq_buf[0] = sequence.message_id;
            1
        };
        encoder.put(2, &seq_buf[..seq_len])?;
    }
    if msg.sequence_reset {
        encoder.put(3, &[])?;
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
        encoder.put(4, &regarding_buf[..regarding_len])?;
    }
    if let Some(editing) = msg.editing {
        encoder.put(5, &[editing])?;
    }
    if let Some(color) = msg.bg_color {
        encoder.put(6, &color)?;
    }
    if let Some(color) = msg.text_color {
        encoder.put(7, &color)?;
    }

    encoder.end_marker()?;
    let prefix_len = encoder.finish();
    if buf.len().saturating_sub(prefix_len) < msg.body.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[prefix_len..prefix_len + msg.body.len()].copy_from_slice(msg.body.as_bytes());
    Ok(prefix_len + msg.body.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_text_message_round_trips() {
        let message = TextMessage {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body: "hello",
        };

        let mut buf = [0u8; 64];
        let len = encode(&message, &mut buf).expect("encode should succeed");
        let parsed = parse(&buf[..len]).expect("parse should succeed");

        assert_eq!(parsed, message);
    }
}
