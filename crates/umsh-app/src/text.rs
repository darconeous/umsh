use umsh_core::{options::OptionDecoder, options::OptionEncoder};

use crate::util::{copy_into, parse_utf8};
use crate::{EncodeError, ParseError};

/// Text-message rendering type.
///
/// This controls how the message body should be interpreted by the receiver.
/// The wire encoding uses option number `0`, and an absent option defaults to
/// [`Basic`](Self::Basic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    /// Regular message text displayed as a normal chat bubble.
    Basic = 0,
    /// Status or `/me` style message displayed inline.
    Status = 1,
    /// Request to retransmit a previously missed message sequence.
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

/// Fragment metadata for a segmented text message.
///
/// Fragment numbering is zero-based. The protocol requires `count >= 2` for the
/// fragmented form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// Zero-based fragment index.
    pub index: u8,
    /// Total number of fragments in the message.
    pub count: u8,
}

/// Sender-local message sequence information.
///
/// This identifies a message for replies, edits, and retransmission requests.
/// Fragmented messages use the same `message_id` for every fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageSequence {
    /// Monotonically increasing per-sender message identifier.
    pub message_id: u8,
    /// Fragment metadata, if the message is split across multiple payloads.
    pub fragment: Option<Fragment>,
}

/// Reference to a previously sent message.
///
/// Unicast references carry only the message ID. Multicast references also need
/// a sender prefix to disambiguate overlapping sender-local message IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regarding {
    /// Reference to a previous unicast message.
    Unicast { message_id: u8 },
    /// Reference to a previous multicast message.
    Multicast { message_id: u8, source_prefix: umsh_core::NodeHint },
}

/// Parsed text-message payload.
///
/// This view borrows all variable-sized fields from the input buffer. It is
/// suitable for immediate UI handling or for conversion into an owned message in
/// a higher layer.
///
/// # Example
///
/// ```rust
/// use umsh_app::{parse_text_message, MessageType};
///
/// let payload = [0xFF, b'h', b'i'];
/// let msg = parse_text_message(&payload).unwrap();
/// assert_eq!(msg.message_type, MessageType::Basic);
/// assert_eq!(msg.body, "hi");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextMessage<'a> {
    /// Rendering type for the message.
    pub message_type: MessageType,
    /// Optional human-friendly sender handle.
    pub sender_handle: Option<&'a str>,
    /// Optional sender-local message sequence metadata.
    pub sequence: Option<MessageSequence>,
    /// Whether this message resets the sender's sequence state.
    pub sequence_reset: bool,
    /// Optional reference to an earlier message.
    pub regarding: Option<Regarding>,
    /// Optional message ID that this payload edits or deletes.
    pub editing: Option<u8>,
    /// Suggested background color for rendering.
    pub bg_color: Option<[u8; 3]>,
    /// Suggested text color for rendering.
    pub text_color: Option<[u8; 3]>,
    /// UTF-8 message body.
    pub body: &'a str,
}

/// Parse a text-message payload body.
///
/// `payload` must start at the text-message option block, not at the outer UMSH
/// payload-type byte. Unknown options are ignored, matching the protocol's
/// non-critical semantics.
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
                        source_prefix: umsh_core::NodeHint([*a, *b, *c]),
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

/// Encode a text-message payload body into `buf`.
///
/// The caller is responsible for prepending [`crate::PayloadType::TextMessage`]
/// if the result is going to be sent as a typed UMSH payload.
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
                regarding_buf[0] = message_id;
                regarding_buf[1..].copy_from_slice(&source_prefix.0);
                4
            }
        };
        encoder.put(4, &regarding_buf[..regarding_len])?;
    }
    if let Some(editing) = msg.editing {
        encoder.put(5, &[editing])?;
    }
    if let Some(bg_color) = msg.bg_color {
        encoder.put(6, &bg_color)?;
    }
    if let Some(text_color) = msg.text_color {
        encoder.put(7, &text_color)?;
    }
    encoder.end_marker()?;
    let mut len = encoder.finish();
    copy_into(buf, &mut len, msg.body.as_bytes())?;
    Ok(len)
}