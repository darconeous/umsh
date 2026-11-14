#![cfg_attr(not(feature = "std"), no_std)]

//! Chat-room management payload codecs for UMSH.

extern crate alloc;

use core::fmt;

use umsh_core::options::{OptionDecoder, OptionEncoder};

/// Error returned when parsing or encoding chat-room management payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Core(umsh_core::ParseError),
    InvalidUtf8,
    InvalidChatAction(u8),
    InvalidOptionValue,
    InvalidLength { expected: usize, actual: usize },
    BufferTooSmall,
    InvalidField,
}

impl From<umsh_core::EncodeError> for Error {
    fn from(_: umsh_core::EncodeError) -> Self {
        Self::BufferTooSmall
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Parsed chat-room management action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatAction<'a> {
    GetRoomInfo,
    RoomInfo(RoomInfo<'a>),
    Login(LoginParams<'a>),
    Logout,
    FetchMessages { timestamp: u32, max_count: u8 },
    FetchUsers,
    AdminCommand(&'a [u8]),
    RoomUpdate(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomInfo<'a> {
    /// The encoded option block, without the end marker.
    pub options: &'a [u8],
    /// The description that follows the end marker. An empty description is
    /// sent as none.
    pub description: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginParams<'a> {
    pub handle: Option<&'a str>,
    pub last_message_timestamp: Option<u32>,
    pub session_timeout_minutes: Option<u8>,
    pub password: Option<&'a [u8]>,
}

pub fn parse(payload: &[u8]) -> Result<ChatAction<'_>, Error> {
    let (&action, body) = payload
        .split_first()
        .ok_or(Error::Core(umsh_core::ParseError::Truncated))?;

    match action {
        0 => {
            if body.is_empty() {
                Ok(ChatAction::GetRoomInfo)
            } else {
                Err(Error::InvalidOptionValue)
            }
        }
        1 => {
            let (options, description) = split_options(body)?;
            let description = match description {
                Some(bytes) if !bytes.is_empty() => Some(parse_utf8(bytes)?),
                _ => None,
            };
            Ok(ChatAction::RoomInfo(RoomInfo {
                options,
                description,
            }))
        }
        2 => Ok(ChatAction::Login(parse_login(body)?)),
        3 => {
            if body.is_empty() {
                Ok(ChatAction::Logout)
            } else {
                Err(Error::InvalidOptionValue)
            }
        }
        5 => match body {
            [a, b, c, d, max_count] => Ok(ChatAction::FetchMessages {
                timestamp: u32::from_be_bytes([*a, *b, *c, *d]),
                max_count: *max_count,
            }),
            _ => Err(Error::InvalidLength {
                expected: 5,
                actual: body.len(),
            }),
        },
        6 => {
            if body.is_empty() {
                Ok(ChatAction::FetchUsers)
            } else {
                Err(Error::InvalidOptionValue)
            }
        }
        7 => Ok(ChatAction::AdminCommand(body)),
        8 => Ok(ChatAction::RoomUpdate(body)),
        other => Err(Error::InvalidChatAction(other)),
    }
}

fn parse_login(payload: &[u8]) -> Result<LoginParams<'_>, Error> {
    let mut handle = None;
    let mut last_message_timestamp = None;
    let mut session_timeout_minutes = None;
    let mut password = None;
    let mut options = OptionDecoder::new(payload);
    for option in &mut options {
        let (number, value) = option.map_err(Error::Core)?;
        match number {
            0 => handle = Some(parse_utf8(value)?),
            1 => {
                if value.len() != 4 {
                    return Err(Error::InvalidLength {
                        expected: 4,
                        actual: value.len(),
                    });
                }
                last_message_timestamp = Some(u32::from_be_bytes(value.try_into().unwrap()));
            }
            2 => {
                if value.len() != 1 {
                    return Err(Error::InvalidLength {
                        expected: 1,
                        actual: value.len(),
                    });
                }
                session_timeout_minutes = Some(value[0]);
            }
            3 => password = Some(value),
            _ => {}
        }
    }

    if !options.remainder().is_empty() {
        return Err(Error::InvalidOptionValue);
    }

    Ok(LoginParams {
        handle,
        last_message_timestamp,
        session_timeout_minutes,
        password,
    })
}

pub fn encode(action: &ChatAction<'_>, buf: &mut [u8]) -> Result<usize, Error> {
    match action {
        ChatAction::GetRoomInfo => {
            if buf.is_empty() {
                return Err(Error::BufferTooSmall);
            }
            buf[0] = 0;
            Ok(1)
        }
        ChatAction::RoomInfo(room_info) => {
            let mut pos = 0usize;
            if split_options(room_info.options)? != (room_info.options, None) {
                return Err(Error::InvalidOptionValue);
            }
            push_byte(buf, &mut pos, 1)?;
            copy_into(buf, &mut pos, room_info.options)?;
            if let Some(description) = room_info.description.filter(|d| !d.is_empty()) {
                push_byte(buf, &mut pos, 0xFF)?;
                copy_into(buf, &mut pos, description.as_bytes())?;
            }
            Ok(pos)
        }
        ChatAction::Login(login) => {
            if buf.is_empty() {
                return Err(Error::BufferTooSmall);
            }
            buf[0] = 2;
            let mut encoder = OptionEncoder::new(&mut buf[1..]);
            if let Some(handle) = login.handle {
                encoder.put(0, handle.as_bytes())?;
            }
            if let Some(timestamp) = login.last_message_timestamp {
                encoder.put(1, &timestamp.to_be_bytes())?;
            }
            if let Some(timeout) = login.session_timeout_minutes {
                encoder.put(2, &[timeout])?;
            }
            if let Some(password) = login.password {
                encoder.put(3, password)?;
            }
            Ok(1 + encoder.finish())
        }
        ChatAction::Logout => {
            if buf.is_empty() {
                return Err(Error::BufferTooSmall);
            }
            buf[0] = 3;
            Ok(1)
        }
        ChatAction::FetchMessages {
            timestamp,
            max_count,
        } => {
            let mut pos = 0usize;
            push_byte(buf, &mut pos, 5)?;
            copy_into(buf, &mut pos, &timestamp.to_be_bytes())?;
            push_byte(buf, &mut pos, *max_count)?;
            Ok(pos)
        }
        ChatAction::FetchUsers => {
            if buf.is_empty() {
                return Err(Error::BufferTooSmall);
            }
            buf[0] = 6;
            Ok(1)
        }
        ChatAction::AdminCommand(payload) => {
            let mut pos = 0usize;
            push_byte(buf, &mut pos, 7)?;
            copy_into(buf, &mut pos, payload)?;
            Ok(pos)
        }
        ChatAction::RoomUpdate(payload) => {
            let mut pos = 0usize;
            push_byte(buf, &mut pos, 8)?;
            copy_into(buf, &mut pos, payload)?;
            Ok(pos)
        }
    }
}

/// Split an option block from the bytes after its end marker, if it has one.
fn split_options(data: &[u8]) -> Result<(&[u8], Option<&[u8]>), Error> {
    let mut options = OptionDecoder::new(data);
    let mut end = options.position();
    while let Some(option) = options.next() {
        option.map_err(Error::Core)?;
        end = options.position();
    }
    if end == data.len() {
        Ok((data, None))
    } else {
        Ok((&data[..end], Some(options.remainder())))
    }
}

fn parse_utf8(input: &[u8]) -> Result<&str, Error> {
    core::str::from_utf8(input).map_err(|_| Error::InvalidUtf8)
}

fn copy_into(dst: &mut [u8], pos: &mut usize, src: &[u8]) -> Result<(), Error> {
    if dst.len().saturating_sub(*pos) < src.len() {
        return Err(Error::BufferTooSmall);
    }
    dst[*pos..*pos + src.len()].copy_from_slice(src);
    *pos += src.len();
    Ok(())
}

fn push_byte(dst: &mut [u8], pos: &mut usize, byte: u8) -> Result<(), Error> {
    copy_into(dst, pos, &[byte])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_room_login_and_room_info_round_trip() {
        let login = ChatAction::Login(LoginParams {
            handle: Some("guest"),
            last_message_timestamp: Some(0x01020304),
            session_timeout_minutes: Some(9),
            password: Some(b"secret"),
        });
        let mut buf = [0u8; 128];
        let len = encode(&login, &mut buf).unwrap();
        let parsed = parse(&buf[..len]).unwrap();
        assert_eq!(parsed, login);

        let room_info = ChatAction::RoomInfo(RoomInfo {
            options: &[0x11, 0x22],
            description: Some("mesh room"),
        });
        let len = encode(&room_info, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"\x01\x11\x22\xFFmesh room");
        let parsed = parse(&buf[..len]).unwrap();
        assert_eq!(parsed, room_info);
    }

    /// Room Info options with a timestamp whose last byte is 0xFF.
    fn options_ending_in_ff(buf: &mut [u8]) -> usize {
        let mut encoder = OptionEncoder::new(buf);
        encoder.put(0, b"lobby").unwrap();
        encoder.put(6, &[0x00, 0x00, 0x01, 0xFF]).unwrap();
        encoder.finish()
    }

    /// A 0xFF inside an option value is data, not the end of the options.
    #[test]
    fn a_room_info_option_value_may_hold_0xff() {
        let mut options = [0u8; 32];
        let options_len = options_ending_in_ff(&mut options);
        let mut payload = [0u8; 64];
        let mut pos = 0;
        push_byte(&mut payload, &mut pos, 1).unwrap();
        copy_into(&mut payload, &mut pos, &options[..options_len]).unwrap();
        push_byte(&mut payload, &mut pos, 0xFF).unwrap();
        copy_into(&mut payload, &mut pos, b"general chat").unwrap();

        assert_eq!(
            parse(&payload[..pos]),
            Ok(ChatAction::RoomInfo(RoomInfo {
                options: &options[..options_len],
                description: Some("general chat"),
            }))
        );
    }

    /// An extended length byte of 0xFF is part of the option header.
    #[test]
    fn a_room_info_extended_length_may_be_0xff() {
        let name = [b'a'; 13 + 0xFF];
        let mut payload = [0u8; 300];
        payload[0] = 1;
        let mut encoder = OptionEncoder::new(&mut payload[1..]);
        encoder.put(0, &name).unwrap();
        let len = 1 + encoder.finish();
        assert_eq!(&payload[1..3], &[0x0D, 0xFF]);

        assert_eq!(
            parse(&payload[..len]),
            Ok(ChatAction::RoomInfo(RoomInfo {
                options: &payload[1..len],
                description: None,
            }))
        );
    }

    /// The encoder marks the end of the options even when their last byte
    /// is 0xFF.
    #[test]
    fn room_info_options_ending_in_0xff_still_get_a_marker() {
        let mut options = [0u8; 32];
        let options_len = options_ending_in_ff(&mut options);
        let room_info = ChatAction::RoomInfo(RoomInfo {
            options: &options[..options_len],
            description: Some("x"),
        });
        let mut buf = [0u8; 64];
        let len = encode(&room_info, &mut buf).unwrap();
        assert_eq!(len, 1 + options_len + 2);
        assert_eq!(&buf[1..1 + options_len], &options[..options_len]);
        assert_eq!(&buf[1 + options_len..len], &[0xFF, b'x']);
        assert_eq!(parse(&buf[..len]), Ok(room_info));
    }

    /// The end marker goes out only when a description follows it.
    #[test]
    fn room_info_without_a_description_has_no_marker() {
        let room_info = ChatAction::RoomInfo(RoomInfo {
            options: &[0x11, 0x22],
            description: None,
        });
        let mut buf = [0u8; 16];
        let len = encode(&room_info, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[1, 0x11, 0x22]);

        let empty = ChatAction::RoomInfo(RoomInfo {
            options: &[0x11, 0x22],
            description: Some(""),
        });
        let len = encode(&empty, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[1, 0x11, 0x22]);
    }

    /// A marker with nothing after it is tolerated and reads as no
    /// description.
    #[test]
    fn a_room_info_marker_with_nothing_after_it_is_no_description() {
        assert_eq!(
            parse(&[1, 0x11, 0x22, 0xFF]),
            Ok(ChatAction::RoomInfo(RoomInfo {
                options: &[0x11, 0x22],
                description: None,
            }))
        );
    }

    #[test]
    fn a_malformed_room_info_option_block_is_rejected() {
        assert_eq!(
            parse(&[1, 0x13, 0x22]),
            Err(Error::Core(umsh_core::ParseError::Truncated))
        );
    }

    /// Options handed to the encoder are a well-formed block without a
    /// marker of their own.
    #[test]
    fn the_room_info_encoder_refuses_options_it_cannot_frame() {
        let mut buf = [0u8; 16];
        for options in [&[0x11, 0x22, 0xFF][..], &[0x13, 0x22][..]] {
            let room_info = ChatAction::RoomInfo(RoomInfo {
                options,
                description: Some("x"),
            });
            assert!(encode(&room_info, &mut buf).is_err());
        }
    }

    /// An extended field past sixteen bits is malformed, not a wrapped value.
    #[test]
    fn an_oversized_option_delta_is_rejected() {
        assert_eq!(
            parse(&[2, 0xE1, 0xFF, 0x00]),
            Err(Error::Core(umsh_core::ParseError::MalformedOption))
        );
    }
}
