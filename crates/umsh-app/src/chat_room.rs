use crate::util::{copy_into, decode_options_allow_eof, parse_utf8, push_byte};
use crate::{EncodeError, ParseError};
use umsh_core::options::OptionEncoder;

/// Parsed chat-room management action.
///
/// Ordinary room messages are plain text-message payloads and do not use this
/// enum. This type is only for the management actions carried by the dedicated
/// chat-room payload type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatAction<'a> {
    /// Request room metadata.
    GetRoomInfo,
    /// Room metadata response.
    RoomInfo(RoomInfo<'a>),
    /// Login request.
    Login(LoginParams<'a>),
    /// Logout request.
    Logout,
    /// Request historical messages up to the given timestamp.
    FetchMessages { timestamp: u32, max_count: u8 },
    /// Request the current active-user list.
    FetchUsers,
    /// Opaque administrator command bytes.
    AdminCommand(&'a [u8]),
    /// Opaque room-update batch bytes.
    RoomUpdate(&'a [u8]),
}

/// Room metadata response.
///
/// `options` preserves the raw room-info option block exactly as received or as
/// supplied for encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomInfo<'a> {
    /// Raw room-info option bytes.
    pub options: &'a [u8],
    /// Optional UTF-8 room description.
    pub description: Option<&'a str>,
}

/// Login parameters for a chat-room login request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginParams<'a> {
    /// Requested or suggested handle.
    pub handle: Option<&'a str>,
    /// Timestamp used to request missed history.
    pub last_message_timestamp: Option<u32>,
    /// Requested inactivity timeout in minutes.
    pub session_timeout_minutes: Option<u8>,
    /// Optional room password bytes.
    pub password: Option<&'a [u8]>,
}

/// Parse a chat-room action payload body.
pub fn parse(payload: &[u8]) -> Result<ChatAction<'_>, ParseError> {
    let (&action, body) = payload
        .split_first()
        .ok_or(ParseError::Core(umsh_core::ParseError::Truncated))?;

    match action {
        0 => {
            if body.is_empty() {
                Ok(ChatAction::GetRoomInfo)
            } else {
                Err(ParseError::InvalidOptionValue)
            }
        }
        1 => {
            let (options, description) = if let Some(index) = body.iter().position(|byte| *byte == 0xFF) {
                (&body[..=index], Some(parse_utf8(&body[index + 1..])?))
            } else {
                (body, None)
            };
            Ok(ChatAction::RoomInfo(RoomInfo { options, description }))
        }
        2 => Ok(ChatAction::Login(parse_login(body)?)),
        3 => {
            if body.is_empty() {
                Ok(ChatAction::Logout)
            } else {
                Err(ParseError::InvalidOptionValue)
            }
        }
        5 => match body {
            [a, b, c, d, max_count] => Ok(ChatAction::FetchMessages {
                timestamp: u32::from_be_bytes([*a, *b, *c, *d]),
                max_count: *max_count,
            }),
            _ => Err(ParseError::InvalidLength {
                expected: 5,
                actual: body.len(),
            }),
        },
        6 => {
            if body.is_empty() {
                Ok(ChatAction::FetchUsers)
            } else {
                Err(ParseError::InvalidOptionValue)
            }
        }
        7 => Ok(ChatAction::AdminCommand(body)),
        8 => Ok(ChatAction::RoomUpdate(body)),
        other => Err(ParseError::InvalidChatAction(other)),
    }
}

fn parse_login(payload: &[u8]) -> Result<LoginParams<'_>, ParseError> {
    let mut handle = None;
    let mut last_message_timestamp = None;
    let mut session_timeout_minutes = None;
    let mut password = None;
    let remainder = decode_options_allow_eof(payload, |number, value| {
        match number {
            0 => handle = Some(parse_utf8(value)?),
            1 => {
                if value.len() != 4 {
                    return Err(ParseError::InvalidLength {
                        expected: 4,
                        actual: value.len(),
                    });
                }
                last_message_timestamp = Some(u32::from_be_bytes(value.try_into().unwrap()));
            }
            2 => {
                if value.len() != 1 {
                    return Err(ParseError::InvalidLength {
                        expected: 1,
                        actual: value.len(),
                    });
                }
                session_timeout_minutes = Some(value[0]);
            }
            3 => password = Some(value),
            _ => {}
        }
        Ok(())
    })?;

    if !remainder.is_empty() {
        return Err(ParseError::InvalidOptionValue);
    }

    Ok(LoginParams {
        handle,
        last_message_timestamp,
        session_timeout_minutes,
        password,
    })
}

/// Encode a chat-room action payload body into `buf`.
pub fn encode(action: &ChatAction<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    match action {
        ChatAction::GetRoomInfo => {
            if buf.is_empty() {
                return Err(EncodeError::BufferTooSmall);
            }
            buf[0] = 0;
            Ok(1)
        }
        ChatAction::RoomInfo(room_info) => {
            let mut pos = 0usize;
            push_byte(buf, &mut pos, 1)?;
            copy_into(buf, &mut pos, room_info.options)?;
            if let Some(description) = room_info.description {
                if room_info.options.last().copied() != Some(0xFF) {
                    push_byte(buf, &mut pos, 0xFF)?;
                }
                copy_into(buf, &mut pos, description.as_bytes())?;
            }
            Ok(pos)
        }
        ChatAction::Login(login) => {
            if buf.is_empty() {
                return Err(EncodeError::BufferTooSmall);
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
                return Err(EncodeError::BufferTooSmall);
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
                return Err(EncodeError::BufferTooSmall);
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