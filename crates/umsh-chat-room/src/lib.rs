#![cfg_attr(not(feature = "std"), no_std)]

//! Chat-room management payload codecs for UMSH.

extern crate alloc;

use core::fmt;

use umsh_core::options::OptionEncoder;

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
    pub options: &'a [u8],
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
            let (options, description) =
                if let Some(index) = body.iter().position(|byte| *byte == 0xFF) {
                    (&body[..=index], Some(parse_utf8(&body[index + 1..])?))
                } else {
                    (body, None)
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
    let remainder = decode_options_allow_eof(payload, |number, value| {
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
        Ok(())
    })?;

    if !remainder.is_empty() {
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

fn decode_options_allow_eof<'a>(
    data: &'a [u8],
    mut on_option: impl FnMut(u16, &'a [u8]) -> Result<(), Error>,
) -> Result<&'a [u8], Error> {
    let mut pos = 0usize;
    let mut last_number = 0u16;

    while pos < data.len() {
        let first = data[pos];
        if first == 0xFF {
            return Ok(&data[pos + 1..]);
        }
        pos += 1;

        let (delta, delta_len) = read_extended(&data[pos..], first >> 4)?;
        pos += delta_len;
        let (len, len_len) = read_extended(&data[pos..], first & 0x0F)?;
        pos += len_len;

        let end = pos
            .checked_add(len as usize)
            .ok_or(Error::InvalidOptionValue)?;
        if end > data.len() {
            return Err(Error::Core(umsh_core::ParseError::Truncated));
        }
        let number = last_number
            .checked_add(delta)
            .ok_or(Error::InvalidOptionValue)?;
        on_option(number, &data[pos..end])?;
        pos = end;
        last_number = number;
    }

    Ok(&data[pos..])
}

fn read_extended(data: &[u8], nibble: u8) -> Result<(u16, usize), Error> {
    match nibble {
        0..=12 => Ok((nibble as u16, 0)),
        13 => {
            if data.is_empty() {
                Err(Error::Core(umsh_core::ParseError::Truncated))
            } else {
                Ok((data[0] as u16 + 13, 1))
            }
        }
        14 => {
            if data.len() < 2 {
                Err(Error::Core(umsh_core::ParseError::Truncated))
            } else {
                Ok((u16::from_be_bytes([data[0], data[1]]) + 269, 2))
            }
        }
        _ => Err(Error::Core(umsh_core::ParseError::InvalidOptionNibble)),
    }
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
            options: &[0x11, 0x22, 0xFF],
            description: Some("mesh room"),
        });
        let len = encode(&room_info, &mut buf).unwrap();
        let parsed = parse(&buf[..len]).unwrap();
        assert_eq!(parsed, room_info);
    }
}
