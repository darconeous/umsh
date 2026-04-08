use bitflags::bitflags;

use crate::app_util::{copy_into, fixed, parse_utf8, push_byte};
use crate::{AppEncodeError, AppParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeRole {
    Unspecified = 0,
    Repeater = 1,
    Chat = 2,
    Tracker = 3,
    Sensor = 4,
    Bridge = 5,
    ChatRoom = 6,
    TemporarySession = 7,
}

impl NodeRole {
    fn from_byte(value: u8) -> Result<Self, AppParseError> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::Repeater),
            2 => Ok(Self::Chat),
            3 => Ok(Self::Tracker),
            4 => Ok(Self::Sensor),
            5 => Ok(Self::Bridge),
            6 => Ok(Self::ChatRoom),
            7 => Ok(Self::TemporarySession),
            _ => Err(AppParseError::InvalidRole(value)),
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Capabilities: u8 {
        const REPEATER = 0x01;
        const MOBILE = 0x02;
        const TEXT_MESSAGES = 0x04;
        const TELEMETRY = 0x08;
        const CHAT_ROOM = 0x10;
        const COAP = 0x20;
        const NAME_INCLUDED = 0x40;
        const OPTS_INCLUDED = 0x80;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeIdentityPayload<'a> {
    pub timestamp: u32,
    pub role: NodeRole,
    pub capabilities: Capabilities,
    pub name: Option<&'a str>,
    pub options: Option<&'a [u8]>,
    pub signature: Option<&'a [u8; 64]>,
}

pub fn parse(payload: &[u8]) -> Result<NodeIdentityPayload<'_>, AppParseError> {
    if payload.len() < 6 {
        return Err(AppParseError::Core(umsh_core::ParseError::Truncated));
    }

    let timestamp = u32::from_be_bytes(*fixed(&payload[..4])?);
    let role = NodeRole::from_byte(payload[4])?;
    let capabilities = Capabilities::from_bits_truncate(payload[5]);
    let mut remaining = &payload[6..];

    let name = if capabilities.contains(Capabilities::NAME_INCLUDED) {
        let nul = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(AppParseError::InvalidOptionValue)?;
        let name = parse_utf8(&remaining[..nul])?;
        remaining = &remaining[nul + 1..];
        Some(name)
    } else {
        None
    };

    let mut signature = None;
    let options = if capabilities.contains(Capabilities::OPTS_INCLUDED) {
        if let Some(term) = remaining.iter().position(|byte| *byte == 0xFF) {
            let option_bytes = &remaining[..=term];
            let after = &remaining[term + 1..];
            if after.is_empty() {
                Some(option_bytes)
            } else if after.len() == 64 {
                signature = Some(fixed(after)?);
                Some(option_bytes)
            } else {
                return Err(AppParseError::InvalidLength {
                    expected: 64,
                    actual: after.len(),
                });
            }
        } else {
            Some(remaining)
        }
    } else if remaining.is_empty() {
        None
    } else if remaining.len() == 64 {
        signature = Some(fixed(remaining)?);
        None
    } else {
        return Err(AppParseError::InvalidLength {
            expected: 64,
            actual: remaining.len(),
        });
    };

    Ok(NodeIdentityPayload {
        timestamp,
        role,
        capabilities,
        name,
        options,
        signature,
    })
}

pub fn encode(id: &NodeIdentityPayload<'_>, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
    let mut pos = 0usize;
    let mut capabilities = id.capabilities;
    capabilities.set(Capabilities::NAME_INCLUDED, id.name.is_some());
    capabilities.set(Capabilities::OPTS_INCLUDED, id.options.is_some());

    copy_into(buf, &mut pos, &id.timestamp.to_be_bytes())?;
    push_byte(buf, &mut pos, id.role as u8)?;
    push_byte(buf, &mut pos, capabilities.bits())?;

    if let Some(name) = id.name {
        copy_into(buf, &mut pos, name.as_bytes())?;
        push_byte(buf, &mut pos, 0)?;
    }

    if let Some(options) = id.options {
        copy_into(buf, &mut pos, options)?;
        if id.signature.is_some() && options.last().copied() != Some(0xFF) {
            push_byte(buf, &mut pos, 0xFF)?;
        }
    }

    if let Some(signature) = id.signature {
        copy_into(buf, &mut pos, signature)?;
    }

    Ok(pos)
}
