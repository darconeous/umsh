use bitflags::bitflags;

use crate::util::{copy_into, fixed, parse_utf8, push_byte};
use crate::{EncodeError, ParseError};

/// Primary role advertised by a node-identity payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeRole {
    /// No specific role is being advertised.
    Unspecified = 0,
    /// Node primarily acts as a repeater.
    Repeater = 1,
    /// Node primarily acts as a chat endpoint.
    Chat = 2,
    /// Node primarily acts as a tracker.
    Tracker = 3,
    /// Node primarily acts as a sensor.
    Sensor = 4,
    /// Node primarily acts as a bridge to another network.
    Bridge = 5,
    /// Node is a chat-room service.
    ChatRoom = 6,
    /// Node is a temporary session identity, such as PFS state.
    TemporarySession = 7,
}

impl NodeRole {
    fn from_byte(value: u8) -> Result<Self, ParseError> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::Repeater),
            2 => Ok(Self::Chat),
            3 => Ok(Self::Tracker),
            4 => Ok(Self::Sensor),
            5 => Ok(Self::Bridge),
            6 => Ok(Self::ChatRoom),
            7 => Ok(Self::TemporarySession),
            _ => Err(ParseError::InvalidRole(value)),
        }
    }
}

bitflags! {
    /// Node-identity capability bitmap.
    ///
    /// The `NAME_INCLUDED` and `OPTS_INCLUDED` bits are both semantic protocol
    /// flags and a convenience for encoders. [`encode`] updates those two bits to
    /// reflect whether `name` and `options` are present in the supplied payload.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Capabilities: u8 {
        /// Node can act as a repeater.
        const REPEATER = 0x01;
        /// Node is mobile or relocatable.
        const MOBILE = 0x02;
        /// Node supports text messaging.
        const TEXT_MESSAGES = 0x04;
        /// Node supports telemetry traffic.
        const TELEMETRY = 0x08;
        /// Node supports the chat-room protocol.
        const CHAT_ROOM = 0x10;
        /// Node supports CoAP-over-UMSH.
        const COAP = 0x20;
        /// Payload contains a NUL-terminated node name.
        const NAME_INCLUDED = 0x40;
        /// Payload contains option bytes after the fixed header and optional name.
        const OPTS_INCLUDED = 0x80;
    }
}

/// Parsed node-identity payload.
///
/// The `options` field preserves the raw CoAP-style option block exactly as it
/// appeared on the wire so higher layers can iterate it according to their own
/// option registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeIdentityPayload<'a> {
    /// Truncated 32-bit UNIX timestamp describing when the identity was updated.
    pub timestamp: u32,
    /// Advertised primary role.
    pub role: NodeRole,
    /// Advertised capability bitmap.
    pub capabilities: Capabilities,
    /// Optional UTF-8 node name.
    pub name: Option<&'a str>,
    /// Optional raw CoAP-style option block.
    pub options: Option<&'a [u8]>,
    /// Optional Ed25519 signature over the preceding identity bytes.
    pub signature: Option<&'a [u8; 64]>,
}

/// Parse a node-identity payload body.
///
/// `payload` must start immediately at the 4-byte timestamp field. The parser is
/// zero-copy for the variable-sized name, option block, and signature.
pub fn parse(payload: &[u8]) -> Result<NodeIdentityPayload<'_>, ParseError> {
    if payload.len() < 6 {
        return Err(ParseError::Core(umsh_core::ParseError::Truncated));
    }

    let timestamp = u32::from_be_bytes(*fixed(&payload[..4])?);
    let role = NodeRole::from_byte(payload[4])?;
    let capabilities = Capabilities::from_bits_truncate(payload[5]);
    let mut remaining = &payload[6..];

    let name = if capabilities.contains(Capabilities::NAME_INCLUDED) {
        let nul = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ParseError::InvalidOptionValue)?;
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
                return Err(ParseError::InvalidLength {
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
        return Err(ParseError::InvalidLength {
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

/// Encode a node-identity payload body into `buf`.
///
/// If `name` or `options` are present, the corresponding capability bits are set
/// automatically in the encoded output even if they were absent in
/// `id.capabilities`.
pub fn encode(id: &NodeIdentityPayload<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
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