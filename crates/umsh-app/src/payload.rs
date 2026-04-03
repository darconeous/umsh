use umsh_core::PacketType;

use crate::{identity, mac_cmd, text, ParseError};

/// UMSH application payload type byte.
///
/// This is the first byte normally found in the application payload carried by a
/// MAC packet. The compatibility rules in [`allowed_for`](Self::allowed_for)
/// intentionally mirror the protocol table from the implementation plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// Empty or application-agnostic payload.
    Unspecified = 0,
    /// Node-identity payload.
    NodeIdentity = 1,
    /// MAC command payload.
    MacCommand = 2,
    /// Text-message payload.
    TextMessage = 3,
    /// Chat-room management payload.
    ChatRoomMessage = 5,
    /// CoAP-over-UMSH payload.
    CoapOverUmsh = 7,
    /// Node-management payload.
    NodeManagement = 8,
}

impl PayloadType {
    /// Convert a raw payload-type byte into a known payload type.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Unspecified),
            1 => Some(Self::NodeIdentity),
            2 => Some(Self::MacCommand),
            3 => Some(Self::TextMessage),
            5 => Some(Self::ChatRoomMessage),
            7 => Some(Self::CoapOverUmsh),
            8 => Some(Self::NodeManagement),
            _ => None,
        }
    }

    /// Return whether this payload type is valid for the given MAC packet type.
    pub fn allowed_for(self, packet_type: PacketType) -> bool {
        match self {
            Self::Unspecified | Self::NodeIdentity => !matches!(packet_type, PacketType::MacAck),
            Self::MacCommand => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
                    | PacketType::Multicast
            ),
            Self::TextMessage | Self::CoapOverUmsh | Self::NodeManagement => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
                    | PacketType::Multicast
            ),
            Self::ChatRoomMessage => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
            ),
        }
    }
}

/// Borrowing view of a typed application payload.
///
/// This enum is returned by [`parse_payload`] after the payload type has been
/// validated and the specific payload body has been parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadRef<'a> {
    /// Empty or otherwise untyped payload bytes.
    Unspecified(&'a [u8]),
    /// Parsed node-identity payload.
    NodeIdentity(identity::NodeIdentityPayload<'a>),
    /// Parsed MAC command.
    MacCommand(mac_cmd::MacCommand<'a>),
    /// Parsed text-message payload.
    TextMessage(text::TextMessage<'a>),
    #[cfg(feature = "chat-rooms")]
    /// Parsed chat-room payload.
    ChatRoomMessage(crate::chat_room::ChatAction<'a>),
    /// Raw CoAP-over-UMSH body.
    CoapOverUmsh(&'a [u8]),
    /// Raw node-management body.
    NodeManagement(&'a [u8]),
}

/// Split a typed application payload into its type byte and body.
///
/// An empty slice is treated as [`PayloadType::Unspecified`].
pub fn split_payload_type(payload: &[u8]) -> Result<(PayloadType, &[u8]), ParseError> {
    if payload.is_empty() {
        return Ok((PayloadType::Unspecified, &[]));
    }
    let payload_type = PayloadType::from_byte(payload[0]).ok_or(ParseError::InvalidPayloadType(payload[0]))?;
    Ok((payload_type, &payload[1..]))
}

/// Parse a typed application payload in the context of the enclosing packet type.
///
/// This helper first validates the payload-type byte, then enforces the protocol's
/// packet-type compatibility matrix, and finally decodes the typed body.
pub fn parse_payload(packet_type: PacketType, payload: &[u8]) -> Result<PayloadRef<'_>, ParseError> {
    let (payload_type, body) = split_payload_type(payload)?;
    if !payload_type.allowed_for(packet_type) {
        return Err(ParseError::PayloadTypeNotAllowed {
            payload_type: payload_type as u8,
            packet_type,
        });
    }

    match payload_type {
        PayloadType::Unspecified => Ok(PayloadRef::Unspecified(body)),
        PayloadType::NodeIdentity => Ok(PayloadRef::NodeIdentity(identity::parse(body)?)),
        PayloadType::MacCommand => Ok(PayloadRef::MacCommand(mac_cmd::parse(body)?)),
        PayloadType::TextMessage => Ok(PayloadRef::TextMessage(text::parse(body)?)),
        #[cfg(feature = "chat-rooms")]
        PayloadType::ChatRoomMessage => Ok(PayloadRef::ChatRoomMessage(crate::chat_room::parse(body)?)),
        #[cfg(not(feature = "chat-rooms"))]
        PayloadType::ChatRoomMessage => Ok(PayloadRef::Unspecified(body)),
        PayloadType::CoapOverUmsh => Ok(PayloadRef::CoapOverUmsh(body)),
        PayloadType::NodeManagement => Ok(PayloadRef::NodeManagement(body)),
    }
}