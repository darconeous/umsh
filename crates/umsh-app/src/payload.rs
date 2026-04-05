use umsh_core::{PacketType, PayloadType};

use crate::{ParseError, identity, mac_cmd, text};

/// Split a typed application payload into its type byte and body.
///
/// If the first byte matches a registered payload type, it is treated as the
/// typed-payload discriminator and removed from the returned body. Otherwise the
/// payload is treated as raw/untyped and the full slice is returned as the body
/// with [`PayloadType::Empty`].
pub fn split_payload_type(payload: &[u8]) -> Result<(PayloadType, &[u8]), ParseError> {
    if payload.is_empty() {
        return Ok((PayloadType::Empty, &[]));
    }
    if let Some(payload_type) = PayloadType::from_byte(payload[0]) {
        Ok((payload_type, &payload[1..]))
    } else {
        Ok((PayloadType::Empty, payload))
    }
}

/// Parse a typed application payload in the context of the enclosing packet type.
///
/// This helper first validates the payload-type byte, then enforces the protocol's
/// packet-type compatibility matrix, and finally decodes the typed body.
pub fn expect_payload_type(
    packet_type: PacketType,
    payload: &[u8],
    expected: PayloadType,
) -> Result<&[u8], ParseError> {
    let (payload_type, body) = split_payload_type(payload)?;
    if !payload_type.allowed_for(packet_type) {
        return Err(ParseError::PayloadTypeNotAllowed {
            payload_type: payload_type as u8,
            packet_type,
        });
    }
    if payload_type != expected {
        return Err(ParseError::InvalidPayloadType(payload_type as u8));
    }
    Ok(body)
}

pub fn parse_text_payload(
    packet_type: PacketType,
    payload: &[u8],
) -> Result<text::TextMessage<'_>, ParseError> {
    text::parse(expect_payload_type(packet_type, payload, PayloadType::TextMessage)?)
}

pub fn parse_mac_command_payload(
    packet_type: PacketType,
    payload: &[u8],
) -> Result<mac_cmd::MacCommand<'_>, ParseError> {
    mac_cmd::parse(expect_payload_type(packet_type, payload, PayloadType::MacCommand)?)
}

pub fn parse_node_identity_payload(
    packet_type: PacketType,
    payload: &[u8],
) -> Result<identity::NodeIdentityPayload<'_>, ParseError> {
    identity::parse(expect_payload_type(packet_type, payload, PayloadType::NodeIdentity)?)
}
