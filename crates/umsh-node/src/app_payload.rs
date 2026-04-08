use umsh_core::{PacketType, PayloadType};

use crate::{AppParseError, MacCommand, NodeIdentityPayload, identity, mac_command};

pub fn split_payload_type(payload: &[u8]) -> Result<(PayloadType, &[u8]), AppParseError> {
    if payload.is_empty() {
        return Ok((PayloadType::Empty, &[]));
    }
    if let Some(payload_type) = PayloadType::from_byte(payload[0]) {
        Ok((payload_type, &payload[1..]))
    } else {
        Ok((PayloadType::Empty, payload))
    }
}

pub fn expect_payload_type(
    packet_type: PacketType,
    payload: &[u8],
    expected: PayloadType,
) -> Result<&[u8], AppParseError> {
    let (payload_type, body) = split_payload_type(payload)?;
    if !payload_type.allowed_for(packet_type) {
        return Err(AppParseError::PayloadTypeNotAllowed {
            payload_type: payload_type as u8,
            packet_type,
        });
    }
    if payload_type != expected {
        return Err(AppParseError::InvalidPayloadType(payload_type as u8));
    }
    Ok(body)
}

pub fn parse_mac_command_payload(
    packet_type: PacketType,
    payload: &[u8],
) -> Result<MacCommand<'_>, AppParseError> {
    mac_command::parse(expect_payload_type(
        packet_type,
        payload,
        PayloadType::MacCommand,
    )?)
}

pub fn parse_node_identity_payload(
    packet_type: PacketType,
    payload: &[u8],
) -> Result<NodeIdentityPayload<'_>, AppParseError> {
    identity::parse(expect_payload_type(
        packet_type,
        payload,
        PayloadType::NodeIdentity,
    )?)
}
