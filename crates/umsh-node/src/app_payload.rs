use umsh_core::{PacketType, PayloadType};

use crate::{AppParseError, MacCommand, NodeIdentityPayload, mac_command};

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
) -> Result<NodeIdentityPayload, AppParseError> {
    NodeIdentityPayload::from_bytes(expect_payload_type(
        packet_type,
        payload,
        PayloadType::NodeIdentity,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- split_payload_type ---

    #[test]
    fn split_empty_gives_empty_type() {
        let (ty, body) = split_payload_type(&[]).unwrap();
        assert_eq!(ty, PayloadType::Empty);
        assert_eq!(body, &[] as &[u8]);
    }

    #[test]
    fn split_unknown_byte_gives_empty_type_with_full_slice() {
        // 0x99 is not a known PayloadType byte; the full slice is returned as body.
        let payload = &[0x99u8, 0x01, 0x02];
        let (ty, body) = split_payload_type(payload).unwrap();
        assert_eq!(ty, PayloadType::Empty);
        assert_eq!(body, payload);
    }

    #[test]
    fn split_known_byte_strips_type_prefix() {
        // 0x02 = MacCommand
        let payload = &[0x02u8, 0xAA, 0xBB];
        let (ty, body) = split_payload_type(payload).unwrap();
        assert_eq!(ty, PayloadType::MacCommand);
        assert_eq!(body, &[0xAAu8, 0xBB]);
    }

    // --- expect_payload_type ---

    #[test]
    fn expect_correct_type_returns_body() {
        // MacCommand is allowed for Unicast.
        let payload = &[0x02u8, 0x01]; // MacCommand prefix + body byte
        let body = expect_payload_type(PacketType::Unicast, payload, PayloadType::MacCommand).unwrap();
        assert_eq!(body, &[0x01u8]);
    }

    #[test]
    fn expect_wrong_type_returns_invalid_payload_type() {
        // Payload carries NodeIdentity (0x01) but caller expects MacCommand.
        let payload = &[0x01u8, 0x02, 0x00];
        let err = expect_payload_type(PacketType::Unicast, payload, PayloadType::MacCommand)
            .unwrap_err();
        assert!(matches!(err, AppParseError::InvalidPayloadType(0x01)));
    }

    #[test]
    fn expect_disallowed_for_packet_type_returns_error() {
        // MacCommand is not allowed in a Broadcast packet.
        let payload = &[0x02u8, 0x01];
        let err =
            expect_payload_type(PacketType::Broadcast, payload, PayloadType::MacCommand)
                .unwrap_err();
        assert!(matches!(err, AppParseError::PayloadTypeNotAllowed { .. }));
    }
}
