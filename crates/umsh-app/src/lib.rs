#![cfg_attr(not(feature = "std"), no_std)]

//! UMSH application-layer payload codecs and URI helpers.
//!
//! This crate is intentionally structural: it parses and formats the bytes used by
//! the application layer, but it does not perform transport I/O, crypto, or policy
//! decisions. All parsers are zero-copy and borrow from the supplied payload slice.
//!
//! Common entry points:
//!
//! - [`PayloadType`] and [`split_payload_type`] to inspect typed application payloads.
//! - [`parse_text_message`] and [`encode_text_message`] for standalone text-message work.
//! - [`parse_text_payload`], [`parse_mac_command_payload`], and
//!   [`parse_node_identity_payload`] for typed payload parsing without a generic event enum.
//! - [`parse_umsh_uri`] and the `format_*` helpers for provisioning URIs.
//!
//! # Examples
//!
//! Parsing a typed text-message payload:
//!
//! ```rust
//! use umsh_app::{parse_text_payload, PayloadType, TextMessage};
//! use umsh_core::PacketType;
//!
//! let mut payload = [0u8; 16];
//! payload[0] = PayloadType::TextMessage as u8;
//! payload[1] = 0xFF;
//! payload[2..7].copy_from_slice(b"hello");
//!
//! let message = parse_text_payload(PacketType::Unicast, &payload[..7]).unwrap();
//! assert_eq!(message.body, "hello");
//! ```

mod error;
mod identity;
mod mac_cmd;
mod payload;
mod text;
mod uri;
mod util;

#[cfg(feature = "chat-rooms")]
pub mod chat_room;

/// Error returned when decoding an application payload or URI.
pub use error::{EncodeError, ParseError};
/// Node-identity payload types and flags.
pub use identity::{Capabilities, NodeIdentityPayload, NodeRole};
/// MAC command identifiers and payload representation.
pub use mac_cmd::{CommandId, MacCommand};
/// Payload dispatch helpers and type-specific payload parsers.
pub use payload::{
    expect_payload_type, parse_mac_command_payload, parse_node_identity_payload, parse_text_payload,
    split_payload_type,
};
pub use umsh_core::PayloadType;
/// Text-message types and standalone codec helpers.
pub use text::{encode as encode_text_message, parse as parse_text_message, Fragment, MessageSequence, MessageType, Regarding, TextMessage};
/// UMSH URI parsing and formatting helpers.
pub use uri::{
    format_channel_key_uri, format_channel_name_uri, format_channel_name_uri_with_params,
    format_node_uri, parse_umsh_uri, ChannelKeyUri, ChannelNameUri, ChannelParams, NodeUri,
    UmshUri,
};

#[cfg(feature = "chat-rooms")]
/// Chat-room action types and payload structs.
pub use chat_room::{ChatAction, LoginParams, RoomInfo};

/// Namespace for node-identity payload codecs.
///
/// This module mirrors the crate-level re-exports but provides a predictable
/// location for the raw `parse` and `encode` functions.
pub mod identity_payload {
    pub use crate::identity::{encode, parse};
}

/// Namespace for MAC-command payload codecs.
pub mod mac_command {
    pub use crate::mac_cmd::{encode, parse};
}

/// Namespace for text-message payload codecs.
pub mod text_message {
    pub use crate::text::{encode, parse};
}

#[cfg(test)]
mod tests {
    use lwuri::UriRef;
    use umsh_core::{NodeHint, PacketType, PublicKey};

    use crate::{
        identity_payload, mac_command, parse_mac_command_payload, parse_text_payload,
        split_payload_type, text_message, ChannelParams, CommandId, Fragment, MacCommand,
        MessageSequence, MessageType, NodeIdentityPayload, NodeRole, PayloadType, Regarding,
        TextMessage,
    };

    #[cfg(feature = "chat-rooms")]
    use crate::chat_room::{self, ChatAction, LoginParams, RoomInfo};

    #[test]
    fn payload_type_compatibility_matrix_matches_phase_three_rules() {
        assert!(PayloadType::NodeIdentity.allowed_for(PacketType::Broadcast));
        assert!(!PayloadType::TextMessage.allowed_for(PacketType::Broadcast));
        assert!(PayloadType::MacCommand.allowed_for(PacketType::Multicast));
        assert!(!PayloadType::ChatRoomMessage.allowed_for(PacketType::Multicast));
    }

    #[test]
    fn text_message_round_trip_preserves_options_and_body() {
        let message = TextMessage {
            message_type: MessageType::Status,
            sender_handle: Some("n0call"),
            sequence: Some(MessageSequence {
                message_id: 7,
                fragment: Some(Fragment { index: 1, count: 3 }),
            }),
            sequence_reset: true,
            regarding: Some(Regarding::Multicast {
                message_id: 4,
                source_prefix: NodeHint([0xAA, 0xBB, 0xCC]),
            }),
            editing: Some(3),
            bg_color: Some([1, 2, 3]),
            text_color: Some([4, 5, 6]),
            body: "hello world",
        };
        let mut buf = [0u8; 128];
        let len = text_message::encode(&message, &mut buf).unwrap();
        let parsed = text_message::parse(&buf[..len]).unwrap();
        assert_eq!(parsed, message);
    }

    #[test]
    fn identity_round_trip_preserves_name_options_and_signature() {
        let signature = [0x44u8; 64];
        let payload = NodeIdentityPayload {
            timestamp: 0x01020304,
            role: NodeRole::ChatRoom,
            capabilities: crate::Capabilities::TEXT_MESSAGES,
            name: Some("room-one"),
            options: Some(&[0x01, 0x02, 0xFF]),
            signature: Some(&signature),
        };
        let mut buf = [0u8; 128];
        let len = identity_payload::encode(&payload, &mut buf).unwrap();
        let parsed = identity_payload::parse(&buf[..len]).unwrap();
        assert_eq!(parsed.timestamp, payload.timestamp);
        assert_eq!(parsed.role, payload.role);
        assert_eq!(parsed.name, payload.name);
        assert_eq!(parsed.options, payload.options);
        assert_eq!(parsed.signature, payload.signature);
        assert!(parsed.capabilities.contains(crate::Capabilities::NAME_INCLUDED));
        assert!(parsed.capabilities.contains(crate::Capabilities::OPTS_INCLUDED));
    }

    #[test]
    fn mac_command_round_trip_covers_all_commands() {
        let key = PublicKey([0x11; 32]);
        let commands = [
            MacCommand::BeaconRequest { nonce: None },
            MacCommand::BeaconRequest {
                nonce: Some(0x01020304),
            },
            MacCommand::IdentityRequest,
            MacCommand::SignalReportRequest,
            MacCommand::SignalReportResponse { rssi: 130, snr: -7 },
            MacCommand::EchoRequest { data: b"ping" },
            MacCommand::EchoResponse { data: b"pong" },
            MacCommand::PfsSessionRequest {
                ephemeral_key: key,
                duration_minutes: 60,
            },
            MacCommand::PfsSessionResponse {
                ephemeral_key: key,
                duration_minutes: 120,
            },
            MacCommand::EndPfsSession,
        ];

        for command in commands {
            let mut buf = [0u8; 80];
            let len = mac_command::encode(&command, &mut buf).unwrap();
            let parsed = mac_command::parse(&buf[..len]).unwrap();
            assert_eq!(parsed, command);
        }

        assert_eq!(CommandId::EchoRequest as u8, 4);
    }

    #[cfg(feature = "chat-rooms")]
    #[test]
    fn chat_room_login_and_room_info_round_trip() {
        let login = ChatAction::Login(LoginParams {
            handle: Some("guest"),
            last_message_timestamp: Some(0x01020304),
            session_timeout_minutes: Some(9),
            password: Some(b"secret"),
        });
        let mut buf = [0u8; 128];
        let len = chat_room::encode(&login, &mut buf).unwrap();
        let parsed = chat_room::parse(&buf[..len]).unwrap();
        assert_eq!(parsed, login);

        let room_info = ChatAction::RoomInfo(RoomInfo {
            options: &[0x11, 0x22, 0xFF],
            description: Some("mesh room"),
        });
        let len = chat_room::encode(&room_info, &mut buf).unwrap();
        let parsed = chat_room::parse(&buf[..len]).unwrap();
        assert_eq!(parsed, room_info);
    }

    #[test]
    fn uri_parse_and_format_cover_node_channel_name_and_key() {
        let key = PublicKey([0x33; 32]);
        let mut buf = [0u8; 128];
        let node_len = crate::format_node_uri(&key, &mut buf).unwrap();
        let node_uri = UriRef::from_str(core::str::from_utf8(&buf[..node_len]).unwrap()).unwrap();
        match crate::parse_umsh_uri(node_uri).unwrap() {
            crate::UmshUri::Node(parsed) => assert_eq!(parsed.public_key, key),
            _ => panic!("expected node uri"),
        }

        let params = ChannelParams {
            display_name: Some("Local"),
            max_flood_hops: Some(6),
            region: Some("Eugine"),
            raw_query: None,
        };
        let channel_name_len = crate::format_channel_name_uri_with_params("Public", &params, &mut buf).unwrap();
        let channel_name_uri =
            UriRef::from_str(core::str::from_utf8(&buf[..channel_name_len]).unwrap()).unwrap();
        match crate::parse_umsh_uri(channel_name_uri).unwrap() {
            crate::UmshUri::ChannelByName(parsed) => {
                assert_eq!(parsed.name, "Public");
                assert_eq!(parsed.params.display_name, Some("Local"));
                assert_eq!(parsed.params.max_flood_hops, Some(6));
                assert_eq!(parsed.params.region, Some("Eugine"));
            }
            _ => panic!("expected channel name uri"),
        }

        let channel_key = umsh_core::ChannelKey([0x44; 32]);
        let channel_key_len = crate::format_channel_key_uri(&channel_key, &mut buf).unwrap();
        let channel_key_uri =
            UriRef::from_str(core::str::from_utf8(&buf[..channel_key_len]).unwrap()).unwrap();
        match crate::parse_umsh_uri(channel_key_uri).unwrap() {
            crate::UmshUri::ChannelByKey(parsed) => assert_eq!(parsed.key.0, channel_key.0),
            _ => panic!("expected channel key uri"),
        }
    }

    #[test]
    fn payload_dispatch_parses_text_messages() {
        let message = TextMessage {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body: "hello",
        };
        let mut inner = [0u8; 64];
        let inner_len = text_message::encode(&message, &mut inner).unwrap();
        let mut payload = [0u8; 65];
        payload[0] = PayloadType::TextMessage as u8;
        payload[1..1 + inner_len].copy_from_slice(&inner[..inner_len]);

        let (kind, body) = split_payload_type(&payload[..1 + inner_len]).unwrap();
        assert_eq!(kind, PayloadType::TextMessage);
        assert_eq!(body, &payload[1..1 + inner_len]);

        let parsed = parse_text_payload(PacketType::Unicast, &payload[..1 + inner_len]).unwrap();
        assert_eq!(parsed.body, "hello");
    }

    #[test]
    fn payload_dispatch_parses_mac_commands() {
        let command = MacCommand::EchoRequest { data: b"ping" };
        let mut inner = [0u8; 64];
        let inner_len = mac_command::encode(&command, &mut inner).unwrap();
        let mut payload = [0u8; 65];
        payload[0] = PayloadType::MacCommand as u8;
        payload[1..1 + inner_len].copy_from_slice(&inner[..inner_len]);

        let parsed = parse_mac_command_payload(PacketType::Unicast, &payload[..1 + inner_len]).unwrap();
        assert_eq!(parsed, command);
    }
}
