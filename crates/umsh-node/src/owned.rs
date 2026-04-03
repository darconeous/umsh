use alloc::{string::String, vec::Vec};

use umsh_app::{MessageSequence, MessageType, NodeIdentityPayload, NodeRole, Regarding, TextMessage};
use umsh_core::{ChannelId, PublicKey};
use umsh_mac::SendReceipt;

/// Owned form of a parsed text-message payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedTextMessage {
    pub message_type: MessageType,
    pub sender_handle: Option<String>,
    pub sequence: Option<MessageSequence>,
    pub sequence_reset: bool,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub body: String,
}

impl OwnedTextMessage {
    pub fn as_borrowed(&self) -> TextMessage<'_> {
        TextMessage {
            message_type: self.message_type,
            sender_handle: self.sender_handle.as_deref(),
            sequence: self.sequence,
            sequence_reset: self.sequence_reset,
            regarding: self.regarding,
            editing: self.editing,
            bg_color: self.bg_color,
            text_color: self.text_color,
            body: &self.body,
        }
    }
}

impl TryFrom<TextMessage<'_>> for OwnedTextMessage {
    type Error = core::fmt::Error;

    fn try_from(value: TextMessage<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            message_type: value.message_type,
            sender_handle: value.sender_handle.map(String::from),
            sequence: value.sequence,
            sequence_reset: value.sequence_reset,
            regarding: value.regarding,
            editing: value.editing,
            bg_color: value.bg_color,
            text_color: value.text_color,
            body: String::from(value.body),
        })
    }
}

/// Owned form of a parsed node-identity payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedNodeIdentityPayload {
    pub timestamp: u32,
    pub role: NodeRole,
    pub capabilities: umsh_app::Capabilities,
    pub name: Option<String>,
    pub options: Option<Vec<u8>>,
    pub signature: Option<[u8; 64]>,
}

impl OwnedNodeIdentityPayload {
    pub fn as_borrowed(&self) -> NodeIdentityPayload<'_> {
        NodeIdentityPayload {
            timestamp: self.timestamp,
            role: self.role,
            capabilities: self.capabilities,
            name: self.name.as_deref(),
            options: self.options.as_deref(),
            signature: self.signature.as_ref(),
        }
    }
}

impl TryFrom<NodeIdentityPayload<'_>> for OwnedNodeIdentityPayload {
    type Error = core::fmt::Error;

    fn try_from(value: NodeIdentityPayload<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            timestamp: value.timestamp,
            role: value.role,
            capabilities: value.capabilities,
            name: value.name.map(String::from),
            options: value.options.map(Vec::from),
            signature: value.signature.copied(),
        })
    }
}

/// Owned form of a parsed MAC command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedMacCommand {
    BeaconRequest { nonce: Option<u32> },
    IdentityRequest,
    SignalReportRequest,
    SignalReportResponse { rssi: u8, snr: i8 },
    EchoRequest { data: Vec<u8> },
    EchoResponse { data: Vec<u8> },
    PfsSessionRequest { ephemeral_key: PublicKey, duration_minutes: u16 },
    PfsSessionResponse { ephemeral_key: PublicKey, duration_minutes: u16 },
    EndPfsSession,
}

impl From<umsh_app::MacCommand<'_>> for OwnedMacCommand {
    fn from(value: umsh_app::MacCommand<'_>) -> Self {
        match value {
            umsh_app::MacCommand::BeaconRequest { nonce } => Self::BeaconRequest { nonce },
            umsh_app::MacCommand::IdentityRequest => Self::IdentityRequest,
            umsh_app::MacCommand::SignalReportRequest => Self::SignalReportRequest,
            umsh_app::MacCommand::SignalReportResponse { rssi, snr } => Self::SignalReportResponse { rssi, snr },
            umsh_app::MacCommand::EchoRequest { data } => Self::EchoRequest { data: Vec::from(data) },
            umsh_app::MacCommand::EchoResponse { data } => Self::EchoResponse { data: Vec::from(data) },
            umsh_app::MacCommand::PfsSessionRequest { ephemeral_key, duration_minutes } => {
                Self::PfsSessionRequest { ephemeral_key, duration_minutes }
            }
            umsh_app::MacCommand::PfsSessionResponse { ephemeral_key, duration_minutes } => {
                Self::PfsSessionResponse { ephemeral_key, duration_minutes }
            }
            umsh_app::MacCommand::EndPfsSession => Self::EndPfsSession,
        }
    }
}

/// Owned endpoint events emitted by the application-facing node layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointEvent {
    TextReceived { from: PublicKey, message: OwnedTextMessage },
    ChannelTextReceived { from: PublicKey, channel_id: ChannelId, message: OwnedTextMessage },
    NodeDiscovered { key: PublicKey, identity: OwnedNodeIdentityPayload },
    BeaconReceived { from_hint: umsh_core::NodeHint, from_key: Option<PublicKey> },
    AckReceived { peer: PublicKey, receipt: SendReceipt },
    AckTimeout { peer: PublicKey, receipt: SendReceipt },
    PfsSessionEstablished { peer: PublicKey },
    PfsSessionEnded { peer: PublicKey },
    MacCommand { from: PublicKey, command: OwnedMacCommand },
}

/// Result of the synchronous endpoint event-handling phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventAction {
    Handled(Option<EndpointEvent>),
    NeedsAsync(DeferredAction),
}

/// Owned work item returned from `handle_event` for later processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferredAction {
    MacCommand { from: PublicKey, command: OwnedMacCommand },
}