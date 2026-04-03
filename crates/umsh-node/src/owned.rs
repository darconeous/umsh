use alloc::{string::String, vec::Vec};

use umsh_app::{MessageSequence, MessageType, NodeIdentityPayload, NodeRole, Regarding, TextMessage};
use umsh_core::{ChannelId, PublicKey};
use umsh_mac::SendReceipt;

/// Owned form of a parsed text-message payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedTextMessage {
    /// Rendering type.
    pub message_type: MessageType,
    /// Optional sender handle.
    pub sender_handle: Option<String>,
    /// Optional sender-local sequence metadata.
    pub sequence: Option<MessageSequence>,
    /// Whether the sender reset its message sequence.
    pub sequence_reset: bool,
    /// Optional reference to an earlier message.
    pub regarding: Option<Regarding>,
    /// Optional edit/delete reference.
    pub editing: Option<u8>,
    /// Suggested background color.
    pub bg_color: Option<[u8; 3]>,
    /// Suggested text color.
    pub text_color: Option<[u8; 3]>,
    /// UTF-8 body.
    pub body: String,
}

impl OwnedTextMessage {
    /// Borrow this message as a zero-copy `umsh-app` view.
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
    /// Identity timestamp.
    pub timestamp: u32,
    /// Advertised role.
    pub role: NodeRole,
    /// Advertised capabilities.
    pub capabilities: umsh_app::Capabilities,
    /// Optional display name.
    pub name: Option<String>,
    /// Optional raw option bytes.
    pub options: Option<Vec<u8>>,
    /// Optional detached signature.
    pub signature: Option<[u8; 64]>,
}

impl OwnedNodeIdentityPayload {
    /// Borrow this payload as a zero-copy `umsh-app` view.
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
    /// Direct text received.
    TextReceived { from: PublicKey, message: OwnedTextMessage },
    /// Channel text received.
    ChannelTextReceived { from: PublicKey, channel_id: ChannelId, message: OwnedTextMessage },
    /// Node identity discovered or updated.
    NodeDiscovered { key: PublicKey, identity: OwnedNodeIdentityPayload },
    /// Empty beacon broadcast received.
    BeaconReceived { from_hint: umsh_core::NodeHint, from_key: Option<PublicKey> },
    /// ACK received for a previously queued send.
    AckReceived { peer: PublicKey, receipt: SendReceipt },
    /// ACK timeout fired for a previously queued send.
    AckTimeout { peer: PublicKey, receipt: SendReceipt },
    /// PFS session became active.
    PfsSessionEstablished { peer: PublicKey },
    /// PFS session ended.
    PfsSessionEnded { peer: PublicKey },
    /// Parsed MAC command surfaced to the caller.
    MacCommand { from: PublicKey, command: OwnedMacCommand },
}

/// Result of the synchronous endpoint event-handling phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventAction {
    /// Event was handled inline, optionally producing an application event.
    Handled(Option<EndpointEvent>),
    /// Event requires follow-up work after the MAC callback returns.
    NeedsAsync(DeferredAction),
}

/// Owned work item returned from `handle_event` for later processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferredAction {
    /// Deferred MAC-command handling.
    MacCommand { from: PublicKey, command: OwnedMacCommand },
}