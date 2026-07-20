//! Node-layer convenience wrappers for chat-style applications
//! (feature `node`).

use alloc::vec::Vec;

use umsh_core::{PacketType, PayloadType};
use umsh_mac::SendOptions;
use umsh_node::{LocalNode, PeerConnection, SendProgressTicket, Subscription, Transport};

#[cfg(feature = "software-crypto")]
use umsh_node::{BoundChannel, MacBackend};

use crate::{
    EncodeError, OwnedTextMessage, ParseError, TextMessage, TextSendError, encode_text_message,
    parse_text_message,
};

/// Reason a received packet did not become a text message callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextReceiveIssue {
    WrongPayloadType(PayloadType),
    Parse(ParseError),
}

/// Parse a typed text payload in the context of the enclosing packet type.
pub fn parse_text_payload(
    packet_type: PacketType,
    payload: &[u8],
) -> Result<TextMessage<'_>, ParseError> {
    parse_text_message(expect_payload_type(
        packet_type,
        payload,
        PayloadType::TextMessage,
    )?)
}

/// Thin convenience wrapper for plain unicast text chat over a peer connection.
#[derive(Clone)]
pub struct UnicastTextChatWrapper<T: Transport + Clone> {
    peer: PeerConnection<T>,
}

impl<T: Transport + Clone> UnicastTextChatWrapper<T> {
    pub fn new(peer: PeerConnection<T>) -> Self {
        Self { peer }
    }

    pub fn from_peer(peer: &PeerConnection<T>) -> Self {
        Self { peer: peer.clone() }
    }

    pub fn peer_connection(&self) -> &PeerConnection<T> {
        &self.peer
    }

    pub fn peer(&self) -> &umsh_core::PublicKey {
        self.peer.peer()
    }

    pub async fn send_message(
        &self,
        message: &TextMessage<'_>,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<T::Error>> {
        let payload = encode_text_payload(message)?;
        self.peer
            .send(&payload, options)
            .await
            .map_err(TextSendError::Transport)
    }

    pub async fn send_owned_message(
        &self,
        message: &OwnedTextMessage,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<T::Error>> {
        self.send_message(&message.as_borrowed(), options).await
    }

    pub async fn send_text(
        &self,
        body: &str,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<T::Error>> {
        self.send_message(&TextMessage::basic(body), options).await
    }
}

impl<M: umsh_node::MacBackend> UnicastTextChatWrapper<LocalNode<M>> {
    pub fn on_text<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
    {
        self.on_text_with_diagnostics(handler, |_, _| {})
    }

    pub fn on_text_with_diagnostics<F, D>(&self, mut handler: F, mut diagnostics: D) -> Subscription
    where
        F: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
        D: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextReceiveIssue) + 'static,
    {
        self.peer.on_receive(move |packet| {
            if packet.payload_type() != PayloadType::TextMessage {
                diagnostics(
                    packet,
                    TextReceiveIssue::WrongPayloadType(packet.payload_type()),
                );
                return false;
            }
            let message = match parse_text_message(packet.payload()) {
                Ok(message) => message,
                Err(error) => {
                    diagnostics(packet, TextReceiveIssue::Parse(error));
                    return false;
                }
            };
            handler(packet, message);
            true
        })
    }
}

#[cfg(feature = "software-crypto")]
#[derive(Clone)]
pub struct MulticastTextChatWrapper<M: MacBackend> {
    channel: BoundChannel<M>,
}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> MulticastTextChatWrapper<M> {
    pub fn new(channel: BoundChannel<M>) -> Self {
        Self { channel }
    }

    pub fn from_channel(channel: &BoundChannel<M>) -> Self {
        Self {
            channel: channel.clone(),
        }
    }

    pub fn bound_channel(&self) -> &BoundChannel<M> {
        &self.channel
    }

    pub async fn send_message(
        &self,
        message: &TextMessage<'_>,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<umsh_node::NodeError<M>>> {
        let payload = encode_text_payload(message)?;
        self.channel
            .send_all(&payload, options)
            .await
            .map_err(TextSendError::Transport)
    }

    pub async fn send_owned_message(
        &self,
        message: &OwnedTextMessage,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<umsh_node::NodeError<M>>> {
        self.send_message(&message.as_borrowed(), options).await
    }

    pub async fn send_text(
        &self,
        body: &str,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<umsh_node::NodeError<M>>> {
        self.send_message(&TextMessage::basic(body), options).await
    }

    pub fn on_text<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
    {
        self.on_text_with_diagnostics(handler, |_, _| {})
    }

    pub fn on_text_with_diagnostics<F, D>(&self, mut handler: F, mut diagnostics: D) -> Subscription
    where
        F: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
        D: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextReceiveIssue) + 'static,
    {
        let channel_id = *self.channel.channel().channel_id();
        self.channel
            .node()
            .on_receive(move |packet: &umsh_node::ReceivedPacketRef<'_>| {
                let Some(channel) = packet.channel() else {
                    return false;
                };
                if channel.id() != channel_id {
                    return false;
                }
                if packet.payload_type() != PayloadType::TextMessage {
                    diagnostics(
                        packet,
                        TextReceiveIssue::WrongPayloadType(packet.payload_type()),
                    );
                    return false;
                }
                let message = match parse_text_message(packet.payload()) {
                    Ok(message) => message,
                    Err(error) => {
                        diagnostics(packet, TextReceiveIssue::Parse(error));
                        return false;
                    }
                };
                handler(packet, message);
                true
            })
    }
}

fn encode_text_payload(message: &TextMessage<'_>) -> Result<Vec<u8>, EncodeError> {
    let mut body = [0u8; 512];
    let len = encode_text_message(message, &mut body)?;
    let mut payload = Vec::with_capacity(len + 1);
    payload.push(PayloadType::TextMessage as u8);
    payload.extend_from_slice(&body[..len]);
    Ok(payload)
}

/// Split a typed application payload into its type byte and body.
fn split_payload_type(payload: &[u8]) -> Result<(PayloadType, &[u8]), ParseError> {
    if payload.is_empty() {
        return Ok((PayloadType::Empty, &[]));
    }
    if let Some(payload_type) = PayloadType::from_byte(payload[0]) {
        Ok((payload_type, &payload[1..]))
    } else {
        Ok((PayloadType::Empty, payload))
    }
}

/// Validate that a packet carries the expected typed text payload.
fn expect_payload_type(
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
