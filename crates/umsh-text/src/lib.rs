#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Text-message support for UMSH.
//!
//! This crate owns the text-message payload types/codecs together with the
//! node-layer convenience wrappers for plain chat-style applications.
//!
//! Applications that want raw packet access can stay at the `umsh-node`
//! layer, while callers that want text-specific ergonomics can build on the
//! wrappers here.

extern crate alloc;

use alloc::vec::Vec;
mod error;
mod text;

use umsh_core::{PacketType, PayloadType};
use umsh_mac::SendOptions;
use umsh_node::{LocalNode, Subscription, Transport};

#[cfg(feature = "software-crypto")]
use umsh_node::{BoundChannel, MacBackend};

pub use error::{EncodeError, ParseError, TextSendError};
pub use text::{
    Fragment, MessageSequence, MessageType, OwnedTextMessage, Regarding, TextMessage,
    encode as encode_text_message, parse as parse_text_message,
};

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

/// Namespace for raw text-message codec functions.
pub mod text_message {
    pub use crate::text::{encode, parse};
}

use umsh_node::PeerConnection;
use umsh_node::SendProgressTicket;

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
    ) -> Result<SendProgressTicket, TextSendError<T::Error>>
    {
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
    ) -> Result<SendProgressTicket, TextSendError<T::Error>>
    {
        self.send_message(&message.as_borrowed(), options).await
    }

    pub async fn send_text(
        &self,
        body: &str,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<T::Error>>
    {
        let message = TextMessage {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body,
        };
        self.send_message(&message, options).await
    }
}

impl<M: umsh_node::MacBackend> UnicastTextChatWrapper<LocalNode<M>> {
    pub fn on_text<F>(&self, mut handler: F) -> Subscription
    where
        F: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
    {
        self.peer.on_receive(move |packet| {
            if packet.payload_type() != PayloadType::TextMessage {
                return false;
            }
            let Ok(message) = parse_text_message(packet.payload()) else {
                return false;
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
    ) -> Result<SendProgressTicket, TextSendError<umsh_node::NodeError<M>>>
    {
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
    ) -> Result<SendProgressTicket, TextSendError<umsh_node::NodeError<M>>>
    {
        self.send_message(&message.as_borrowed(), options).await
    }

    pub async fn send_text(
        &self,
        body: &str,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, TextSendError<umsh_node::NodeError<M>>>
    {
        let message = TextMessage {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body,
        };
        self.send_message(&message, options).await
    }

    pub fn on_text<F>(&self, mut handler: F) -> Subscription
    where
        F: FnMut(&umsh_node::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
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
                    return false;
                }
                let Ok(message) = parse_text_message(packet.payload()) else {
                    return false;
                };
                handler(packet, message);
                true
            })
    }
}

fn encode_text_payload(message: &TextMessage<'_>) -> Result<Vec<u8>, EncodeError> {
    let mut body = [0u8; 512];
    let len = text_message::encode(message, &mut body)?;
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
