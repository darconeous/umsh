use alloc::string::String;
use alloc::vec::Vec;

use umsh_app::{MessageType, TextMessage, parse_text_message, text_message};
use umsh_core::{PayloadType, PublicKey};
use umsh_mac::SendOptions;

use crate::mac::MacBackend;
use crate::node::{LocalNode, Subscription};
use crate::owned::OwnedTextMessage;
use crate::peer::PeerConnection;
use crate::ticket::SendProgressTicket;
use crate::transport::Transport;
#[cfg(feature = "software-crypto")]
use crate::BoundChannel;

/// Thin convenience wrapper for plain unicast text chat over a peer connection.
///
/// This adapter keeps text-message encoding and filtering out of [`LocalNode`]
/// while still making common app code pleasant to write.
#[derive(Clone)]
pub struct UnicastTextChatWrapper<T: Transport + Clone> {
    peer: PeerConnection<T>,
}

impl<T: Transport + Clone> UnicastTextChatWrapper<T> {
    /// Create a wrapper around an existing peer connection.
    pub fn new(peer: PeerConnection<T>) -> Self {
        Self { peer }
    }

    /// Clone a wrapper from a borrowed peer connection.
    pub fn from_peer(peer: &PeerConnection<T>) -> Self {
        Self { peer: peer.clone() }
    }

    /// Return the underlying peer connection.
    pub fn peer_connection(&self) -> &PeerConnection<T> {
        &self.peer
    }

    /// Return the wrapped peer's public key.
    pub fn peer(&self) -> &PublicKey {
        self.peer.peer()
    }

    /// Encode and send a full text-message payload.
    pub async fn send_message(
        &self,
        message: &OwnedTextMessage,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, T::Error>
    where
        T::Error: From<umsh_app::EncodeError>,
    {
        let payload = encode_text_payload(message).map_err(T::Error::from)?;
        self.peer.send(&payload, options).await
    }

    /// Encode and send a basic text body.
    pub async fn send_text(
        &self,
        body: &str,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, T::Error>
    where
        T::Error: From<umsh_app::EncodeError>,
    {
        let message = OwnedTextMessage {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body: String::from(body),
        };
        self.send_message(&message, options).await
    }
}

impl<M: MacBackend> UnicastTextChatWrapper<LocalNode<M>> {
    /// Register a callback that fires only for text messages on this peer.
    ///
    /// The callback receives both the raw accepted packet view and the decoded
    /// text payload so callers can inspect hops, channel metadata, security
    /// details, and the parsed text body together.
    pub fn on_text<F>(&self, mut handler: F) -> Subscription
    where
        F: FnMut(&crate::receive::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
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

/// Thin convenience wrapper for text chat over a bound multicast/blind-unicast channel.
///
/// Like [`UnicastTextChatWrapper`], this keeps payload parsing out of the node core
/// and offers the same raw-packet-plus-decoded-text callback style.
#[cfg(feature = "software-crypto")]
#[derive(Clone)]
pub struct MulticastTextChatWrapper<M: MacBackend> {
    channel: BoundChannel<M>,
}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> MulticastTextChatWrapper<M> {
    /// Create a wrapper around an existing bound channel.
    pub fn new(channel: BoundChannel<M>) -> Self {
        Self { channel }
    }

    /// Clone a wrapper from a borrowed bound channel.
    pub fn from_channel(channel: &BoundChannel<M>) -> Self {
        Self {
            channel: channel.clone(),
        }
    }

    /// Return the underlying bound channel.
    pub fn bound_channel(&self) -> &BoundChannel<M> {
        &self.channel
    }

    /// Encode and send a full text-message payload to the whole channel.
    pub async fn send_message(
        &self,
        message: &OwnedTextMessage,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, crate::node::NodeError<M>>
    where
        crate::node::NodeError<M>: From<umsh_app::EncodeError>,
    {
        let payload = encode_text_payload(message).map_err(crate::node::NodeError::from)?;
        self.channel.send_all(&payload, options).await
    }

    /// Encode and send a basic text body to the whole channel.
    pub async fn send_text(
        &self,
        body: &str,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, crate::node::NodeError<M>>
    where
        crate::node::NodeError<M>: From<umsh_app::EncodeError>,
    {
        let message = OwnedTextMessage {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body: String::from(body),
        };
        self.send_message(&message, options).await
    }

    /// Register a callback that fires only for text messages on this channel.
    ///
    /// The callback receives both the raw accepted packet view and the decoded
    /// text payload so callers can inspect hops, channel metadata, security
    /// details, and the parsed text body together.
    pub fn on_text<F>(&self, mut handler: F) -> Subscription
    where
        F: FnMut(&crate::receive::ReceivedPacketRef<'_>, TextMessage<'_>) + 'static,
    {
        let channel_id = *self.channel.channel().channel_id();
        self.channel.node().on_receive(move |packet| {
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

fn encode_text_payload(message: &OwnedTextMessage) -> Result<Vec<u8>, umsh_app::EncodeError> {
    let mut body = [0u8; 512];
    let len = text_message::encode(&message.as_borrowed(), &mut body)?;
    let mut payload = Vec::with_capacity(len + 1);
    payload.push(PayloadType::TextMessage as u8);
    payload.extend_from_slice(&body[..len]);
    Ok(payload)
}
