use alloc::string::String;
use alloc::vec::Vec;

use umsh_app::{MessageType, PayloadType, text_message};
use umsh_core::PublicKey;
use umsh_mac::SendOptions;

use crate::mac::MacBackend;
use crate::node::{LocalNode, SubscriptionHandle};
use crate::owned::OwnedTextMessage;
use crate::peer::PeerConnection;
use crate::ticket::SendProgressTicket;
use crate::transport::Transport;

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
    pub fn on_text<F>(&self, mut handler: F) -> SubscriptionHandle
    where
        F: FnMut(&str) + 'static,
    {
        self.peer.on_receive(move |packet| {
            let Ok(parsed) = umsh_app::parse_payload(packet.packet_type(), packet.payload()) else {
                return false;
            };
            match parsed {
                umsh_app::PayloadRef::TextMessage(message) => {
                    handler(message.body);
                    true
                }
                _ => false,
            }
        })
    }

    /// Remove a previously-registered text callback.
    pub fn remove_text_handler(&self, handle: SubscriptionHandle) -> bool {
        self.peer.remove_receive_handler(handle)
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
