use umsh_core::PublicKey;
use umsh_mac::SendOptions;

use crate::ticket::SendProgressTicket;
use crate::transport::Transport;

/// Relationship with one remote peer, bound to a transport context.
///
/// Generic over `T: Transport` — works with `LocalNode` (unicast) or
/// `BoundChannel` (blind unicast) identically.
#[derive(Clone)]
pub struct PeerConnection<T: Transport> {
    transport: T,
    peer: PublicKey,
}

impl<T: Transport> PeerConnection<T> {
    /// Create a new peer connection.
    pub(crate) fn new(transport: T, peer: PublicKey) -> Self {
        Self { transport, peer }
    }

    /// The remote peer's public key.
    pub fn peer(&self) -> &PublicKey {
        &self.peer
    }

    /// Send a raw payload to this peer (delegates to `transport.send()`).
    pub async fn send(
        &self,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, T::Error> {
        self.transport.send(&self.peer, payload, options).await
    }
}
