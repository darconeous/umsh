use umsh_core::PublicKey;
use umsh_mac::SendOptions;

use crate::ticket::SendProgressTicket;

/// A context through which UMSH frames can be sent.
///
/// Both `LocalNode` and `BoundChannel` implement this trait, allowing
/// generic code over the transport context.
///
/// **Important:** `Transport` is a *context* abstraction, not a *security*
/// abstraction. `LocalNode::send()` produces a unicast frame (destination-
/// encrypted, only the recipient can decrypt). `BoundChannel::send()`
/// produces a blind unicast frame (channel-encrypted — any node with the
/// channel key can decrypt). Generic code over `Transport` must not assume
/// identical delivery or privacy properties.
pub trait Transport {
    type Error;

    /// Send a payload to a specific destination.
    ///
    /// - On `LocalNode`: unicast (destination-encrypted)
    /// - On `BoundChannel`: blind unicast (channel-encrypted)
    async fn send(
        &self,
        to: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error>;

    /// Send a payload to all reachable nodes in this transport's scope.
    ///
    /// - On `LocalNode`: broadcast (unauthenticated)
    /// - On `BoundChannel`: multicast (channel-encrypted)
    async fn send_all(
        &self,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error>;
}
