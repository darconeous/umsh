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

/// The node a transport context sends through.
///
/// Bookkeeping that belongs to the node rather than the carriage—pending
/// pings, per-peer subscriptions, the MAC's clock and route cache—lives on
/// [`LocalNode`](crate::LocalNode) whichever way a frame goes out. Reaching it
/// through this trait is what lets one implementation of ping, identity
/// requests, and peer subscriptions serve both a plain unicast peer and one
/// bound to a channel.
///
/// Sealed: implemented for `LocalNode` and `BoundChannel` only.
pub trait NodeAccess: sealed::Sealed {
    type Backend: crate::mac::MacBackend;

    fn local_node(&self) -> &crate::node::LocalNode<Self::Backend>;
}

pub(crate) mod sealed {
    pub trait Sealed {}
}
