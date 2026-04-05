use alloc::boxed::Box;

use umsh_core::PublicKey;
use umsh_mac::SendOptions;

use crate::node::{LocalNode, NodeError, SubscriptionHandle};
use crate::receive::ReceivedPacketRef;
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

impl<M: crate::mac::MacBackend> PeerConnection<LocalNode<M>> {
    pub fn on_receive<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(&ReceivedPacketRef<'_>) -> bool + 'static,
    {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .receive_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_receive_handler(&self, handle: SubscriptionHandle) -> bool {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .receive_handlers
            .remove(handle)
    }

    pub fn on_ack_received<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(crate::SendToken) + 'static,
    {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .ack_received_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_ack_received_handler(&self, handle: SubscriptionHandle) -> bool {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .ack_received_handlers
            .remove(handle)
    }

    pub fn on_ack_timeout<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(crate::SendToken) + 'static,
    {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .ack_timeout_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_ack_timeout_handler(&self, handle: SubscriptionHandle) -> bool {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .ack_timeout_handlers
            .remove(handle)
    }

    pub fn on_pfs_established<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut() + 'static,
    {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_established_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_pfs_established_handler(&self, handle: SubscriptionHandle) -> bool {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_established_handlers
            .remove(handle)
    }

    pub fn on_pfs_ended<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut() + 'static,
    {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_ended_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_pfs_ended_handler(&self, handle: SubscriptionHandle) -> bool {
        self.transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_ended_handlers
            .remove(handle)
    }

    #[cfg(feature = "software-crypto")]
    pub async fn request_pfs(
        &self,
        duration_minutes: u16,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        self.transport
            .request_pfs(&self.peer, duration_minutes, options)
            .await
    }

    #[cfg(feature = "software-crypto")]
    pub async fn end_pfs(&self, options: &SendOptions) -> Result<(), NodeError<M>> {
        self.transport.end_pfs(&self.peer, options).await
    }

    #[cfg(feature = "software-crypto")]
    pub fn pfs_status(&self) -> Result<crate::node::PfsStatus, NodeError<M>> {
        self.transport.pfs_status(&self.peer)
    }
}
