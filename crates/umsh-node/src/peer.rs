use alloc::boxed::Box;

use umsh_core::PublicKey;
use umsh_mac::SendOptions;

use crate::node::{LocalNode, NodeError, Subscription, SubscriptionHandle};
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
    fn add_receive_handler<F>(&self, handler: F) -> SubscriptionHandle
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

    pub fn on_receive<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(&ReceivedPacketRef<'_>) -> bool + 'static,
    {
        let handle = self.add_receive_handler(handler);
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.receive_handlers.remove(handle)
        })
    }

    fn add_ack_received_handler<F>(&self, handler: F) -> SubscriptionHandle
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

    pub fn on_ack_received<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(crate::SendToken) + 'static,
    {
        let handle = self.add_ack_received_handler(handler);
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.ack_received_handlers.remove(handle)
        })
    }

    fn add_ack_timeout_handler<F>(&self, handler: F) -> SubscriptionHandle
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

    pub fn on_ack_timeout<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(crate::SendToken) + 'static,
    {
        let handle = self.add_ack_timeout_handler(handler);
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.ack_timeout_handlers.remove(handle)
        })
    }

    pub fn on_pfs_established<F>(&self, handler: F) -> Subscription
    where
        F: FnMut() + 'static,
    {
        let handle = self
            .transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_established_handlers
            .insert(Box::new(handler));
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.pfs_established_handlers.remove(handle)
        })
    }

    pub fn on_pfs_ended<F>(&self, handler: F) -> Subscription
    where
        F: FnMut() + 'static,
    {
        let handle = self
            .transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_ended_handlers
            .insert(Box::new(handler));
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.pfs_ended_handlers.remove(handle)
        })
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
