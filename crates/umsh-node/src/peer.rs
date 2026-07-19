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

    pub fn on_pong<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(u64) + 'static,
    {
        let handle = self
            .transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pong_handlers
            .insert(Box::new(handler));
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.pong_handlers.remove(handle)
        })
    }

    pub fn on_ping_timeout<F>(&self, handler: F) -> Subscription
    where
        F: FnMut() + 'static,
    {
        let handle = self
            .transport
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .ping_timeout_handlers
            .insert(Box::new(handler));
        let state = self.transport.state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.ping_timeout_handlers.remove(handle)
        })
    }

    pub async fn ping(
        &self,
        extra_bytes: usize,
        options: &SendOptions,
        timeout_ms: u64,
    ) -> Result<crate::ticket::SendProgressTicket, NodeError<M>> {
        // Generate a 2-byte nonce via the MAC RNG.
        let mut nonce_bytes = [0u8; 2];
        self.transport.fill_random(&mut nonce_bytes).await;
        let nonce = u16::from_be_bytes(nonce_bytes);

        // Build data: [nonce_hi, nonce_lo, 0xA5, 0xA5, ...] capped at 60 bytes.
        let total = (2 + extra_bytes).min(60);
        let mut data = alloc::vec![0xA5u8; total];
        data[0] = nonce_bytes[0];
        data[1] = nonce_bytes[1];

        // Encode the outbound payload: PayloadType::MacCommand byte followed by
        // the encoded command body. The receiver's MAC dispatches on payload[0]
        // and the EchoRequest auto-reply in the coordinator depends on this
        // framing.
        let cmd = crate::mac_command::MacCommand::EchoRequest { data: &data };
        let mut buf = [0u8; 128];
        buf[0] = umsh_core::PayloadType::MacCommand as u8;
        let n = crate::mac_command::encode(&cmd, &mut buf[1..])?;
        let n = n + 1;

        // Record the pending ping BEFORE sending (avoid race if response is very fast).
        let sent_at_ms = self.transport.now_ms().await;
        self.transport
            .record_ping(nonce, self.peer, sent_at_ms, sent_at_ms + timeout_ms);

        // Send without MAC ack — the EchoResponse IS the ack.
        let mut opts = SendOptions::default().with_ack_requested(false);
        if let Some(hops) = options.flood_hops {
            opts = opts.with_flood_hops(hops);
        } else {
            opts = opts.no_flood();
        }
        if options.trace_route {
            opts = opts.with_trace_route();
        }
        self.send(&buf[..n], &opts).await
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
    pub async fn pfs_status(&self) -> Result<crate::node::PfsStatus, NodeError<M>> {
        self.transport.pfs_status(&self.peer).await
    }
}
