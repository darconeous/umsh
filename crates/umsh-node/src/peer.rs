use alloc::boxed::Box;

use umsh_core::{MicSize, PublicKey};
use umsh_mac::SendOptions;

/// MIC size callers should normally ask for on a ping.
///
/// A ping frame is otherwise nearly half MIC: with a 2-byte nonce the whole
/// frame is 34 bytes, 16 of them the authenticator. Dropping to 8 takes a
/// quarter off the airtime while leaving forgery resistance at 2^-64 — far
/// out of reach at LoRa packet rates, and the echo payload is a random nonce
/// and filler that is worth nothing to forge.
///
/// Not applied inside [`PeerConnection::ping`], which honours whatever it is
/// given: a caller measuring how 16-byte-MIC traffic fares should ping with a
/// 16-byte MIC.
pub const PING_MIC_SIZE: MicSize = MicSize::Mic8;

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

/// Everything a peer relationship needs from the node behind its transport.
///
/// Implemented once for both carriages: a peer reached through a channel gets
/// the same pings, subscriptions, and identity requests as one reached by
/// plain unicast, and each frame goes out over the transport it was built on.
impl<M, T> PeerConnection<T>
where
    M: crate::mac::MacBackend,
    T: Transport<Error = NodeError<M>> + crate::transport::NodeAccess<Backend = M>,
{
    fn add_receive_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(&ReceivedPacketRef<'_>) -> bool + 'static,
    {
        self.transport
            .local_node()
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
        let state = self.transport.local_node().state().clone();
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
            .local_node()
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
        let state = self.transport.local_node().state().clone();
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
            .local_node()
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
        let state = self.transport.local_node().state().clone();
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
            .local_node()
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_established_handlers
            .insert(Box::new(handler));
        let state = self.transport.local_node().state().clone();
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
            .local_node()
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pfs_ended_handlers
            .insert(Box::new(handler));
        let state = self.transport.local_node().state().clone();
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
            .local_node()
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .pong_handlers
            .insert(Box::new(handler));
        let state = self.transport.local_node().state().clone();
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
            .local_node()
            .state()
            .borrow_mut()
            .peer_subscriptions_mut(self.peer)
            .ping_timeout_handlers
            .insert(Box::new(handler));
        let state = self.transport.local_node().state().clone();
        let peer = self.peer;
        Subscription::new(move || {
            let mut state = state.borrow_mut();
            let Some(entry) = state.find_peer_subscriptions_mut(peer) else {
                return false;
            };
            entry.ping_timeout_handlers.remove(handle)
        })
    }

    /// Send an echo request and record it as pending until the matching echo
    /// response arrives or `timeout_ms` elapses.
    ///
    /// `options` is honoured as given, so a ping travels the same way the
    /// traffic it is measuring would: same MIC size, same encryption, same
    /// routing and region options. Only `ack_requested` is overridden — the
    /// echo response *is* the acknowledgement, so asking for a MAC ack as
    /// well would put a second frame on the air for nothing.
    ///
    /// `extra_bytes` pads the payload beyond the 2-byte nonce. Padding
    /// matters for the same reason the MIC size does: packet error rate rises
    /// with frame length, so a minimal ping reports a link as usable when a
    /// full-size message would not get through. See [`PING_MIC_SIZE`] for the
    /// MIC size callers should normally ask for.
    ///
    /// The padding is bounded by what one frame can carry, not by this call:
    /// a ping too large to build fails with the MAC's own send error rather
    /// than being quietly shortened into a measurement of a smaller frame.
    pub async fn ping(
        &self,
        extra_bytes: usize,
        options: &SendOptions,
        timeout_ms: u64,
    ) -> Result<crate::ticket::SendProgressTicket, NodeError<M>> {
        // Generate a 2-byte nonce via the MAC RNG.
        let mut nonce_bytes = [0u8; 2];
        self.transport
            .local_node()
            .fill_random(&mut nonce_bytes)
            .await;
        let nonce = u16::from_be_bytes(nonce_bytes);

        // Build data: [nonce_hi, nonce_lo, 0xA5, 0xA5, ...].
        let total = 2 + extra_bytes;
        let mut data = alloc::vec![0xA5u8; total];
        data[0] = nonce_bytes[0];
        data[1] = nonce_bytes[1];

        // Encode the outbound payload: PayloadType::MacCommand byte followed by
        // the encoded command body. The receiver's MAC dispatches on payload[0]
        // and the EchoRequest auto-reply in the coordinator depends on this
        // framing.
        let cmd = crate::mac_command::MacCommand::EchoRequest { data: &data };
        let mut buf = alloc::vec![0u8; total + 2];
        buf[0] = umsh_core::PayloadType::MacCommand as u8;
        let n = crate::mac_command::encode(&cmd, &mut buf[1..])?;
        let n = n + 1;

        // Record the pending ping BEFORE sending (avoid race if response is very fast).
        let sent_at_ms = self.transport.local_node().now_ms().await;
        self.transport.local_node().record_ping(
            nonce,
            self.peer,
            sent_at_ms,
            sent_at_ms + timeout_ms,
        );

        // The caller's options carry through unchanged: a ping that is
        // secured, sized or routed differently from real traffic measures a
        // link the real traffic will not use. Only the ack request is
        // dropped, because the EchoResponse already serves as one.
        let opts = options.clone().with_ack_requested(false);
        self.send(&buf[..n], &opts).await
    }

    /// Solicit this peer's current identity by sending a targeted MAC
    /// Identity Request (command 1). Because the request is a unicast to a
    /// specific peer, no filter options are needed — filters exist only to
    /// narrow a broadcast solicitation. A random NONCE is included so the
    /// peer echoes it in its identity response, matching the responder's
    /// correlation contract.
    ///
    /// The response arrives asynchronously as a `PayloadType::NodeIdentity`
    /// frame on the normal receive path, not as the return value here.
    pub async fn request_identity(
        &self,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let mut nonce_bytes = [0u8; 4];
        self.transport
            .local_node()
            .fill_random(&mut nonce_bytes)
            .await;
        let nonce = u32::from_be_bytes(nonce_bytes);

        let opts_block = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(nonce)?
            .build();
        let cmd = crate::mac_command::MacCommand::IdentityRequest {
            options: &opts_block,
        };
        let mut buf = [0u8; 128];
        buf[0] = umsh_core::PayloadType::MacCommand as u8;
        let n = crate::mac_command::encode(&cmd, &mut buf[1..])? + 1;

        self.send(&buf[..n], options).await
    }

    /// Ask this peer for one page of its known peer repeaters (command 10).
    ///
    /// `nonce` is echoed in the response, which is what tells one page's
    /// answer from a stale copy of an earlier one. `cursor` resumes an
    /// enumeration from where a previous response said to; pass `None` for
    /// the first page, and expect a Total on the answer to that one.
    ///
    /// The response arrives asynchronously as a MAC command on the normal
    /// receive path, not as the return value here.
    pub async fn request_peer_repeaters(
        &self,
        nonce: u16,
        cursor: Option<&[u8]>,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let mut builder = crate::mac_command::PeerRepeatersRequestBuilder::new().nonce(nonce)?;
        if let Some(cursor) = cursor {
            builder = builder.cursor(cursor)?;
        }
        let opts_block = builder.build();
        let cmd = crate::mac_command::MacCommand::PeerRepeatersRequest {
            options: &opts_block,
        };
        let mut buf = [0u8; 128];
        buf[0] = umsh_core::PayloadType::MacCommand as u8;
        let n = crate::mac_command::encode(&cmd, &mut buf[1..])? + 1;

        self.send(&buf[..n], options).await
    }

    /// The route the MAC has cached for this peer, if any.
    pub async fn route(&self) -> Option<umsh_mac::CachedRoute> {
        self.transport.local_node().peer_route(&self.peer).await
    }

    /// Forget this peer's cached route, returning whether one was held.
    pub async fn clear_route(&self) -> bool {
        self.transport
            .local_node()
            .clear_peer_route(&self.peer)
            .await
    }

    /// Install a route learned before this MAC existed, returning whether
    /// it could be installed.
    pub async fn restore_route(&self, route: umsh_mac::CachedRoute) -> bool {
        self.transport
            .local_node()
            .restore_peer_route(&self.peer, route)
            .await
    }
}

/// Forward secrecy is negotiated between two nodes, not inside a channel: the
/// session it establishes replaces the pairwise keys a unicast is sealed with.
/// These stay on the plain-unicast transport.
impl<M: crate::mac::MacBackend> PeerConnection<LocalNode<M>> {
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
