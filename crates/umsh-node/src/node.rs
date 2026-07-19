use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::num::NonZeroU32;

use umsh_core::NodeHint;
use umsh_core::PublicKey;
use umsh_mac::{LocalIdentityId, SendOptions};

#[cfg(feature = "software-crypto")]
use crate::channel::Channel;
use crate::dispatch::EventDispatcher;
use crate::mac::MacBackend;
use crate::peer::PeerConnection;
#[cfg(feature = "software-crypto")]
use crate::pfs::{PfsSessionManager, PfsState};
use crate::receive::ReceivedPacketRef;
use crate::ticket::{SendProgressTicket, SendToken};
use crate::transport::Transport;
use crate::{AppEncodeError, OwnedMacCommand};

/// Per-node shared membership state. All cloned `LocalNode` handles and
/// their `BoundChannel`s share the same instance via `Rc<RefCell<...>>`.
pub(crate) struct NodeMembership {
    #[cfg(feature = "software-crypto")]
    pub channels: Vec<ChannelMembershipEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SubscriptionHandle(NonZeroU32);

/// Owned subscription guard.
///
/// Dropping the value automatically unregisters the callback.
pub struct Subscription {
    cancel: Rc<RefCell<Option<Box<dyn FnMut() -> bool>>>>,
}

impl Subscription {
    pub(crate) fn new(cancel: impl FnMut() -> bool + 'static) -> Self {
        Self {
            cancel: Rc::new(RefCell::new(Some(Box::new(cancel)))),
        }
    }

    /// Unregister immediately instead of waiting for drop.
    pub fn unsubscribe(self) -> bool {
        Self::run_cancel(&self.cancel)
    }

    fn run_cancel(cancel: &Rc<RefCell<Option<Box<dyn FnMut() -> bool>>>>) -> bool {
        let Some(mut cancel) = cancel.borrow_mut().take() else {
            return false;
        };
        cancel()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let _ = Self::run_cancel(&self.cancel);
    }
}

pub(crate) struct HandlerTable<T> {
    slots: Vec<Option<T>>,
}

impl<T> Default for HandlerTable<T> {
    fn default() -> Self {
        Self { slots: Vec::new() }
    }
}

impl<T> HandlerTable<T> {
    pub(crate) fn insert(&mut self, handler: T) -> SubscriptionHandle {
        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(handler);
            return SubscriptionHandle(NonZeroU32::new((index + 1) as u32).unwrap());
        }
        self.slots.push(Some(handler));
        SubscriptionHandle(NonZeroU32::new(self.slots.len() as u32).unwrap())
    }

    pub(crate) fn remove(&mut self, handle: SubscriptionHandle) -> bool {
        let index = handle.0.get() as usize - 1;
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        slot.take().is_some()
    }

    fn any_mut(&mut self, mut f: impl FnMut(&mut T) -> bool) -> bool {
        for slot in &mut self.slots {
            let Some(handler) = slot.as_mut() else {
                continue;
            };
            if f(handler) {
                return true;
            }
        }
        false
    }

    fn for_each_mut(&mut self, mut f: impl FnMut(&mut T)) {
        for slot in &mut self.slots {
            let Some(handler) = slot.as_mut() else {
                continue;
            };
            f(handler);
        }
    }
}

pub(crate) struct PendingPing {
    pub nonce: u16,
    pub peer: PublicKey,
    pub sent_at_ms: u64,
    pub deadline_ms: u64,
}

pub(crate) struct PeerSubscriptions {
    peer: PublicKey,
    pub(crate) receive_handlers: HandlerTable<Box<dyn FnMut(&ReceivedPacketRef<'_>) -> bool>>,
    pub(crate) ack_received_handlers: HandlerTable<Box<dyn FnMut(SendToken)>>,
    pub(crate) ack_timeout_handlers: HandlerTable<Box<dyn FnMut(SendToken)>>,
    pub(crate) pfs_established_handlers: HandlerTable<Box<dyn FnMut()>>,
    pub(crate) pfs_ended_handlers: HandlerTable<Box<dyn FnMut()>>,
    pub(crate) pong_handlers: HandlerTable<Box<dyn FnMut(u64)>>,
    pub(crate) ping_timeout_handlers: HandlerTable<Box<dyn FnMut()>>,
}

impl PeerSubscriptions {
    fn new(peer: PublicKey) -> Self {
        Self {
            peer,
            receive_handlers: HandlerTable::default(),
            ack_received_handlers: HandlerTable::default(),
            ack_timeout_handlers: HandlerTable::default(),
            pfs_established_handlers: HandlerTable::default(),
            pfs_ended_handlers: HandlerTable::default(),
            pong_handlers: HandlerTable::default(),
            ping_timeout_handlers: HandlerTable::default(),
        }
    }
}

pub(crate) struct LocalNodeState {
    receive_handlers: HandlerTable<Box<dyn FnMut(&ReceivedPacketRef<'_>) -> bool>>,
    node_discovered_handlers: HandlerTable<Box<dyn FnMut(PublicKey, Option<&str>)>>,
    beacon_handlers: HandlerTable<Box<dyn FnMut(NodeHint, Option<PublicKey>)>>,
    mac_command_handlers: HandlerTable<Box<dyn FnMut(PublicKey, &OwnedMacCommand)>>,
    transmitted_handlers: HandlerTable<Box<dyn FnMut(&[u8])>>,
    ack_received_handlers: HandlerTable<Box<dyn FnMut(PublicKey, SendToken)>>,
    ack_timeout_handlers: HandlerTable<Box<dyn FnMut(PublicKey, SendToken)>>,
    pfs_established_handlers: HandlerTable<Box<dyn FnMut(PublicKey)>>,
    pfs_ended_handlers: HandlerTable<Box<dyn FnMut(PublicKey)>>,
    pfs_failed_handlers: HandlerTable<Box<dyn FnMut(PublicKey, PfsFailure)>>,
    pong_handlers: HandlerTable<Box<dyn FnMut(PublicKey, u64)>>,
    ping_timeout_handlers: HandlerTable<Box<dyn FnMut(PublicKey)>>,
    pending_pings: Vec<PendingPing>,
    peer_subscriptions: Vec<PeerSubscriptions>,
    #[cfg(feature = "software-crypto")]
    pfs: PfsSessionManager,
}

impl LocalNodeState {
    pub(crate) fn new() -> Self {
        Self {
            receive_handlers: HandlerTable::default(),
            node_discovered_handlers: HandlerTable::default(),
            beacon_handlers: HandlerTable::default(),
            mac_command_handlers: HandlerTable::default(),
            transmitted_handlers: HandlerTable::default(),
            ack_received_handlers: HandlerTable::default(),
            ack_timeout_handlers: HandlerTable::default(),
            pfs_established_handlers: HandlerTable::default(),
            pfs_ended_handlers: HandlerTable::default(),
            pfs_failed_handlers: HandlerTable::default(),
            pong_handlers: HandlerTable::default(),
            ping_timeout_handlers: HandlerTable::default(),
            pending_pings: Vec::new(),
            peer_subscriptions: Vec::new(),
            #[cfg(feature = "software-crypto")]
            pfs: PfsSessionManager::new(),
        }
    }

    pub(crate) fn peer_subscriptions_mut(&mut self, peer: PublicKey) -> &mut PeerSubscriptions {
        if let Some(index) = self
            .peer_subscriptions
            .iter()
            .position(|entry| entry.peer == peer)
        {
            return &mut self.peer_subscriptions[index];
        }
        self.peer_subscriptions.push(PeerSubscriptions::new(peer));
        self.peer_subscriptions
            .last_mut()
            .expect("peer subscriptions just inserted")
    }

    pub(crate) fn find_peer_subscriptions_mut(
        &mut self,
        peer: PublicKey,
    ) -> Option<&mut PeerSubscriptions> {
        self.peer_subscriptions
            .iter_mut()
            .find(|entry| entry.peer == peer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "software-crypto")]
pub enum PfsStatus {
    Inactive,
    Requested,
    Active {
        local_ephemeral_id: LocalIdentityId,
        peer_ephemeral: PublicKey,
        expires_ms: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PfsLifecycle {
    Established(PublicKey),
    Ended(PublicKey),
}

/// Why a local PFS negotiation step failed. Surfaced to applications via
/// [`LocalNode::on_pfs_failed`] so a failed/stalled negotiation reports a
/// reason instead of silently doing nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PfsFailure {
    /// No free identity or peer slot to activate the ephemeral session —
    /// e.g. the MAC `IDENTITIES`/peer table is exhausted, or more concurrent
    /// PFS sessions were requested than there are ephemeral identity slots.
    Capacity,
    /// A PFS response or teardown referenced a session that does not exist.
    SessionMissing,
    /// Crypto failure while deriving the ephemeral session keys.
    Crypto,
    /// Failed to transmit a PFS control frame to the peer.
    Send,
    /// A sent PFS request was not answered before its deadline (the peer never
    /// responded, or its response was lost).
    Timeout,
    /// Any other node-layer failure during PFS processing.
    Other,
}

#[cfg(feature = "software-crypto")]
pub(crate) struct ChannelMembershipEntry {
    pub channel: Channel,
    /// Monotonically increasing per this (node, channel) pair.
    /// Bumped on leave; BoundChannel snapshots this at creation.
    pub generation: u64,
    /// False after leave(); entry kept until re-joined or GC'd.
    pub active: bool,
}

impl NodeMembership {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "software-crypto")]
            channels: Vec::new(),
        }
    }
}

/// Errors produced by node-layer operations.
#[derive(Clone, PartialEq, Eq)]
pub enum NodeError<M: MacBackend> {
    /// Underlying MAC-layer failure.
    Mac(crate::mac::MacBackendError<M::SendError, M::CapacityError>),
    /// The node has left this channel since the handle was created.
    ChannelLeft,
    /// The peer is not registered.
    PeerMissing,
    /// Control-payload encode failure.
    AppEncode(AppEncodeError),
    /// The referenced PFS session was missing.
    #[cfg(feature = "software-crypto")]
    PfsSessionMissing,
    /// The PFS session table is full.
    #[cfg(feature = "software-crypto")]
    PfsSessionTableFull,
    /// Crypto failure during PFS processing.
    #[cfg(feature = "software-crypto")]
    Crypto(umsh_crypto::CryptoError),
}

impl<M: MacBackend> NodeError<M> {
    /// Coarse classification of this error for surfacing PFS failures to
    /// applications (the concrete error type is generic over `M`, so callers
    /// that just want to report a failure use this instead).
    pub(crate) fn pfs_failure(&self) -> PfsFailure {
        use crate::mac::MacBackendError;
        match self {
            NodeError::Mac(MacBackendError::Capacity(_)) => PfsFailure::Capacity,
            NodeError::Mac(MacBackendError::Send(_)) => PfsFailure::Send,
            #[cfg(feature = "software-crypto")]
            NodeError::PfsSessionTableFull => PfsFailure::Capacity,
            #[cfg(feature = "software-crypto")]
            NodeError::PfsSessionMissing => PfsFailure::SessionMissing,
            #[cfg(feature = "software-crypto")]
            NodeError::Crypto(_) => PfsFailure::Crypto,
            _ => PfsFailure::Other,
        }
    }
}

impl<M> core::fmt::Debug for NodeError<M>
where
    M: MacBackend,
    M::SendError: core::fmt::Debug,
    M::CapacityError: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mac(e) => f.debug_tuple("Mac").field(e).finish(),
            Self::ChannelLeft => f.write_str("ChannelLeft"),
            Self::PeerMissing => f.write_str("PeerMissing"),
            Self::AppEncode(e) => f.debug_tuple("AppEncode").field(e).finish(),
            #[cfg(feature = "software-crypto")]
            Self::PfsSessionMissing => f.write_str("PfsSessionMissing"),
            #[cfg(feature = "software-crypto")]
            Self::PfsSessionTableFull => f.write_str("PfsSessionTableFull"),
            #[cfg(feature = "software-crypto")]
            Self::Crypto(e) => f.debug_tuple("Crypto").field(e).finish(),
        }
    }
}

impl<M: MacBackend> From<crate::mac::MacBackendError<M::SendError, M::CapacityError>>
    for NodeError<M>
{
    fn from(e: crate::mac::MacBackendError<M::SendError, M::CapacityError>) -> Self {
        Self::Mac(e)
    }
}

impl<M: MacBackend> From<AppEncodeError> for NodeError<M> {
    fn from(e: AppEncodeError) -> Self {
        Self::AppEncode(e)
    }
}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> From<umsh_crypto::CryptoError> for NodeError<M> {
    fn from(e: umsh_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Per-identity application handle.
///
/// `LocalNode` owns its channel membership set via shared interior state.
/// Different `LocalNode` instances (for different identities) may join
/// different channel sets.
#[derive(Clone)]
pub struct LocalNode<M: MacBackend> {
    identity_id: LocalIdentityId,
    mac: M,
    dispatcher: Rc<RefCell<EventDispatcher>>,
    #[allow(dead_code)] // Used by channel methods (software-crypto feature)
    membership: Rc<RefCell<NodeMembership>>,
    state: Rc<RefCell<LocalNodeState>>,
}

impl<M: MacBackend> LocalNode<M> {
    /// Create a new local node.
    pub(crate) fn new(
        identity_id: LocalIdentityId,
        mac: M,
        dispatcher: Rc<RefCell<EventDispatcher>>,
        membership: Rc<RefCell<NodeMembership>>,
        state: Rc<RefCell<LocalNodeState>>,
    ) -> Self {
        Self {
            identity_id,
            mac,
            dispatcher,
            membership,
            state,
        }
    }

    /// The identity slot this node operates on.
    pub fn identity_id(&self) -> LocalIdentityId {
        self.identity_id
    }

    /// Create a peer connection (registers peer in MAC if new).
    pub async fn peer(&self, key: PublicKey) -> Result<PeerConnection<Self>, NodeError<M>> {
        self.mac.add_peer(key).await?;
        Ok(PeerConnection::new(self.clone(), key))
    }

    /// Return the live TX frame counter for this node's identity, if available.
    pub async fn frame_counter(&self) -> Option<u32> {
        self.mac.frame_counter(self.identity_id).await
    }

    /// Return the persisted TX frame-counter boundary for this node's identity.
    pub async fn persisted_frame_counter(&self) -> Option<u32> {
        self.mac.persisted_frame_counter(self.identity_id).await
    }

    /// Invoke `f` for every peer currently registered in the MAC-layer peer registry.
    ///
    /// Covers all known peers, not just those with an active crypto session.
    pub async fn for_each_peer(&self, f: &mut dyn FnMut(PublicKey)) {
        self.mac.for_each_peer(f).await
    }

    /// Invoke `f` for each peer with established crypto state, passing the
    /// peer's public key, last-accepted RX counter, and persisted RX boundary.
    pub async fn for_each_peer_counter(&self, f: &mut dyn FnMut(PublicKey, u32, u32)) {
        self.mac.for_each_peer_counter(self.identity_id, f).await
    }

    fn add_receive_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(&ReceivedPacketRef<'_>) -> bool + 'static,
    {
        self.state
            .borrow_mut()
            .receive_handlers
            .insert(Box::new(handler))
    }

    pub fn on_receive<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(&ReceivedPacketRef<'_>) -> bool + 'static,
    {
        let handle = self.add_receive_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().receive_handlers.remove(handle))
    }

    fn add_node_discovered_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, Option<&str>) + 'static,
    {
        self.state
            .borrow_mut()
            .node_discovered_handlers
            .insert(Box::new(handler))
    }

    pub fn on_node_discovered<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, Option<&str>) + 'static,
    {
        let handle = self.add_node_discovered_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().node_discovered_handlers.remove(handle))
    }

    fn add_beacon_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(NodeHint, Option<PublicKey>) + 'static,
    {
        self.state
            .borrow_mut()
            .beacon_handlers
            .insert(Box::new(handler))
    }

    pub fn on_beacon<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(NodeHint, Option<PublicKey>) + 'static,
    {
        let handle = self.add_beacon_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().beacon_handlers.remove(handle))
    }

    fn add_mac_command_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, &OwnedMacCommand) + 'static,
    {
        self.state
            .borrow_mut()
            .mac_command_handlers
            .insert(Box::new(handler))
    }

    pub fn on_mac_command<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, &OwnedMacCommand) + 'static,
    {
        let handle = self.add_mac_command_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().mac_command_handlers.remove(handle))
    }

    fn add_transmitted_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(&[u8]) + 'static,
    {
        self.state
            .borrow_mut()
            .transmitted_handlers
            .insert(Box::new(handler))
    }

    /// Subscribe to raw on-wire bytes of every frame successfully handed to the radio.
    pub fn on_transmitted<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(&[u8]) + 'static,
    {
        let handle = self.add_transmitted_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().transmitted_handlers.remove(handle))
    }

    fn add_ack_received_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, SendToken) + 'static,
    {
        self.state
            .borrow_mut()
            .ack_received_handlers
            .insert(Box::new(handler))
    }

    pub fn on_ack_received<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, SendToken) + 'static,
    {
        let handle = self.add_ack_received_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().ack_received_handlers.remove(handle))
    }

    fn add_ack_timeout_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, SendToken) + 'static,
    {
        self.state
            .borrow_mut()
            .ack_timeout_handlers
            .insert(Box::new(handler))
    }

    pub fn on_ack_timeout<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, SendToken) + 'static,
    {
        let handle = self.add_ack_timeout_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().ack_timeout_handlers.remove(handle))
    }

    fn add_pfs_established_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey) + 'static,
    {
        self.state
            .borrow_mut()
            .pfs_established_handlers
            .insert(Box::new(handler))
    }

    pub fn on_pfs_established<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey) + 'static,
    {
        let handle = self.add_pfs_established_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().pfs_established_handlers.remove(handle))
    }

    fn add_pfs_ended_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey) + 'static,
    {
        self.state
            .borrow_mut()
            .pfs_ended_handlers
            .insert(Box::new(handler))
    }

    pub fn on_pfs_ended<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey) + 'static,
    {
        let handle = self.add_pfs_ended_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().pfs_ended_handlers.remove(handle))
    }

    fn add_pfs_failed_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, PfsFailure) + 'static,
    {
        self.state
            .borrow_mut()
            .pfs_failed_handlers
            .insert(Box::new(handler))
    }

    /// Subscribe to PFS negotiation failures for any peer. The handler is
    /// invoked with the peer's long-term key and a coarse [`PfsFailure`]
    /// reason whenever a local PFS step (accepting a request, completing a
    /// response, or tearing down) fails — so a stalled negotiation reports a
    /// reason instead of silently doing nothing.
    pub fn on_pfs_failed<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, PfsFailure) + 'static,
    {
        let handle = self.add_pfs_failed_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().pfs_failed_handlers.remove(handle))
    }

    fn add_pong_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, u64) + 'static,
    {
        self.state
            .borrow_mut()
            .pong_handlers
            .insert(Box::new(handler))
    }

    pub fn on_pong<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, u64) + 'static,
    {
        let handle = self.add_pong_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().pong_handlers.remove(handle))
    }

    fn add_ping_timeout_handler<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey) + 'static,
    {
        self.state
            .borrow_mut()
            .ping_timeout_handlers
            .insert(Box::new(handler))
    }

    pub fn on_ping_timeout<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey) + 'static,
    {
        let handle = self.add_ping_timeout_handler(handler);
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().ping_timeout_handlers.remove(handle))
    }

    pub(crate) fn record_ping(
        &self,
        nonce: u16,
        peer: PublicKey,
        sent_at_ms: u64,
        deadline_ms: u64,
    ) {
        self.state.borrow_mut().pending_pings.push(PendingPing {
            nonce,
            peer,
            sent_at_ms,
            deadline_ms,
        });
    }

    pub(crate) async fn now_ms(&self) -> u64 {
        self.mac.now_ms().await
    }

    pub(crate) async fn fill_random(&self, dest: &mut [u8]) {
        self.mac.fill_random(dest).await
    }

    /// Called when an EchoResponse arrives. Matches against pending pings and fires pong handlers.
    pub(crate) fn match_pong(&self, from: PublicKey, data: &[u8], now_ms: u64) {
        if data.len() < 2 {
            return;
        }
        let nonce = u16::from_be_bytes([data[0], data[1]]);
        let mut state = self.state.borrow_mut();
        let idx = state
            .pending_pings
            .iter()
            .position(|p| p.nonce == nonce && p.peer == from);
        if let Some(idx) = idx {
            let ping = state.pending_pings.swap_remove(idx);
            let rtt_ms = now_ms.saturating_sub(ping.sent_at_ms);
            if let Some(entry) = state.peer_subscriptions.iter_mut().find(|e| e.peer == from) {
                entry.pong_handlers.for_each_mut(|h| h(rtt_ms));
            }
            state.pong_handlers.for_each_mut(|h| h(from, rtt_ms));
        }
    }

    /// Called periodically by the host timeout service. Fires timeout handlers for expired pings.
    pub(crate) fn expire_pings(&self, now_ms: u64) {
        let mut state = self.state.borrow_mut();
        let mut i = 0;
        while i < state.pending_pings.len() {
            if now_ms >= state.pending_pings[i].deadline_ms {
                let ping = state.pending_pings.swap_remove(i);
                if let Some(entry) = state
                    .peer_subscriptions
                    .iter_mut()
                    .find(|e| e.peer == ping.peer)
                {
                    entry.ping_timeout_handlers.for_each_mut(|h| h());
                }
                state.ping_timeout_handlers.for_each_mut(|h| h(ping.peer));
            } else {
                i += 1;
            }
        }
    }

    #[cfg(feature = "software-crypto")]
    pub async fn request_pfs(
        &self,
        peer: &PublicKey,
        duration_minutes: u16,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let receipt = self
            .state
            .borrow_mut()
            .pfs
            .request_session(&self.mac, self.identity_id, peer, duration_minutes, options)
            .await?;
        Ok(self.register_ack_send(self.identity_id, receipt))
    }

    #[cfg(feature = "software-crypto")]
    pub async fn end_pfs(
        &self,
        peer: &PublicKey,
        options: &SendOptions,
    ) -> Result<(), NodeError<M>> {
        let _ = self
            .state
            .borrow_mut()
            .pfs
            .end_session(&self.mac, self.identity_id, peer, true, options)
            .await?;
        Ok(())
    }

    #[cfg(feature = "software-crypto")]
    pub async fn pfs_status(&self, peer: &PublicKey) -> Result<PfsStatus, NodeError<M>> {
        let now_ms = self.mac.now_ms().await;
        let state = self.state.borrow();
        if let Some(session) = state
            .pfs
            .sessions()
            .iter()
            .find(|session| session.peer_long_term == *peer)
        {
            return Ok(match session.state {
                PfsState::Requested => PfsStatus::Requested,
                PfsState::Active => PfsStatus::Active {
                    local_ephemeral_id: session.local_ephemeral_id,
                    peer_ephemeral: session.peer_ephemeral,
                    expires_ms: session.expires_ms,
                },
            });
        }
        if state.pfs.active_route(peer, now_ms).is_some() {
            // Defensive fallback for any future session bookkeeping changes.
            return Ok(PfsStatus::Requested);
        }
        Ok(PfsStatus::Inactive)
    }

    /// Join a channel. Registers the channel key in the MAC if this is
    /// the first node to join it. Returns the bound channel handle.
    #[cfg(feature = "software-crypto")]
    pub async fn join(&self, channel: &Channel) -> Result<BoundChannel<M>, NodeError<M>> {
        let mut membership = self.membership.borrow_mut();

        // Check if already joined.
        if let Some(entry) = membership
            .channels
            .iter_mut()
            .find(|e| e.channel == *channel)
        {
            if entry.active {
                return Ok(BoundChannel {
                    node: self.clone(),
                    channel: entry.channel.clone(),
                    join_generation: entry.generation,
                });
            }
            // Re-joining after leave — mark active again, bump generation.
            entry.active = true;
            entry.generation = entry.generation.wrapping_add(1);
            return Ok(BoundChannel {
                node: self.clone(),
                channel: entry.channel.clone(),
                join_generation: entry.generation,
            });
        }

        // New channel — register with MAC.
        drop(membership);
        self.mac.add_private_channel(channel.key().clone()).await?;
        let mut membership = self.membership.borrow_mut();

        let generation = 0;
        membership.channels.push(ChannelMembershipEntry {
            channel: channel.clone(),
            generation,
            active: true,
        });

        Ok(BoundChannel {
            node: self.clone(),
            channel: channel.clone(),
            join_generation: generation,
        })
    }

    /// Leave a channel. Marks the membership entry inactive and bumps
    /// that entry's generation counter.
    #[cfg(feature = "software-crypto")]
    pub fn leave(&self, channel: &Channel) -> Result<(), NodeError<M>> {
        let mut membership = self.membership.borrow_mut();
        if let Some(entry) = membership
            .channels
            .iter_mut()
            .find(|e| e.channel == *channel && e.active)
        {
            entry.active = false;
            entry.generation = entry.generation.wrapping_add(1);
        }
        Ok(())
    }

    /// Get a handle to an already-joined channel.
    #[cfg(feature = "software-crypto")]
    pub fn bound_channel(&self, channel: &Channel) -> Option<BoundChannel<M>> {
        let membership = self.membership.borrow();
        membership
            .channels
            .iter()
            .find(|e| e.channel == *channel && e.active)
            .map(|entry| BoundChannel {
                node: self.clone(),
                channel: entry.channel.clone(),
                join_generation: entry.generation,
            })
    }

    /// List all joined channels.
    #[cfg(feature = "software-crypto")]
    pub fn bound_channels(&self) -> Vec<BoundChannel<M>> {
        let membership = self.membership.borrow();
        membership
            .channels
            .iter()
            .filter(|e| e.active)
            .map(|entry| BoundChannel {
                node: self.clone(),
                channel: entry.channel.clone(),
                join_generation: entry.generation,
            })
            .collect()
    }

    /// Register an ACK-tracked send with the dispatcher and return a progress ticket.
    fn register_ack_send(
        &self,
        send_identity_id: LocalIdentityId,
        receipt: Option<umsh_mac::SendReceipt>,
    ) -> SendProgressTicket {
        match receipt {
            Some(receipt) => {
                let token = SendToken::new(send_identity_id, receipt);
                let state = self.dispatcher.borrow_mut().register_ticket(token, false);
                SendProgressTicket::new(token, state)
            }
            // Unicast/blind-unicast without ACK requested — no tracking.
            None => SendProgressTicket::fire_and_forget(),
        }
    }

    /// Register a non-ACK send (broadcast/multicast) with the dispatcher.
    ///
    /// The ticket starts unfinished. The dispatcher marks it transmitted and
    /// finished when the MAC fires the `Transmitted` event with this receipt.
    fn register_non_ack_send(
        &self,
        send_identity_id: LocalIdentityId,
        receipt: umsh_mac::SendReceipt,
    ) -> SendProgressTicket {
        let token = SendToken::new(send_identity_id, receipt);
        let state = self.dispatcher.borrow_mut().register_ticket(token, true);
        SendProgressTicket::new(token, state)
    }

    pub(crate) fn state(&self) -> &Rc<RefCell<LocalNodeState>> {
        &self.state
    }

    #[cfg(feature = "software-crypto")]
    pub(crate) fn owns_ephemeral_identity(&self, identity_id: LocalIdentityId) -> bool {
        self.state
            .borrow()
            .pfs
            .sessions()
            .iter()
            .any(|session| session.local_ephemeral_id == identity_id)
    }

    #[cfg(feature = "software-crypto")]
    pub(crate) async fn handle_pfs_command(
        &self,
        from: &PublicKey,
        command: &OwnedMacCommand,
        options: &SendOptions,
    ) -> Result<Option<PfsLifecycle>, NodeError<M>> {
        match *command {
            OwnedMacCommand::PfsSessionRequest {
                ephemeral_key,
                duration_minutes,
            } => {
                self.state
                    .borrow_mut()
                    .pfs
                    .accept_request(
                        &self.mac,
                        self.identity_id,
                        *from,
                        ephemeral_key,
                        duration_minutes,
                        options,
                    )
                    .await?;
                Ok(Some(PfsLifecycle::Established(*from)))
            }
            OwnedMacCommand::PfsSessionResponse {
                ephemeral_key,
                duration_minutes,
            } => {
                if self
                    .state
                    .borrow_mut()
                    .pfs
                    .accept_response(
                        &self.mac,
                        self.identity_id,
                        *from,
                        ephemeral_key,
                        duration_minutes,
                    )
                    .await?
                {
                    Ok(Some(PfsLifecycle::Established(*from)))
                } else {
                    Ok(None)
                }
            }
            OwnedMacCommand::EndPfsSession => {
                let _ = self
                    .state
                    .borrow_mut()
                    .pfs
                    .end_session(&self.mac, self.identity_id, from, false, options)
                    .await?;
                Ok(Some(PfsLifecycle::Ended(*from)))
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn dispatch_received_packet(&self, packet: &ReceivedPacketRef<'_>) -> bool {
        let peer = packet.from_key();
        let mut state = self.state.borrow_mut();

        if let Some(peer) = peer.map(|peer| canonical_peer(&state, peer)) {
            if let Some(entry) = state
                .peer_subscriptions
                .iter_mut()
                .find(|entry| entry.peer == peer)
            {
                if entry.receive_handlers.any_mut(|handler| handler(packet)) {
                    return true;
                }
            }
        }

        state.receive_handlers.any_mut(|handler| handler(packet))
    }

    pub(crate) fn dispatch_node_discovered(&self, key: PublicKey, name: Option<&str>) {
        self.state
            .borrow_mut()
            .node_discovered_handlers
            .for_each_mut(|handler| handler(key, name));
    }

    pub(crate) fn dispatch_beacon(&self, from_hint: NodeHint, from_key: Option<PublicKey>) {
        self.state
            .borrow_mut()
            .beacon_handlers
            .for_each_mut(|handler| handler(from_hint, from_key));
    }

    pub(crate) fn dispatch_mac_command(&self, from: PublicKey, command: &OwnedMacCommand) {
        self.state
            .borrow_mut()
            .mac_command_handlers
            .for_each_mut(|handler| handler(from, command));
    }

    pub(crate) fn dispatch_transmitted(&self, wire_bytes: &[u8]) {
        self.state
            .borrow_mut()
            .transmitted_handlers
            .for_each_mut(|handler| handler(wire_bytes));
    }

    pub(crate) fn dispatch_ack_received(&self, peer: PublicKey, token: SendToken) {
        let mut state = self.state.borrow_mut();
        let peer = canonical_peer(&state, peer);
        if let Some(entry) = state
            .peer_subscriptions
            .iter_mut()
            .find(|entry| entry.peer == peer)
        {
            entry
                .ack_received_handlers
                .for_each_mut(|handler| handler(token));
        }
        state
            .ack_received_handlers
            .for_each_mut(|handler| handler(peer, token));
    }

    pub(crate) fn dispatch_ack_timeout(&self, peer: PublicKey, token: SendToken) {
        let mut state = self.state.borrow_mut();
        let peer = canonical_peer(&state, peer);
        if let Some(entry) = state
            .peer_subscriptions
            .iter_mut()
            .find(|entry| entry.peer == peer)
        {
            entry
                .ack_timeout_handlers
                .for_each_mut(|handler| handler(token));
        }
        state
            .ack_timeout_handlers
            .for_each_mut(|handler| handler(peer, token));
    }

    pub(crate) fn dispatch_pfs_established(&self, peer: PublicKey) {
        let mut state = self.state.borrow_mut();
        let peer = canonical_peer(&state, peer);
        if let Some(entry) = state
            .peer_subscriptions
            .iter_mut()
            .find(|entry| entry.peer == peer)
        {
            entry
                .pfs_established_handlers
                .for_each_mut(|handler| handler());
        }
        state
            .pfs_established_handlers
            .for_each_mut(|handler| handler(peer));
    }

    pub(crate) fn dispatch_pfs_ended(&self, peer: PublicKey) {
        let mut state = self.state.borrow_mut();
        let peer = canonical_peer(&state, peer);
        if let Some(entry) = state
            .peer_subscriptions
            .iter_mut()
            .find(|entry| entry.peer == peer)
        {
            entry.pfs_ended_handlers.for_each_mut(|handler| handler());
        }
        state
            .pfs_ended_handlers
            .for_each_mut(|handler| handler(peer));
    }

    pub(crate) fn dispatch_pfs_failed(&self, peer: PublicKey, reason: PfsFailure) {
        let mut state = self.state.borrow_mut();
        let peer = canonical_peer(&state, peer);
        state
            .pfs_failed_handlers
            .for_each_mut(|handler| handler(peer, reason));
    }

    pub(crate) async fn expire_pfs_sessions(&self) -> Result<Vec<PublicKey>, NodeError<M>> {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.mac.now_ms().await;
            return self
                .state
                .borrow_mut()
                .pfs
                .expire_sessions(&self.mac, now_ms)
                .await;
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            Ok(Vec::new())
        }
    }

    /// Drop any sent PFS requests that were not answered before their deadline,
    /// returning the peers so the caller can report a [`PfsFailure::Timeout`].
    #[cfg(feature = "software-crypto")]
    pub(crate) fn expire_pfs_requests(&self, now_ms: u64) -> Vec<PublicKey> {
        self.state.borrow_mut().pfs.expire_requests(now_ms)
    }
}

fn canonical_peer(state: &LocalNodeState, peer: PublicKey) -> PublicKey {
    #[cfg(feature = "software-crypto")]
    {
        if let Some(session) = state
            .pfs
            .sessions()
            .iter()
            .find(|session| session.state == PfsState::Active && session.peer_ephemeral == peer)
        {
            return session.peer_long_term;
        }
    }
    peer
}

impl<M: MacBackend> Transport for LocalNode<M> {
    type Error = NodeError<M>;

    async fn send(
        &self,
        to: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error> {
        #[cfg(feature = "software-crypto")]
        let (send_identity_id, receipt) = {
            let now_ms = self.mac.now_ms().await;
            if let Some((local_id, peer_ephemeral)) =
                self.state.borrow().pfs.active_route(to, now_ms)
            {
                let receipt = self
                    .mac
                    .send_unicast(local_id, &peer_ephemeral, payload, options)
                    .await?;
                (local_id, receipt)
            } else {
                let receipt = self
                    .mac
                    .send_unicast(self.identity_id, to, payload, options)
                    .await?;
                (self.identity_id, receipt)
            }
        };
        #[cfg(not(feature = "software-crypto"))]
        let (send_identity_id, receipt) = (
            self.identity_id,
            self.mac
                .send_unicast(self.identity_id, to, payload, options)
                .await?,
        );
        Ok(self.register_ack_send(send_identity_id, receipt))
    }

    async fn send_all(
        &self,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error> {
        let receipt = self
            .mac
            .send_broadcast(self.identity_id, payload, options)
            .await?;
        Ok(self.register_non_ack_send(self.identity_id, receipt))
    }
}

/// A channel bound to a specific `LocalNode`. Implements `Transport`.
///
/// Holds a snapshot of the per-channel membership generation at creation
/// time. If the node leaves this channel, operations return
/// `NodeError::ChannelLeft`.
#[cfg(feature = "software-crypto")]
#[derive(Clone)]
pub struct BoundChannel<M: MacBackend> {
    node: LocalNode<M>,
    channel: Channel,
    join_generation: u64,
}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> BoundChannel<M> {
    /// The underlying channel descriptor.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// True if the node is still a member of this channel.
    pub fn is_active(&self) -> bool {
        let membership = self.node.membership.borrow();
        membership
            .channels
            .iter()
            .any(|e| e.channel == self.channel && e.active && e.generation == self.join_generation)
    }

    /// Create a peer connection through this channel.
    pub fn peer(&self, key: PublicKey) -> PeerConnection<Self> {
        PeerConnection::new(self.clone(), key)
    }

    /// Check membership is still valid.
    fn check_active(&self) -> Result<(), NodeError<M>> {
        if self.is_active() {
            Ok(())
        } else {
            Err(NodeError::ChannelLeft)
        }
    }

    /// Return the owning local node for this bound channel.
    pub fn node(&self) -> &LocalNode<M> {
        &self.node
    }
}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> Transport for BoundChannel<M> {
    type Error = NodeError<M>;

    async fn send(
        &self,
        to: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error> {
        self.check_active()?;
        let receipt = self
            .node
            .mac
            .send_blind_unicast(
                self.node.identity_id,
                to,
                self.channel.channel_id(),
                payload,
                options,
            )
            .await?;
        Ok(self.node.register_ack_send(self.node.identity_id, receipt))
    }

    async fn send_all(
        &self,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error> {
        self.check_active()?;
        let receipt = self
            .node
            .mac
            .send_multicast(
                self.node.identity_id,
                self.channel.channel_id(),
                payload,
                options,
            )
            .await?;
        Ok(self
            .node
            .register_non_ack_send(self.node.identity_id, receipt))
    }
}
