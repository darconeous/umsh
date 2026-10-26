use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::num::NonZeroU32;

use umsh_core::{ChannelId, NodeHint, PublicKey, RouterHint};
use umsh_mac::{CachedRoute, LocalIdentityId, SendOptions};

#[cfg(feature = "software-crypto")]
use crate::channel::Channel;
use crate::dispatch::EventDispatcher;
use crate::identity_responder::{
    IdentityRequestContext, IdentityResponder, IdentityResponsePlan, NodeIdentityProfile,
    RespondDecision, default_respond_policy,
};
use crate::mac::MacBackend;
use crate::peer::PeerConnection;
use crate::peer_repeaters::{self, PeerRepeaterTable};
#[cfg(feature = "software-crypto")]
use crate::pfs::{PfsSessionManager, PfsState};
use crate::receive::ReceivedPacketRef;
use crate::ticket::{SendProgressTicket, SendToken};
use crate::transport::Transport;
use crate::{AppEncodeError, NodeCapabilities, NodeRole, OwnedMacCommand};

/// Octets one Peer Repeaters Response body may occupy.
///
/// Sized against the same 192-octet reply buffer the identity responder
/// works to, less the payload-type and command bytes and the MAC's own
/// per-frame overhead. A list that does not fit is paged, so this is a
/// packing budget rather than a limit on what the node can report.
const PEER_REPEATERS_RESPONSE_BUDGET: usize = 160;

/// A cursor is the listing generation and the index to resume at.
///
/// The generation moves when an identity is recorded, which is what makes a
/// stale cursor recognizable. It does not move when the MAC hears a new
/// transmitter, so a neighbor first heard part way through a walk can shift
/// the entries after it by one—a listing describes a neighborhood at a
/// moment, and the spec lets a responder page imperfectly rather than freeze
/// a snapshot per requester.
const PEER_REPEATERS_CURSOR_LEN: usize = 3;

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

/// Measurements attached to an authenticated echo response.
///
/// RSSI, SNR, and LQI describe the final radio hop into this node. Route
/// hints are the authenticated trace-route entries accumulated by repeaters;
/// endpoints are not included in that list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PongMetadata {
    pub round_trip_ms: u64,
    /// Radio links the response crossed, counting the final one into this
    /// node: a direct reply is one hop. `None` when the reply was
    /// source-routed without a trace route, which crosses hops nobody
    /// recorded. See
    /// [`ReceivedPacketRef::hop_count`](umsh_mac::ReceivedPacketRef::hop_count).
    pub hop_count: Option<u8>,
    pub route_hints: Vec<RouterHint>,
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
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
    pong_metadata_handlers: HandlerTable<Box<dyn FnMut(PublicKey, &PongMetadata)>>,
    ping_timeout_handlers: HandlerTable<Box<dyn FnMut(PublicKey)>>,
    pending_pings: Vec<PendingPing>,
    peer_subscriptions: Vec<PeerSubscriptions>,
    identity_responder: Option<IdentityResponder>,
    /// The repeaters whose identities this node has seen, and whether it
    /// answers questions about them.
    peer_repeaters: PeerRepeaterTable,
    peer_repeaters_responder: bool,
    #[cfg(feature = "software-crypto")]
    pfs: PfsSessionManager,
    /// The session identity of a contact exchange in progress.
    #[cfg(feature = "software-crypto")]
    meet: Option<MeetSlot>,
}

/// A contact exchange's session identity and the peers registered to reach
/// it, all dropped together when the session closes.
#[cfg(feature = "software-crypto")]
struct MeetSlot {
    id: LocalIdentityId,
    peers: Vec<PublicKey>,
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
            pong_metadata_handlers: HandlerTable::default(),
            ping_timeout_handlers: HandlerTable::default(),
            pending_pings: Vec::new(),
            peer_subscriptions: Vec::new(),
            identity_responder: None,
            peer_repeaters: PeerRepeaterTable::new(),
            peer_repeaters_responder: false,
            #[cfg(feature = "software-crypto")]
            pfs: PfsSessionManager::new(),
            #[cfg(feature = "software-crypto")]
            meet: None,
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

#[cfg(feature = "software-crypto")]
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
    /// No free identity or peer slot to activate the ephemeral session—
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
    /// A source route longer than a frame can carry.
    RouteTooLong,
    /// The referenced PFS session was missing.
    #[cfg(feature = "software-crypto")]
    PfsSessionMissing,
    /// The PFS session table is full.
    #[cfg(feature = "software-crypto")]
    PfsSessionTableFull,
    /// Crypto failure during PFS processing.
    #[cfg(feature = "software-crypto")]
    Crypto(umsh_crypto::CryptoError),
    /// No contact-exchange session is open.
    #[cfg(feature = "software-crypto")]
    MeetClosed,
}

impl<M: MacBackend> NodeError<M> {
    /// Coarse classification of this error for surfacing PFS failures to
    /// applications (the concrete error type is generic over `M`, so callers
    /// that just want to report a failure use this instead).
    #[cfg(feature = "software-crypto")]
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
            Self::RouteTooLong => f.write_str("RouteTooLong"),
            #[cfg(feature = "software-crypto")]
            Self::PfsSessionMissing => f.write_str("PfsSessionMissing"),
            #[cfg(feature = "software-crypto")]
            Self::PfsSessionTableFull => f.write_str("PfsSessionTableFull"),
            #[cfg(feature = "software-crypto")]
            Self::Crypto(e) => f.debug_tuple("Crypto").field(e).finish(),
            #[cfg(feature = "software-crypto")]
            Self::MeetClosed => f.write_str("MeetClosed"),
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
/// What an [Identity Request](LocalNode::request_identities) asks of the
/// nodes it reaches. Nothing set asks every one of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdentityFilter<'a> {
    /// The leading bytes of the answering node's key: one to three, so a
    /// router hint names a repeater.
    pub hint_prefix: Option<&'a [u8]>,
    pub role: Option<NodeRole>,
    pub capabilities: Option<NodeCapabilities>,
}

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

    /// Remove a peer from the MAC and drop this node's per-peer bookkeeping:
    /// outstanding pings and per-peer subscription tables. Returns whether
    /// the peer was registered in the MAC. Idempotent—removing an unknown
    /// peer still clears any node-layer residue and reports `false`.
    pub async fn remove_peer(&self, key: &PublicKey) -> bool {
        let removed = self.mac.remove_peer(key).await;
        let mut state = self.state.borrow_mut();
        state.pending_pings.retain(|ping| ping.peer != *key);
        state.peer_subscriptions.retain(|entry| entry.peer != *key);
        removed
    }

    /// Return the live TX frame counter for this node's identity, if available.
    pub async fn frame_counter(&self) -> Option<u32> {
        self.mac.frame_counter(self.identity_id).await
    }

    /// Return the persisted TX frame-counter boundary for this node's identity.
    pub async fn persisted_frame_counter(&self) -> Option<u32> {
        self.mac.persisted_frame_counter(self.identity_id).await
    }

    /// Derive the pairwise transport keys this node's identity shares with
    /// `peer`—what a host exports to a companion radio so it can verify
    /// and acknowledge unicast traffic while the host is away. Deterministic
    /// per (identity, peer); the peer need not have exchanged anything yet.
    /// `None` when the backend cannot derive keys.
    pub async fn pairwise_keys_for_peer(
        &self,
        peer: &PublicKey,
    ) -> Option<umsh_crypto::PairwiseKeys> {
        self.mac
            .pairwise_keys_for_peer(self.identity_id, peer)
            .await
    }

    /// Invoke `f` for every peer currently registered in the MAC-layer peer registry.
    ///
    /// Covers all known peers, not just those with an active crypto session.
    pub async fn for_each_peer(&self, f: &mut dyn FnMut(PublicKey)) {
        self.mac.for_each_peer(f).await
    }

    /// Invoke `f` with the key of every channel registered in the MAC.
    pub async fn for_each_channel(&self, f: &mut dyn FnMut(&umsh_core::ChannelKey)) {
        self.mac.for_each_channel(f).await
    }

    /// Invoke `f` for each peer with established crypto state, passing the
    /// peer's public key, last-accepted RX counter, and persisted RX boundary.
    pub async fn for_each_peer_counter(&self, f: &mut dyn FnMut(PublicKey, u32, u32)) {
        self.mac.for_each_peer_counter(self.identity_id, f).await
    }

    /// Return the route the MAC has cached for `peer`, if any.
    ///
    /// A cached route is what the next send to this peer will use, so this is
    /// the state to inspect when traffic takes an unexpected path.
    pub async fn peer_route(&self, peer: &PublicKey) -> Option<CachedRoute> {
        self.mac.peer_route(peer).await
    }

    /// Forget the route cached for `peer`, returning whether one was held.
    ///
    /// Sends fall back to the default delivery mode until an inbound packet
    /// teaches a route again; the peer and its crypto state are untouched.
    pub async fn clear_peer_route(&self, peer: &PublicKey) -> bool {
        self.mac.clear_peer_route(peer).await
    }

    /// Install a route learned before this MAC existed, returning whether
    /// `peer` was registered to receive it.
    ///
    /// For a host that remembers routes across the lifetime of the stack
    /// underneath it; see [`umsh_mac::MacHandle::restore_peer_route`].
    pub async fn restore_peer_route(&self, peer: &PublicKey, route: CachedRoute) -> bool {
        self.mac.restore_peer_route(peer, route).await
    }

    /// Record whether `peer` advertises itself as mobile; see
    /// [`umsh_mac::MacHandle::set_peer_mobile`]. For a host that remembers
    /// an advertisement across the lifetime of the stack underneath it;
    /// one heard live is recorded without being asked.
    pub async fn set_peer_mobile(&self, peer: &PublicKey, mobile: bool) -> bool {
        self.mac.set_peer_mobile(peer, mobile).await
    }

    /// Install `route` for `peer` and hold it for `hold_ms`; see
    /// [`umsh_mac::MacHandle::hold_peer_route`].
    pub async fn hold_peer_route(
        &self,
        peer: &PublicKey,
        route: CachedRoute,
        flood_hops: u8,
        hold_ms: u64,
    ) -> bool {
        self.mac
            .hold_peer_route(peer, route, flood_hops, hold_ms)
            .await
    }

    /// Switch a held route to the best path learned while it was held; see
    /// [`umsh_mac::MacHandle::adopt_learned_peer_route`].
    pub async fn adopt_learned_peer_route(&self, peer: &PublicKey) -> bool {
        self.mac.adopt_learned_peer_route(peer).await
    }

    /// The route cached for `peer` with its hold and confirmation state.
    pub async fn peer_route_status(&self, peer: &PublicKey) -> Option<umsh_mac::PeerRouteStatus> {
        self.mac.peer_route_status(peer).await
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

    /// Enable the built-in Identity Request responder with a custom respond
    /// policy.
    ///
    /// The node will answer a matching [Identity Request](crate::mac_command)
    /// with an authenticated unicast identity response (see
    /// [`identity_responder`](crate::identity_responder)). `policy` is the
    /// registerable discriminator invoked for each selected request; return
    /// [`RespondDecision::Ignore`] to decline. Replaces any previously enabled
    /// responder.
    pub fn enable_identity_responder<P>(&self, profile: NodeIdentityProfile, policy: P)
    where
        P: FnMut(&IdentityRequestContext<'_>) -> RespondDecision + 'static,
    {
        self.state.borrow_mut().identity_responder =
            Some(IdentityResponder::new(profile, Box::new(policy)));
    }

    /// Enable the Identity Request responder with the
    /// [`default_respond_policy`](crate::identity_responder::default_respond_policy).
    pub fn enable_identity_responder_default(&self, profile: NodeIdentityProfile) {
        self.enable_identity_responder(profile, default_respond_policy);
    }

    /// Disable the Identity Request responder, if enabled.
    pub fn disable_identity_responder(&self) {
        self.state.borrow_mut().identity_responder = None;
    }

    /// Update the live fields of the enabled responder's identity profile
    /// (e.g. refresh `location`/`altitude_m` from a GPS fix). No-op if the
    /// responder is not enabled.
    pub fn update_identity_profile(&self, f: impl FnOnce(&mut NodeIdentityProfile)) {
        if let Some(responder) = self.state.borrow_mut().identity_responder.as_mut() {
            f(&mut responder.profile);
        }
    }

    /// Read the enabled responder's identity profile, returning `None`
    /// if the responder is not enabled.
    ///
    /// The point of reading it rather than reconstructing it is that
    /// there is one statement of what this node is, and every framing of
    /// it—the Identity Request reply, a standalone signed
    /// advertisement, a local-control read—has to be that same
    /// statement.
    pub fn with_identity_profile<R>(&self, f: impl FnOnce(&NodeIdentityProfile) -> R) -> Option<R> {
        self.state
            .borrow()
            .identity_responder
            .as_ref()
            .map(|responder| f(&responder.profile))
    }

    /// Evaluate an incoming Identity Request against the enabled responder,
    /// producing a reply plan the async pump can execute. Returns `None` when
    /// no responder is enabled, the request does not select this node, or the
    /// policy declines.
    pub(crate) fn evaluate_identity_request(
        &self,
        packet: &ReceivedPacketRef<'_>,
        from: PublicKey,
        options: &[u8],
        now_ms: u64,
    ) -> Option<IdentityResponsePlan> {
        // Flood management for solicitations that can reach many nodes: a
        // broadcast (or multicast) Identity Request must not carry a routing
        // constraint (a Route option is fine only when empty)—a steered
        // request is still on its way to the neighborhood it meant to ask.
        //
        // A request that no FILTER_NODE_HINT narrows may additionally be
        // answered by every node it reaches, so it must also arrive
        // unrepeated, FHOPS absent or fully zero; flood routing such a request
        // multiplies replies across the mesh. A hint-filtered request names
        // one answering node and so may travel as far as it likes.
        let filters = crate::mac_command::IdentityRequestFilters::new(options);
        if matches!(
            packet.packet_family(),
            crate::PacketFamily::Broadcast | crate::PacketFamily::Multicast
        ) {
            if packet.source_route().is_some_and(|route| !route.is_empty()) {
                return None;
            }
            if !filters.hint_filtered() && packet.flood_hops().is_some_and(|hops| hops.0 != 0) {
                return None;
            }
        }
        let ctx = IdentityRequestContext {
            from_key: from,
            from_hint: packet.from_hint(),
            source_authenticated: packet.source_authenticated(),
            has_full_source: packet.has_full_source(),
            channel: packet.channel().map(|c| c.id()),
            family: packet.packet_family(),
            filters,
            rssi: packet.rssi(),
            snr: packet.snr(),
            trace_route: packet.trace_route(),
            trace_signal: packet.trace_signal(),
        };
        self.state
            .borrow_mut()
            .identity_responder
            .as_mut()?
            .evaluate(&ctx, now_ms)
    }

    /// Observe local transmission of a response without adding a wire ACK.
    ///
    /// `ack_mic`, from the request's [`ReceivedPacketRef::ack_mic`], lets
    /// the response acknowledge that request too. It is taken on its own
    /// rather than as a whole [`SendOptions`]: a device awaits this from a
    /// task whose future lives in a static, and on the smaller boards the
    /// stack is whatever the statics leave.
    pub async fn send_response_tracked(
        &self,
        to: &PublicKey,
        channel: Option<ChannelId>,
        payload: &[u8],
        ack_mic: Option<[u8; 4]>,
    ) -> Result<SendProgressTicket, crate::MacBackendError<M::SendError, M::CapacityError>> {
        let options = SendOptions {
            track_transmission: true,
            ack_mic,
            ..SendOptions::default()
        };
        let receipt = self
            .send_response(to, channel, payload, &options)
            .await?
            .expect("tracked response must return a local receipt");
        Ok(self.register_non_ack_send(self.identity_id, receipt))
    }

    /// Stop a queued response, including any forwarding-confirmation retries.
    pub async fn cancel_send(&self, token: SendToken) {
        self.mac.cancel_send(token.identity_id, token.receipt).await;
    }

    /// Send a response over the carriage its request arrived on.
    ///
    /// A blind unicast conceals both endpoints from anyone without the channel
    /// key, so an answer sent off the channel would name the pair the request
    /// took care to hide. `channel` is `Some` only when the request was itself
    /// a blind unicast—take it from the received packet's
    /// [`channel`](crate::ReceivedPacketRef::channel).
    pub async fn send_response(
        &self,
        to: &PublicKey,
        channel: Option<ChannelId>,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<umsh_mac::SendReceipt>, crate::MacBackendError<M::SendError, M::CapacityError>>
    {
        match channel {
            Some(channel) => {
                self.mac
                    .send_blind_unicast(self.identity_id, to, &channel, payload, options)
                    .await
            }
            None => {
                self.mac
                    .send_unicast(self.identity_id, to, payload, options)
                    .await
            }
        }
    }

    /// Send a resolved Identity Request reply as an authenticated unicast.
    ///
    /// Uses the node's long-term identity (not a PFS ephemeral). Relies on the
    /// crypto state the MAC already resolved for the requester—permanent or
    /// transient—and never promotes/pins the peer. Failures are dropped: the
    /// requester can always ask again.
    pub(crate) async fn send_identity_response(&self, plan: IdentityResponsePlan) {
        let unrouted = || {
            let options = SendOptions::default();
            if plan.full_source {
                options.with_full_source()
            } else {
                options
            }
        };
        // Steer the reply back down the trace the request arrived by. An
        // explicit route beats whatever the peer registry cached, which for a
        // broadcast solicitation is nothing at all. A route too long to
        // express falls back to no route rather than to a truncated one,
        // which would strand the reply mid-path.
        //
        // Routed before the no_flood block deliberately: try_with_source_route
        // back-fills a flood budget from the route length, and the reply to an
        // unhinted solicitation must carry no FHOPS field at all.
        let mut options = if plan.route.is_empty() {
            unrouted()
        } else {
            unrouted()
                .try_with_source_route(&plan.route)
                .unwrap_or_else(|_| unrouted())
        };
        // Mirror the trace options the request carried. A reply steered down
        // a trace is the case this exists for: the requester learns a route
        // home from its own trace and nothing from the answer, since a routed
        // reply arrives with its source route consumed and teaches the MAC no
        // path. Asking costs nothing on a reply no repeater may carry—the
        // MAC drops the request rather than airing an option that could only
        // arrive empty.
        if plan.trace_route {
            options = options.with_trace_route();
        }
        if plan.trace_signal {
            options = options.with_trace_signal();
        }
        if plan.no_flood {
            // The solicitation named no single node, so it was allowed one hop
            // and no more; the reply carries no FHOPS field so no repeater can
            // flood it back across the mesh.
            options = options.no_flood();
        }
        if plan.delayed {
            // Every node the solicitation selected is answering the same
            // frame; a random hold spreads the replies across the window.
            // Channel-activity failures then follow the MAC's normal bounded
            // CCA backoff-and-retry.
            let mut jitter = [0u8; 2];
            self.mac.fill_random(&mut jitter).await;
            let delay = u16::from_be_bytes(jitter)
                % (crate::identity_responder::RESPONSE_MAX_DELAY_MS
                    - crate::identity_responder::RESPONSE_MIN_DELAY_MS
                    + 1)
                + crate::identity_responder::RESPONSE_MIN_DELAY_MS;
            options = options.with_tx_delay_ms(delay);
        }
        // A broadcast solicitation's source is not auto-registered on
        // receive, so the requester may be a complete stranger. Take a
        // transient slot for them—never a pinned one—so the unicast
        // below has somewhere to go.
        let _ = self.mac.ensure_transient_peer(&plan.to).await;
        let _ = self
            .send_response(&plan.to, plan.channel, &plan.framed, &options)
            .await;
    }

    /// Answer Peer Repeaters Requests with what this node knows about the
    /// repeaters around it.
    ///
    /// Off by default. The table itself fills regardless—an identity is
    /// recorded when it arrives, whether or not anyone will ever ask—so
    /// switching this on does not start from an empty neighborhood.
    pub fn enable_peer_repeaters_responder(&self) {
        self.state.borrow_mut().peer_repeaters_responder = true;
    }

    pub fn disable_peer_repeaters_responder(&self) {
        self.state.borrow_mut().peer_repeaters_responder = false;
    }

    pub fn peer_repeaters_responder_enabled(&self) -> bool {
        self.state.borrow().peer_repeaters_responder
    }

    /// Record what an identity heard directly off the air said, if it came
    /// from a repeater.
    ///
    /// The caller vouches that the frame came off its sender's own
    /// transmitter; `rssi_snr` is that reception's measurement, when the
    /// radio made one. An identity that arrived forwarded is not offered
    /// here—it says nothing about whether its owner is in range.
    pub(crate) fn observe_peer_identity(
        &self,
        from: PublicKey,
        identity: &crate::NodeIdentityPayload,
        rssi_snr: Option<(i16, umsh_hal::Snr)>,
        now_ms: u64,
    ) {
        self.state
            .borrow_mut()
            .peer_repeaters
            .observe_identity(&from, identity, rssi_snr, now_ms);
    }

    /// The repeaters this node has heard directly: those introduced by their
    /// own identity advertisements, merged with those the radio has heard
    /// forwarding.
    pub async fn peer_repeaters(&self) -> Vec<peer_repeaters::MergedPeerRepeater> {
        let now_ms = self.mac.now_ms().await;
        let own_key = self.mac.identity_public_key(self.identity_id).await;
        let mut observations = Vec::new();
        self.mac
            .for_each_transmitter_observation(&mut |observation| observations.push(observation))
            .await;
        // The borrow ends before the merge so a handler holding the state
        // across an await cannot deadlock against it.
        let identities = self.state.borrow().peer_repeaters.clone();
        let mut peers = peer_repeaters::merge(&identities, observations.iter(), now_ms);
        // A node is not its own neighbor. A copy of its own advertisement can
        // come back off the air, and delivery does not screen a broadcast's
        // source, so the identity table can hold this node too.
        if let Some(own_key) = own_key {
            peers.retain(|peer| !own_key.0.starts_with(&peer.hint));
        }
        peers
    }

    /// Ask for the identities of the nodes an aimed request reaches: an
    /// Identity Request (command 1) narrowed by `filter`, with a random
    /// NONCE for each answer to echo.
    ///
    /// It goes along `route`, the repeaters ahead of where it is aimed in
    /// send order, and an empty route keeps it to direct range. It never
    /// floods. A role- or capability-filtered request is answered by every
    /// node it reaches, and even a hint-filtered one is aimed at a place
    /// rather than the mesh: a route that cannot be expressed is a
    /// failure, not a license to broadcast.
    ///
    /// The answers arrive as `PayloadType::NodeIdentity` frames on the
    /// normal receive path.
    pub async fn request_identities(
        &self,
        filter: &IdentityFilter<'_>,
        route: &[RouterHint],
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let mut nonce_bytes = [0u8; 4];
        self.fill_random(&mut nonce_bytes).await;
        // Options are emitted in ascending key order: the nonce, the hint
        // filter, the role, the capabilities.
        let mut builder = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(u32::from_be_bytes(nonce_bytes))?;
        if let Some(hint) = filter.hint_prefix {
            builder = builder.filter_hint_prefix(hint)?;
        }
        if let Some(role) = filter.role {
            builder = builder.filter_role(role)?;
        }
        // A broadcast request must carry at least one filter option. An
        // unrestricted ask carries a zero-bit capability filter, which every
        // node satisfies; any other filter already narrows it, and padding
        // it would only cost bytes.
        let unfiltered = filter.hint_prefix.is_none() && filter.role.is_none();
        let capabilities = filter
            .capabilities
            .or(unfiltered.then(NodeCapabilities::empty));
        if let Some(capabilities) = capabilities {
            builder = builder.filter_caps(capabilities)?;
        }
        let options_block = builder.build();
        let command = crate::mac_command::MacCommand::IdentityRequest {
            options: &options_block,
        };
        let mut frame = [0u8; 128];
        frame[0] = umsh_core::PayloadType::MacCommand as u8;
        let length = crate::mac_command::encode(&command, &mut frame[1..])? + 1;

        // Full source lets a stranger unicast back.
        let mut options = SendOptions::default().with_full_source();
        if !route.is_empty() {
            options = options
                .try_with_source_route(route)
                .map_err(|_| NodeError::RouteTooLong)?
                // The trace the request accumulates is the answering
                // strangers' only path home: a broadcast teaches the MAC no
                // route, and the reply carries no flood budget.
                .with_trace_route();
        }
        // Last, always: a source route back-fills a flood budget from its
        // length, and any FHOPS field at all makes the far end drop an
        // unhinted solicitation.
        let options = options.no_flood();
        self.send_all(&frame[..length], &options).await
    }

    /// Build and send one page of this node's peer-repeater list.
    ///
    /// Evaluated here rather than in the synchronous receive dispatch because
    /// the answer needs the MAC's observations, which only an async borrow
    /// reaches.
    pub(crate) async fn answer_peer_repeaters_request(
        &self,
        to: PublicKey,
        channel: Option<ChannelId>,
        request: &[u8],
    ) {
        if !self.peer_repeaters_responder_enabled() {
            return;
        }
        let view = crate::mac_command::PeerRepeatersRequestView::new(request);
        let generation = self.state.borrow().peer_repeaters.generation();
        let peers = self.peer_repeaters().await;

        // A cursor from a listing that has since changed names a place in a
        // list that no longer exists, so the enumeration restarts rather than
        // resuming into a different neighborhood.
        let start = match view.cursor() {
            Some([high, low, index]) if u16::from_be_bytes([*high, *low]) == generation => {
                usize::from(*index)
            }
            _ => 0,
        };
        let total = u8::try_from(peers.len()).unwrap_or(u8::MAX);

        let mut builder =
            crate::mac_command::PeerRepeatersResponseBuilder::new(PEER_REPEATERS_RESPONSE_BUDGET)
                .total(total)
                .reserve_cursor(PEER_REPEATERS_CURSOR_LEN);
        if let Some(nonce) = view.nonce() {
            builder = builder.nonce(nonce);
        }

        let mut next = start;
        for peer in peers.iter().skip(start) {
            let regions: Vec<u8> = peer.regions.iter().flatten().copied().collect();
            let entry = crate::mac_command::PeerRepeaterEntry {
                hint: &peer.hint,
                name: peer.name.as_deref(),
                rssi_snr: match (peer.rssi_dbm, peer.snr) {
                    (Some(rssi), Some(snr)) => Some((rssi, snr)),
                    _ => None,
                },
                last_heard_min: peer.last_heard_min,
                location: peer.location,
                regions: &regions,
            };
            // A single entry too large for a whole page would stall the
            // enumeration on it forever, so it is skipped rather than retried.
            match builder.try_push(&entry) {
                Ok(true) => next += 1,
                Ok(false) => break,
                Err(_) => next += 1,
            }
        }
        if next < peers.len() {
            let [high, low] = generation.to_be_bytes();
            builder = builder.cursor(&[high, low, u8::try_from(next).unwrap_or(u8::MAX)]);
        }
        let Ok(body) = builder.build() else {
            return;
        };

        // The payload-type byte, then the command—the framing every MAC
        // command travels in.
        let mut framed = [0u8; PEER_REPEATERS_RESPONSE_BUDGET + 8];
        framed[0] = umsh_core::PayloadType::MacCommand as u8;
        let Ok(len) = crate::mac_command::encode(
            &crate::mac_command::MacCommand::PeerRepeatersResponse { body: &body },
            &mut framed[1..],
        ) else {
            return;
        };
        let _ = self.mac.ensure_transient_peer(&to).await;
        let _ = self
            .send_response(&to, channel, &framed[..len + 1], &SendOptions::default())
            .await;
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
    /// response, or tearing down) fails—so a stalled negotiation reports a
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

    pub fn on_pong_with_metadata<F>(&self, handler: F) -> Subscription
    where
        F: FnMut(PublicKey, &PongMetadata) + 'static,
    {
        let handle = self
            .state
            .borrow_mut()
            .pong_metadata_handlers
            .insert(Box::new(handler));
        let state = self.state.clone();
        Subscription::new(move || state.borrow_mut().pong_metadata_handlers.remove(handle))
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
    pub(crate) fn match_pong(
        &self,
        from: PublicKey,
        data: &[u8],
        packet: &ReceivedPacketRef<'_>,
        now_ms: u64,
    ) {
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
            let route_hints = packet.trace_route_hints().collect::<Vec<_>>();
            let metadata = PongMetadata {
                round_trip_ms: rtt_ms,
                hop_count: packet.hop_count(),
                route_hints,
                rssi_dbm: packet.rssi(),
                snr_centibels: packet.snr().map(|snr| snr.as_centibels()),
                lqi: packet.lqi().map(core::num::NonZeroU8::get),
            };
            if let Some(entry) = state.peer_subscriptions.iter_mut().find(|e| e.peer == from) {
                entry.pong_handlers.for_each_mut(|h| h(rtt_ms));
            }
            state.pong_handlers.for_each_mut(|h| h(from, rtt_ms));
            state
                .pong_metadata_handlers
                .for_each_mut(|handler| handler(from, &metadata));
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

    /// Sends `payload` to `to` under the session with forward secrecy held
    /// with them, or, without `forward_secret`, under the long-term keys
    /// alone even while one is held. Fails with
    /// [`NodeError::PfsSessionMissing`] when a session is wanted and none
    /// is held: it never goes without one.
    #[cfg(feature = "software-crypto")]
    pub async fn send_with_secrecy(
        &self,
        to: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
        forward_secret: bool,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let route = if forward_secret {
            let now_ms = self.mac.now_ms().await;
            let route = self.state.borrow().pfs.active_route(to, now_ms);
            Some(route.ok_or(NodeError::PfsSessionMissing)?)
        } else {
            None
        };
        self.send_via(route, to, payload, options).await
    }

    /// Sends `payload` to `to` from the session identity `route` names, to
    /// the peer's ephemeral key, or without one from this node's own.
    #[cfg(feature = "software-crypto")]
    async fn send_via(
        &self,
        route: Option<(LocalIdentityId, PublicKey)>,
        to: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let (identity, receipt) = match route {
            Some((local_id, peer_ephemeral)) => (
                local_id,
                self.mac
                    .send_unicast(local_id, &peer_ephemeral, payload, options)
                    .await?,
            ),
            None => (
                self.identity_id,
                self.mac
                    .send_unicast(self.identity_id, to, payload, options)
                    .await?,
            ),
        };
        Ok(self.register_ack_send(identity, receipt))
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

    /// The local ephemeral keys of every active session with forward
    /// secrecy: the addresses besides this node's own that unicast to it
    /// names while those sessions last.
    #[cfg(feature = "software-crypto")]
    pub fn pfs_local_keys(&self) -> Vec<PublicKey> {
        self.state
            .borrow()
            .pfs
            .sessions()
            .iter()
            .filter(|session| session.state == PfsState::Active)
            .map(|session| session.local_ephemeral)
            .collect()
    }

    /// Join a channel. Registers the channel key in the MAC if this is
    /// the first node to join it. Returns the bound channel handle.
    #[cfg(feature = "software-crypto")]
    pub async fn join(&self, channel: &Channel) -> Result<BoundChannel<M>, NodeError<M>> {
        let membership = self.membership.borrow_mut();

        // Check if already joined.
        if let Some(entry) = membership.channels.iter().find(|e| e.channel == *channel) {
            if entry.active {
                return Ok(BoundChannel {
                    node: self.clone(),
                    channel: entry.channel.clone(),
                    join_generation: entry.generation,
                });
            }
        }

        // Either new or re-joining after a leave. Both register with the MAC:
        // `leave` unregisters the key, so a dormant entry has no MAC state to
        // reuse.
        drop(membership);
        self.mac.add_private_channel(channel.key().clone()).await?;
        let mut membership = self.membership.borrow_mut();

        if let Some(entry) = membership
            .channels
            .iter_mut()
            .find(|e| e.channel == *channel)
        {
            entry.active = true;
            entry.generation = entry.generation.wrapping_add(1);
            return Ok(BoundChannel {
                node: self.clone(),
                channel: entry.channel.clone(),
                join_generation: entry.generation,
            });
        }

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

    /// Leave a channel. Marks the membership entry inactive, bumps that
    /// entry's generation counter, and unregisters the channel key from the
    /// MAC so inbound traffic on it is no longer decrypted.
    #[cfg(feature = "software-crypto")]
    pub async fn leave(&self, channel: &Channel) -> Result<(), NodeError<M>> {
        {
            let mut membership = self.membership.borrow_mut();
            let Some(entry) = membership
                .channels
                .iter_mut()
                .find(|e| e.channel == *channel && e.active)
            else {
                return Ok(());
            };
            entry.active = false;
            entry.generation = entry.generation.wrapping_add(1);
        }
        self.mac.remove_channel(channel.key()).await;
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
            // Unicast/blind-unicast without ACK requested—no tracking.
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
        let state = self.state.borrow();
        state
            .pfs
            .sessions()
            .iter()
            .any(|session| session.local_ephemeral_id == identity_id)
            || state
                .meet
                .as_ref()
                .is_some_and(|slot| slot.id == identity_id)
    }

    /// The session identity of the contact exchange in progress, if any.
    #[cfg(feature = "software-crypto")]
    pub fn meet_identity(&self) -> Option<LocalIdentityId> {
        self.state.borrow().meet.as_ref().map(|slot| slot.id)
    }

    /// Open a contact-exchange session (app-meet.md) under a freshly drawn
    /// key, closing any earlier one. Every attempt opens its own: a session
    /// key is never reused. The session sends, and acks, at
    /// [`TX_POWER_DBM`](crate::meet::TX_POWER_DBM).
    ///
    /// Returns the session's public key and a seed for
    /// [`Meet::start`](crate::meet::Meet::start).
    #[cfg(feature = "software-crypto")]
    pub async fn open_meet(&self) -> Result<(PublicKey, [u8; 32]), NodeError<M>> {
        use umsh_crypto::NodeIdentity;
        use zeroize::Zeroize;

        self.close_meet().await;
        let mut secret = [0u8; 32];
        self.mac.fill_random(&mut secret).await;
        let identity = umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&secret);
        secret.zeroize();
        let key = *identity.public_key();
        let id = self
            .mac
            .register_ephemeral(self.identity_id, identity)
            .await?;
        self.mac
            .set_tx_power_dbm(id, Some(crate::meet::TX_POWER_DBM))
            .await;
        let mut seed = [0u8; 32];
        self.mac.fill_random(&mut seed).await;
        self.state.borrow_mut().meet = Some(MeetSlot {
            id,
            peers: Vec::new(),
        });
        Ok((key, seed))
    }

    /// Close the contact-exchange session: its key and the peers it reached
    /// go away, and nothing more is heard or sent under it.
    #[cfg(feature = "software-crypto")]
    pub async fn close_meet(&self) {
        let Some(slot) = self.state.borrow_mut().meet.take() else {
            return;
        };
        let _ = self.mac.remove_ephemeral(slot.id).await;
        for peer in slot.peers {
            let _ = self.mac.remove_peer(&peer).await;
        }
    }

    /// Send one Meet frame from the session identity: ack-requested and not
    /// flooded to `to`, or as a broadcast with the full source when `to` is
    /// `None`.
    #[cfg(feature = "software-crypto")]
    pub async fn send_meet(
        &self,
        to: Option<&PublicKey>,
        frame: &[u8],
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let id = self.meet_identity().ok_or(NodeError::MeetClosed)?;
        let options = SendOptions::default().no_flood().with_full_source();
        let Some(peer) = to else {
            let receipt = self.mac.send_broadcast(id, frame, &options).await?;
            return Ok(self.register_non_ack_send(id, receipt));
        };
        // A session key is a stranger to the MAC until something registers
        // it; register it here, and remember it for close.
        if !self.mac.ensure_transient_peer(peer).await {
            return Err(NodeError::PeerMissing);
        }
        if let Some(slot) = self.state.borrow_mut().meet.as_mut()
            && !slot.peers.contains(peer)
        {
            slot.peers.push(*peer);
        }
        let receipt = self
            .mac
            .send_unicast(id, peer, frame, &options.with_ack_requested(true))
            .await?;
        Ok(self.register_ack_send(id, receipt))
    }

    #[cfg(feature = "software-crypto")]
    pub(crate) async fn handle_pfs_command(
        &self,
        from: &PublicKey,
        channel: Option<ChannelId>,
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
                        channel,
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

    /// Hands `packet` to the receive handlers, naming as its sender the peer
    /// whose session key with forward secrecy sent it, so that what a peer
    /// says under a session reaches every handler as theirs.
    pub(crate) fn dispatch_received_packet(&self, packet: &ReceivedPacketRef<'_>) -> bool {
        let mut state = self.state.borrow_mut();
        let peer = packet
            .from_key()
            .map(|key| (key, canonical_peer(&state, key)));
        let attributed = match peer {
            Some((key, peer)) if peer != key => Some(packet.attributed_to(peer)),
            _ => None,
        };
        let packet = attributed.as_ref().unwrap_or(packet);

        if let Some((_, peer)) = peer {
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

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
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

    #[cfg(feature = "software-crypto")]
    pub(crate) fn dispatch_pfs_failed(&self, peer: PublicKey, reason: PfsFailure) {
        let mut state = self.state.borrow_mut();
        let peer = canonical_peer(&state, peer);
        state
            .pfs_failed_handlers
            .for_each_mut(|handler| handler(peer, reason));
    }

    #[cfg(feature = "software-crypto")]
    pub(crate) async fn expire_pfs_sessions(&self) -> Result<Vec<PublicKey>, NodeError<M>> {
        let now_ms = self.mac.now_ms().await;
        self.state
            .borrow_mut()
            .pfs
            .expire_sessions(&self.mac, now_ms)
            .await
    }

    /// Drop any sent PFS requests that were not answered before their deadline,
    /// returning the peers so the caller can report a [`PfsFailure::Timeout`].
    #[cfg(feature = "software-crypto")]
    pub(crate) fn expire_pfs_requests(&self, now_ms: u64) -> Vec<PublicKey> {
        self.state.borrow_mut().pfs.expire_requests(now_ms)
    }
}

#[cfg_attr(not(feature = "software-crypto"), allow(unused_variables))]
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

impl<M: MacBackend> crate::transport::sealed::Sealed for LocalNode<M> {}

impl<M: MacBackend> crate::transport::NodeAccess for LocalNode<M> {
    type Backend = M;

    fn local_node(&self) -> &LocalNode<M> {
        self
    }
}

impl<M: MacBackend> Transport for LocalNode<M> {
    type Error = NodeError<M>;

    async fn send(
        &self,
        to: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error> {
        // Under the session with forward secrecy held with them, if one is.
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.mac.now_ms().await;
            let route = self.state.borrow().pfs.active_route(to, now_ms);
            self.send_via(route, to, payload, options).await
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let receipt = self
                .mac
                .send_unicast(self.identity_id, to, payload, options)
                .await?;
            Ok(self.register_ack_send(self.identity_id, receipt))
        }
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
impl<M: MacBackend> BoundChannel<M> {
    /// Ask the channel for the identity of the member whose hint is
    /// `hint`: an Identity Request (command 1) filtered by the hint, as one
    /// multicast, with a random NONCE for the member to echo.
    ///
    /// The response arrives asynchronously as a `PayloadType::NodeIdentity`
    /// frame on the normal receive path, not as the return value here.
    /// `options` should carry the full source key, so the member can answer
    /// with a unicast.
    pub async fn request_identity(
        &self,
        hint: &NodeHint,
        options: &SendOptions,
    ) -> Result<SendProgressTicket, NodeError<M>> {
        let mut nonce_bytes = [0u8; 4];
        self.node.fill_random(&mut nonce_bytes).await;
        let opts_block = crate::mac_command::IdentityRequestBuilder::new()
            .nonce(u32::from_be_bytes(nonce_bytes))?
            .filter_hint(hint)?
            .build();
        let cmd = crate::mac_command::MacCommand::IdentityRequest {
            options: &opts_block,
        };
        let mut buf = [0u8; 128];
        buf[0] = umsh_core::PayloadType::MacCommand as u8;
        let n = crate::mac_command::encode(&cmd, &mut buf[1..])? + 1;
        self.send_all(&buf[..n], options).await
    }
}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> crate::transport::sealed::Sealed for BoundChannel<M> {}

#[cfg(feature = "software-crypto")]
impl<M: MacBackend> crate::transport::NodeAccess for BoundChannel<M> {
    type Backend = M;

    fn local_node(&self) -> &LocalNode<M> {
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
