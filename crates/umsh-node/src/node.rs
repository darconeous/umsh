use alloc::rc::Rc;
use alloc::boxed::Box;
#[cfg(feature = "software-crypto")]
use alloc::vec::Vec;
use core::cell::RefCell;
use core::num::NonZeroU32;

use umsh_core::PublicKey;
use umsh_mac::{LocalIdentityId, SendOptions};
use umsh_core::NodeHint;

#[cfg(feature = "software-crypto")]
use crate::channel::Channel;
use crate::dispatch::EventDispatcher;
use crate::mac::MacBackend;
use crate::owned::OwnedMacCommand;
use crate::peer::PeerConnection;
use crate::receive::ReceivedPacketRef;
use crate::ticket::{SendProgressTicket, SendToken};
use crate::transport::Transport;
#[cfg(feature = "software-crypto")]
use crate::pfs::{PfsSessionManager, PfsState};

/// Per-node shared membership state. All cloned `LocalNode` handles and
/// their `BoundChannel`s share the same instance via `Rc<RefCell<...>>`.
pub(crate) struct NodeMembership {
    #[cfg(feature = "software-crypto")]
    pub channels: Vec<ChannelMembershipEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubscriptionHandle(NonZeroU32);

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

pub(crate) struct PeerSubscriptions {
    peer: PublicKey,
    pub(crate) receive_handlers: HandlerTable<Box<dyn FnMut(&ReceivedPacketRef<'_>) -> bool>>,
    pub(crate) ack_received_handlers: HandlerTable<Box<dyn FnMut(SendToken)>>,
    pub(crate) ack_timeout_handlers: HandlerTable<Box<dyn FnMut(SendToken)>>,
    pub(crate) pfs_established_handlers: HandlerTable<Box<dyn FnMut()>>,
    pub(crate) pfs_ended_handlers: HandlerTable<Box<dyn FnMut()>>,
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
        }
    }
}

pub(crate) struct LocalNodeState {
    receive_handlers: HandlerTable<Box<dyn FnMut(&ReceivedPacketRef<'_>) -> bool>>,
    node_discovered_handlers: HandlerTable<Box<dyn FnMut(PublicKey, Option<&str>)>>,
    beacon_handlers: HandlerTable<Box<dyn FnMut(NodeHint, Option<PublicKey>)>>,
    mac_command_handlers: HandlerTable<Box<dyn FnMut(PublicKey, &OwnedMacCommand)>>,
    ack_received_handlers: HandlerTable<Box<dyn FnMut(PublicKey, SendToken)>>,
    ack_timeout_handlers: HandlerTable<Box<dyn FnMut(PublicKey, SendToken)>>,
    pfs_established_handlers: HandlerTable<Box<dyn FnMut(PublicKey)>>,
    pfs_ended_handlers: HandlerTable<Box<dyn FnMut(PublicKey)>>,
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
            ack_received_handlers: HandlerTable::default(),
            ack_timeout_handlers: HandlerTable::default(),
            pfs_established_handlers: HandlerTable::default(),
            pfs_ended_handlers: HandlerTable::default(),
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
    /// Application payload encode failure.
    AppEncode(umsh_app::EncodeError),
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

impl<M: MacBackend> From<umsh_app::EncodeError> for NodeError<M> {
    fn from(e: umsh_app::EncodeError) -> Self {
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
    pub fn peer(&self, key: PublicKey) -> Result<PeerConnection<Self>, NodeError<M>> {
        self.mac.add_peer(key)?;
        Ok(PeerConnection::new(self.clone(), key))
    }

    pub fn on_receive<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(&ReceivedPacketRef<'_>) -> bool + 'static,
    {
        self.state
            .borrow_mut()
            .receive_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_receive_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().receive_handlers.remove(handle)
    }

    pub fn on_node_discovered<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, Option<&str>) + 'static,
    {
        self.state
            .borrow_mut()
            .node_discovered_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_node_discovered_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().node_discovered_handlers.remove(handle)
    }

    pub fn on_beacon<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(NodeHint, Option<PublicKey>) + 'static,
    {
        self.state
            .borrow_mut()
            .beacon_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_beacon_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().beacon_handlers.remove(handle)
    }

    pub fn on_mac_command<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, &OwnedMacCommand) + 'static,
    {
        self.state
            .borrow_mut()
            .mac_command_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_mac_command_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().mac_command_handlers.remove(handle)
    }

    pub fn on_ack_received<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, SendToken) + 'static,
    {
        self.state
            .borrow_mut()
            .ack_received_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_ack_received_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().ack_received_handlers.remove(handle)
    }

    pub fn on_ack_timeout<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey, SendToken) + 'static,
    {
        self.state
            .borrow_mut()
            .ack_timeout_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_ack_timeout_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().ack_timeout_handlers.remove(handle)
    }

    pub fn on_pfs_established<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey) + 'static,
    {
        self.state
            .borrow_mut()
            .pfs_established_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_pfs_established_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().pfs_established_handlers.remove(handle)
    }

    pub fn on_pfs_ended<F>(&self, handler: F) -> SubscriptionHandle
    where
        F: FnMut(PublicKey) + 'static,
    {
        self.state
            .borrow_mut()
            .pfs_ended_handlers
            .insert(Box::new(handler))
    }

    pub fn remove_pfs_ended_handler(&self, handle: SubscriptionHandle) -> bool {
        self.state.borrow_mut().pfs_ended_handlers.remove(handle)
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
    pub fn pfs_status(&self, peer: &PublicKey) -> Result<PfsStatus, NodeError<M>> {
        let now_ms = self.mac.now_ms()?;
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
    pub fn join(&self, channel: &Channel) -> Result<BoundChannel<M>, NodeError<M>> {
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
        self.mac.add_private_channel(channel.key().clone())?;

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
        command: &crate::owned::OwnedMacCommand,
        options: &SendOptions,
    ) -> Result<Option<PfsLifecycle>, NodeError<M>> {
        use crate::owned::OwnedMacCommand;

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
                    )?
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
            entry.pfs_established_handlers.for_each_mut(|handler| handler());
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

    pub(crate) fn expire_pfs_sessions(&self) -> Result<Vec<PublicKey>, NodeError<M>> {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.mac.now_ms()?;
            return self
                .state
                .borrow_mut()
                .pfs
                .expire_sessions(&self.mac, now_ms);
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            Ok(Vec::new())
        }
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
            let now_ms = self.mac.now_ms()?;
            if let Some((local_id, peer_ephemeral)) =
                self.state.borrow().pfs.active_route(to, now_ms)
            {
                let receipt = self.mac
                    .send_unicast(local_id, &peer_ephemeral, payload, options)
                    .await?;
                (local_id, receipt)
            } else {
                let receipt = self.mac
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
        let receipt = self.mac
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
        let receipt = self.node.mac.send_blind_unicast(
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
        let receipt = self.node.mac.send_multicast(
            self.node.identity_id,
            self.channel.channel_id(),
            payload,
            options,
        )
        .await?;
        Ok(self.node.register_non_ack_send(self.node.identity_id, receipt))
    }
}
