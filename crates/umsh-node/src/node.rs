use alloc::rc::Rc;
#[cfg(feature = "software-crypto")]
use alloc::vec::Vec;
use core::cell::RefCell;

use umsh_core::PublicKey;
use umsh_mac::{LocalIdentityId, SendOptions};

#[cfg(feature = "software-crypto")]
use crate::channel::Channel;
use crate::dispatch::EventDispatcher;
use crate::mac::MacBackend;
use crate::peer::PeerConnection;
use crate::ticket::{SendProgressTicket, SendToken};
use crate::transport::Transport;

/// Per-node shared membership state. All cloned `LocalNode` handles and
/// their `BoundChannel`s share the same instance via `Rc<RefCell<...>>`.
pub(crate) struct NodeMembership {
    #[cfg(feature = "software-crypto")]
    pub channels: Vec<ChannelMembershipEntry>,
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

    /// Check if this node is currently a member of a channel with the given key.
    ///
    /// Uses the full `ChannelKey` (not the 2-byte `ChannelId`) to avoid
    /// false matches from ID collisions.
    pub fn has_channel_key(&self, _key: &umsh_core::ChannelKey) -> bool {
        #[cfg(feature = "software-crypto")]
        {
            self.channels.iter().any(|e| e.active && e.channel.key() == _key)
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            false
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
}

impl<M: MacBackend> LocalNode<M> {
    /// Create a new local node.
    pub(crate) fn new(
        identity_id: LocalIdentityId,
        mac: M,
        dispatcher: Rc<RefCell<EventDispatcher>>,
        membership: Rc<RefCell<NodeMembership>>,
    ) -> Self {
        Self {
            identity_id,
            mac,
            dispatcher,
            membership,
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
        receipt: Option<umsh_mac::SendReceipt>,
    ) -> SendProgressTicket {
        match receipt {
            Some(receipt) => {
                let token = SendToken::new(self.identity_id, receipt);
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
        receipt: umsh_mac::SendReceipt,
    ) -> SendProgressTicket {
        let token = SendToken::new(self.identity_id, receipt);
        let state = self.dispatcher.borrow_mut().register_ticket(token, true);
        SendProgressTicket::new(token, state)
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
        let receipt = self
            .mac
            .send_unicast(self.identity_id, to, payload, options)
            .await?;
        Ok(self.register_ack_send(receipt))
    }

    async fn send_all(
        &self,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendProgressTicket, Self::Error> {
        let receipt = self.mac
            .send_broadcast(self.identity_id, payload, options)
            .await?;
        Ok(self.register_non_ack_send(receipt))
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
        Ok(self.node.register_ack_send(receipt))
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
        Ok(self.node.register_non_ack_send(receipt))
    }
}
