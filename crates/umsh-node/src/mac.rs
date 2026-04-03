use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_crypto::PairwiseKeys;
use umsh_mac::{CapacityError, LocalIdentityId, MacHandle, MacHandleError, PeerCryptoState, PeerId, Platform, SendError, SendOptions, SendReceipt};

/// Endpoint-facing abstraction over the MAC send and configuration surface.
///
/// [`crate::Endpoint`] depends on this trait so it can be used with a real
/// [`umsh_mac::MacHandle`] or with test doubles.
pub trait NodeMac: Clone {
    /// Error type returned by send-oriented operations.
    type SendError;
    /// Error type returned by fixed-capacity operations.
    type CapacityError;

    /// Add or refresh a peer.
    fn add_peer(&self, key: PublicKey) -> Result<PeerId, NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Add or refresh a private channel.
    fn add_private_channel(&self, key: ChannelKey) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Add or refresh a named channel.
    fn add_named_channel(&self, name: &str) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Install pairwise transport keys.
    fn install_pairwise_keys(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<PeerCryptoState>, NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Queue a broadcast frame.
    fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Queue a multicast frame.
    fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Queue a unicast frame.
    fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Queue a blind-unicast frame.
    fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Fill `dest` with random bytes.
    fn fill_random(&self, dest: &mut [u8]) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    /// Return the current MAC clock time.
    fn now_ms(&self) -> Result<u64, NodeMacError<Self::SendError, Self::CapacityError>>;

    #[cfg(feature = "software-crypto")]
    fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, NodeMacError<Self::SendError, Self::CapacityError>>;

    #[cfg(feature = "software-crypto")]
    fn remove_ephemeral(&self, id: LocalIdentityId) -> Result<bool, NodeMacError<Self::SendError, Self::CapacityError>>;
}

/// Normalized wrapper around MAC-handle failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeMacError<S, C> {
    /// Shared MAC state was temporarily busy.
    Busy,
    /// Send-oriented MAC failure.
    Send(S),
    /// Capacity-related MAC failure.
    Capacity(C),
}

impl<S, C> NodeMacError<S, C> {
    fn from_send_error(error: MacHandleError<S>) -> Self {
        match error {
            MacHandleError::Busy => Self::Busy,
            MacHandleError::Inner(inner) => Self::Send(inner),
        }
    }

    fn from_capacity_error(error: MacHandleError<C>) -> Self {
        match error {
            MacHandleError::Busy => Self::Busy,
            MacHandleError::Inner(inner) => Self::Capacity(inner),
        }
    }

    fn from_infallible_error(error: MacHandleError<core::convert::Infallible>) -> Self {
        match error {
            MacHandleError::Busy => Self::Busy,
            MacHandleError::Inner(inner) => match inner {},
        }
    }
}

impl<
        'a,
        P: Platform,
        const IDENTITIES: usize,
        const PEERS: usize,
        const CHANNELS: usize,
        const ACKS: usize,
        const TX: usize,
        const FRAME: usize,
        const DUP: usize,
    > NodeMac
    for MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    type SendError = SendError;
    type CapacityError = CapacityError;

    fn add_peer(&self, key: PublicKey) -> Result<PeerId, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.add_peer(key).map_err(|error| match error {
            MacHandleError::Busy => NodeMacError::Busy,
            MacHandleError::Inner(inner) => match inner {},
        })
    }

    fn add_private_channel(&self, key: ChannelKey) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
        self.add_channel(key).map_err(NodeMacError::from_capacity_error)
    }

    fn add_named_channel(&self, name: &str) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
        self.add_named_channel(name).map_err(NodeMacError::from_capacity_error)
    }

    fn install_pairwise_keys(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<PeerCryptoState>, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.install_pairwise_keys(identity_id, peer_id, pairwise_keys)
            .map_err(NodeMacError::from_send_error)
    }

    fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
        self.send_broadcast(from, payload, options)
            .map_err(NodeMacError::from_send_error)
    }

    fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
        self.send_multicast(from, channel, payload, options)
            .map_err(NodeMacError::from_send_error)
    }

    fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.send_unicast(from, dst, payload, options)
            .map_err(NodeMacError::from_send_error)
    }

    fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.send_blind_unicast(from, dst, channel, payload, options)
            .map_err(NodeMacError::from_send_error)
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
        self.fill_random(dest).map_err(NodeMacError::from_infallible_error)
    }

    fn now_ms(&self) -> Result<u64, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.now_ms().map_err(NodeMacError::from_infallible_error)
    }

    #[cfg(feature = "software-crypto")]
    fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.register_ephemeral(parent, identity).map_err(NodeMacError::from_capacity_error)
    }

    #[cfg(feature = "software-crypto")]
    fn remove_ephemeral(&self, id: LocalIdentityId) -> Result<bool, NodeMacError<Self::SendError, Self::CapacityError>> {
        self.remove_ephemeral(id).map_err(NodeMacError::from_infallible_error)
    }
}