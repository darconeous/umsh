use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_crypto::PairwiseKeys;
use umsh_mac::{CapacityError, LocalIdentityId, MacHandle, MacHandleError, PeerCryptoState, PeerId, SendError, SendOptions, SendReceipt};

/// Endpoint-facing abstraction over the MAC send and configuration surface.
pub trait NodeMac: Clone {
    type SendError;
    type CapacityError;

    fn add_peer(&self, key: PublicKey) -> Result<PeerId, NodeMacError<Self::SendError, Self::CapacityError>>;
    fn add_private_channel(&self, key: ChannelKey) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    fn add_named_channel(&self, name: &str) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    fn install_pairwise_keys(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<PeerCryptoState>, NodeMacError<Self::SendError, Self::CapacityError>>;
    fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
    fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>>;
    fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>>;
    fn fill_random(&self, dest: &mut [u8]) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>>;
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
    Busy,
    Send(S),
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
        R: umsh_hal::Radio,
        I: umsh_crypto::NodeIdentity,
        A: umsh_crypto::AesProvider,
        S: umsh_crypto::Sha256Provider,
        C: umsh_hal::Clock,
        G: umsh_hal::Rng,
        CS: umsh_hal::CounterStore,
        const IDENTITIES: usize,
        const PEERS: usize,
        const CHANNELS: usize,
        const ACKS: usize,
        const TX: usize,
        const FRAME: usize,
        const DUP: usize,
    > NodeMac
    for MacHandle<'a, R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
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