use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_mac::{
    CapacityError, LocalIdentityId, MacHandle, PeerId, Platform, SendError, SendOptions,
    SendReceipt,
};

/// Pluggable backend that the node layer delegates to for MAC operations.
///
/// [`MacHandle`](umsh_mac::MacHandle) implements `MacBackend`, and test code can provide a
/// lightweight fake.
pub trait MacBackend: Clone {
    /// Error type returned by send-oriented operations.
    type SendError;
    /// Error type returned by fixed-capacity operations.
    type CapacityError;

    /// Add or refresh a peer.
    async fn add_peer(
        &self,
        key: PublicKey,
    ) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Add or refresh a private channel.
    async fn add_private_channel(
        &self,
        key: ChannelKey,
    ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Add or refresh a named channel.
    async fn add_named_channel(
        &self,
        name: &str,
    ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Queue a broadcast frame.
    async fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Queue a multicast frame.
    async fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Queue a unicast frame.
    async fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Queue a blind-unicast frame.
    async fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Fill `dest` with random bytes.
    async fn fill_random(&self, dest: &mut [u8]);
    /// Return the current MAC clock time.
    async fn now_ms(&self) -> u64;

    #[cfg(feature = "software-crypto")]
    async fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, MacBackendError<Self::SendError, Self::CapacityError>>;

    #[cfg(feature = "software-crypto")]
    async fn remove_ephemeral(&self, id: LocalIdentityId) -> bool;
}

/// Normalized wrapper around MAC-backend failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacBackendError<S, C> {
    /// Send-oriented MAC failure.
    Send(S),
    /// Capacity-related MAC failure.
    Capacity(C),
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
> MacBackend for MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    type SendError = SendError;
    type CapacityError = CapacityError;

    async fn add_peer(
        &self,
        key: PublicKey,
    ) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.add_peer(key).await.map_err(MacBackendError::Capacity)
    }

    async fn add_private_channel(
        &self,
        key: ChannelKey,
    ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
        self.add_channel(key)
            .await
            .map_err(MacBackendError::Capacity)
    }

    async fn add_named_channel(
        &self,
        name: &str,
    ) -> Result<(), MacBackendError<Self::SendError, Self::CapacityError>> {
        self.add_named_channel(name)
            .await
            .map_err(MacBackendError::Capacity)
    }

    async fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.send_broadcast(from, payload, options)
            .await
            .map_err(MacBackendError::Send)
    }

    async fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.send_multicast(from, channel, payload, options)
            .await
            .map_err(MacBackendError::Send)
    }

    async fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.send_unicast(from, dst, payload, options)
            .await
            .map_err(MacBackendError::Send)
    }

    async fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.send_blind_unicast(from, dst, channel, payload, options)
            .await
            .map_err(MacBackendError::Send)
    }

    async fn fill_random(&self, dest: &mut [u8]) {
        self.fill_random(dest).await
    }

    async fn now_ms(&self) -> u64 {
        self.now_ms().await
    }

    #[cfg(feature = "software-crypto")]
    async fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.register_ephemeral(parent, identity)
            .await
            .map_err(MacBackendError::Capacity)
    }

    #[cfg(feature = "software-crypto")]
    async fn remove_ephemeral(&self, id: LocalIdentityId) -> bool {
        self.remove_ephemeral(id).await
    }
}
