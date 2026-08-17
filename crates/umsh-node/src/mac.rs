use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_mac::{
    AddPeerError, CachedRoute, CapacityError, LocalIdentityId, MacError, MacEventRef, MacHandle,
    PeerId, Platform, SendError, SendOptions, SendReceipt,
};

/// Pluggable backend that the node layer delegates to for MAC operations.
///
/// [`MacHandle`](umsh_mac::MacHandle) implements `MacBackend`, and test code can provide a
/// lightweight fake. Making the node layer ([`Host`](crate::Host),
/// [`LocalNode`](crate::LocalNode), …) generic over this trait keeps the MAC's eight
/// fixed-capacity const generics confined to the `MacHandle` type rather than propagating
/// through every node-layer type and free function.
pub trait MacBackend: Clone {
    /// Error type returned by send-oriented operations.
    type SendError;
    /// Error type returned by fixed-capacity operations.
    type CapacityError;
    /// Error type returned by the event-loop driver, [`next_event`](Self::next_event).
    type RunError;

    /// Drive the MAC until one wake cycle completes, invoking `on_event` for
    /// each emitted event.
    ///
    /// This is the single wake-driven step the node layer builds `pump_once` /
    /// `run` on top of; it waits for radio activity or a protocol deadline
    /// rather than busy-polling.
    async fn next_event(
        &self,
        on_event: impl FnMut(LocalIdentityId, MacEventRef<'_>),
    ) -> Result<(), Self::RunError>;

    /// Add or refresh a peer.
    async fn add_peer(
        &self,
        key: PublicKey,
    ) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>>;
    /// Remove a peer and its per-peer transport state, reporting whether it
    /// was registered.
    async fn remove_peer(&self, key: &PublicKey) -> bool {
        let _ = key;
        false
    }
    /// Ensure `key` holds at least a transient (unpinned, LRU-evictable)
    /// peer slot, so an explicit reply to a stranger can be sent. Reports
    /// whether a slot is held.
    async fn ensure_transient_peer(&self, key: &PublicKey) -> bool {
        let _ = key;
        false
    }
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
    /// Remove a channel and its replay state, reporting whether it was
    /// registered.
    async fn remove_channel(&self, key: &ChannelKey) -> bool {
        let _ = key;
        false
    }
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

    /// Return the live TX frame counter for `from`, if it identifies a registered identity.
    async fn frame_counter(&self, from: LocalIdentityId) -> Option<u32> {
        let _ = from;
        None
    }

    /// Return the persisted TX frame-counter boundary for `from`, if registered.
    async fn persisted_frame_counter(&self, from: LocalIdentityId) -> Option<u32> {
        let _ = from;
        None
    }

    /// Invoke `f` for every peer registered in the MAC-layer peer registry.
    ///
    /// Covers all known peers, not just those with an active crypto session.
    async fn for_each_peer(&self, f: &mut dyn FnMut(umsh_core::PublicKey)) {
        let _ = f;
    }

    /// Invoke `f` for each peer with established crypto state for `from`.
    /// Arguments are `(peer public key, last-accepted RX counter, persisted RX boundary)`.
    async fn for_each_peer_counter(
        &self,
        from: LocalIdentityId,
        f: &mut dyn FnMut(umsh_core::PublicKey, u32, u32),
    ) {
        let _ = (from, f);
    }

    /// Invoke `f` for each transmitter the radio has heard, with the most
    /// recent measurements from it.
    ///
    /// This is what a peer-repeater listing reports about the hops it names:
    /// a frame forwarded past this node or simply overheard proves a
    /// neighbor was on the air, and no peer-oriented view sees it.
    async fn for_each_transmitter_observation(
        &self,
        f: &mut dyn FnMut(umsh_mac::TransmitterObservation),
    ) {
        let _ = f;
    }

    /// Return the route the MAC currently has cached for `peer`.
    async fn peer_route(&self, peer: &PublicKey) -> Option<CachedRoute> {
        let _ = peer;
        None
    }

    /// Forget the route cached for `peer`, returning whether one was held.
    async fn clear_peer_route(&self, peer: &PublicKey) -> bool {
        let _ = peer;
        false
    }
}

/// Normalized wrapper around MAC-backend failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacBackendError<S, C> {
    /// Send-oriented MAC failure.
    Send(S),
    /// Capacity-related MAC failure.
    Capacity(C),
    /// A supplied public key did not decode to a valid Ed25519 point on the curve.
    InvalidPublicKey,
    /// A channel name failed canonicalization (non-ASCII or too long).
    InvalidChannelName(umsh_crypto::ChannelNameError),
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
    const RN: usize,
    const HN: usize,
> MacBackend for MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP, RN, HN>
{
    type SendError = SendError;
    type CapacityError = CapacityError;
    type RunError = MacError<<P::Radio as umsh_hal::Radio>::Error>;

    async fn next_event(
        &self,
        on_event: impl FnMut(LocalIdentityId, MacEventRef<'_>),
    ) -> Result<(), Self::RunError> {
        self.next_event(on_event).await
    }

    async fn add_peer(
        &self,
        key: PublicKey,
    ) -> Result<PeerId, MacBackendError<Self::SendError, Self::CapacityError>> {
        self.add_peer(key).await.map_err(|err| match err {
            AddPeerError::Capacity => MacBackendError::Capacity(CapacityError),
            AddPeerError::InvalidPublicKey => MacBackendError::InvalidPublicKey,
        })
    }

    async fn remove_peer(&self, key: &PublicKey) -> bool {
        self.remove_peer(key).await
    }

    async fn ensure_transient_peer(&self, key: &PublicKey) -> bool {
        self.ensure_transient_peer(key).await
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
        self.add_named_channel(name).await.map_err(|err| match err {
            umsh_mac::AddChannelError::Capacity => MacBackendError::Capacity(CapacityError),
            umsh_mac::AddChannelError::InvalidName(reason) => {
                MacBackendError::InvalidChannelName(reason)
            }
        })
    }

    async fn remove_channel(&self, key: &ChannelKey) -> bool {
        self.remove_channel(key).await
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

    async fn frame_counter(&self, from: LocalIdentityId) -> Option<u32> {
        self.frame_counter(from).await
    }

    async fn persisted_frame_counter(&self, from: LocalIdentityId) -> Option<u32> {
        self.persisted_frame_counter(from).await
    }

    async fn for_each_peer(&self, f: &mut dyn FnMut(umsh_core::PublicKey)) {
        self.for_each_peer(f).await
    }

    async fn for_each_peer_counter(
        &self,
        from: LocalIdentityId,
        f: &mut dyn FnMut(umsh_core::PublicKey, u32, u32),
    ) {
        self.for_each_peer_counter(from, f).await
    }

    async fn for_each_transmitter_observation(
        &self,
        f: &mut dyn FnMut(umsh_mac::TransmitterObservation),
    ) {
        self.for_each_transmitter_observation(f).await
    }

    async fn peer_route(&self, peer: &PublicKey) -> Option<CachedRoute> {
        self.peer_route(peer).await
    }

    async fn clear_peer_route(&self, peer: &PublicKey) -> bool {
        self.clear_peer_route(peer).await
    }
}
