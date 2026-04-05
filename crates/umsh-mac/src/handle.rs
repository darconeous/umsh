use core::cell::RefCell;

use rand::Rng;
use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_hal::{Clock, CounterStore};

use crate::{
    CapacityError, DEFAULT_ACKS, DEFAULT_CHANNELS, DEFAULT_DUP, DEFAULT_FRAME, DEFAULT_IDENTITIES,
    DEFAULT_PEERS, DEFAULT_TX, Platform,
    coordinator::{CounterPersistenceError, LocalIdentityId, Mac, MacError, SendError},
    peers::PeerId,
    send::{SendOptions, SendReceipt},
};

/// Error returned when a `MacHandle` operation cannot access the shared coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacHandleError<E> {
    /// Another caller is already borrowing the shared coordinator.
    Busy,
    /// The underlying coordinator operation failed.
    Inner(E),
}

/// Lightweight, cloneable handle for queuing MAC operations against shared state.
///
/// The handle borrows a `RefCell` that owns the underlying coordinator, which
/// keeps queuing and configuration operations lightweight while the main MAC run
/// loop continues to own radio receive/transmit progression.
pub struct MacHandle<
    'a,
    P: Platform,
    const IDENTITIES: usize = DEFAULT_IDENTITIES,
    const PEERS: usize = DEFAULT_PEERS,
    const CHANNELS: usize = DEFAULT_CHANNELS,
    const ACKS: usize = DEFAULT_ACKS,
    const TX: usize = DEFAULT_TX,
    const FRAME: usize = DEFAULT_FRAME,
    const DUP: usize = DEFAULT_DUP,
> {
    mac: &'a RefCell<Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
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
> Copy for MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
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
> Clone for MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    fn clone(&self) -> Self {
        *self
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
> MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    /// Creates a cloneable handle backed by shared coordinator state.
    pub fn new(
        mac: &'a RefCell<Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
    ) -> Self {
        Self { mac }
    }

    /// Registers a local identity with the shared coordinator.
    pub fn add_identity(
        &self,
        identity: P::Identity,
    ) -> Result<LocalIdentityId, MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.add_identity(identity))
    }

    /// Load the persisted frame-counter boundary for one identity.
    pub async fn load_persisted_counter(
        &self,
        id: LocalIdentityId,
    ) -> Result<
        u32,
        MacHandleError<CounterPersistenceError<<P::CounterStore as CounterStore>::Error>>,
    > {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.load_persisted_counter(id)
            .await
            .map_err(MacHandleError::Inner)
    }

    /// Persist all currently scheduled frame-counter reservations.
    pub async fn service_counter_persistence(
        &self,
    ) -> Result<usize, MacHandleError<<P::CounterStore as CounterStore>::Error>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.service_counter_persistence()
            .await
            .map_err(MacHandleError::Inner)
    }

    /// Registers or refreshes a remote peer in the shared registry.
    pub fn add_peer(&self, key: PublicKey) -> Result<PeerId, MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.add_peer(key))
    }

    /// Adds or updates a shared channel and derives its multicast keys.
    pub fn add_channel(&self, key: ChannelKey) -> Result<(), MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.add_channel(key))
    }

    /// Adds or updates a named channel using the coordinator's channel-key derivation.
    pub fn add_named_channel(&self, name: &str) -> Result<(), MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.add_named_channel(name))
    }

    /// Return whether inbound secure packets carrying a full source key may auto-register peers.
    pub fn auto_register_full_key_peers(
        &self,
    ) -> Result<bool, MacHandleError<core::convert::Infallible>> {
        self.with_mac(|mac| Ok(mac.auto_register_full_key_peers()))
    }

    /// Enable or disable inbound full-key peer auto-registration.
    pub fn set_auto_register_full_key_peers(
        &self,
        enabled: bool,
    ) -> Result<(), MacHandleError<core::convert::Infallible>> {
        self.with_mac(|mac| {
            mac.set_auto_register_full_key_peers(enabled);
            Ok(())
        })
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    ///
    /// This is a crate-internal method. External callers should use the
    /// `unsafe-advanced` feature or go through the node-layer PFS session manager.
    #[cfg(any(feature = "unsafe-advanced", test))]
    pub(crate) fn install_pairwise_keys(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: umsh_crypto::PairwiseKeys,
    ) -> Result<Option<crate::peers::PeerCryptoState>, MacHandleError<SendError>> {
        self.with_mac(|mac| mac.install_pairwise_keys(identity_id, peer_id, pairwise_keys))
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    ///
    /// # Safety (logical)
    /// Installing wrong keys will silently corrupt the session. This method
    /// is deliberately gated behind the `unsafe-advanced` feature. Prefer
    /// going through the node-layer PFS session manager instead.
    #[cfg(feature = "unsafe-advanced")]
    pub fn install_pairwise_keys_advanced(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: umsh_crypto::PairwiseKeys,
    ) -> Result<Option<crate::peers::PeerCryptoState>, MacHandleError<SendError>> {
        self.install_pairwise_keys(identity_id, peer_id, pairwise_keys)
    }

    /// Enqueues a broadcast frame for transmission.
    ///
    /// Returns a [`SendReceipt`] for tracking transmission progress.
    pub async fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, MacHandleError<SendError>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.send_broadcast(from, payload, options)
            .await
            .map_err(MacHandleError::Inner)
    }

    /// Enqueues a multicast frame for transmission.
    ///
    /// Returns a [`SendReceipt`] for tracking transmission progress.
    pub async fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, MacHandleError<SendError>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.send_multicast(from, channel, payload, options)
            .await
            .map_err(MacHandleError::Inner)
    }

    /// Enqueues a unicast frame for transmission.
    ///
    /// Returns a [`SendReceipt`] when `options.ack_requested` is enabled.
    pub async fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacHandleError<SendError>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.send_unicast(from, dst, payload, options)
            .await
            .map_err(MacHandleError::Inner)
    }

    /// Enqueues a blind-unicast frame for transmission.
    ///
    /// Returns a [`SendReceipt`] when `options.ack_requested` is enabled.
    pub async fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacHandleError<SendError>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.send_blind_unicast(from, dst, channel, payload, options)
            .await
            .map_err(MacHandleError::Inner)
    }

    /// Drive the shared MAC until one wake cycle completes and invoke `on_event` for emitted events.
    pub async fn next_event(
        &self,
        on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacHandleError<MacError<<P::Radio as umsh_hal::Radio>::Error>>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        mac.next_event(on_event).await.map_err(MacHandleError::Inner)
    }

    /// Drive the shared MAC forever, invoking `on_event` for delivered events.
    ///
    /// This is the preferred long-lived driver API for standalone MAC-backed tasks.
    /// It keeps the wait policy inside the coordinator instead of requiring callers to
    /// hand-roll `poll_cycle` loops with arbitrary sleeps.
    pub async fn run(
        &self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacHandleError<MacError<<P::Radio as umsh_hal::Radio>::Error>>> {
        loop {
            self.next_event(&mut on_event).await?;
        }
    }

    /// Drive the shared MAC forever while ignoring emitted events.
    pub async fn run_quiet(
        &self,
    ) -> Result<(), MacHandleError<MacError<<P::Radio as umsh_hal::Radio>::Error>>> {
        self.run(|_, _| {}).await
    }

    /// Fills a caller-provided buffer with random bytes from the shared coordinator RNG.
    pub fn fill_random(
        &self,
        dest: &mut [u8],
    ) -> Result<(), MacHandleError<core::convert::Infallible>> {
        self.with_mac(|mac| {
            mac.rng_mut().fill_bytes(dest);
            Ok(())
        })
    }

    /// Returns the current coordinator clock time in milliseconds.
    pub fn now_ms(&self) -> Result<u64, MacHandleError<core::convert::Infallible>> {
        self.with_mac(|mac| Ok(mac.clock().now_ms()))
    }

    #[cfg(feature = "software-crypto")]
    /// Registers an ephemeral software identity with the shared coordinator.
    ///
    /// This is primarily used by the node layer when a PFS session becomes active.
    pub fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.register_ephemeral(parent, identity))
    }

    #[cfg(feature = "software-crypto")]
    /// Removes a previously registered ephemeral identity.
    pub fn remove_ephemeral(
        &self,
        id: LocalIdentityId,
    ) -> Result<bool, MacHandleError<core::convert::Infallible>> {
        self.with_mac(|mac| Ok(mac.remove_ephemeral(id)))
    }

    /// Cancel a pending ACK-requested send, stopping retransmissions.
    ///
    /// Returns `true` if the pending ACK was found and removed. Returns
    /// `false` if the send was not found or the coordinator was busy.
    pub fn cancel_pending_ack(&self, identity_id: LocalIdentityId, receipt: SendReceipt) -> bool {
        self.mac
            .try_borrow_mut()
            .map(|mut mac| mac.cancel_pending_ack(identity_id, receipt))
            .unwrap_or(false)
    }

    fn with_mac<T, E>(
        &self,
        f: impl FnOnce(&mut Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>) -> Result<T, E>,
    ) -> Result<T, MacHandleError<E>> {
        let mut mac = self
            .mac
            .try_borrow_mut()
            .map_err(|_| MacHandleError::Busy)?;
        f(&mut mac).map_err(MacHandleError::Inner)
    }
}
