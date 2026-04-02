use core::cell::RefCell;

use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_crypto::{AesProvider, NodeIdentity, PairwiseKeys, Sha256Provider};
use umsh_hal::{Clock, CounterStore, Radio, Rng};

use crate::{
    coordinator::{LocalIdentityId, Mac, SendError},
    peers::{PeerCryptoState, PeerId},
    send::{SendOptions, SendReceipt},
    CapacityError,
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
    R: Radio,
    I: NodeIdentity,
    A: AesProvider,
    S: Sha256Provider,
    C: Clock,
    G: Rng,
    CS: CounterStore,
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
> {
    mac: &'a RefCell<Mac<R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
}

impl<
        'a,
        R: Radio,
        I: NodeIdentity,
        A: AesProvider,
        S: Sha256Provider,
        C: Clock,
        G: Rng,
        CS: CounterStore,
        const IDENTITIES: usize,
        const PEERS: usize,
        const CHANNELS: usize,
        const ACKS: usize,
        const TX: usize,
        const FRAME: usize,
        const DUP: usize,
    > Copy for MacHandle<'a, R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
}

impl<
        'a,
        R: Radio,
        I: NodeIdentity,
        A: AesProvider,
        S: Sha256Provider,
        C: Clock,
        G: Rng,
        CS: CounterStore,
        const IDENTITIES: usize,
        const PEERS: usize,
        const CHANNELS: usize,
        const ACKS: usize,
        const TX: usize,
        const FRAME: usize,
        const DUP: usize,
    > Clone for MacHandle<'a, R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<
        'a,
        R: Radio,
        I: NodeIdentity,
        A: AesProvider,
        S: Sha256Provider,
        C: Clock,
        G: Rng,
        CS: CounterStore,
        const IDENTITIES: usize,
        const PEERS: usize,
        const CHANNELS: usize,
        const ACKS: usize,
        const TX: usize,
        const FRAME: usize,
        const DUP: usize,
    > MacHandle<'a, R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    /// Creates a cloneable handle backed by shared coordinator state.
    pub fn new(
        mac: &'a RefCell<Mac<R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
    ) -> Self {
        Self { mac }
    }

    /// Registers a local identity with the shared coordinator.
    pub fn add_identity(&self, identity: I) -> Result<LocalIdentityId, MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.add_identity(identity))
    }

    /// Registers or refreshes a remote peer in the shared registry.
    pub fn add_peer(&self, key: PublicKey) -> Result<PeerId, MacHandleError<core::convert::Infallible>> {
        self.with_mac(|mac| Ok(mac.add_peer(key)))
    }

    /// Adds or updates a shared channel and derives its multicast keys.
    pub fn add_channel(&self, key: ChannelKey) -> Result<(), MacHandleError<CapacityError>> {
        self.with_mac(|mac| mac.add_channel(key))
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    pub fn install_pairwise_keys(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<PeerCryptoState>, MacHandleError<SendError>> {
        self.with_mac(|mac| mac.install_pairwise_keys(identity_id, peer_id, pairwise_keys))
    }

    /// Enqueues a broadcast frame for transmission.
    pub fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), MacHandleError<SendError>> {
        self.with_mac(|mac| mac.queue_broadcast(from, payload, options))
    }

    /// Enqueues a multicast frame for transmission.
    pub fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), MacHandleError<SendError>> {
        self.with_mac(|mac| mac.queue_multicast(from, channel, payload, options))
    }

    /// Enqueues a unicast frame for transmission.
    pub fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacHandleError<SendError>> {
        self.with_mac(|mac| mac.queue_unicast(from, dst, payload, options))
    }

    /// Enqueues a blind-unicast frame for transmission.
    pub fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, MacHandleError<SendError>> {
        self.with_mac(|mac| mac.queue_blind_unicast(from, dst, channel, payload, options))
    }

    fn with_mac<T, E>(
        &self,
        f: impl FnOnce(&mut Mac<R, I, A, S, C, G, CS, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>) -> Result<T, E>,
    ) -> Result<T, MacHandleError<E>> {
        let mut mac = self.mac.try_borrow_mut().map_err(|_| MacHandleError::Busy)?;
        f(&mut mac).map_err(MacHandleError::Inner)
    }
}