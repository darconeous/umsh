use core::future::poll_fn;

use rand::Rng;
use umsh_core::{ChannelId, ChannelKey, PublicKey};
use umsh_hal::{Clock, CounterStore};
use umsh_sync::AsyncRefCell;

use crate::{
    AddPeerError, CapacityError, DEFAULT_ACKS, DEFAULT_CHANNELS, DEFAULT_DUP, DEFAULT_FRAME,
    DEFAULT_IDENTITIES, DEFAULT_PEERS, DEFAULT_TX, Platform,
    coordinator::{CounterPersistenceError, LocalIdentityId, Mac, MacError, SendError},
    peers::PeerId,
    send::{SendOptions, SendReceipt},
};

/// Lightweight, cloneable handle for queuing MAC operations against shared state.
///
/// The handle borrows an [`AsyncRefCell`] that owns the underlying coordinator.
/// Every operation takes the cell asynchronously: if another caller currently
/// holds the coordinator (for example, the long-running `run()` loop that is
/// waiting on the radio), operations wait rather than failing.
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
    mac: &'a AsyncRefCell<Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
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
        mac: &'a AsyncRefCell<Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
    ) -> Self {
        Self { mac }
    }

    /// Registers a local identity with the shared coordinator.
    pub async fn add_identity(
        &self,
        identity: P::Identity,
    ) -> Result<LocalIdentityId, CapacityError> {
        self.mac.borrow_mut().await.add_identity(identity)
    }

    /// Load the persisted frame-counter boundary for one identity.
    pub async fn load_persisted_counter(
        &self,
        id: LocalIdentityId,
    ) -> Result<u32, CounterPersistenceError<<P::CounterStore as CounterStore>::Error>> {
        self.mac.borrow_mut().await.load_persisted_counter(id).await
    }

    /// Persist all currently scheduled frame-counter reservations.
    pub async fn service_counter_persistence(
        &self,
    ) -> Result<usize, <P::CounterStore as CounterStore>::Error> {
        self.mac
            .borrow_mut()
            .await
            .service_counter_persistence()
            .await
    }

    /// Load persisted RX counter boundaries for all registered peers from
    /// durable storage, storing them in each peer's [`PeerInfo::initial_rx_counter`].
    ///
    /// Call this once at boot, after all known peers have been registered with
    /// [`add_peer`](Self::add_peer), and before the first call to
    /// [`next_event`](crate::Mac::next_event). When pairwise keys are later
    /// derived for a peer, the replay window is automatically initialised to
    /// the loaded boundary.
    pub async fn load_all_persisted_rx_counters(
        &self,
    ) -> Result<usize, <P::CounterStore as CounterStore>::Error> {
        self.mac
            .borrow_mut()
            .await
            .load_all_persisted_rx_counters()
            .await
    }

    /// Registers or refreshes a remote peer in the shared registry.
    pub async fn add_peer(&self, key: PublicKey) -> Result<PeerId, AddPeerError> {
        self.mac.borrow_mut().await.add_peer(key)
    }

    /// Adds or updates a shared channel and derives its multicast keys.
    pub async fn add_channel(&self, key: ChannelKey) -> Result<(), CapacityError> {
        self.mac.borrow_mut().await.add_channel(key)
    }

    /// Adds or updates a named channel using the coordinator's channel-key derivation.
    ///
    /// The name is canonicalized (ASCII lowercase fold) before derivation.
    pub async fn add_named_channel(&self, name: &str) -> Result<(), crate::AddChannelError> {
        self.mac.borrow_mut().await.add_named_channel(name)
    }

    /// Return whether inbound secure packets carrying a full source key may auto-register peers.
    pub async fn auto_register_full_key_peers(&self) -> bool {
        self.mac.borrow().await.auto_register_full_key_peers()
    }

    /// Enable or disable inbound full-key peer auto-registration.
    pub async fn set_auto_register_full_key_peers(&self, enabled: bool) {
        self.mac
            .borrow_mut()
            .await
            .set_auto_register_full_key_peers(enabled);
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    ///
    /// This is a crate-internal method. External callers should use the
    /// `unsafe-advanced` feature or go through the node-layer PFS session manager.
    #[cfg(any(feature = "unsafe-advanced", test))]
    pub(crate) async fn install_pairwise_keys(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: umsh_crypto::PairwiseKeys,
    ) -> Result<Option<crate::peers::PeerCryptoState>, SendError> {
        self.mac
            .borrow_mut()
            .await
            .install_pairwise_keys(identity_id, peer_id, pairwise_keys)
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    ///
    /// # Safety (logical)
    /// Installing wrong keys will silently corrupt the session. This method
    /// is deliberately gated behind the `unsafe-advanced` feature. Prefer
    /// going through the node-layer PFS session manager instead.
    #[cfg(feature = "unsafe-advanced")]
    pub async fn install_pairwise_keys_advanced(
        &self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: umsh_crypto::PairwiseKeys,
    ) -> Result<Option<crate::peers::PeerCryptoState>, SendError> {
        self.install_pairwise_keys(identity_id, peer_id, pairwise_keys)
            .await
    }

    /// Enqueues a broadcast frame for transmission.
    pub async fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        self.mac
            .borrow_mut()
            .await
            .send_broadcast(from, payload, options)
            .await
    }

    /// Enqueues a multicast frame for transmission.
    pub async fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        self.mac
            .borrow_mut()
            .await
            .send_multicast(from, channel, payload, options)
            .await
    }

    /// Enqueues a unicast frame for transmission.
    pub async fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        self.mac
            .borrow_mut()
            .await
            .send_unicast(from, dst, payload, options)
            .await
    }

    /// Enqueues a blind-unicast frame for transmission.
    pub async fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        self.mac
            .borrow_mut()
            .await
            .send_blind_unicast(from, dst, channel, payload, options)
            .await
    }

    /// Drive the shared MAC until one wake cycle completes and invoke `on_event` for emitted events.
    ///
    /// The exclusive borrow on the shared coordinator is released between
    /// every internal phase so that other handles (CLI sends, UI queries,
    /// counter-persistence services) can interleave their own async work
    /// while this driver is waiting on the radio or a timer.
    pub async fn next_event(
        &self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as umsh_hal::Radio>::Error>> {
        loop {
            // Phase 1: drain any ready transmit work.
            self.mac
                .borrow_mut()
                .await
                .drain_tx_queue(&mut on_event)
                .await?;

            // Phase 2: wait for a radio frame or timer deadline. Acquire the
            // borrow briefly each poll so concurrent tasks can obtain it too.
            // `poll_with_mut` keeps us registered on the cell's wake condition
            // across Pending polls, so we re-poll both when the cell frees up
            // and when another handle mutates coordinator state (e.g.
            // `cli.send_unicast` enqueues a frame and drops its borrow) —
            // without that, TX queued by concurrent handles would sit until
            // the next radio/timer event. It also deregisters us around our
            // own borrow so our guard release cannot self-wake into a spin,
            // and the scoped ticket deregisters on drop so this wait can be
            // cancelled (e.g. losing a `select!` race) without leaking its
            // waker registration.
            let mut buf = [0u8; FRAME];
            let mut cond_ticket = self.mac.scoped_ticket();
            let reason = poll_fn(|cx| {
                self.mac.poll_with_mut(cx, &mut cond_ticket, |mac, cx| {
                    // Register radio/timer wakers and check readiness in one shot.
                    mac.poll_wait_for_wake(cx, &mut buf)
                })
            })
            .await
            .map_err(MacError::Radio)?;
            drop(cond_ticket);

            // Phases 3-5: re-acquire the borrow and finish the cycle.
            self.mac
                .borrow_mut()
                .await
                .process_wake_reason(reason, &mut buf, &mut on_event)
                .await?;

            // Flush any pending TX or RX counter boundaries to durable storage.
            // Mirrors `Mac::next_event`. Errors are intentionally ignored —
            // persistence is best-effort and must not block the radio event
            // loop. Borrow is dropped before the next phase.
            {
                let mut mac = self.mac.borrow_mut().await;
                let _ = mac.service_counter_persistence().await;
                let _ = mac.service_rx_counter_persistence().await;
            }

            // If new transmit work appeared during processing (e.g. a
            // retransmit was enqueued), loop back to drain it before
            // waiting again.
            let tx_empty = self.mac.borrow().await.tx_queue().is_empty();
            if !tx_empty {
                continue;
            }
            return Ok(());
        }
    }

    /// Drive the shared MAC forever, invoking `on_event` for delivered events.
    ///
    /// This is the preferred long-lived driver API for standalone MAC-backed tasks.
    pub async fn run(
        &self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as umsh_hal::Radio>::Error>> {
        loop {
            self.next_event(&mut on_event).await?;
        }
    }

    /// Drive the shared MAC forever while ignoring emitted events.
    pub async fn run_quiet(&self) -> Result<(), MacError<<P::Radio as umsh_hal::Radio>::Error>> {
        self.run(|_, _| {}).await
    }

    /// Fills a caller-provided buffer with random bytes from the shared coordinator RNG.
    pub async fn fill_random(&self, dest: &mut [u8]) {
        self.mac.borrow_mut().await.rng_mut().fill_bytes(dest);
    }

    /// Returns the current coordinator clock time in milliseconds.
    pub async fn now_ms(&self) -> u64 {
        self.mac.borrow().await.clock().now_ms()
    }

    #[cfg(feature = "software-crypto")]
    /// Registers an ephemeral software identity with the shared coordinator.
    pub async fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, CapacityError> {
        self.mac
            .borrow_mut()
            .await
            .register_ephemeral(parent, identity)
    }

    #[cfg(feature = "software-crypto")]
    /// Removes a previously registered ephemeral identity.
    pub async fn remove_ephemeral(&self, id: LocalIdentityId) -> bool {
        self.mac.borrow_mut().await.remove_ephemeral(id)
    }

    /// Cancel a pending ACK-requested send, stopping retransmissions.
    ///
    /// Returns `true` if the pending ACK was found and removed.
    pub async fn cancel_pending_ack(
        &self,
        identity_id: LocalIdentityId,
        receipt: SendReceipt,
    ) -> bool {
        self.mac
            .borrow_mut()
            .await
            .cancel_pending_ack(identity_id, receipt)
    }

    /// Return the live TX frame counter for one identity, if registered.
    pub async fn frame_counter(&self, id: LocalIdentityId) -> Option<u32> {
        self.mac
            .borrow()
            .await
            .identity(id)
            .map(|slot| slot.frame_counter())
    }

    /// Return the persisted TX frame-counter boundary for one identity, if registered.
    pub async fn persisted_frame_counter(&self, id: LocalIdentityId) -> Option<u32> {
        self.mac
            .borrow()
            .await
            .identity(id)
            .map(|slot| slot.persisted_counter())
    }

    /// Invoke `f` for every peer currently registered in the shared registry.
    ///
    /// This covers all known peers, not just those with an active crypto session.
    pub async fn for_each_peer(&self, f: &mut dyn FnMut(umsh_core::PublicKey)) {
        let mac = self.mac.borrow().await;
        for (_, info) in mac.peer_registry().iter() {
            f(info.public_key);
        }
    }

    /// Invoke `f` for each peer with an established crypto state for `id`,
    /// passing the peer's public key, last-accepted RX counter, and persisted RX boundary.
    pub async fn for_each_peer_counter(
        &self,
        id: LocalIdentityId,
        f: &mut dyn FnMut(umsh_core::PublicKey, u32, u32),
    ) {
        let mac = self.mac.borrow().await;
        let Some(slot) = mac.identity(id) else {
            return;
        };
        for (peer_id, state) in slot.peer_crypto().iter() {
            let Some(info) = mac.peer_registry().get(*peer_id) else {
                continue;
            };
            f(
                info.public_key,
                state.replay_window.last_accepted,
                state.persisted_rx_counter,
            );
        }
    }
}
