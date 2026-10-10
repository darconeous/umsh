use heapless::{LinearMap, Vec};
use umsh_core::{ChannelId, ChannelKey, NodeHint, PublicKey, RouterHint};
use umsh_crypto::{DerivedChannelKeys, PairwiseKeys};

use crate::{CapacityError, cache::ReplayWindow};

const FAILED_ROUTE_HOLDOFF_MS: u64 = 30_000;

/// Opaque identifier for one remote peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub u8);

/// Learned routing information for a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CachedRoute {
    /// Peer was heard directly; this is not proof of reverse reachability.
    ///
    /// Inferred when a packet arrives with no source-route or traceroute option
    /// (or an empty traceroute) and `FHOPS_ACC == 0`.
    Direct,
    /// Explicit source route taken from the inbound traceroute (already in return order).
    /// Each hint names one repeater; the path is one hop longer than the
    /// route has hints.
    Source(Vec<RouterHint, 15>),
    /// Flood-delivery parameters learned from an inbound packet.
    ///
    /// `flood_hops` is the `FHOPS_ACC` the peer was last heard at, which is
    /// also the `FHOPS_REM` budget the next send needs. It is one less than
    /// the distance in hops: the final transmission of a flood spends no
    /// budget. Learned only from a packet that carried no source route, so
    /// that relation holds for it; see [`CachedRoute::hop_count`].
    Flood {
        flood_hops: u8,
        regions: Vec<[u8; 2], 8>,
    },
}

impl CachedRoute {
    /// Maximum repeater hints a source route can name, matching
    /// `MAX_SOURCE_ROUTE_HINTS`.
    pub const MAX_HINTS: usize = 15;
    /// Maximum region codes a learned flood route carries.
    pub const MAX_REGIONS: usize = 8;

    /// Build a source route from `hints`, or `None` if there are more
    /// than a packet could carry.
    ///
    /// For callers outside this crate, which have no reason to name a
    /// fixed-capacity container. Refusing an over-long route beats
    /// truncating one, which would send traffic to the wrong place.
    pub fn source(hints: &[RouterHint]) -> Option<Self> {
        Vec::from_slice(hints).ok().map(Self::Source)
    }

    /// Build a flood route from `flood_hops` and `regions`, or `None` if
    /// there are more region codes than one carries.
    pub fn flood(flood_hops: u8, regions: &[[u8; 2]]) -> Option<Self> {
        Vec::from_slice(regions).ok().map(|regions| Self::Flood {
            flood_hops,
            regions,
        })
    }

    /// The distance to the peer in hops, per the spec's definition: one
    /// transmission between adjacent nodes.
    ///
    /// The counterpart of `ReceivedPacketRef::hop_count` for a cached route,
    /// so a route and the frame that taught it report the same number. A
    /// direct peer is one hop away. A source route is one hop longer than it
    /// has hints, the leg into the first repeater belonging to no hint. A
    /// flood route is one hop past its `flood_hops`, the final transmission
    /// spending no budget.
    pub fn hop_count(&self) -> u8 {
        match self {
            Self::Direct => 1,
            Self::Source(hints) => u8::try_from(hints.len())
                .unwrap_or(u8::MAX)
                .saturating_add(1),
            Self::Flood { flood_hops, .. } => flood_hops.saturating_add(1),
        }
    }
}

/// Shared metadata tracked for a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Full public key.
    pub public_key: PublicKey,
    /// Whether this peer was explicitly configured by the local application.
    pub pinned: bool,
    /// Most recent learned route, if any.
    pub route: Option<CachedRoute>,
    /// Revision of the selected route. Use registry route methods to mutate it.
    pub(crate) route_revision: u64,
    /// How the selected route scored on the latest evidence for it (see
    /// [`crate::route_score`]). `None` for a route nothing has measured: a
    /// flood distance, or a route installed by hand.
    pub(crate) route_score: Option<i16>,
    /// When an acknowledgment last came back for a send on the selected
    /// route.
    pub(crate) route_confirmed_ms: Option<u64>,
    /// One recently failed route, suppressed only for passive route learning.
    failed_route: Option<(CachedRoute, u64)>,
    /// Most recent observation timestamp.
    pub last_seen_ms: u64,
    /// Highest RX frame counter loaded from persistent storage at boot.
    ///
    /// Non-zero means a stored boundary was found. When pairwise keys are
    /// first installed for this peer, the replay window is initialized to
    /// this value so that frames from before the reboot are rejected.
    pub initial_rx_counter: u32,
}

impl PeerInfo {
    fn new(public_key: PublicKey, pinned: bool, last_seen_ms: u64) -> Self {
        Self {
            public_key,
            pinned,
            route: None,
            route_revision: 0,
            route_score: None,
            route_confirmed_ms: None,
            failed_route: None,
            last_seen_ms,
            initial_rx_counter: 0,
        }
    }

    /// How the selected route scored on the latest evidence for it, in
    /// centibels; higher is better. `None` when nothing has measured it.
    pub fn route_score(&self) -> Option<i16> {
        self.route_score
    }

    /// Select `route`, forgetting what was known about the one it replaces.
    fn select_route(&mut self, route: Option<CachedRoute>, score: Option<i16>, revision: u64) {
        self.route = route;
        self.route_score = score;
        self.route_confirmed_ms = None;
        self.route_revision = revision;
    }
}

/// Evidence for a route, as one received frame offers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouteOffer {
    pub route: CachedRoute,
    /// How the path scored on what the frame measured. `None` for a flood
    /// distance, which names no path to score.
    pub score: Option<i16>,
    /// The sender declared its own route failed and is rediscovering, so
    /// whatever this node held is suspect too.
    pub supersedes: bool,
    /// The path is the one an acknowledgment came back on.
    pub acknowledgment: bool,
}

/// Outcome of inserting or updating an auto-learned peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoPeerUpdate {
    /// Slot assigned to the peer.
    pub peer_id: PeerId,
    /// Previous peer key displaced from this slot, if any.
    pub evicted_key: Option<PublicKey>,
}

/// Outcome of removing a peer from the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerRemoval {
    /// Public key of the removed peer.
    pub removed_key: PublicKey,
    /// When removal swap-moved the last entry into the freed slot: that
    /// entry's `(old, new)` identifiers. Every `PeerId`-keyed structure must
    /// be re-keyed accordingly.
    pub moved: Option<(PeerId, PeerId)>,
}

/// Fixed-capacity registry of remote peers.
#[derive(Clone, Debug)]
pub struct PeerRegistry<const N: usize> {
    peers: Vec<PeerInfo, N>,
    next_route_revision: u64,
}

impl<const N: usize> Default for PeerRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerRegistry<N> {
    /// Create an empty peer registry.
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            next_route_revision: 0,
        }
    }

    /// Iterate over peers whose derived hint matches `hint`.
    pub fn lookup_by_hint(&self, hint: &NodeHint) -> impl Iterator<Item = (PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .enumerate()
            .filter(move |(_, peer)| peer.public_key.hint() == *hint)
            .map(|(index, peer)| (PeerId(index as u8), peer))
    }

    /// Look up a peer by full public key.
    pub fn lookup_by_key(&self, key: &PublicKey) -> Option<(PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .enumerate()
            .find(|(_, peer)| peer.public_key == *key)
            .map(|(index, peer)| (PeerId(index as u8), peer))
    }

    /// Iterate over all registered peers.
    pub fn iter(&self) -> impl Iterator<Item = (PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (PeerId(index as u8), peer))
    }

    /// Borrow peer metadata by identifier.
    pub fn get(&self, id: PeerId) -> Option<&PeerInfo> {
        self.peers.get(id.0 as usize)
    }

    /// Mutably borrow peer metadata by identifier.
    pub fn get_mut(&mut self, id: PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(id.0 as usize)
    }

    /// Insert or refresh an explicitly configured peer entry.
    pub fn try_insert_or_update(&mut self, key: PublicKey) -> Result<PeerId, CapacityError> {
        if let Some((id, peer)) = self
            .peers
            .iter_mut()
            .enumerate()
            .find(|(_, peer)| peer.public_key == key)
        {
            peer.public_key = key;
            peer.pinned = true;
            return Ok(PeerId(id as u8));
        }

        self.peers
            .push(PeerInfo::new(key, true, 0))
            .map_err(|_| CapacityError)?;
        Ok(PeerId((self.peers.len() - 1) as u8))
    }

    /// Insert or refresh an opportunistically learned peer entry.
    ///
    /// When the registry is full, this may recycle the oldest non-pinned entry in place
    /// rather than failing. Explicitly configured (`pinned`) peers are never displaced.
    pub fn try_insert_or_update_auto(
        &mut self,
        key: PublicKey,
        now_ms: u64,
    ) -> Result<AutoPeerUpdate, CapacityError> {
        if let Some((id, peer)) = self
            .peers
            .iter_mut()
            .enumerate()
            .find(|(_, peer)| peer.public_key == key)
        {
            peer.last_seen_ms = now_ms;
            return Ok(AutoPeerUpdate {
                peer_id: PeerId(id as u8),
                evicted_key: None,
            });
        }

        if self.peers.len() < N {
            self.peers
                .push(PeerInfo::new(key, false, now_ms))
                .map_err(|_| CapacityError)?;
            return Ok(AutoPeerUpdate {
                peer_id: PeerId((self.peers.len() - 1) as u8),
                evicted_key: None,
            });
        }

        let Some((index, oldest)) = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| !peer.pinned)
            .min_by_key(|(_, peer)| peer.last_seen_ms)
        else {
            return Err(CapacityError);
        };

        let evicted_key = oldest.public_key;
        self.peers[index] = PeerInfo::new(key, false, now_ms);
        Ok(AutoPeerUpdate {
            peer_id: PeerId(index as u8),
            evicted_key: Some(evicted_key),
        })
    }

    /// Remove a peer, freeing its slot for reuse.
    ///
    /// The registry is dense—a `PeerId` is an index—so removal swap-moves
    /// the last entry into the freed slot. The returned record names that
    /// move so the caller can re-key any state held under the moved peer's
    /// old identifier.
    pub fn remove(&mut self, id: PeerId) -> Option<PeerRemoval> {
        let index = id.0 as usize;
        if index >= self.peers.len() {
            return None;
        }
        let last = self.peers.len() - 1;
        let removed = self.peers.swap_remove(index);
        let moved = (index != last).then_some((PeerId(last as u8), id));
        Some(PeerRemoval {
            removed_key: removed.public_key,
            moved,
        })
    }

    fn next_revision(&mut self) -> u64 {
        self.next_route_revision = self.next_route_revision.wrapping_add(1).max(1);
        self.next_route_revision
    }

    /// Explicitly restore a route, overriding any passive-learning holdoff.
    ///
    /// Nothing has measured a route installed this way, so the first
    /// received frame that offers a scored path replaces it.
    pub fn update_route(&mut self, id: PeerId, route: CachedRoute) {
        let revision = self.next_revision();
        if let Some(peer) = self.get_mut(id) {
            peer.select_route(Some(route), None, revision);
            peer.failed_route = None;
        }
    }

    /// Weigh the route one received frame offers against the one held,
    /// without immediately resurrecting a failed path.
    ///
    /// - The path already held is not replaced but re-scored: the newest
    ///   measurement of it is the one that says what it is worth now. An
    ///   identical observation is not fresh outbound success, so it does
    ///   not count as confirmation.
    /// - A path displaces a flood distance, which only stands in for a path
    ///   not yet known; a flood distance never displaces a path.
    /// - A scored path displaces one nothing has measured.
    /// - Otherwise the offer has to score clearly better, and better still
    ///   when an acknowledgment has recently vouched for the route held.
    pub(crate) fn offer_route(&mut self, id: PeerId, offer: RouteOffer, now_ms: u64) {
        let Some(peer) = self.get_mut(id) else {
            return;
        };
        if let Some((failed, until)) = &peer.failed_route {
            if now_ms < *until
                && (failed == &offer.route
                    || (failed.hop_count() == 1 && offer.route.hop_count() == 1))
            {
                return;
            }
            if now_ms >= *until {
                peer.failed_route = None;
            }
        }
        if peer.route.as_ref() == Some(&offer.route) {
            if offer.score.is_some() {
                peer.route_score = offer.score;
            }
            return;
        }
        let confirmed = peer
            .route_confirmed_ms
            .is_some_and(|at| now_ms.saturating_sub(at) <= crate::route_score::CONFIRMATION_TTL_MS);
        let replace = offer.supersedes
            || match (&peer.route, offer.score) {
                (None | Some(CachedRoute::Flood { .. }), _) => true,
                (Some(_), None) => false,
                (Some(current), Some(score)) => match peer.route_score {
                    Some(held) => crate::route_score::displaces(score, held, confirmed),
                    // Nothing scored the route in use: it was installed by
                    // hand or restored, and any measured path replaces it.
                    // An acknowledgment's way back replaces only a direct
                    // route, which is often just an observation of the
                    // peer's transmitter and says nothing about whether the
                    // peer hears us. A longer route the ack answered is not
                    // contradicted by a different way back.
                    None => !offer.acknowledgment || current.hop_count() <= 1,
                },
            };
        if !replace {
            return;
        }
        let revision = self.next_revision();
        let peer = self.get_mut(id).expect("peer was just found");
        peer.select_route(Some(offer.route), offer.score, revision);
    }

    /// Forget a route explicitly; passive learning remains allowed.
    pub fn clear_route(&mut self, id: PeerId) -> bool {
        let revision = self.next_revision();
        self.get_mut(id)
            .map(|peer| {
                let held = peer.route.is_some();
                peer.select_route(None, None, revision);
                peer.failed_route = None;
                held
            })
            .unwrap_or(false)
    }

    /// Retire only the cached route used by the failed on-air attempt.
    pub(crate) fn fail_route(&mut self, key: &PublicKey, revision: u64, now_ms: u64) {
        let Some((id, peer)) = self.lookup_by_key(key) else {
            return;
        };
        if revision == 0 || peer.route_revision != revision {
            return;
        }
        let next_revision = self.next_revision();
        let peer = self.get_mut(id).expect("peer was just found");
        if let Some(route) = peer.route.take() {
            peer.failed_route = Some((route, now_ms.saturating_add(FAILED_ROUTE_HOLDOFF_MS)));
            peer.select_route(None, None, next_revision);
        }
    }

    /// A matching ACK protects this route from older outstanding failures,
    /// and credits it against new candidates for a while.
    ///
    /// It confirms the whole send policy, including its optional flood
    /// tail, which is why the credit is not a guarantee: the tail may be
    /// what delivered the exchange.
    pub(crate) fn confirm_route(&mut self, key: &PublicKey, revision: u64, now_ms: u64) {
        let Some((id, peer)) = self.lookup_by_key(key) else {
            return;
        };
        if revision == 0 || peer.route_revision != revision || peer.route.is_none() {
            return;
        }
        let next_revision = self.next_revision();
        let peer = self.get_mut(id).expect("peer was just found");
        peer.route_revision = next_revision;
        peer.route_confirmed_ms = Some(now_ms);
    }

    /// Refresh the last-seen timestamp for `id`.
    pub fn touch(&mut self, id: PeerId, now_ms: u64) {
        if let Some(peer) = self.get_mut(id) {
            peer.last_seen_ms = now_ms;
        }
    }
}

/// Per-peer secure transport state.
#[derive(Clone)]
pub struct PeerCryptoState {
    /// Pairwise encryption and MIC keys.
    pub pairwise_keys: PairwiseKeys,
    /// Replay state for traffic from this peer.
    pub replay_window: ReplayWindow,
    /// Highest `last_accepted` value written to persistent storage.
    /// Updated by `service_rx_counter_persistence` after each flush.
    pub persisted_rx_counter: u32,
    /// Set when `last_accepted` has advanced `COUNTER_PERSIST_BLOCK_SIZE`
    /// beyond `persisted_rx_counter`. Cleared after the next flush.
    pub needs_rx_persist: bool,
}

/// Fixed-capacity map of per-peer secure transport state.
#[derive(Clone)]
pub struct PeerCryptoMap<const N: usize> {
    entries: LinearMap<PeerId, PeerCryptoState, N>,
}

impl<const N: usize> Default for PeerCryptoMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerCryptoMap<N> {
    /// Create an empty peer-crypto map.
    pub fn new() -> Self {
        Self {
            entries: LinearMap::new(),
        }
    }

    /// Borrow one peer state.
    pub fn get(&self, id: &PeerId) -> Option<&PeerCryptoState> {
        self.entries.get(id)
    }

    /// Mutably borrow one peer state.
    pub fn get_mut(&mut self, id: &PeerId) -> Option<&mut PeerCryptoState> {
        self.entries.get_mut(id)
    }

    /// Insert or replace state for a peer.
    pub fn insert(
        &mut self,
        id: PeerId,
        state: PeerCryptoState,
    ) -> Result<Option<PeerCryptoState>, CapacityError> {
        self.entries.insert(id, state).map_err(|_| CapacityError)
    }

    /// Remove state for a peer.
    pub fn remove(&mut self, id: &PeerId) -> Option<PeerCryptoState> {
        self.entries.remove(id)
    }

    /// Iterate over all peer crypto entries.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &PeerCryptoState)> {
        self.entries.iter()
    }

    /// Iterate mutably over all peer crypto entries.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&PeerId, &mut PeerCryptoState)> {
        self.entries.iter_mut()
    }
}

/// Replay state for a sender known only by hint.
#[derive(Clone)]
pub struct HintReplayState {
    /// Replay window for the hint-only sender.
    pub window: ReplayWindow,
    /// Most recent observation timestamp.
    pub last_seen_ms: u64,
}

/// Shared state for one multicast channel.
#[derive(Clone)]
pub struct ChannelState<const RN: usize = 8, const HN: usize = 8> {
    /// Raw channel key.
    pub channel_key: ChannelKey,
    /// Derived transport keys and identifier.
    pub derived: DerivedChannelKeys,
    /// Replay windows for peers resolved to full identities.
    pub replay: LinearMap<PeerId, ReplayWindow, RN>,
    /// Replay windows for senders known only by hint.
    pub hint_replay: LinearMap<NodeHint, HintReplayState, HN>,
}

impl<const RN: usize, const HN: usize> ChannelState<RN, HN> {
    /// Create a new channel-state record.
    pub fn new(channel_key: ChannelKey, derived: DerivedChannelKeys) -> Self {
        Self {
            channel_key,
            derived,
            replay: LinearMap::new(),
            hint_replay: LinearMap::new(),
        }
    }
}

/// Fixed-capacity channel table shared by the MAC coordinator.
#[derive(Clone)]
pub struct ChannelTable<const N: usize, const RN: usize = 8, const HN: usize = 8> {
    channels: Vec<ChannelState<RN, HN>, N>,
}

impl<const N: usize, const RN: usize, const HN: usize> Default for ChannelTable<N, RN, HN> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const RN: usize, const HN: usize> ChannelTable<N, RN, HN> {
    /// Create an empty channel table.
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
        }
    }

    /// Return the number of configured channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Return whether no channels are configured.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Iterate over channels whose derived identifier matches `id`.
    pub fn lookup_by_id(&self, id: &ChannelId) -> impl Iterator<Item = &ChannelState<RN, HN>> {
        self.channels
            .iter()
            .filter(move |channel| channel.derived.channel_id == *id)
    }

    /// Mutably borrow the first channel whose derived identifier matches `id`.
    pub fn get_mut_by_id(&mut self, id: &ChannelId) -> Option<&mut ChannelState<RN, HN>> {
        self.channels
            .iter_mut()
            .find(|channel| channel.derived.channel_id == *id)
    }

    /// Mutably iterate over all channel states.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ChannelState<RN, HN>> {
        self.channels.iter_mut()
    }

    /// Remove the channel holding this exact key, discarding its replay
    /// state with it (re-adding the key later starts at first contact).
    /// Returns whether a channel was removed.
    pub fn remove_by_key(&mut self, key: &ChannelKey) -> bool {
        let Some(index) = self
            .channels
            .iter()
            .position(|channel| channel.channel_key.0 == key.0)
        else {
            return false;
        };
        self.channels.swap_remove(index);
        true
    }

    /// Add or replace a channel entry.
    pub fn try_add(
        &mut self,
        key: ChannelKey,
        derived: DerivedChannelKeys,
    ) -> Result<(), CapacityError> {
        if let Some(channel) = self.get_mut_by_id(&derived.channel_id) {
            channel.channel_key = key;
            channel.derived = derived;
            return Ok(());
        }

        self.channels
            .push(ChannelState::new(key, derived))
            .map_err(|_| CapacityError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distance a cached route reports agrees with what a received
    /// frame reports for the same path: a direct peer is one hop, and each
    /// repeater hint or flood hop adds one to the leg no count covers.
    #[test]
    fn hop_count_is_one_more_than_what_the_route_names() {
        assert_eq!(CachedRoute::Direct.hop_count(), 1);
        assert_eq!(CachedRoute::source(&[]).unwrap().hop_count(), 1);
        assert_eq!(
            CachedRoute::source(&[RouterHint([1, 2]), RouterHint([3, 4])])
                .unwrap()
                .hop_count(),
            3
        );
        assert_eq!(CachedRoute::flood(0, &[]).unwrap().hop_count(), 1);
        assert_eq!(
            CachedRoute::flood(2, &[[0x68, 0xAC]]).unwrap().hop_count(),
            3
        );
        assert_eq!(
            CachedRoute::flood(u8::MAX, &[]).unwrap().hop_count(),
            u8::MAX
        );
    }
}
