use heapless::{LinearMap, Vec};
use umsh_core::{ChannelId, ChannelKey, NodeHint, PublicKey, RouterHint};
use umsh_crypto::{DerivedChannelKeys, PairwiseKeys};

use crate::{cache::ReplayWindow, CapacityError};

/// Opaque identifier for one remote peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub u8);

/// Learned routing information for a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CachedRoute {
    /// Explicit source route.
    Source(Vec<RouterHint, 15>),
    /// Flood-distance estimate.
    Flood { hops: u8 },
}

/// Shared metadata tracked for a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Full public key.
    pub public_key: PublicKey,
    /// Most recent learned route, if any.
    pub route: Option<CachedRoute>,
    /// Most recent observation timestamp.
    pub last_seen_ms: u64,
}

/// Fixed-capacity registry of remote peers.
#[derive(Clone, Debug)]
pub struct PeerRegistry<const N: usize> {
    peers: Vec<PeerInfo, N>,
}

impl<const N: usize> Default for PeerRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerRegistry<N> {
    /// Create an empty peer registry.
    pub fn new() -> Self {
        Self { peers: Vec::new() }
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

    /// Borrow peer metadata by identifier.
    pub fn get(&self, id: PeerId) -> Option<&PeerInfo> {
        self.peers.get(id.0 as usize)
    }

    /// Mutably borrow peer metadata by identifier.
    pub fn get_mut(&mut self, id: PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(id.0 as usize)
    }

    /// Insert or refresh a peer entry.
    pub fn try_insert_or_update(&mut self, key: PublicKey) -> Result<PeerId, CapacityError> {
        if let Some((id, peer)) = self
            .peers
            .iter_mut()
            .enumerate()
            .find(|(_, peer)| peer.public_key == key)
        {
            peer.public_key = key;
            return Ok(PeerId(id as u8));
        }

        self.peers
            .push(PeerInfo {
                public_key: key,
                route: None,
                last_seen_ms: 0,
            })
            .map_err(|_| CapacityError)?;
        Ok(PeerId((self.peers.len() - 1) as u8))
    }

    /// Insert or refresh a peer entry, panicking on capacity exhaustion.
    pub fn insert_or_update(&mut self, key: PublicKey) -> PeerId {
        self.try_insert_or_update(key)
            .expect("peer registry capacity exceeded")
    }

    /// Update the cached route for `id`.
    pub fn update_route(&mut self, id: PeerId, route: CachedRoute) {
        if let Some(peer) = self.get_mut(id) {
            peer.route = Some(route);
        }
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

    /// Add or replace a channel entry, panicking on capacity exhaustion.
    pub fn add(&mut self, key: ChannelKey, derived: DerivedChannelKeys) {
        self.try_add(key, derived)
            .expect("channel table capacity exceeded")
    }
}