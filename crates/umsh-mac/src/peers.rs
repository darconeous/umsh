use heapless::{LinearMap, Vec};
use umsh_core::{ChannelId, ChannelKey, NodeHint, PublicKey, RouterHint};
use umsh_crypto::{DerivedChannelKeys, PairwiseKeys};

use crate::{cache::ReplayWindow, CapacityError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub u8);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CachedRoute {
    Source(Vec<RouterHint, 15>),
    Flood { hops: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub public_key: PublicKey,
    pub route: Option<CachedRoute>,
    pub last_seen_ms: u64,
}

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
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    pub fn lookup_by_hint(&self, hint: &NodeHint) -> impl Iterator<Item = (PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .enumerate()
            .filter(move |(_, peer)| peer.public_key.hint() == *hint)
            .map(|(index, peer)| (PeerId(index as u8), peer))
    }

    pub fn lookup_by_key(&self, key: &PublicKey) -> Option<(PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .enumerate()
            .find(|(_, peer)| peer.public_key == *key)
            .map(|(index, peer)| (PeerId(index as u8), peer))
    }

    pub fn get(&self, id: PeerId) -> Option<&PeerInfo> {
        self.peers.get(id.0 as usize)
    }

    pub fn get_mut(&mut self, id: PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(id.0 as usize)
    }

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

    pub fn insert_or_update(&mut self, key: PublicKey) -> PeerId {
        self.try_insert_or_update(key)
            .expect("peer registry capacity exceeded")
    }

    pub fn update_route(&mut self, id: PeerId, route: CachedRoute) {
        if let Some(peer) = self.get_mut(id) {
            peer.route = Some(route);
        }
    }

    pub fn touch(&mut self, id: PeerId, now_ms: u64) {
        if let Some(peer) = self.get_mut(id) {
            peer.last_seen_ms = now_ms;
        }
    }
}

#[derive(Clone)]
pub struct PeerCryptoState {
    pub pairwise_keys: PairwiseKeys,
    pub replay_window: ReplayWindow,
}

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
    pub fn new() -> Self {
        Self {
            entries: LinearMap::new(),
        }
    }

    pub fn get(&self, id: &PeerId) -> Option<&PeerCryptoState> {
        self.entries.get(id)
    }

    pub fn get_mut(&mut self, id: &PeerId) -> Option<&mut PeerCryptoState> {
        self.entries.get_mut(id)
    }

    pub fn insert(
        &mut self,
        id: PeerId,
        state: PeerCryptoState,
    ) -> Result<Option<PeerCryptoState>, CapacityError> {
        self.entries.insert(id, state).map_err(|_| CapacityError)
    }

    pub fn remove(&mut self, id: &PeerId) -> Option<PeerCryptoState> {
        self.entries.remove(id)
    }
}

#[derive(Clone)]
pub struct HintReplayState {
    pub window: ReplayWindow,
    pub last_seen_ms: u64,
}

#[derive(Clone)]
pub struct ChannelState<const RN: usize = 8, const HN: usize = 8> {
    pub channel_key: ChannelKey,
    pub derived: DerivedChannelKeys,
    pub replay: LinearMap<PeerId, ReplayWindow, RN>,
    pub hint_replay: LinearMap<NodeHint, HintReplayState, HN>,
}

impl<const RN: usize, const HN: usize> ChannelState<RN, HN> {
    pub fn new(channel_key: ChannelKey, derived: DerivedChannelKeys) -> Self {
        Self {
            channel_key,
            derived,
            replay: LinearMap::new(),
            hint_replay: LinearMap::new(),
        }
    }
}

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
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub fn lookup_by_id(&self, id: &ChannelId) -> impl Iterator<Item = &ChannelState<RN, HN>> {
        self.channels
            .iter()
            .filter(move |channel| channel.derived.channel_id == *id)
    }

    pub fn get_mut_by_id(&mut self, id: &ChannelId) -> Option<&mut ChannelState<RN, HN>> {
        self.channels
            .iter_mut()
            .find(|channel| channel.derived.channel_id == *id)
    }

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

    pub fn add(&mut self, key: ChannelKey, derived: DerivedChannelKeys) {
        self.try_add(key, derived)
            .expect("channel table capacity exceeded")
    }
}