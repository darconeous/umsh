use core::num::NonZeroU32;

use heapless::{LinearMap, Vec};
use umsh_core::{ChannelId, ChannelKey, NodeHint, PublicKey, RouterHint, options::HopSignal};
use umsh_crypto::{DerivedChannelKeys, PairwiseKeys};

use crate::CapacityError;

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

    /// The node at the destination's end of the route's last hop: the one
    /// that hears the destination first.
    ///
    /// A flood distance of zero is a peer heard off its own transmitter, the
    /// same as a direct route. A longer flood distance names no path, and an
    /// empty source route constrains no hop.
    pub(crate) fn far_hop(&self) -> Option<FarHop> {
        match self {
            Self::Direct | Self::Flood { flood_hops: 0, .. } => Some(FarHop::Peer),
            Self::Source(hints) => hints.last().copied().map(FarHop::Repeater),
            Self::Flood { .. } => None,
        }
    }
}

/// Who hears a route's destination first; see [`CachedRoute::far_hop`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FarHop {
    /// This node, directly.
    Peer,
    /// The repeater named by the route's last hint.
    Repeater(RouterHint),
}

/// Who takes or gives back a hold on a peer entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerHolder {
    /// The local application, for a contact it added. It holds an entry at
    /// most once: adding the same contact again only refreshes it.
    Application,
    /// One session that addresses the peer under this key: a PFS session's
    /// peer ephemeral, or a peer a contact exchange reached. Every hold taken
    /// is given back once.
    Session,
}

/// The holders of a peer entry. An entry anything holds is never evicted,
/// and it is removed only when its last holder gives it back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerHolds {
    application: bool,
    sessions: u8,
}

impl PeerHolds {
    /// How many holders the entry has, the application counting once.
    pub fn count(&self) -> u8 {
        u8::from(self.application).saturating_add(self.sessions)
    }

    /// Whether anything holds the entry.
    pub fn is_held(&self) -> bool {
        self.application || self.sessions > 0
    }

    /// Whether the local application holds the entry: a contact it added.
    pub fn by_application(&self) -> bool {
        self.application
    }

    /// How many sessions hold the entry.
    pub fn sessions(&self) -> u8 {
        self.sessions
    }

    /// Take `holder`'s hold. Fails only when the session count is full.
    fn take(&mut self, holder: PeerHolder) -> Result<(), CapacityError> {
        match holder {
            PeerHolder::Application => self.application = true,
            PeerHolder::Session => {
                self.sessions = self.sessions.checked_add(1).ok_or(CapacityError)?;
            }
        }
        Ok(())
    }

    /// Give back `holder`'s hold, reporting whether it had one.
    fn give_back(&mut self, holder: PeerHolder) -> bool {
        match holder {
            PeerHolder::Application => core::mem::take(&mut self.application),
            PeerHolder::Session => match self.sessions.checked_sub(1) {
                Some(sessions) => {
                    self.sessions = sessions;
                    true
                }
                None => false,
            },
        }
    }
}

/// Shared metadata tracked for a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Full public key.
    pub public_key: PublicKey,
    /// Who holds this entry. An entry nobody holds was learned, and may be
    /// recycled for another.
    pub holds: PeerHolds,
    /// Whether this entry rests on more than a claim: a frame authenticated
    /// under the key, or the local application asking for it. An entry that
    /// does not is only a slot to answer a stranger through, and a stranger
    /// that has proven nothing never displaces one that does.
    pub proven: bool,
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
    /// How the selected route's last hop was most recently measured: the
    /// link between the peer and whoever hears it first (see
    /// [`CachedRoute::far_hop`]). `None` when nothing has measured it.
    pub(crate) route_last_hop: Option<HopSignal>,
    /// The selected route was chosen by the application
    /// ([`PeerRegistry::hold_route`]) rather than learned. It stays so after
    /// the hold ends, until a learned route replaces it.
    pub(crate) route_hand_set: bool,
    /// The peer advertises itself as mobile.
    pub(crate) mobile: bool,
    /// One recently failed route, suppressed only for passive route learning.
    failed_route: Option<(CachedRoute, u64)>,
    /// When a packet from this peer last reached us without flooding
    /// (`FHOPS_ACC` of zero): proof the peer holds a working path here.
    /// Kept in wrapping whole seconds, offset by one so the first second
    /// after boot is representable: every peer entry lives in the MAC's static, and a
    /// `u64` here costs a constrained board its stack headroom.
    unflooded_arrival_s: Option<NonZeroU32>,
    /// The peer's latest packet reached us by flooding, and nothing traced
    /// has gone back since: the next packet to it owes a trace route.
    pub(crate) trace_owed: bool,
    /// When the peer was last heard, offset so that it is never zero: zero
    /// means it has not been heard since it was registered, as for a peer
    /// the application configured. Use [`PeerInfo::heard_within`] to
    /// read it.
    pub last_seen_ms: u64,
    /// An acknowledgment from this peer has completed a send of ours: proof
    /// of an exchange, which a key minted to send one frame does not have.
    pub acknowledged: bool,
}

/// What an entry rests on, for choosing which may give way to a newcomer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Standing {
    /// A claim: nothing has authenticated under the key.
    Claimed,
    /// Frames have authenticated under the key, which anyone who mints one
    /// can arrange.
    Authenticated,
    /// The peer has acknowledged a send of ours.
    Acknowledged,
}

impl PeerInfo {
    fn new(public_key: PublicKey, holds: PeerHolds, last_seen_ms: u64) -> Self {
        Self {
            public_key,
            holds,
            proven: holds.is_held(),
            route: None,
            route_revision: 0,
            route_score: None,
            route_confirmed_ms: None,
            route_last_hop: None,
            route_hand_set: false,
            mobile: false,
            failed_route: None,
            unflooded_arrival_s: None,
            trace_owed: false,
            last_seen_ms,
            acknowledged: false,
        }
    }

    fn standing(&self) -> Standing {
        if self.acknowledged {
            Standing::Acknowledged
        } else if self.proven {
            Standing::Authenticated
        } else {
            Standing::Claimed
        }
    }

    /// How the selected route's last hop was most recently measured, if it
    /// was. A point-to-point entry marks a hop with no radio in it.
    pub fn route_last_hop(&self) -> Option<HopSignal> {
        self.route_last_hop
    }

    /// Whether the peer was heard within the last `window_ms` before
    /// `now_ms`. A peer registered but never heard was not.
    pub fn heard_within(&self, window_ms: u64, now_ms: u64) -> bool {
        self.last_seen_ms != 0 && now_ms.saturating_sub(self.last_seen_ms) <= window_ms
    }

    /// Whether the peer advertises itself as mobile.
    pub fn is_mobile(&self) -> bool {
        self.mobile
    }

    /// How the selected route scored on the latest evidence for it, in
    /// centibels; higher is better. `None` when nothing has measured it.
    pub fn route_score(&self) -> Option<i16> {
        self.route_score
    }

    /// When an acknowledgment last came back for a send on the selected
    /// route.
    pub fn route_confirmed_ms(&self) -> Option<u64> {
        self.route_confirmed_ms
    }

    /// Select `route`, forgetting what was known about the one it replaces.
    fn select_route(&mut self, selection: RouteSelection, revision: u64) {
        self.route = selection.route;
        self.route_score = selection.score;
        self.route_last_hop = selection.last_hop;
        self.route_hand_set = selection.hand_set;
        self.route_confirmed_ms = None;
        self.route_revision = revision;
    }
}

/// A route about to become a peer's selected route, with what is known
/// about it.
#[derive(Default)]
struct RouteSelection {
    route: Option<CachedRoute>,
    score: Option<i16>,
    last_hop: Option<HopSignal>,
    hand_set: bool,
}

impl RouteSelection {
    /// No route at all.
    fn none() -> Self {
        Self::default()
    }

    /// A route nothing has measured, installed from outside the MAC.
    fn installed(route: CachedRoute, hand_set: bool) -> Self {
        Self {
            route: Some(route),
            hand_set,
            ..Self::default()
        }
    }

    /// A route a received frame taught.
    fn learned(candidate: RouteCandidate) -> Self {
        Self {
            route: Some(candidate.route),
            score: candidate.score,
            last_hop: candidate.last_hop,
            hand_set: false,
        }
    }
}

/// A learned path waiting beside a held route; see [`RouteHold::candidate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteCandidate {
    /// The path.
    pub route: CachedRoute,
    /// How it scored on what the frame that taught it measured.
    pub score: Option<i16>,
    /// How its last hop was measured, if it was.
    pub last_hop: Option<HopSignal>,
}

impl From<RouteOffer> for RouteCandidate {
    fn from(offer: RouteOffer) -> Self {
        Self {
            route: offer.route,
            score: offer.score,
            last_hop: offer.last_hop,
        }
    }
}

/// A route the application chose for a peer, kept in place until a deadline.
///
/// While the hold is in force no learned path replaces the route and no
/// failure retires it. A send that misses its acknowledgment still falls
/// back to a flood, and what that teaches is kept beside the route as a
/// candidate the application may adopt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteHold {
    /// When the hold ends, on the MAC's clock.
    pub until_ms: u64,
    /// Flood budget past the end of the held route: what a send on it
    /// spends once its hints are consumed, or from the start for a direct
    /// route. Replaces the slack [`crate::established_route_slack`] would
    /// grant while the hold lasts; zero floods nothing. An ack along the
    /// route spends whichever of the two is larger.
    pub flood_hops: u8,
    /// Consecutive sends on the held route that missed their acknowledgment
    /// and were then acknowledged through the flood fallback.
    pub fallback_acks: u8,
    /// The best path learned while the hold was in force.
    pub candidate: Option<RouteCandidate>,
}

/// A snapshot of the route to one peer, for an application to present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRouteStatus {
    /// The route the next send will use, if any.
    pub route: Option<CachedRoute>,
    /// How much longer the route is held; `None` when it is not.
    pub hold_remaining_ms: Option<u64>,
    /// See [`RouteHold::flood_hops`]; `None` when nothing is held.
    pub hold_flood_hops: Option<u8>,
    /// See [`RouteHold::fallback_acks`]; zero when nothing is held.
    pub fallback_acks: u8,
    /// See [`RouteHold::candidate`].
    pub candidate: Option<CachedRoute>,
    /// How long ago an acknowledgment last came back for a send on the
    /// route.
    pub confirmed_age_ms: Option<u64>,
}

/// What became of a route whose send went unacknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteFailure {
    /// The route was not the one the send used, or there was none.
    Unrelated,
    /// The route was retired and held off from passive learning.
    Retired,
    /// The route is held, so it stays.
    Held,
}

/// How a send to a peer with a held route ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeldRouteOutcome {
    /// The held route itself carried the exchange.
    RouteAcked,
    /// The held route missed, and the flood fallback was acknowledged.
    FallbackAcked,
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
    /// How the frame measured the route's last hop (see
    /// [`CachedRoute::far_hop`]), if it did.
    pub last_hop: Option<HopSignal>,
}

/// Outcome of inserting or updating an auto-learned peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoPeerUpdate {
    /// Slot assigned to the peer.
    pub peer_id: PeerId,
    /// Previous peer key displaced from this slot, if any.
    pub evicted_key: Option<PublicKey>,
}

/// Outcome of giving back a hold on a peer entry
/// ([`PeerRegistry::release`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldRelease {
    /// The holder had no hold to give back; nothing changed.
    NotHeld,
    /// The hold was given back, and another holder keeps the entry.
    StillHeld,
    /// Nothing holds the entry any more, and it should be removed.
    LastHolder,
}

/// Where a new entry would go in the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vacancy {
    /// A slot no entry occupies.
    Free,
    /// One another entry gives up.
    Displacing,
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
///
/// `H` bounds how many peers may have a held route at once (see
/// [`PeerRegistry::hold_route`]). Holds live beside the peer table rather
/// than in it, so a node that never holds a route sets `H` to zero and
/// spends nothing on them.
#[derive(Clone, Debug)]
pub struct PeerRegistry<const N: usize, const H: usize = 0> {
    peers: Vec<PeerInfo, N>,
    holds: Vec<(PeerId, RouteHold), H>,
    next_route_revision: u64,
}

impl<const N: usize, const H: usize> Default for PeerRegistry<N, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const H: usize> PeerRegistry<N, H> {
    /// Create an empty peer registry.
    pub fn new() -> Self {
        // Peer ids are slot indices carried in a `u8`.
        const { assert!(N <= u8::MAX as usize + 1) };
        Self {
            peers: Vec::new(),
            holds: Vec::new(),
            next_route_revision: 0,
        }
    }

    /// The hold on `id`'s route, if one is still in force at `now_ms`.
    pub fn route_hold(&self, id: PeerId, now_ms: u64) -> Option<&RouteHold> {
        self.holds
            .iter()
            .find(|(held, hold)| *held == id && now_ms < hold.until_ms)
            .map(|(_, hold)| hold)
    }

    /// Where `id`'s hold sits, if it is in force at `now_ms`. A hold that
    /// has run out is dropped here; the route itself stays, an ordinary
    /// route the next measured path replaces.
    fn hold_index(&mut self, id: PeerId, now_ms: u64) -> Option<usize> {
        let index = self.holds.iter().position(|(held, _)| *held == id)?;
        if now_ms < self.holds[index].1.until_ms {
            return Some(index);
        }
        self.holds.swap_remove(index);
        None
    }

    fn drop_hold(&mut self, id: PeerId) {
        self.holds.retain(|(held, _)| *held != id);
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

    /// Insert or refresh a peer entry `holder` holds.
    ///
    /// An application hold is taken at most once; every session hold
    /// counts, and each must be given back with [`Self::release`].
    pub fn try_insert_or_update(
        &mut self,
        key: PublicKey,
        holder: PeerHolder,
    ) -> Result<PeerId, CapacityError> {
        if let Some((id, peer)) = self
            .peers
            .iter_mut()
            .enumerate()
            .find(|(_, peer)| peer.public_key == key)
        {
            peer.holds.take(holder)?;
            return Ok(PeerId(id as u8));
        }

        let mut holds = PeerHolds::default();
        holds.take(holder)?;
        self.peers
            .push(PeerInfo::new(key, holds, 0))
            .map_err(|_| CapacityError)?;
        Ok(PeerId((self.peers.len() - 1) as u8))
    }

    /// Give back `holder`'s hold on `id`. The entry stays in the registry;
    /// [`HoldRelease::LastHolder`] says it is now the caller's to
    /// [`remove`](Self::remove).
    ///
    /// The application may also remove an entry nobody holds, such as a
    /// learned peer. A session never removes an entry it did not hold, so a
    /// stray release cannot take a contact or a learned peer with it.
    pub fn release(&mut self, id: PeerId, holder: PeerHolder) -> HoldRelease {
        let Some(peer) = self.get_mut(id) else {
            return HoldRelease::NotHeld;
        };
        let held = peer.holds.give_back(holder);
        if !held && (holder == PeerHolder::Session || peer.holds.is_held()) {
            HoldRelease::NotHeld
        } else if peer.holds.is_held() {
            HoldRelease::StillHeld
        } else {
            HoldRelease::LastHolder
        }
    }

    /// Insert or refresh an opportunistically learned peer entry, for a key
    /// a verified frame or the local application stands behind.
    ///
    /// When the registry is full, this may recycle an entry nobody holds in
    /// place rather than failing: the oldest that has proven least. A held
    /// entry (see [`PeerHolds`]) is never displaced.
    pub fn try_insert_or_update_auto(
        &mut self,
        key: PublicKey,
        now_ms: u64,
    ) -> Result<AutoPeerUpdate, CapacityError> {
        self.insert_or_update_auto(key, true, Standing::Acknowledged, now_ms)
    }

    /// Insert or refresh an entry for a stranger whose only proof is a frame
    /// it authenticated under its own key.
    ///
    /// Anyone can mint a key to send such a frame, so when the registry is
    /// full this recycles only an entry that has not
    /// [acknowledged](PeerInfo::acknowledged) a send of ours. A full
    /// registry otherwise fails.
    pub fn try_insert_or_update_self_proven(
        &mut self,
        key: PublicKey,
        now_ms: u64,
    ) -> Result<AutoPeerUpdate, CapacityError> {
        self.insert_or_update_auto(key, true, Standing::Authenticated, now_ms)
    }

    /// Insert or refresh an entry for a key nothing has proven, such as a
    /// stranger an unauthenticated request asks this node to answer.
    ///
    /// When the registry is full this recycles only another entry that has
    /// proven nothing, so an unauthenticated frame never costs a peer its
    /// place. A full registry otherwise fails.
    pub fn try_insert_or_update_unproven(
        &mut self,
        key: PublicKey,
        now_ms: u64,
    ) -> Result<AutoPeerUpdate, CapacityError> {
        self.insert_or_update_auto(key, false, Standing::Claimed, now_ms)
    }

    /// Where [`try_insert_or_update_self_proven`](Self::try_insert_or_update_self_proven)
    /// would put a key not yet registered at `now_ms`, or `None` if nowhere.
    pub fn vacancy_for_self_proven(&self, now_ms: u64) -> Option<Vacancy> {
        if self.peers.len() < N {
            return Some(Vacancy::Free);
        }
        self.displaceable(Standing::Authenticated, now_ms)
            .map(|_| Vacancy::Displacing)
    }

    /// The entry a newcomer recycles at a full registry: the oldest of those
    /// resting on least, among those resting on no more than `displaces`.
    fn displaceable(&self, displaces: Standing, now_ms: u64) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .filter(|(index, peer)| {
                !peer.holds.is_held()
                    && peer.standing() <= displaces
                    && self.route_hold(PeerId(*index as u8), now_ms).is_none()
            })
            .min_by_key(|(_, peer)| (peer.standing(), peer.last_seen_ms))
            .map(|(index, _)| index)
    }

    /// `displaces` is the most an entry may rest on and still give way.
    fn insert_or_update_auto(
        &mut self,
        key: PublicKey,
        proven: bool,
        displaces: Standing,
        now_ms: u64,
    ) -> Result<AutoPeerUpdate, CapacityError> {
        if let Some((id, peer)) = self
            .peers
            .iter_mut()
            .enumerate()
            .find(|(_, peer)| peer.public_key == key)
        {
            peer.last_seen_ms = seen_ms(now_ms);
            peer.proven |= proven;
            return Ok(AutoPeerUpdate {
                peer_id: PeerId(id as u8),
                evicted_key: None,
            });
        }

        let mut entry = PeerInfo::new(key, PeerHolds::default(), seen_ms(now_ms));
        entry.proven = proven;

        if self.peers.len() < N {
            self.peers.push(entry).map_err(|_| CapacityError)?;
            return Ok(AutoPeerUpdate {
                peer_id: PeerId((self.peers.len() - 1) as u8),
                evicted_key: None,
            });
        }

        let Some(index) = self.displaceable(displaces, now_ms) else {
            return Err(CapacityError);
        };

        let evicted_key = self.peers[index].public_key;
        self.drop_hold(PeerId(index as u8));
        self.peers[index] = entry;
        Ok(AutoPeerUpdate {
            peer_id: PeerId(index as u8),
            evicted_key: Some(evicted_key),
        })
    }

    /// Record that a frame authenticated under this peer's key.
    pub fn mark_proven(&mut self, id: PeerId) {
        if let Some(peer) = self.get_mut(id) {
            peer.proven = true;
        }
    }

    /// Record that an acknowledgment from this peer completed a send of ours.
    pub fn mark_acknowledged(&mut self, id: PeerId) {
        if let Some(peer) = self.get_mut(id) {
            peer.proven = true;
            peer.acknowledged = true;
        }
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
        self.drop_hold(id);
        if let Some((old, new)) = moved {
            for (held, _) in self.holds.iter_mut().filter(|(held, _)| *held == old) {
                *held = new;
            }
        }
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
    /// received frame that offers a scored path replaces it. It is a learned
    /// route put back, not one chosen by hand.
    pub fn update_route(&mut self, id: PeerId, route: CachedRoute) {
        let revision = self.next_revision();
        if let Some(peer) = self.get_mut(id) {
            peer.select_route(RouteSelection::installed(route, false), revision);
            peer.failed_route = None;
        }
        self.drop_hold(id);
    }

    /// Record whether `id` advertises itself as mobile. `false` when the
    /// peer is unknown.
    pub fn set_mobile(&mut self, id: PeerId, mobile: bool) -> bool {
        self.get_mut(id).map(|peer| peer.mobile = mobile).is_some()
    }

    /// Install `route` and hold it until `until_ms`, spending `flood_hops`
    /// past its end (see [`RouteHold::flood_hops`]).
    ///
    /// Until then no learned path replaces it and no missed acknowledgment
    /// retires it; a send that misses still falls back to a flood. After the
    /// deadline it is an ordinary unscored route, which the next measured
    /// path replaces. Installing a route restarts the hold and its record.
    ///
    /// The route counts as chosen by hand until a learned one replaces it,
    /// so once the hold and its allowance are over, no send along it
    /// carries flood slack past its end.
    ///
    /// `false`, changing nothing, when the peer is unknown or `H` holds are
    /// already in force for other peers.
    pub fn hold_route(
        &mut self,
        id: PeerId,
        route: CachedRoute,
        flood_hops: u8,
        until_ms: u64,
        now_ms: u64,
    ) -> bool {
        if self.get(id).is_none() {
            return false;
        }
        let hold = RouteHold {
            until_ms,
            flood_hops,
            fallback_acks: 0,
            candidate: None,
        };
        if let Some(index) = self.holds.iter().position(|(held, _)| *held == id) {
            self.holds[index].1 = hold;
        } else {
            self.holds.retain(|(_, held)| now_ms < held.until_ms);
            if self.holds.push((id, hold)).is_err() {
                return false;
            }
        }
        let revision = self.next_revision();
        let peer = self.get_mut(id).expect("peer was just found");
        peer.select_route(RouteSelection::installed(route, true), revision);
        peer.failed_route = None;
        true
    }

    /// Replace a held route with the best path learned while it was held,
    /// ending the hold. `false` when there is no hold or nothing was learned.
    pub fn adopt_candidate(&mut self, id: PeerId, now_ms: u64) -> bool {
        let Some(index) = self.hold_index(id, now_ms) else {
            return false;
        };
        let Some(candidate) = self.holds[index].1.candidate.take() else {
            return false;
        };
        self.holds.swap_remove(index);
        let revision = self.next_revision();
        if let Some(peer) = self.get_mut(id) {
            peer.select_route(RouteSelection::learned(candidate), revision);
        }
        true
    }

    /// Record how a send to a peer with a held route ended.
    pub(crate) fn note_held_outcome(
        &mut self,
        key: &PublicKey,
        outcome: HeldRouteOutcome,
        now_ms: u64,
    ) {
        let Some((id, _)) = self.lookup_by_key(key) else {
            return;
        };
        let Some(index) = self.hold_index(id, now_ms) else {
            return;
        };
        let hold = &mut self.holds[index].1;
        hold.fallback_acks = match outcome {
            HeldRouteOutcome::RouteAcked => 0,
            HeldRouteOutcome::FallbackAcked => hold.fallback_acks.saturating_add(1),
        };
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
    ///
    /// Whatever becomes of the route, an offer that measured the same last
    /// hop as the route held refreshes its reading: that link is the same
    /// link however the frame traveled after it.
    pub(crate) fn offer_route(&mut self, id: PeerId, offer: RouteOffer, now_ms: u64) {
        let Some(peer) = self.get_mut(id) else {
            return;
        };
        if offer.last_hop.is_some()
            && offer.route.far_hop().is_some()
            && peer.route.as_ref().and_then(CachedRoute::far_hop) == offer.route.far_hop()
        {
            peer.route_last_hop = offer.last_hop;
        }
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
        if let Some(index) = self.hold_index(id, now_ms) {
            // A held route stays, whatever the offer; a path it teaches is
            // kept as the candidate the application may switch to. Even a
            // superseding offer only proposes: the person chose this route.
            let hold = &mut self.holds[index].1;
            hold.candidate = better_candidate(hold.candidate.take(), offer);
            return;
        }
        let peer = self.get_mut(id).expect("peer was just found");
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
        peer.select_route(RouteSelection::learned(offer.into()), revision);
    }

    /// Forget a route explicitly; passive learning remains allowed.
    pub fn clear_route(&mut self, id: PeerId) -> bool {
        let revision = self.next_revision();
        self.drop_hold(id);
        self.get_mut(id)
            .map(|peer| {
                let held = peer.route.is_some();
                peer.select_route(RouteSelection::none(), revision);
                peer.failed_route = None;
                held
            })
            .unwrap_or(false)
    }

    /// Retire only the cached route used by the failed on-air attempt.
    ///
    /// A held route is not retired: the caller still falls back to a flood,
    /// and the route stays for the next send.
    pub(crate) fn fail_route(
        &mut self,
        key: &PublicKey,
        revision: u64,
        now_ms: u64,
    ) -> RouteFailure {
        let Some((id, peer)) = self.lookup_by_key(key) else {
            return RouteFailure::Unrelated;
        };
        if revision == 0 || peer.route_revision != revision {
            return RouteFailure::Unrelated;
        }
        self.retire_route(id, now_ms)
    }

    /// Retire `id`'s selected route, whatever it is: a reply sent along it
    /// was lost. Like a failed send, it is suppressed for passive learning
    /// for a while, and a held route stays.
    pub(crate) fn retire_route(&mut self, id: PeerId, now_ms: u64) -> RouteFailure {
        if self.get(id).is_none() {
            return RouteFailure::Unrelated;
        }
        if self.hold_index(id, now_ms).is_some() {
            return RouteFailure::Held;
        }
        let next_revision = self.next_revision();
        let peer = self.get_mut(id).expect("peer was just found");
        match peer.route.take() {
            Some(route) => {
                peer.failed_route = Some((route, now_ms.saturating_add(FAILED_ROUTE_HOLDOFF_MS)));
                peer.select_route(RouteSelection::none(), next_revision);
                RouteFailure::Retired
            }
            None => RouteFailure::Unrelated,
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

    /// Record how a packet from `id` reached us: by flooding or not.
    pub(crate) fn note_arrival(&mut self, id: PeerId, flooded: bool, now_ms: u64) {
        if let Some(peer) = self.get_mut(id) {
            if !flooded {
                peer.unflooded_arrival_s = Some(arrival_seconds(now_ms));
            }
            peer.trace_owed = flooded;
        }
    }

    /// Whether a packet from `id` reached us without flooding within the
    /// last `window_ms` before `now_ms`.
    pub(crate) fn arrived_unflooded_within(&self, id: PeerId, window_ms: u64, now_ms: u64) -> bool {
        self.get(id)
            .and_then(|peer| peer.unflooded_arrival_s)
            .is_some_and(|at| {
                let elapsed_s = arrival_seconds(now_ms).get().wrapping_sub(at.get());
                u64::from(elapsed_s) * 1000 < window_ms
            })
    }

    /// A packet carrying a trace route went to `id`, settling what a flooded
    /// arrival owed it.
    pub(crate) fn note_trace_sent(&mut self, id: PeerId) {
        if let Some(peer) = self.get_mut(id) {
            peer.trace_owed = false;
        }
    }

    /// Refresh the last-seen timestamp for `id`.
    pub fn touch(&mut self, id: PeerId, now_ms: u64) {
        if let Some(peer) = self.get_mut(id) {
            peer.last_seen_ms = seen_ms(now_ms);
        }
    }
}

/// `now_ms` as a [`PeerInfo::last_seen_ms`]: never zero, which is reserved
/// for a peer not yet heard. Clocks start at zero at boot.
fn seen_ms(now_ms: u64) -> u64 {
    now_ms.max(1)
}

/// The better of a held route's candidate and a new offer.
///
/// A flood distance names no path to switch to. A measured path beats one
/// nothing has measured; between two measured paths the newcomer must clear
/// the usual switching margin.
fn better_candidate(
    candidate: Option<RouteCandidate>,
    offer: RouteOffer,
) -> Option<RouteCandidate> {
    if matches!(offer.route, CachedRoute::Flood { .. }) {
        return candidate;
    }
    let Some(candidate) = candidate else {
        return Some(offer.into());
    };
    if candidate.route == offer.route {
        return Some(RouteCandidate {
            score: offer.score.or(candidate.score),
            last_hop: offer.last_hop.or(candidate.last_hop),
            ..candidate
        });
    }
    let replace = match (candidate.score, offer.score) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(held), Some(new)) => crate::route_score::displaces(new, held, false),
    };
    Some(if replace { offer.into() } else { candidate })
}

/// Secure transport state for one local identity and one remote peer.
///
/// Only the pairwise keys are per identity pair. Replay state follows the
/// sender's one counter sequence, so it lives in
/// [`RxWindows`](crate::RxWindows), keyed by the remote key alone.
#[derive(Clone)]
pub struct PeerCryptoState {
    /// Pairwise encryption and MIC keys.
    pub pairwise_keys: PairwiseKeys,
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

/// Shared state for one multicast channel.
#[derive(Clone)]
pub struct ChannelState {
    /// Raw channel key.
    pub channel_key: ChannelKey,
    /// Derived transport keys and identifier.
    pub derived: DerivedChannelKeys,
    /// Whether this is the `EMERGENCY` channel, whose signed frames are
    /// remembered past their signers' windows.
    pub emergency: bool,
}

/// Fixed-capacity channel table shared by the MAC coordinator.
///
/// It keeps no replay state. An unsigned multicast proves only that its
/// sender holds the channel's key, so nothing kept for the source it claims
/// may be judged against or moved by it: any other member could push that
/// state forward and silence the claimed sender. Such a frame is judged by
/// duplicate suppression alone, and a signed one by its signer's receive
/// window.
#[derive(Clone)]
pub struct ChannelTable<const N: usize> {
    channels: Vec<ChannelState, N>,
}

impl<const N: usize> Default for ChannelTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ChannelTable<N> {
    /// Create an empty channel table.
    #[inline(always)]
    pub const fn new() -> Self {
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

    /// Iterate over channels whose derived identifier matches `id`, in the
    /// order they were added. Distinct keys can share an identifier, so a
    /// frame naming `id` is tried against each until one authenticates it.
    pub fn lookup_by_id(&self, id: &ChannelId) -> impl Iterator<Item = &ChannelState> {
        self.channels
            .iter()
            .filter(move |channel| channel.derived.channel_id == *id)
    }

    /// The channel holding exactly this key.
    pub fn lookup_by_key(&self, key: &ChannelKey) -> Option<&ChannelState> {
        self.channels
            .iter()
            .find(|channel| channel.channel_key == *key)
    }

    /// Mutably borrow the channel holding exactly this key.
    pub fn lookup_by_key_mut(&mut self, key: &ChannelKey) -> Option<&mut ChannelState> {
        self.channels
            .iter_mut()
            .find(|channel| channel.channel_key == *key)
    }

    /// Iterate over all channel states.
    pub fn iter(&self) -> impl Iterator<Item = &ChannelState> {
        self.channels.iter()
    }

    /// Mutably iterate over all channel states.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ChannelState> {
        self.channels.iter_mut()
    }

    /// Remove the channel holding this exact key. Returns whether a channel
    /// was removed.
    pub fn remove_by_key(&mut self, key: &ChannelKey) -> bool {
        let Some(index) = self
            .channels
            .iter()
            .position(|channel| channel.channel_key == *key)
        else {
            return false;
        };
        self.channels.swap_remove(index);
        true
    }

    /// Add a channel, or refresh the entry already holding this key. A
    /// different key that derives the same identifier gets an entry of its
    /// own: identifiers are two bytes and collide. `emergency` says whether
    /// `key` is the `EMERGENCY` channel's.
    pub fn try_add(
        &mut self,
        key: ChannelKey,
        derived: DerivedChannelKeys,
        emergency: bool,
    ) -> Result<(), CapacityError> {
        if let Some(channel) = self.lookup_by_key_mut(&key) {
            channel.derived = derived;
            channel.emergency = emergency;
            return Ok(());
        }
        self.channels
            .push(ChannelState {
                channel_key: key,
                derived,
                emergency,
            })
            .map_err(|_| CapacityError)
    }
}

/// `now_ms` as the whole seconds an arrival is recorded in, plus one. The
/// count wraps, and is only ever compared by wrapping difference; the one
/// second in every wrap that lands on zero is recorded a second late.
fn arrival_seconds(now_ms: u64) -> NonZeroU32 {
    NonZeroU32::new(((now_ms / 1000) as u32).wrapping_add(1)).unwrap_or(NonZeroU32::MIN)
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
