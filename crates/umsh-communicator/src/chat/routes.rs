//! The way to each saved peer: the route the device node holds for the
//! next message, and how the last ping went and the path its answer took.
//!
//! The device node is reached only from the chat task, so a route is
//! asked for as a command, and kept here once it arrives for the
//! interface to read.

use alloc::collections::BTreeMap;

use core::fmt::Write as _;

use umsh_core::options::HopSignal;
use umsh_core::{PublicKey, RouterHint};
use umsh_mac::CachedRoute;
use umsh_text::node_adapter::RxSummary;
use umsh_ux_communicator::heapless::{String, Vec};
use umsh_ux_communicator::model::{
    self, Leg, MAX_PATH, ManualRoute, NodeEvent, PeerRoute, PingReply, PingView, RouteKind, Signal,
};

use umsh_text::ConversationKey;

use super::Chats;
use super::peers::long_age;
use crate::store::ChatStore;
use crate::task::{Command, HeldRoute, Learned};

/// How many peers' routes, and how many peers' pings, are kept. Past it,
/// the one heard of longest ago goes.
const KEPT: usize = 16;

/// How many changes to each peer's route the device node has yet to answer.
/// Few are ever outstanding: a short list, searched in turn, costs less
/// code than a map.
pub(super) type Changing = Vec<([u8; 32], u8), KEPT>;

/// How many sends in a row must miss on a route held by hand, each
/// carried by the flood after, before the route learned meanwhile is
/// offered in its place.
const OFFER_AFTER: u8 = 2;

/// How far apart two readings of when a route was confirmed may be and
/// still be the same confirmation: each is worked out from an age, on the
/// board's clock as it reads.
const CONFIRMED_SLACK_MS: u64 = 1_000;

/// A route to a peer, as the device node last told it.
pub(crate) struct Route {
    /// `None` when the device node holds none.
    route: Option<CachedRoute>,
    /// When, on the board's clock, a send on it was last acknowledged.
    confirmed_at_ms: Option<u64>,
    /// While it is a route chosen by hand, how it is held.
    held: Option<Hold>,
    /// The route learned while it was held was turned down: it is not
    /// offered again until a route is held anew.
    settled: bool,
    at_ms: u64,
}

/// How a route chosen by hand is held.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Hold {
    /// When, on the board's clock, the device node stops holding it.
    until_ms: u64,
    /// How far it floods past its last repeater.
    flood_hops: u8,
    /// How many sends in a row missed on it and were carried by the flood.
    fallback_acks: u8,
    /// The best route those floods taught.
    learned: Option<Learned>,
}

/// The pings to a peer.
pub(crate) struct Ping {
    /// One is waiting for its answer.
    pending: bool,
    last: Option<Outcome>,
    at_ms: u64,
}

/// How a ping went.
enum Outcome {
    /// An answer came, by way of `hints`, the repeater nearest this device
    /// first, and past them more when `truncated`. `legs` are how each hop
    /// of it was heard, the hop into this device first. `flooded` when
    /// it got through only as a Route Retry.
    Reply {
        round_trip_ms: u64,
        hops: Option<u8>,
        hints: Vec<RouterHint, MAX_PATH>,
        truncated: bool,
        legs: Vec<Leg, { MAX_PATH + 1 }>,
        flooded: bool,
    },
    NoReply,
}

impl<S: ChatStore> Chats<S> {
    // ─── Routes ──────────────────────────────────────────────────────

    /// Asks the device node for the route to the saved peer `peer`.
    pub fn load_route(&mut self, peer: model::PeerId) {
        if let Some(kept) = self.saved_peer(peer) {
            self.read_route(kept.key);
        }
    }

    /// Asks the device node for the route to `key`, unless that is already
    /// asked.
    pub(super) fn read_route(&mut self, key: PublicKey) {
        if self.reading.insert(key.0) {
            self.commands.push_back(Command::ReadRoute { peer: key });
        }
    }

    /// Whether a route to `key` is kept, which anything heard from them
    /// can change.
    pub(super) fn routed(&self, key: &PublicKey) -> bool {
        self.routes.contains_key(&key.0)
    }

    /// Has the device node forget its route to the saved peer `peer`, then
    /// read what it holds after.
    pub fn reset_route(&mut self, peer: model::PeerId) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        self.withdraw_offer(&kept.key);
        self.reading.insert(kept.key.0);
        self.commands
            .push_back(Command::ResetRoute { peer: kept.key });
    }

    /// Has the device node hold `hints`, the repeater nearest this device
    /// first, as the route to the saved peer `peer` for `hold_ms`, flooding
    /// `flood_hops` past the last of them; no hints is a direct route.
    pub fn hold_route(
        &mut self,
        peer: model::PeerId,
        hints: &[[u8; 2]],
        flood_hops: u8,
        hold_ms: u32,
    ) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        // Held anew, its learned rival may be offered again.
        if let Some(route) = self.routes.get_mut(&kept.key.0) {
            route.settled = false;
        }
        self.withdraw_offer(&kept.key);
        self.reading.insert(kept.key.0);
        self.commands.push_back(Command::HoldRoute {
            peer: kept.key,
            hints: hints
                .iter()
                .take(CachedRoute::MAX_HINTS)
                .map(|&hint| RouterHint(hint))
                .collect(),
            flood_hops,
            hold_ms,
        });
    }

    /// Offers no learned route to `key` while the device node changes its
    /// hold: it starts the count of floods over, and what was offered
    /// against the old hold is stale until the new one is read back.
    fn withdraw_offer(&mut self, key: &PublicKey) {
        match self.changing.iter_mut().find(|(peer, _)| *peer == key.0) {
            Some((_, count)) => *count = count.saturating_add(1),
            // With no room, a read before the change may offer what is
            // stale until the change's own answer comes.
            None => _ = self.changing.push((key.0, 1)),
        }
        if let Some(hold) = self
            .routes
            .get_mut(&key.0)
            .and_then(|route| route.held.as_mut())
        {
            hold.fallback_acks = 0;
            hold.learned = None;
        }
    }

    /// Takes the route to `key` the device node holds, `route`, whose
    /// sends were last acknowledged `confirmed_age_ms` ago, and which it
    /// holds by hand as `held` says.
    #[allow(clippy::too_many_arguments)]
    pub fn route_read(
        &mut self,
        key: PublicKey,
        route: Option<CachedRoute>,
        confirmed_age_ms: Option<u64>,
        held: Option<HeldRoute>,
        changed: bool,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        self.reading.remove(&key.0);
        let pending = self.changing.iter().position(|(peer, _)| *peer == key.0);
        if changed && let Some(at) = pending {
            let count = &mut self.changing[at].1;
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.changing.swap_remove(at);
            }
        }
        // Read before a change still to be answered, what it offers is
        // stale.
        let stale = self.changing.iter().any(|(peer, _)| *peer == key.0);
        let confirmed_at_ms = confirmed_age_ms.map(|age| now_ms.saturating_sub(age));
        let held = held.map(|held| Hold {
            until_ms: now_ms.saturating_add(held.remaining_ms),
            flood_hops: held.flood_hops,
            fallback_acks: if stale { 0 } else { held.fallback_acks },
            learned: if stale { None } else { held.learned },
        });
        let was = self.routes.get(&key.0);
        let changed = was.is_none_or(|was| {
            was.route != route
                || !same_moment(was.confirmed_at_ms, confirmed_at_ms)
                || was
                    .held
                    .map(|hold| (hold.flood_hops, hold.fallback_acks, hold.learned))
                    != held.map(|hold| (hold.flood_hops, hold.fallback_acks, hold.learned))
                || !same_moment(
                    was.held.map(|hold| hold.until_ms),
                    held.map(|hold| hold.until_ms),
                )
        });
        // A chat's header says how far a route held by hand goes.
        let was_held = was.and_then(|was| was.held.and(was.route.as_ref()));
        let reheaded = was_held.map(CachedRoute::hop_count)
            != held.and(route.as_ref()).map(CachedRoute::hop_count);
        // Turned down, the offer stays turned down while the route is held.
        let settled = held.is_some() && was.is_some_and(|was| was.settled && was.held.is_some());
        make_room(&mut self.routes, &key.0, now_ms);
        self.routes.insert(
            key.0,
            Route {
                route,
                confirmed_at_ms,
                held,
                settled,
                at_ms: now_ms,
            },
        );
        if changed && let Ok(Some(record)) = self.store.peer(&key) {
            events(NodeEvent::RouteChanged(record.id.0));
        }
        if reheaded {
            self.header_changed(&key, events);
        }
    }

    /// Asks the device node for the route to the peer my message `id` went
    /// to, once it is delivered, when that route is held by hand: the
    /// delivery can have taught it a rival, or shown it failing. One sent
    /// over a channel went by that route too.
    pub(super) fn delivered_on_hold(&mut self, id: crate::ids::MessageId) {
        if !self.routes.values().any(|route| route.held.is_some()) {
            return;
        }
        let Some(chat) = self.store.message(id).ok().flatten().map(|m| m.chat) else {
            return;
        };
        if let Some(ConversationKey::Direct { peer } | ConversationKey::ChannelDirect { peer, .. }) =
            self.conversation(chat.0)
            && self
                .routes
                .get(&peer.0)
                .is_some_and(|route| route.held.is_some())
        {
            self.read_route(peer);
        }
    }

    /// The route learned while the one to the saved peer `peer` was held by
    /// hand, once it is time to offer it in its place.
    pub fn learned_route(&self, peer: model::PeerId, now_ms: u64) -> Option<model::LearnedRoute> {
        let kept = self.saved_peer(peer)?;
        let route = self.routes.get(&kept.key.0)?;
        let hold = route.held.filter(|hold| now_ms < hold.until_ms)?;
        if route.settled || hold.fallback_acks < OFFER_AFTER {
            return None;
        }
        let learned = hold.learned?;
        Some(model::LearnedRoute {
            hops: learned.hops,
            via: learned
                .via
                .and_then(|hint| self.repeater(hint))
                .map(|repeater| repeater.name),
        })
    }

    /// Has the device node switch the route held by hand to the saved peer
    /// `peer` for the one learned meanwhile.
    pub fn adopt_learned_route(&mut self, peer: model::PeerId) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        self.withdraw_offer(&kept.key);
        self.reading.insert(kept.key.0);
        self.commands
            .push_back(Command::AdoptRoute { peer: kept.key });
    }

    /// Stops offering the route learned while the one to the saved peer
    /// `peer` is held, until a route is held anew.
    pub fn keep_manual_route(&mut self, peer: model::PeerId) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        if let Some(route) = self.routes.get_mut(&kept.key.0) {
            route.settled = true;
        }
    }

    /// Whether the route to `key` is held by hand, and how far it goes:
    /// what the header of the chat with them says.
    pub(super) fn held_hops(&self, key: &PublicKey) -> Option<u8> {
        let route = self.routes.get(&key.0)?;
        route.held?;
        route.route.as_ref().map(CachedRoute::hop_count)
    }

    /// That the header of the direct chat with `key` reads differently.
    fn header_changed(&self, key: &PublicKey, events: &mut dyn FnMut(NodeEvent)) {
        if let Some(chat) = self.store.chat_for(&ConversationKey::Direct { peer: *key }) {
            events(NodeEvent::ChatChanged(chat.0));
        }
    }

    /// Lets go of the holds that have run out, so that whatever shows their
    /// routes says so: the device node keeps each route as an ordinary one.
    pub(super) fn lapse_holds(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        let mut lapsed: Vec<[u8; 32], KEPT> = Vec::new();
        for (key, route) in &mut self.routes {
            if route.held.is_some_and(|hold| now_ms >= hold.until_ms) {
                route.held = None;
                route.settled = false;
                _ = lapsed.push(*key);
            }
        }
        for key in lapsed {
            let key = PublicKey(key);
            if let Ok(Some(record)) = self.store.peer(&key) {
                events(NodeEvent::RouteChanged(record.id.0));
            }
            self.header_changed(&key, events);
        }
    }

    /// The route to the saved peer `peer`, once it has been read.
    pub fn peer_route(&self, peer: model::PeerId, now_ms: u64) -> Option<PeerRoute> {
        let kept = self.saved_peer(peer)?;
        let held = self.routes.get(&kept.key.0)?;
        let mut shown = PeerRoute {
            kind: RouteKind::Unknown,
            hops: None,
            repeaters: Vec::new(),
            unnamed: 0,
            confirmed: None,
            signal: None,
            manual: None,
        };
        let Some(route) = &held.route else {
            return Some(shown);
        };
        shown.hops = Some(route.hop_count());
        shown.confirmed = held.confirmed_at_ms.map(|at| {
            long_age(u32::try_from(now_ms.saturating_sub(at) / 1_000).unwrap_or(u32::MAX))
        });
        // A hold that has run out leaves the route as an ordinary one.
        shown.manual = held
            .held
            .filter(|hold| now_ms < hold.until_ms)
            .map(|hold| ManualRoute {
                flood_hops: hold.flood_hops,
                left: time_left(hold.until_ms - now_ms),
            });
        match route {
            CachedRoute::Direct => {
                shown.kind = RouteKind::Direct;
                // How this device last heard them, when that was directly.
                shown.signal = self
                    .links
                    .get(&kept.key.0)
                    .and_then(|link| link.direct_signal());
            }
            CachedRoute::Source(hints) => {
                shown.kind = RouteKind::Source;
                shown.repeaters = self.path(hints);
            }
            CachedRoute::Flood { flood_hops, .. } => {
                shown.kind = RouteKind::Flood;
                shown.unnamed = *flood_hops;
            }
        }
        Some(shown)
    }

    /// The repeaters `hints` name, in their order. The list ends where the
    /// text heap does, so that each still lines up with its hop.
    fn path(&self, hints: &[RouterHint]) -> Vec<model::Repeater, MAX_PATH> {
        hints
            .iter()
            .map_while(|&hint| self.repeater(hint))
            .take(MAX_PATH)
            .collect()
    }

    // ─── Pings ───────────────────────────────────────────────────────

    /// Notes that `key` was just pinged.
    pub(super) fn pinged(&mut self, key: PublicKey, now_ms: u64) {
        make_room(&mut self.pings, &key.0, now_ms);
        let ping = self.pings.entry(key.0).or_insert(Ping {
            pending: false,
            last: None,
            at_ms: now_ms,
        });
        ping.pending = true;
        ping.at_ms = now_ms;
    }

    /// Takes a peer's answer to a ping, heard as `rx` says, and what each
    /// repeater it came by measured, `signal`, the nearest first. A
    /// `truncated` answer names only the repeaters nearest this device; a
    /// `flooded` one got through only as a Route Retry.
    #[allow(clippy::too_many_arguments)]
    pub fn pong(
        &mut self,
        peer: PublicKey,
        round_trip_ms: u64,
        rx: &RxSummary,
        signal: &[HopSignal],
        truncated: bool,
        flooded: bool,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        self.hear(&peer, rx, now_ms, events);
        let hints: Vec<RouterHint, MAX_PATH> =
            rx.route_hints.iter().take(MAX_PATH).copied().collect();
        let mut legs: Vec<Leg, { MAX_PATH + 1 }> = Vec::new();
        _ = legs.push(match (rx.rssi_dbm, rx.snr_centibels) {
            (Some(rssi), Some(snr)) => Leg::Heard(Signal { rssi, snr }),
            _ => Leg::Unknown,
        });
        // Entry `i` is how repeater `i` heard the node beyond it.
        for i in 0..hints.len() {
            _ = legs.push(signal.get(i).map_or(Leg::Unknown, |&entry| leg(entry)));
        }
        let outcome = Outcome::Reply {
            round_trip_ms,
            hops: rx.hop_count,
            truncated: truncated || rx.route_hints.len() > MAX_PATH,
            hints,
            legs,
            flooded,
        };
        self.settle_ping(peer, outcome, now_ms, events);
        // The answer can have taught the device node a route.
        self.read_route(peer);
    }

    /// Takes that the ping to `peer` went unanswered.
    pub fn ping_timed_out(
        &mut self,
        peer: PublicKey,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        if self.pings.get(&peer.0).is_some_and(|ping| ping.pending) {
            self.settle_ping(peer, Outcome::NoReply, now_ms, events);
        }
    }

    fn settle_ping(
        &mut self,
        key: PublicKey,
        outcome: Outcome,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        make_room(&mut self.pings, &key.0, now_ms);
        self.pings.insert(
            key.0,
            Ping {
                pending: false,
                last: Some(outcome),
                at_ms: now_ms,
            },
        );
        if let Ok(Some(record)) = self.store.peer(&key) {
            events(NodeEvent::PingSettled(record.id.0));
        }
    }

    /// How the last ping to the saved peer `peer` went, or that it waits.
    pub fn ping_view(&self, peer: model::PeerId) -> Option<PingView> {
        let kept = self.saved_peer(peer)?;
        let ping = self.pings.get(&kept.key.0)?;
        if ping.pending {
            return Some(PingView::Waiting);
        }
        Some(match ping.last.as_ref()? {
            Outcome::NoReply => PingView::NoReply,
            Outcome::Reply {
                round_trip_ms,
                hops,
                hints,
                truncated,
                legs,
                flooded,
            } => PingView::Reply(PingReply {
                round_trip_ms: u32::try_from(*round_trip_ms).unwrap_or(u32::MAX),
                hops: *hops,
                repeaters: self.path(hints),
                // Hops past the traced ones: the answer flooded through
                // repeaters that named none, or its trace lost them. A
                // truncated trace with no count leaves how many unknown.
                unnamed: match hops.map(|hops| {
                    hops.saturating_sub(u8::try_from(hints.len()).unwrap_or(u8::MAX) + 1)
                }) {
                    Some(0) | None if *truncated => None,
                    count => Some(count.unwrap_or(0)),
                },
                legs: legs.clone(),
                flooded: *flooded,
            }),
        })
    }

    /// Forgets the way to `key`. A route held by hand no longer heads the
    /// chat with them.
    pub(super) fn forget_way(&mut self, key: &PublicKey, events: &mut dyn FnMut(NodeEvent)) {
        self.pings.remove(&key.0);
        let held = self.held_hops(key).is_some();
        self.routes.remove(&key.0);
        if held {
            self.header_changed(key, events);
        }
    }
}

/// Whether two readings of a moment, each worked out from an age on the
/// board's clock, are the same moment.
fn same_moment(was: Option<u64>, now: Option<u64>) -> bool {
    match (was, now) {
        (Some(was), Some(now)) => was.abs_diff(now) <= CONFIRMED_SLACK_MS,
        (was, now) => was.is_some() == now.is_some(),
    }
}

/// How long a held route has left, such as `52 min left`: whole minutes,
/// rounded up, and whole hours from two hours on.
fn time_left(ms: u64) -> String<12> {
    const MINUTE: u64 = 60_000;
    let minutes = ms.div_ceil(MINUTE);
    let mut left = String::new();
    if minutes < 120 {
        _ = write!(left, "{minutes} min left");
    } else {
        _ = write!(left, "{} hr left", minutes / 60);
    }
    left
}

/// How a repeater says it heard a hop.
fn leg(entry: HopSignal) -> Leg {
    if entry.is_point_to_point() {
        return Leg::Bridge;
    }
    match (entry.rssi_dbm(), entry.snr_centibels()) {
        (Some(rssi), Some(snr)) => Leg::Heard(Signal { rssi, snr }),
        _ => Leg::Unknown,
    }
}

/// What [`make_room`] lets go of: the entry read longest ago, but never a
/// route while it is held by hand, whose offer to switch must outlast it.
trait Kept {
    fn at_ms(&self) -> u64;
    fn held(&self, now_ms: u64) -> bool;
}

impl Kept for Route {
    fn at_ms(&self) -> u64 {
        self.at_ms
    }

    fn held(&self, now_ms: u64) -> bool {
        self.held.is_some_and(|hold| now_ms < hold.until_ms)
    }
}

impl Kept for Ping {
    fn at_ms(&self) -> u64 {
        self.at_ms
    }

    fn held(&self, _now_ms: u64) -> bool {
        false
    }
}

/// Makes room in `kept` for `key`, by letting go of the entry read longest
/// ago that is not held. The device node holds fewer routes than are kept.
fn make_room<T: Kept>(kept: &mut BTreeMap<[u8; 32], T>, key: &[u8; 32], now_ms: u64) {
    if !kept.contains_key(key)
        && kept.len() >= KEPT
        && let Some(oldest) = kept
            .iter()
            .filter(|(_, entry)| !entry.held(now_ms))
            .min_by_key(|(_, entry)| entry.at_ms())
            .map(|(key, _)| *key)
    {
        kept.remove(&oldest);
    }
}
