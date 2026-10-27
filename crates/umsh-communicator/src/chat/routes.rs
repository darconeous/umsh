//! The way to each saved peer: the route the device node holds for the
//! next message, and how the last ping went and the path its answer took.
//!
//! The device node is reached only from the chat task, so a route is
//! asked for as a command, and kept here once it arrives for the
//! interface to read.

use alloc::collections::BTreeMap;

use umsh_core::options::TraceSignalEntry;
use umsh_core::{PublicKey, RouterHint};
use umsh_mac::CachedRoute;
use umsh_text::node_adapter::RxSummary;
use umsh_ux_communicator::heapless::Vec;
use umsh_ux_communicator::model::{
    self, Leg, MAX_PATH, NodeEvent, PeerRoute, PingReply, PingView, RouteKind, Signal,
};

use super::Chats;
use super::peers::long_age;
use crate::store::ChatStore;
use crate::task::Command;

/// How many peers' routes, and how many peers' pings, are kept. Past it,
/// the one heard of longest ago goes.
const KEPT: usize = 16;

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
    at_ms: u64,
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
    /// first. `legs` are how each hop of it was heard, the hop into this
    /// device first.
    Reply {
        round_trip_ms: u64,
        hops: Option<u8>,
        hints: Vec<RouterHint, MAX_PATH>,
        legs: Vec<Leg, { MAX_PATH + 1 }>,
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
        self.reading.insert(kept.key.0);
        self.commands
            .push_back(Command::ResetRoute { peer: kept.key });
    }

    /// Takes the route to `key` the device node holds, `route`, whose
    /// sends were last acknowledged `confirmed_age_ms` ago.
    pub fn route_read(
        &mut self,
        key: PublicKey,
        route: Option<CachedRoute>,
        confirmed_age_ms: Option<u64>,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        self.reading.remove(&key.0);
        let confirmed_at_ms = confirmed_age_ms.map(|age| now_ms.saturating_sub(age));
        let changed = self.routes.get(&key.0).is_none_or(|was| {
            was.route != route
                || match (was.confirmed_at_ms, confirmed_at_ms) {
                    (Some(was), Some(now)) => was.abs_diff(now) > CONFIRMED_SLACK_MS,
                    (was, now) => was.is_some() != now.is_some(),
                }
        });
        make_room(&mut self.routes, &key.0, |route| route.at_ms);
        self.routes.insert(
            key.0,
            Route {
                route,
                confirmed_at_ms,
                at_ms: now_ms,
            },
        );
        if changed && let Ok(Some(record)) = self.store.peer(&key) {
            events(NodeEvent::RouteChanged(record.id.0));
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
        };
        let Some(route) = &held.route else {
            return Some(shown);
        };
        shown.hops = Some(route.hop_count());
        shown.confirmed = held.confirmed_at_ms.map(|at| {
            long_age(u32::try_from(now_ms.saturating_sub(at) / 1_000).unwrap_or(u32::MAX))
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
        make_room(&mut self.pings, &key.0, |ping| ping.at_ms);
        let ping = self.pings.entry(key.0).or_insert(Ping {
            pending: false,
            last: None,
            at_ms: now_ms,
        });
        ping.pending = true;
        ping.at_ms = now_ms;
    }

    /// Takes a peer's answer to a ping, heard as `rx` says, and what each
    /// repeater it came by measured, `signal`, the nearest first.
    pub fn pong(
        &mut self,
        peer: PublicKey,
        round_trip_ms: u64,
        rx: &RxSummary,
        signal: &[TraceSignalEntry],
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
            hints,
            legs,
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
        make_room(&mut self.pings, &key.0, |ping| ping.at_ms);
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
                legs,
            } => PingView::Reply(PingReply {
                round_trip_ms: u32::try_from(*round_trip_ms).unwrap_or(u32::MAX),
                hops: *hops,
                repeaters: self.path(hints),
                // Hops past the traced ones: the answer flooded through
                // repeaters that named none.
                unnamed: hops.map_or(0, |hops| {
                    hops.saturating_sub(u8::try_from(hints.len()).unwrap_or(u8::MAX) + 1)
                }),
                legs: legs.clone(),
            }),
        })
    }

    /// Forgets the way to `key`.
    pub(super) fn forget_way(&mut self, key: &PublicKey) {
        self.pings.remove(&key.0);
        self.routes.remove(&key.0);
    }
}

/// How a repeater says it heard a hop.
fn leg(entry: TraceSignalEntry) -> Leg {
    if entry.is_point_to_point() {
        return Leg::Bridge;
    }
    match (entry.rssi_dbm(), entry.snr_centibels()) {
        (Some(rssi), Some(snr)) => Leg::Heard(Signal { rssi, snr }),
        _ => Leg::Unknown,
    }
}

/// Makes room in `kept` for `key`, by letting go of the entry whose
/// `at` is earliest.
fn make_room<T>(kept: &mut BTreeMap<[u8; 32], T>, key: &[u8; 32], at: impl Fn(&T) -> u64) {
    if !kept.contains_key(key)
        && kept.len() >= KEPT
        && let Some(oldest) = kept
            .iter()
            .min_by_key(|(_, entry)| at(entry))
            .map(|(key, _)| *key)
    {
        kept.remove(&oldest);
    }
}
