//! What routers report hearing: the repeaters each one lists in answer to
//! a Peer Repeaters Request, a page at a time, kept for the interface to
//! read. Nothing is kept across a reboot.
//!
//! The device node is reached only from the chat task, so a page is asked
//! for as a command, and its answer comes back whole as an arrival.

use alloc::vec::Vec as AllocVec;
use core::fmt::Write as _;

use umsh_core::{NodeHint, PublicKey, RouterHint, base58};
use umsh_node::NodeIdentityPayload;
use umsh_node::location::NodeLocation;
use umsh_node::mac_command::PeerRepeatersResponseView;
use umsh_ux_communicator::avatar::AvatarStyle;
use umsh_ux_communicator::heapless::String;
use umsh_ux_communicator::model::{
    Listed, Listing, ListingAsk, MAX_LISTED, NodeEvent, Signal, meters_between,
};

use super::peers::{avatar, name};
use super::{Chats, cut};
use crate::record::PeerRecord;
use crate::store::ChatStore;
use crate::task::{Command, NeighborsCursor};

/// How many routers' listings are kept. Past it, the one asked longest ago
/// whose screen is not open goes. More than the interface can have open at
/// once.
const KEPT: usize = 4;

/// How long an ask waits for its answer.
pub(crate) const ANSWER_MS: u64 = 30_000;

/// One router's listing.
pub(crate) struct Router {
    /// The repeaters it reported, the one it heard most recently first.
    entries: AllocVec<Entry>,
    /// How many it said it hears.
    total: Option<u8>,
    /// Where its next page starts; `None` once the last page is held.
    cursor: Option<NeighborsCursor>,
    /// When the top of the listing was read.
    read_at_ms: Option<u64>,
    /// The ask waiting for its answer.
    asking: Option<Asking>,
    /// The last ask went unanswered.
    no_answer: bool,
    /// When the listing was last asked for or answered.
    used_ms: u64,
}

/// An ask waiting for its answer.
#[derive(Clone, Copy)]
struct Asking {
    nonce: u16,
    more: bool,
    until_ms: u64,
}

/// A repeater as the router reported it.
struct Entry {
    /// Its node hint, or router hint, as the router gave it: two or three
    /// bytes of its address.
    hint: [u8; 3],
    hint_len: u8,
    /// What it calls itself, as the router heard.
    name: Option<String<24>>,
    signal: Option<Signal>,
    heard_min: Option<u16>,
    at: Option<NodeLocation>,
}

impl Entry {
    fn hint(&self) -> &[u8] {
        &self.hint[..usize::from(self.hint_len)]
    }

    fn router_hint(&self) -> [u8; 2] {
        [self.hint[0], self.hint[1]]
    }
}

impl<S: ChatStore> Chats<S> {
    /// Asks the router at `address` for the top of what it hears, or, when
    /// `more`, the page after the last one held. An ask already waiting is
    /// left to its answer. The listings of the routers at `shown` are kept.
    pub fn ask_listing(
        &mut self,
        address: &str,
        more: bool,
        shown: &[&str],
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let Some(key) = key_at(address) else {
            return;
        };
        if self
            .routers
            .get(&key.0)
            .is_some_and(|router| router.asking.is_some() || (more && router.cursor.is_none()))
        {
            return;
        }
        if !self.routers.contains_key(&key.0)
            && self.routers.len() >= KEPT
            && let Some(oldest) = self
                .routers
                .iter()
                .filter(|(key, _)| {
                    !shown
                        .iter()
                        .any(|shown| key_at(shown).is_some_and(|shown| shown.0 == **key))
                })
                .min_by_key(|(_, router)| router.used_ms)
                .map(|(key, _)| *key)
        {
            self.routers.remove(&oldest);
        }
        self.nonce = self.nonce.wrapping_add(1);
        let nonce = self.nonce;
        let router = self.routers.entry(key.0).or_insert_with(|| Router {
            entries: AllocVec::new(),
            total: None,
            cursor: None,
            read_at_ms: None,
            asking: None,
            no_answer: false,
            used_ms: now_ms,
        });
        router.used_ms = now_ms;
        router.no_answer = false;
        router.asking = Some(Asking {
            nonce,
            more,
            until_ms: now_ms + ANSWER_MS,
        });
        let cursor = if more { router.cursor.clone() } else { None };
        self.commands.push_back(Command::AskNeighbors {
            router: key,
            nonce,
            cursor,
            route: heapless::Vec::new(),
        });
        events(NodeEvent::ListingChanged);
    }

    /// Takes a page of what `router` reports hearing, `body` its Peer
    /// Repeaters Response. One that answers no ask waiting is ignored. A
    /// page of the top replaces the listing; a later one adds to it what it
    /// does not already hold.
    pub fn neighbors_page(
        &mut self,
        router: PublicKey,
        body: &[u8],
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let page = PeerRepeatersResponseView::new(body);
        let Some(kept) = self.routers.get_mut(&router.0) else {
            return;
        };
        let Some(asking) = kept
            .asking
            .filter(|asking| page.nonce() == Some(asking.nonce))
        else {
            return;
        };
        if !asking.more {
            kept.entries.clear();
            kept.read_at_ms = Some(now_ms);
        }
        for entry in page.entries() {
            if kept.entries.len() >= MAX_LISTED {
                break;
            }
            let Some(hint) = entry.hint() else {
                continue;
            };
            // A cursor gone stale starts the listing over, so a later page
            // can repeat what is held.
            if kept
                .entries
                .iter()
                .any(|held| held.hint().starts_with(hint) || hint.starts_with(held.hint()))
            {
                continue;
            }
            let mut bytes = [0; 3];
            bytes[..hint.len()].copy_from_slice(hint);
            kept.entries.push(Entry {
                hint: bytes,
                hint_len: hint.len() as u8,
                name: entry.name().map(cut::<24>),
                signal: entry.rssi_snr().map(|(rssi, snr)| Signal {
                    rssi,
                    snr: snr.as_centibels(),
                }),
                heard_min: entry.last_heard_min(),
                at: entry.location().filter(|at| !at.is_unspecified()),
            });
        }
        // Later pages need not repeat it.
        if !asking.more || page.total().is_some() {
            kept.total = page.total();
        }
        // One too long to keep ends the listing where it is.
        kept.cursor = page
            .cursor()
            .and_then(|cursor| NeighborsCursor::from_slice(cursor).ok());
        kept.asking = None;
        kept.no_answer = false;
        kept.used_ms = now_ms;
        events(NodeEvent::ListingChanged);
    }

    /// Gives up on asks that have waited past [`ANSWER_MS`].
    pub(super) fn lapse_listings(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        let mut lapsed = false;
        for router in self.routers.values_mut() {
            if router
                .asking
                .is_some_and(|asking| asking.until_ms <= now_ms)
            {
                router.asking = None;
                router.no_answer = true;
                lapsed = true;
            }
        }
        if lapsed {
            events(NodeEvent::ListingChanged);
        }
    }

    /// What the router at `address` reports hearing, as last read.
    pub fn listing(&self, address: &str, now_ms: u64) -> Option<Listing> {
        let key = key_at(address)?;
        let router = self.routers.get(&key.0)?;
        Some(Listing {
            count: router.entries.len() as u8,
            total: router.total,
            more: router.cursor.is_some() && router.entries.len() < MAX_LISTED,
            read_ms_ago: router.read_at_ms.map(|at| now_ms.saturating_sub(at)),
            asking: router.asking.map(|asking| {
                if asking.more {
                    ListingAsk::More
                } else {
                    ListingAsk::Top
                }
            }),
            no_answer: router.no_answer,
            hint: [key.0[0], key.0[1]],
        })
    }

    /// The `index`th repeater the router at `address` reports hearing: as
    /// the node it most plausibly is, else as the router named it, else by
    /// its hint.
    pub fn listed(&self, address: &str, index: usize) -> Option<Listed> {
        let key = key_at(address)?;
        let entry = self.routers.get(&key.0)?.entries.get(index)?;
        let kept = self.kept_with(entry.hint());
        let (name_text, avatar, address) = match &kept {
            Some(kept) => (
                cut::<24>(&name(&kept.key, Some(kept))),
                avatar(&kept.key, Some(kept)),
                Some(super::address(&kept.key.0)),
            ),
            None => {
                let mut hint = String::<24>::new();
                match entry.hint_len {
                    3 => _ = write!(hint, "{}", NodeHint(entry.hint)),
                    _ => _ = write!(hint, "{}", RouterHint(entry.router_hint())),
                }
                let avatar = AvatarStyle::router_hint(&hint);
                (entry.name.clone().unwrap_or(hint), avatar, None)
            }
        };
        let distance_m = match (entry.at, self.located(&key)) {
            (Some(at), Some(router)) => Some(meters_between(router.center(), at.center())),
            _ => None,
        };
        Some(Listed {
            name: name_text,
            avatar,
            address,
            hint: entry.router_hint(),
            signal: entry.signal,
            heard_min: entry.heard_min,
            distance_m,
        })
    }

    /// The known node `hint`, two or three bytes of an address, most
    /// plausibly names.
    fn kept_with(&self, hint: &[u8]) -> Option<PeerRecord> {
        match *hint {
            [a, b, c] => {
                let key = self.only_peer_with(NodeHint([a, b, c]))?;
                self.store.peer(&key).ok().flatten()
            }
            [a, b] => self.name_router_hint(RouterHint([a, b])),
            _ => None,
        }
    }

    /// Where `key` last said it is, when it placed itself.
    fn located(&self, key: &PublicKey) -> Option<NodeLocation> {
        let kept = self.store.peer(key).ok().flatten()?;
        NodeIdentityPayload::from_bytes(&kept.identity)
            .ok()?
            .location
            .filter(|at| !at.is_unspecified())
    }
}

/// The key a whole address names.
fn key_at(address: &str) -> Option<PublicKey> {
    Some(PublicKey(base58::decode(address.trim().as_bytes()).ok()?))
}
