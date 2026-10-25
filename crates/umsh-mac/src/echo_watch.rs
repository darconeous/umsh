//! Which of this node's recent frames it is still listening for repeats of.
//!
//! The pending-ack table answers a narrower question: whether a send that
//! is waiting on a repeat has had one, so its retry ladder can stand down.
//! That table holds unicast only, and it is done with a send at its first
//! repeat. Whoever sent the frame wants to hear more than that: every
//! repeater that carries it is one more node the message reached, and a
//! channel message has no other evidence of reaching anyone at all. So
//! every tracked frame that asks to be repeated is watched for a while
//! after it airs, keyed the way repeaters key it, and each forward of it
//! that is overheard is reported.
//!
//! A forward names its repeater only when the frame says who sent it:
//!
//! - a trace route is prepended to, so its first hint is the node that just
//!   transmitted;
//! - a source route loses its first hint at each repeater, so before any
//!   flood hop is spent, what is missing from the route this node sent is
//!   the repeater that removed it.
//!
//! A flood with neither says only that someone forwarded it.

use heapless::Vec;
use umsh_core::{PacketHeader, ParsedOptions, RouterHint};

use crate::{
    LocalIdentityId, MAX_SOURCE_ROUTE_HINTS, cache::DupCacheKey, forward_id, send::SendReceipt,
};

/// How long after a frame airs its forwards are still reported. A flood
/// several hops deep is still being carried onward seconds after it left;
/// past this, an echo is no longer news to anyone watching the send.
pub const ECHO_WATCH_MS: u64 = 20_000;

/// How many frames are watched at once, the oldest dropped first.
const MAX_ECHO_WATCHES: usize = 8;

/// One overheard forward of a watched frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Echo {
    pub identity_id: LocalIdentityId,
    pub receipt: SendReceipt,
    /// The repeater that transmitted the forward, when the frame names it.
    pub repeater: Option<RouterHint>,
}

#[derive(Clone, Debug)]
struct EchoWatch {
    key: DupCacheKey,
    identity_id: LocalIdentityId,
    receipt: SendReceipt,
    until_ms: u64,
    /// The source route the frame left with, empty for a flood.
    route: Vec<RouterHint, MAX_SOURCE_ROUTE_HINTS>,
}

/// A bounded table of frames being listened for.
#[derive(Clone, Debug, Default)]
pub(crate) struct EchoWatches {
    entries: Vec<EchoWatch, MAX_ECHO_WATCHES>,
}

impl EchoWatches {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Start, or restart, listening for forwards of `frame`, which just
    /// aired. A retransmission keys the same as the frame it repeats, so it
    /// extends the watch already running.
    pub(crate) fn arm(
        &mut self,
        identity_id: LocalIdentityId,
        receipt: SendReceipt,
        frame: &[u8],
        now_ms: u64,
    ) {
        let Ok(header) = PacketHeader::parse(frame) else {
            return;
        };
        let Some(key) = forward_id::forwarding_dup_key_parsed(&header, frame) else {
            return;
        };
        let until_ms = now_ms.saturating_add(ECHO_WATCH_MS);
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.key == key) {
            entry.until_ms = until_ms;
            return;
        }
        let mut route = Vec::new();
        if let Some(bytes) = ParsedOptions::extract(frame, header.options_range.clone())
            .ok()
            .and_then(|options| options.source_route)
            .and_then(|range| frame.get(range))
        {
            for pair in bytes.chunks_exact(2) {
                let _ = route.push(RouterHint([pair[0], pair[1]]));
            }
        }
        self.expire(now_ms);
        if self.entries.is_full() {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.until_ms)
                .map(|(index, _)| index);
            if let Some(index) = oldest {
                self.entries.remove(index);
            }
        }
        let _ = self.entries.push(EchoWatch {
            key,
            identity_id,
            receipt,
            until_ms,
            route,
        });
    }

    /// The watched send `frame` is a forward of, if any.
    pub(crate) fn heard(&mut self, frame: &[u8], now_ms: u64) -> Option<Echo> {
        self.expire(now_ms);
        if self.entries.is_empty() {
            return None;
        }
        let header = PacketHeader::parse(frame).ok()?;
        let key = forward_id::forwarding_dup_key_parsed(&header, frame)?;
        let entry = self.entries.iter().find(|entry| entry.key == key)?;
        let options = ParsedOptions::extract(frame, header.options_range.clone()).ok()?;
        Some(Echo {
            identity_id: entry.identity_id,
            receipt: entry.receipt,
            repeater: forwarding_repeater(&header, &options, frame, &entry.route),
        })
    }

    fn expire(&mut self, now_ms: u64) {
        self.entries.retain(|entry| entry.until_ms > now_ms);
    }
}

/// The repeater that transmitted `frame`, a forward of a frame this node
/// sent along `route`, when the frame says.
pub(crate) fn forwarding_repeater(
    header: &PacketHeader,
    options: &ParsedOptions,
    frame: &[u8],
    route: &[RouterHint],
) -> Option<RouterHint> {
    if let Some(trace) = options
        .trace_route
        .as_ref()
        .and_then(|range| frame.get(range.clone()))
        && trace.len() >= 2
        && trace.len() % 2 == 0
    {
        return Some(RouterHint([trace[0], trace[1]]));
    }
    // Once a flood hop is spent the route is used up, and every forward
    // after that leaves it the same length.
    if route.is_empty() || header.flood_hops.is_some_and(|hops| hops.accumulated() > 0) {
        return None;
    }
    let left = options
        .source_route
        .as_ref()
        .map_or(0, |range| range.len() / 2);
    let removed = route.len().checked_sub(left)?.checked_sub(1)?;
    route.get(removed).copied()
}
