//! Which repeaters have shown whether they hear this node.
//!
//! [`TransmitterObservations`](crate::TransmitterObservations) records the
//! repeaters this node hears. A route is used in the other direction, and
//! hearing a repeater well says nothing about whether it hears us: a
//! hilltop site with a strong transmitter is audible long after a handheld
//! has dropped out of its reach.
//!
//! The evidence for that direction comes from this node's own frames as
//! repeaters forward them. A trace route lists the repeaters a frame
//! crossed, the first one last, and the trace signal beside it carries how
//! well each of them heard the transmitter before it. So when a frame this
//! node originated comes back forwarded:
//!
//! - the last hint is the repeater that took the frame off this node's
//!   transmission, and its trace-signal entry is how well it heard us;
//! - on a flood, every other hint is a repeater that forwarded a copy it
//!   took from another repeater. A flood repeater forwards the first copy
//!   it accepts, and this node's own transmission comes first, so those
//!   repeaters either did not hear it or heard it too weakly to use.

use umsh_core::{RouterHint, options::TraceSignalEntry};

/// How many repeaters the table remembers.
pub(crate) const MAX_UPLINK_OBSERVATIONS: usize = 16;

/// How long a piece of evidence stays worth acting on. Long enough to
/// outlast the gaps in ordinary traffic, short enough that a node that has
/// moved stops trusting what it learned before.
const EVIDENCE_TTL_MS: u64 = 30 * 60 * 1000;

/// What this node knows about whether one repeater hears it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Uplink {
    /// The repeater recently took a frame off this node's transmission,
    /// measured as the entry says when the frame carried a trace signal.
    Heard(Option<TraceSignalEntry>),
    /// The repeater recently forwarded a frame of ours it had taken from
    /// another repeater instead, and has not been seen to hear us since.
    Unheard,
    /// Nothing recent either way.
    Unknown,
}

#[derive(Clone, Copy, Debug)]
struct UplinkObservation {
    hint: RouterHint,
    /// When the repeater last heard us, in whole seconds of the monotonic
    /// clock, and how well when the frame said.
    heard: Option<(u32, Option<TraceSignalEntry>)>,
    /// When it last forwarded a frame of ours it had not heard from us.
    unheard_s: Option<u32>,
}

impl UplinkObservation {
    fn latest_s(&self) -> u32 {
        let heard = self.heard.map_or(0, |(at, _)| at);
        heard.max(self.unheard_s.unwrap_or(0))
    }
}

/// A bounded table of uplink evidence, least recently updated dropped
/// first.
#[derive(Clone, Debug, Default)]
pub(crate) struct UplinkObservations {
    entries: heapless::Vec<UplinkObservation, MAX_UPLINK_OBSERVATIONS>,
}

fn seconds(now_ms: u64) -> u32 {
    (now_ms / 1000) as u32
}

impl UplinkObservations {
    pub(crate) const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// Record that `hint` took a frame off this node's transmission.
    pub(crate) fn note_heard(
        &mut self,
        hint: RouterHint,
        signal: Option<TraceSignalEntry>,
        now_ms: u64,
    ) {
        self.entry(hint, now_ms).heard = Some((seconds(now_ms), signal));
    }

    /// Record that `hint` forwarded a frame of ours it had taken from
    /// another repeater.
    pub(crate) fn note_unheard(&mut self, hint: RouterHint, now_ms: u64) {
        self.entry(hint, now_ms).unheard_s = Some(seconds(now_ms));
    }

    /// What the table says about `hint` now. The more recent of the two
    /// kinds of evidence wins; a tie goes to having been heard, since that
    /// one is a positive observation.
    pub(crate) fn uplink(&self, hint: &RouterHint, now_ms: u64) -> Uplink {
        let Some(entry) = self.entries.iter().find(|entry| &entry.hint == hint) else {
            return Uplink::Unknown;
        };
        let now_s = seconds(now_ms);
        let fresh = |at_s: u32| u64::from(now_s.wrapping_sub(at_s)) * 1000 <= EVIDENCE_TTL_MS;
        let heard = entry.heard.filter(|(at, _)| fresh(*at));
        let unheard = entry.unheard_s.filter(|at| fresh(*at));
        match (heard, unheard) {
            (Some((heard_at, _)), Some(unheard_at)) if unheard_at > heard_at => Uplink::Unheard,
            (Some((_, signal)), _) => Uplink::Heard(signal),
            (None, Some(_)) => Uplink::Unheard,
            (None, None) => Uplink::Unknown,
        }
    }

    fn entry(&mut self, hint: RouterHint, now_ms: u64) -> &mut UplinkObservation {
        if let Some(index) = self.entries.iter().position(|entry| entry.hint == hint) {
            return &mut self.entries[index];
        }
        let fresh = UplinkObservation {
            hint,
            heard: None,
            unheard_s: None,
        };
        if self.entries.push(fresh).is_err() {
            // Full: the repeater whose evidence is oldest says the least.
            let now_s = seconds(now_ms);
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .max_by_key(|(_, entry)| now_s.wrapping_sub(entry.latest_s()))
                .map(|(index, _)| index)
                .unwrap_or(0);
            self.entries[oldest] = fresh;
            return &mut self.entries[oldest];
        }
        let last = self.entries.len() - 1;
        &mut self.entries[last]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(seed: u8) -> RouterHint {
        RouterHint([seed, seed])
    }

    #[test]
    fn the_more_recent_evidence_wins() {
        let mut table = UplinkObservations::new();
        let signal = Some(TraceSignalEntry::new(-64, 80));
        table.note_heard(hint(1), signal, 10_000);
        assert_eq!(table.uplink(&hint(1), 10_000), Uplink::Heard(signal));

        table.note_unheard(hint(1), 20_000);
        assert_eq!(table.uplink(&hint(1), 20_000), Uplink::Unheard);

        table.note_heard(hint(1), None, 30_000);
        assert_eq!(table.uplink(&hint(1), 30_000), Uplink::Heard(None));
        assert_eq!(table.uplink(&hint(2), 30_000), Uplink::Unknown);
    }

    #[test]
    fn evidence_expires() {
        let mut table = UplinkObservations::new();
        table.note_unheard(hint(1), 1_000);
        assert_eq!(
            table.uplink(&hint(1), 1_000 + EVIDENCE_TTL_MS),
            Uplink::Unheard
        );
        assert_eq!(
            table.uplink(&hint(1), 2_000 + EVIDENCE_TTL_MS),
            Uplink::Unknown
        );
    }

    #[test]
    fn a_full_table_drops_the_stalest_repeater() {
        let mut table = UplinkObservations::new();
        for seed in 0..MAX_UPLINK_OBSERVATIONS as u8 {
            table.note_heard(hint(seed), None, 1_000 * (u64::from(seed) + 1));
        }
        // Refresh the first so insertion order would pick the wrong one.
        table.note_unheard(hint(0), 100_000);
        table.note_heard(hint(200), None, 101_000);
        assert_eq!(table.entries.len(), MAX_UPLINK_OBSERVATIONS);
        assert_eq!(table.uplink(&hint(0), 101_000), Uplink::Unheard);
        assert_eq!(table.uplink(&hint(1), 101_000), Uplink::Unknown);
        assert_eq!(table.uplink(&hint(200), 101_000), Uplink::Heard(None));
    }
}
