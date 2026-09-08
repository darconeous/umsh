//! Which repeaters this node has heard forwarding, and how well.
//!
//! Route learning records the way to a *peer*; this records the last
//! reception from a neighboring *repeater*. A repeater prepends its router
//! hint to the trace route of every frame it forwards, so the first hint of
//! a trace names the transmitter just heard, and a frame with no such hint
//! came off its originator and names no repeater at all. The two differ for
//! exactly the traffic that makes a repeater useful: a frame forwarded past
//! this node teaches nothing about a peer, and a frame overheard on the air
//! never reaches the host, but both prove a neighboring repeater was on the
//! air. That is what a
//! [Peer Repeaters Response](../../docs/protocol/src/mac-commands.md) reports
//! about the hops it names.
//!
//! A neighbor need not be on the air at all: a host attached over a
//! point-to-point link forwards like any other repeater and is recorded like
//! one, with no measurement, since no radio was between it and this node.

use umsh_core::RouterHint;
use umsh_hal::Snr;

/// How many repeaters the table remembers.
///
/// A neighborhood larger than this is one where the least recently heard
/// entries are the ones worth losing, and the whole table has to fit a
/// single response page's worth of answers anyway.
pub const MAX_TRANSMITTER_OBSERVATIONS: usize = 16;

/// The most recent reception from one neighboring repeater.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransmitterObservation {
    /// All a trace route reveals about the hop that forwarded a frame, and
    /// so all this table can key on.
    pub hint: RouterHint,
    /// RSSI in dBm and SNR of the most recent reception, when a radio
    /// measured it. `None` for a neighbor reached over a link with no radio
    /// in it.
    pub rssi_snr: Option<(i16, Snr)>,
    /// When that reception was, on the monotonic clock.
    pub last_seen_ms: u64,
}

/// A bounded, least-recently-heard table of repeater observations.
#[derive(Clone, Debug, Default)]
pub struct TransmitterObservations {
    entries: heapless::Vec<TransmitterObservation, MAX_TRANSMITTER_OBSERVATIONS>,
}

impl TransmitterObservations {
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// Record a reception from `hint`, replacing whatever was known before.
    ///
    /// Only the latest reception is kept: a peer-repeater entry reports the
    /// most recent measurement, and an average across a moving neighbor
    /// would describe a link that no longer exists.
    pub fn observe(&mut self, hint: RouterHint, rssi_snr: Option<(i16, Snr)>, now_ms: u64) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.hint == hint) {
            entry.rssi_snr = rssi_snr;
            entry.last_seen_ms = now_ms;
            return;
        }
        let observation = TransmitterObservation {
            hint,
            rssi_snr,
            last_seen_ms: now_ms,
        };
        if self.entries.push(observation).is_ok() {
            return;
        }
        // Full: the least recently heard transmitter is the one whose
        // absence says the least.
        let Some(oldest) = self
            .entries
            .iter_mut()
            .min_by_key(|entry| entry.last_seen_ms)
        else {
            return;
        };
        *oldest = observation;
    }

    pub fn iter(&self) -> impl Iterator<Item = &TransmitterObservation> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The observation for one transmitter, if it is still held.
    pub fn get(&self, hint: &RouterHint) -> Option<&TransmitterObservation> {
        self.entries.iter().find(|entry| &entry.hint == hint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(seed: u8) -> RouterHint {
        RouterHint([seed, seed])
    }

    fn measured(rssi_dbm: i16, snr_db: i8) -> Option<(i16, Snr)> {
        Some((rssi_dbm, Snr::from_decibels(snr_db)))
    }

    #[test]
    fn a_repeat_reception_replaces_what_was_known_rather_than_adding_to_it() {
        let mut table = TransmitterObservations::new();
        table.observe(hint(1), measured(-100, -9), 1_000);
        table.observe(hint(1), measured(-70, 6), 2_000);
        assert_eq!(table.len(), 1);
        let entry = table.get(&hint(1)).unwrap();
        assert_eq!(entry.rssi_snr, measured(-70, 6));
        assert_eq!(entry.last_seen_ms, 2_000);

        // A neighbor that moved onto a link with no radio in it is still
        // the same neighbor, now without a reading.
        table.observe(hint(1), None, 3_000);
        let entry = table.get(&hint(1)).unwrap();
        assert_eq!(entry.rssi_snr, None);
        assert_eq!(entry.last_seen_ms, 3_000);
    }

    #[test]
    fn a_full_table_drops_the_least_recently_heard_transmitter() {
        let mut table = TransmitterObservations::new();
        for seed in 0..MAX_TRANSMITTER_OBSERVATIONS as u8 {
            table.observe(hint(seed), measured(-90, 0), 1_000 + u64::from(seed));
        }
        // Refresh the oldest so a plain insertion-order eviction would pick
        // the wrong one.
        table.observe(hint(0), measured(-80, 1), 9_000);
        table.observe(hint(200), measured(-95, -2), 10_000);

        assert_eq!(table.len(), MAX_TRANSMITTER_OBSERVATIONS);
        assert!(table.get(&hint(200)).is_some());
        assert!(
            table.get(&hint(0)).is_some(),
            "refreshed, so not the oldest"
        );
        assert!(table.get(&hint(1)).is_none(), "least recently heard");
    }
}
