//! What the radio has heard from whom, independent of who it was for.
//!
//! Route learning records the way to a *peer*; this records the last
//! reception from a *transmitter*. The two differ for exactly the traffic
//! that makes a repeater useful: a frame forwarded past this node teaches
//! nothing about a peer, and a frame overheard on the air never reaches the
//! host at all, but both prove a neighbor was on the air and how well it was
//! heard. That is what a
//! [Peer Repeaters Response](../../docs/protocol/src/mac-commands.md) reports
//! about the hops it names.

use umsh_core::RouterHint;
use umsh_hal::Snr;

/// How many transmitters the table remembers.
///
/// A neighborhood larger than this is one where the least recently heard
/// entries are the ones worth losing, and the whole table has to fit a
/// single response page's worth of answers anyway.
pub const MAX_TRANSMITTER_OBSERVATIONS: usize = 16;

/// The most recent reception from one transmitter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransmitterObservation {
    /// All a trace or source route reveals about a hop, and so all this
    /// table can key on.
    pub hint: RouterHint,
    /// Received signal strength of the most recent reception, in dBm.
    pub rssi_dbm: i16,
    /// Signal-to-noise ratio of the most recent reception.
    pub snr: Snr,
    /// When that reception was, on the monotonic clock.
    pub last_seen_ms: u64,
}

/// A bounded, least-recently-heard table of transmitter observations.
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
    pub fn observe(&mut self, hint: RouterHint, rssi_dbm: i16, snr: Snr, now_ms: u64) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.hint == hint) {
            entry.rssi_dbm = rssi_dbm;
            entry.snr = snr;
            entry.last_seen_ms = now_ms;
            return;
        }
        let observation = TransmitterObservation {
            hint,
            rssi_dbm,
            snr,
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

    #[test]
    fn a_repeat_reception_replaces_what_was_known_rather_than_adding_to_it() {
        let mut table = TransmitterObservations::new();
        table.observe(hint(1), -100, Snr::from_decibels(-9), 1_000);
        table.observe(hint(1), -70, Snr::from_decibels(6), 2_000);
        assert_eq!(table.len(), 1);
        let entry = table.get(&hint(1)).unwrap();
        assert_eq!(entry.rssi_dbm, -70);
        assert_eq!(entry.snr, Snr::from_decibels(6));
        assert_eq!(entry.last_seen_ms, 2_000);
    }

    #[test]
    fn a_full_table_drops_the_least_recently_heard_transmitter() {
        let mut table = TransmitterObservations::new();
        for seed in 0..MAX_TRANSMITTER_OBSERVATIONS as u8 {
            table.observe(
                hint(seed),
                -90,
                Snr::from_decibels(0),
                1_000 + u64::from(seed),
            );
        }
        // Refresh the oldest so a plain insertion-order eviction would pick
        // the wrong one.
        table.observe(hint(0), -80, Snr::from_decibels(1), 9_000);
        table.observe(hint(200), -95, Snr::from_decibels(-2), 10_000);

        assert_eq!(table.len(), MAX_TRANSMITTER_OBSERVATIONS);
        assert!(table.get(&hint(200)).is_some());
        assert!(
            table.get(&hint(0)).is_some(),
            "refreshed, so not the oldest"
        );
        assert!(table.get(&hint(1)).is_none(), "least recently heard");
    }
}
