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
//!
//! A trace hint is not authenticated: anyone on the air can put any router
//! hint at the front of a frame. So an entry is *unproven* until the
//! repeater it names is heard forwarding one of this node's own frames,
//! which no one can produce on demand, and a full table never lets an
//! unproven reception displace a proven entry.

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
    /// One bit per slot of `entries`: set for a repeater heard forwarding
    /// one of this node's own frames. Slots are overwritten in place and
    /// never removed, so an index names the same entry for as long as it
    /// holds it.
    proven: u16,
}

const _: () = assert!(MAX_TRANSMITTER_OBSERVATIONS <= u16::BITS as usize);

impl TransmitterObservations {
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
            proven: 0,
        }
    }

    /// Record a reception from `hint`, replacing whatever was known before.
    ///
    /// Only the latest reception is kept: a peer-repeater entry reports the
    /// most recent measurement, and an average across a moving neighbor
    /// would describe a link that no longer exists.
    ///
    /// The reception proves nothing about `hint`, so a full table makes room
    /// for it only by displacing an unproven entry. Returns `false` when it
    /// was left out because every entry is proven.
    pub fn observe(&mut self, hint: RouterHint, rssi_snr: Option<(i16, Snr)>, now_ms: u64) -> bool {
        self.record(hint, rssi_snr, now_ms, false)
    }

    /// Record a reception from `hint` that showed it forwarding one of this
    /// node's own frames, and mark its entry proven.
    ///
    /// A full table makes room by displacing the least recently heard
    /// unproven entry, or, when every entry is proven, the least recently
    /// heard of those.
    pub fn vouch(&mut self, hint: RouterHint, rssi_snr: Option<(i16, Snr)>, now_ms: u64) {
        self.record(hint, rssi_snr, now_ms, true);
    }

    /// Whether the entry for `hint` is held and proven.
    pub fn is_proven(&self, hint: &RouterHint) -> bool {
        self.position(hint)
            .is_some_and(|index| self.proven & (1 << index) != 0)
    }

    fn position(&self, hint: &RouterHint) -> Option<usize> {
        self.entries.iter().position(|entry| &entry.hint == hint)
    }

    fn record(
        &mut self,
        hint: RouterHint,
        rssi_snr: Option<(i16, Snr)>,
        now_ms: u64,
        proven: bool,
    ) -> bool {
        let observation = TransmitterObservation {
            hint,
            rssi_snr,
            last_seen_ms: now_ms,
        };
        let index = match self.position(&hint) {
            Some(index) => index,
            None => {
                let index = self.entries.len();
                if self.entries.push(observation).is_err() {
                    let Some(index) = self.displaceable(proven) else {
                        return false;
                    };
                    // An unproven newcomer only ever takes an unproven
                    // slot, so the slot's bit is already what it should be
                    // unless the newcomer is proven.
                    self.entries[index] = observation;
                    if proven {
                        self.proven |= 1 << index;
                    }
                    return true;
                }
                index
            }
        };
        // An unproven reception of a proven repeater is still news of it,
        // so it refreshes the entry, but proof is never withdrawn by one.
        self.entries[index] = observation;
        if proven {
            self.proven |= 1 << index;
        }
        true
    }

    /// The slot a new entry may take in a full table: the least recently
    /// heard transmitter is the one whose absence says the least, and an
    /// unproven entry goes before any proven one. Only a proven newcomer
    /// may take a proven entry's slot.
    fn displaceable(&self, newcomer_proven: bool) -> Option<usize> {
        let oldest = |want_proven: bool| {
            self.entries
                .iter()
                .enumerate()
                .filter(|(index, _)| (self.proven & (1 << index) != 0) == want_proven)
                .min_by_key(|(_, entry)| entry.last_seen_ms)
                .map(|(index, _)| index)
        };
        oldest(false).or_else(|| oldest(true).filter(|_| newcomer_proven))
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

    /// A flood of frames naming made-up repeaters takes only unproven
    /// slots; the repeaters proven by carrying this node's frames stay.
    #[test]
    fn an_unproven_reception_never_displaces_a_proven_entry() {
        let mut table = TransmitterObservations::new();
        table.vouch(hint(0), measured(-80, 2), 1_000);
        for seed in 1..MAX_TRANSMITTER_OBSERVATIONS as u8 {
            assert!(table.observe(hint(seed), measured(-90, 0), 1_000 + u64::from(seed)));
        }
        assert!(table.is_proven(&hint(0)));
        assert!(!table.is_proven(&hint(1)));

        // The proven entry is the oldest, and still survives the flood.
        for seed in 100..140 {
            assert!(table.observe(hint(seed), measured(-95, -2), 5_000 + u64::from(seed)));
        }
        assert!(table.get(&hint(0)).is_some());
        assert!(table.is_proven(&hint(0)));

        // A table that is all proven turns an unproven newcomer away.
        let mut proven = TransmitterObservations::new();
        for seed in 0..MAX_TRANSMITTER_OBSERVATIONS as u8 {
            proven.vouch(hint(seed), measured(-90, 0), 1_000 + u64::from(seed));
        }
        assert!(!proven.observe(hint(200), measured(-60, 9), 9_000));
        assert!(proven.get(&hint(200)).is_none());

        // An unproven reception of a proven repeater refreshes it and
        // leaves it proven.
        assert!(proven.observe(hint(3), measured(-70, 4), 9_500));
        assert_eq!(proven.get(&hint(3)).unwrap().last_seen_ms, 9_500);
        assert!(proven.is_proven(&hint(3)));

        // A proven newcomer takes the least recently heard proven slot.
        proven.vouch(hint(201), measured(-85, 1), 10_000);
        assert!(proven.is_proven(&hint(201)));
        assert!(proven.get(&hint(0)).is_none(), "least recently heard");
        assert_eq!(proven.len(), MAX_TRANSMITTER_OBSERVATIONS);
    }
}
