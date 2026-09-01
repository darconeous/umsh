//! Traffic counters for the `PROP_STAT_*` properties.
//!
//! [`StatsLedger`] is the one place a device tallies what its radio did.
//! It sits in a `static` and is written by whichever parts of the stack
//! are in a position to see each event exactly once — on a firmware that
//! is the radio multiplexer for frames on the air, the PHY runner for
//! receptions the demodulator rejected, and the device node's pump for
//! what the MAC decided — and it is read by the ULCP session, by the
//! device's own display, and by anything else that wants the same
//! numbers rather than its own.
//!
//! # Every producer adds
//!
//! Each counter is a pair of `u32`s: a `raw` tally that only ever grows
//! (wrapping, never resetting) and a `base` that a host's write moves.
//! What a host reads is `raw - base`, and clearing a counter is
//! `base = raw`.
//!
//! Zeroing `raw` instead would be wrong twice over. Two of the producers
//! mirror tallies the ledger does not own — the MAC's counters and the
//! PHY's — so a zeroed cell would be overwritten by the next mirror pass
//! and the clear would visibly bounce back; and a cell another task is
//! concurrently `fetch_add`-ing cannot be zeroed without losing whatever
//! landed in between. Mirroring producers therefore feed the *difference*
//! since their last pass, which makes every write to the ledger an
//! addition and leaves the base as the only thing a reset touches.
//!
//! Counters wrap rather than saturate. Wrapping arithmetic is what makes
//! `raw - base` right across the boundary; a saturating counter would
//! pin at the maximum and never move again, which is worse than starting
//! over.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ids::prop;

/// The counters a device keeps.
///
/// The discriminants are the ledger's slot indices and are not on the
/// wire; [`Counter::property`] gives the identifier that is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// Frames that reached the air, from any client of the radio.
    TxPackets,
    /// Transmit attempts the channel-activity check held back.
    TxChannelBusy,
    /// Receptions off the air that are UMSH packets.
    RxPackets,
    /// Receptions the radio rejected on CRC.
    RxBadCrc,
    /// Receptions that passed CRC and are not UMSH packets.
    RxNonUmsh,
    /// Receptions the device's own node acted on.
    RxAccepted,
    /// Receptions this node chose to repeat.
    Forwarded,
    /// Receptions declined under the operator's forwarding policy.
    ForwardDropped,
    /// Queued repeats dropped after overhearing the destination's ack.
    ForwardCancelled,
}

/// How many counters a ledger holds.
pub const COUNTERS: usize = 9;

impl Counter {
    /// Every counter, in identifier order.
    pub const ALL: [Counter; COUNTERS] = [
        Counter::TxPackets,
        Counter::TxChannelBusy,
        Counter::RxPackets,
        Counter::RxBadCrc,
        Counter::RxNonUmsh,
        Counter::RxAccepted,
        Counter::Forwarded,
        Counter::ForwardDropped,
        Counter::ForwardCancelled,
    ];

    /// The property identifier this counter is read and cleared through.
    pub const fn property(self) -> u32 {
        match self {
            Counter::TxPackets => prop::STAT_TX_PACKETS,
            Counter::TxChannelBusy => prop::STAT_TX_CHANNEL_BUSY,
            Counter::RxPackets => prop::STAT_RX_PACKETS,
            Counter::RxBadCrc => prop::STAT_RX_BAD_CRC,
            Counter::RxNonUmsh => prop::STAT_RX_NON_UMSH,
            Counter::RxAccepted => prop::STAT_RX_ACCEPTED,
            Counter::Forwarded => prop::STAT_FORWARDED,
            Counter::ForwardDropped => prop::STAT_FORWARD_DROPPED,
            Counter::ForwardCancelled => prop::STAT_FORWARD_CANCELLED,
        }
    }

    /// The counter a property identifier names, if it names one.
    pub const fn from_property(key: u32) -> Option<Counter> {
        Some(match key {
            prop::STAT_TX_PACKETS => Counter::TxPackets,
            prop::STAT_TX_CHANNEL_BUSY => Counter::TxChannelBusy,
            prop::STAT_RX_PACKETS => Counter::RxPackets,
            prop::STAT_RX_BAD_CRC => Counter::RxBadCrc,
            prop::STAT_RX_NON_UMSH => Counter::RxNonUmsh,
            prop::STAT_RX_ACCEPTED => Counter::RxAccepted,
            prop::STAT_FORWARDED => Counter::Forwarded,
            prop::STAT_FORWARD_DROPPED => Counter::ForwardDropped,
            prop::STAT_FORWARD_CANCELLED => Counter::ForwardCancelled,
            _ => return None,
        })
    }

    /// Whether this counter can only be answered by a device running a
    /// node of its own.
    ///
    /// The four that come from the MAC. A session with nothing behind it
    /// does not have these properties at all, rather than reporting a
    /// zero that reads as "this repeater has never repeated anything".
    pub const fn needs_node(self) -> bool {
        matches!(
            self,
            Counter::RxAccepted
                | Counter::Forwarded
                | Counter::ForwardDropped
                | Counter::ForwardCancelled
        )
    }
}

/// One counter: what has happened, and where the host last started
/// counting from.
struct Cell {
    raw: AtomicU32,
    base: AtomicU32,
}

impl Cell {
    const fn new() -> Self {
        Self {
            raw: AtomicU32::new(0),
            base: AtomicU32::new(0),
        }
    }
}

/// The shared traffic ledger.
///
/// Lock-free and `const`-constructible, so a board declares one `static`
/// and hands out `&'static` references to every producer and reader.
/// Ordering is `Relaxed` throughout: each counter is independent, no
/// reader is deciding anything from the ordering between two of them,
/// and the alternative buys a fence on the radio's hot path to make
/// diagnostics agree about an instant nobody is looking at.
pub struct StatsLedger {
    cells: [Cell; COUNTERS],
}

impl StatsLedger {
    pub const fn new() -> Self {
        Self {
            cells: [const { Cell::new() }; COUNTERS],
        }
    }

    /// Record one event.
    pub fn bump(&self, counter: Counter) {
        self.add(counter, 1);
    }

    /// Record `n` events. Adding zero is free and is the ordinary case
    /// for a mirroring producer whose source has not moved.
    pub fn add(&self, counter: Counter, n: u32) {
        if n != 0 {
            self.cells[counter as usize]
                .raw
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    /// What a host reads: events since boot, or since it last cleared
    /// this counter.
    pub fn get(&self, counter: Counter) -> u32 {
        let cell = &self.cells[counter as usize];
        cell.raw
            .load(Ordering::Relaxed)
            .wrapping_sub(cell.base.load(Ordering::Relaxed))
    }

    /// The underlying tally, ignoring any clear. Nothing on the wire
    /// reports this; it is here so a device that wants a since-boot view
    /// of its own has one.
    pub fn raw(&self, counter: Counter) -> u32 {
        self.cells[counter as usize].raw.load(Ordering::Relaxed)
    }

    /// Start this counter over from here.
    ///
    /// Clearing several counters is several of these, so a frame landing
    /// mid-sweep is counted before one and after another. Nothing reads
    /// them closely enough for that to matter, and the alternative is a
    /// lock on the radio's hot path.
    pub fn reset(&self, counter: Counter) {
        let cell = &self.cells[counter as usize];
        cell.base
            .store(cell.raw.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

impl Default for StatsLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for StatsLedger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatsLedger")
            .field("tx_packets", &self.get(Counter::TxPackets))
            .field("rx_packets", &self.get(Counter::RxPackets))
            .finish_non_exhaustive()
    }
}

/// A mirror of a monotone tally kept somewhere else.
///
/// Producers that copy someone else's counters — the MAC's, the PHY's —
/// hold one of these per source field and feed the ledger the difference
/// since the last pass, so the ledger only ever sees additions. A source
/// that goes backwards (a counter reconstructed, a peripheral restarted)
/// contributes nothing rather than a nonsensical jump.
#[derive(Clone, Copy, Debug, Default)]
pub struct Mirror {
    last: u32,
}

impl Mirror {
    pub const fn new() -> Self {
        Self { last: 0 }
    }

    /// Fold the source's current value in, returning what was added.
    pub fn advance(&mut self, ledger: &StatsLedger, counter: Counter, now: u32) -> u32 {
        let delta = now.saturating_sub(self.last);
        self.last = now;
        ledger.add(counter, delta);
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn properties_round_trip() {
        for counter in Counter::ALL {
            assert_eq!(Counter::from_property(counter.property()), Some(counter));
        }
        assert_eq!(Counter::from_property(prop::PHY_DUTY_NOW), None);
    }

    #[test]
    fn counting_and_clearing() {
        let ledger = StatsLedger::new();
        assert_eq!(ledger.get(Counter::TxPackets), 0);

        ledger.bump(Counter::TxPackets);
        ledger.add(Counter::TxPackets, 4);
        assert_eq!(ledger.get(Counter::TxPackets), 5);
        // Counters are independent.
        assert_eq!(ledger.get(Counter::RxPackets), 0);

        ledger.reset(Counter::TxPackets);
        assert_eq!(ledger.get(Counter::TxPackets), 0);
        // The underlying tally is untouched, and counting resumes from
        // the clear rather than from boot.
        assert_eq!(ledger.raw(Counter::TxPackets), 5);
        ledger.bump(Counter::TxPackets);
        assert_eq!(ledger.get(Counter::TxPackets), 1);
    }

    #[test]
    fn reported_value_survives_the_wrap() {
        let ledger = StatsLedger::new();
        ledger.add(Counter::RxPackets, u32::MAX - 1);
        ledger.reset(Counter::RxPackets);
        // Three more events take the raw tally across the boundary; the
        // reported value is still three.
        ledger.add(Counter::RxPackets, 3);
        assert_eq!(ledger.raw(Counter::RxPackets), 1);
        assert_eq!(ledger.get(Counter::RxPackets), 3);
    }

    #[test]
    fn mirrors_feed_the_difference() {
        let ledger = StatsLedger::new();
        let mut mirror = Mirror::new();

        // A source that is already nonzero when the mirror starts
        // contributes its whole value once, and nothing again until it
        // moves.
        assert_eq!(mirror.advance(&ledger, Counter::Forwarded, 7), 7);
        assert_eq!(mirror.advance(&ledger, Counter::Forwarded, 7), 0);
        assert_eq!(mirror.advance(&ledger, Counter::Forwarded, 9), 2);
        assert_eq!(ledger.get(Counter::Forwarded), 9);

        // A clear holds even though the source keeps climbing.
        ledger.reset(Counter::Forwarded);
        mirror.advance(&ledger, Counter::Forwarded, 9);
        assert_eq!(ledger.get(Counter::Forwarded), 0);
        mirror.advance(&ledger, Counter::Forwarded, 11);
        assert_eq!(ledger.get(Counter::Forwarded), 2);

        // A source that goes backwards contributes nothing rather than
        // dragging the ledger with it.
        mirror.advance(&ledger, Counter::Forwarded, 0);
        assert_eq!(ledger.get(Counter::Forwarded), 2);
        mirror.advance(&ledger, Counter::Forwarded, 1);
        assert_eq!(ledger.get(Counter::Forwarded), 3);
    }

    #[test]
    fn only_the_mac_sourced_counters_need_a_node() {
        let needs: Vec<Counter> = Counter::ALL
            .into_iter()
            .filter(|c| c.needs_node())
            .collect();
        assert_eq!(
            needs,
            [
                Counter::RxAccepted,
                Counter::Forwarded,
                Counter::ForwardDropped,
                Counter::ForwardCancelled
            ]
        );
    }
}
