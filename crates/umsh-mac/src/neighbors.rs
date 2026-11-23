//! How many nodes stand beside this one.
//!
//! A frame nobody has forwarded came off its originator's own transmitter,
//! so its source address names a node in earshot, and one heard strongly
//! is close enough to hear and reach what this node does. Counting the
//! distinct ones heard lately says how many others would forward a flood
//! to the same ground, which an adaptive forwarder thins its own
//! forwarding by (UEP-0018).
//!
//! A node is told apart by the first two bytes of its address, the part a
//! repeater hint also carries.

/// How many neighbors are remembered. The count stops here.
pub const MAX_NEIGHBORS_HEARD: usize = 128;

/// How long a neighbor counts after it was last heard, in milliseconds.
pub const NEIGHBORS_HEARD_WINDOW_MS: u64 = 10 * 60 * 1000;

/// The neighbors heard first-hand, and when each last was.
#[derive(Clone, Debug)]
pub struct NeighborsHeard {
    prefixes: [[u8; 2]; MAX_NEIGHBORS_HEARD],
    /// Seconds, plus one so that zero marks an empty place.
    heard_s: [u32; MAX_NEIGHBORS_HEARD],
}

impl NeighborsHeard {
    pub const fn new() -> Self {
        Self {
            prefixes: [[0; 2]; MAX_NEIGHBORS_HEARD],
            heard_s: [0; MAX_NEIGHBORS_HEARD],
        }
    }

    fn stamp(now_ms: u64) -> u32 {
        (now_ms / 1000).min(u64::from(u32::MAX - 1)) as u32 + 1
    }

    /// Record that the node whose address begins `prefix` was heard at
    /// `now_ms`. With every place taken, the one heard longest ago gives
    /// way.
    pub fn record(&mut self, prefix: [u8; 2], now_ms: u64) {
        let stamp = Self::stamp(now_ms);
        let mut oldest = 0;
        for place in 0..MAX_NEIGHBORS_HEARD {
            if self.heard_s[place] != 0 && self.prefixes[place] == prefix {
                self.heard_s[place] = self.heard_s[place].max(stamp);
                return;
            }
            if self.heard_s[place] < self.heard_s[oldest] {
                oldest = place;
            }
        }
        self.prefixes[oldest] = prefix;
        self.heard_s[oldest] = stamp;
    }

    /// How many distinct neighbors were heard in the window ending at
    /// `now_ms`.
    pub fn count(&self, now_ms: u64) -> usize {
        let now = Self::stamp(now_ms);
        let window_s = (NEIGHBORS_HEARD_WINDOW_MS / 1000) as u32;
        self.heard_s
            .iter()
            .filter(|&&heard| heard != 0 && now.saturating_sub(heard) < window_s)
            .count()
    }
}

impl Default for NeighborsHeard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_neighbor_is_counted_once_and_ages_out() {
        let mut heard = NeighborsHeard::new();
        assert_eq!(heard.count(0), 0);
        heard.record([1, 2], 0);
        heard.record([1, 2], 5_000);
        heard.record([3, 4], 60_000);
        assert_eq!(heard.count(60_000), 2);
        assert_eq!(heard.count(5_000 + NEIGHBORS_HEARD_WINDOW_MS), 1);
        assert_eq!(heard.count(60_000 + NEIGHBORS_HEARD_WINDOW_MS), 0);
    }

    #[test]
    fn a_full_table_gives_up_the_one_heard_longest_ago() {
        let mut heard = NeighborsHeard::new();
        for index in 0..MAX_NEIGHBORS_HEARD {
            heard.record([index as u8, 0], index as u64 * 1000);
        }
        heard.record([0xEE, 1], 200_000);
        assert_eq!(heard.count(200_000), MAX_NEIGHBORS_HEARD);
        // The first one recorded is the one that went.
        heard.record([0, 0], 201_000);
        assert_eq!(heard.count(201_000), MAX_NEIGHBORS_HEARD);
    }
}
