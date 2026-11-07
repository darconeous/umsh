//! Forwards waiting out their retransmit delay.

use heapless::Vec;

use crate::packet::Frame;

/// One forward and when it may go.
struct Scheduled {
    due_ms: u64,
    priority: u8,
    frame: Frame,
}

/// A bounded set of scheduled forwards.
///
/// Of the forwards that are due, the lowest priority value goes first,
/// and among equals the one scheduled first: the baseline's order. Kept
/// in insertion order, so the tie-break is the position.
pub struct DelayQueue<const N: usize> {
    entries: Vec<Scheduled, N>,
}

impl<const N: usize> DelayQueue<N> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Schedule `frame`, or hand it back when the queue is full: new work
    /// is what gets dropped, never work already accepted.
    #[allow(
        clippy::result_large_err,
        reason = "handing the frame back is the contract; no allocator here"
    )]
    pub fn push(&mut self, due_ms: u64, priority: u8, frame: Frame) -> Result<(), Frame> {
        self.entries
            .push(Scheduled {
                due_ms,
                priority,
                frame,
            })
            .map_err(|rejected| rejected.frame)
    }

    /// The forward to send now, if any is due.
    pub fn pop_due(&mut self, now_ms: u64) -> Option<Frame> {
        let mut best: Option<usize> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.due_ms > now_ms {
                continue;
            }
            if best.is_none_or(|best| entry.priority < self.entries[best].priority) {
                best = Some(index);
            }
        }
        best.map(|index| self.entries.remove(index).frame)
    }

    /// The priority of the forward `pop_due` would hand out at `now_ms`.
    #[cfg(test)]
    pub fn due_priority(&self, now_ms: u64) -> Option<u8> {
        self.entries
            .iter()
            .filter(|entry| entry.due_ms <= now_ms)
            .map(|entry| entry.priority)
            .min()
    }

    /// When the earliest forward falls due, or `None` when empty.
    pub fn next_due_ms(&self) -> Option<u64> {
        self.entries.iter().map(|entry| entry.due_ms).min()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl<const N: usize> Default for DelayQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8) -> Frame {
        Frame::from_slice(&[tag]).unwrap()
    }

    #[test]
    fn due_entries_go_by_priority_then_by_arrival() {
        let mut queue = DelayQueue::<4>::new();
        queue.push(10, 3, frame(1)).unwrap();
        queue.push(0, 3, frame(2)).unwrap();
        queue.push(5, 0, frame(3)).unwrap();
        queue.push(50, 0, frame(4)).unwrap();
        assert_eq!(queue.next_due_ms(), Some(0));
        assert_eq!(queue.pop_due(4).unwrap()[0], 2);
        assert_eq!(queue.pop_due(10).unwrap()[0], 3);
        assert_eq!(queue.pop_due(10).unwrap()[0], 1);
        // Higher priority, but not yet due.
        assert!(queue.pop_due(10).is_none());
        assert_eq!(queue.pop_due(50).unwrap()[0], 4);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn a_full_queue_refuses_the_new_work() {
        let mut queue = DelayQueue::<1>::new();
        queue.push(0, 5, frame(1)).unwrap();
        assert_eq!(queue.push(0, 0, frame(2)).unwrap_err()[0], 2);
        assert_eq!(queue.pop_due(0).unwrap()[0], 1);
    }
}
