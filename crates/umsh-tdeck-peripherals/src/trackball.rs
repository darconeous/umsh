//! Rolls from the trackball's four Hall sensors (§9). Each sensor pulses
//! as the ball's magnets pass, so a roll is a run of edges on one pin,
//! with stray edges on the others from a ball never rolled quite square.
//! [`Trackball`] counts edges per direction and reports a step once one
//! direction has [`Trackball::threshold`] more than its opposite; for a
//! moment after a step, edges on the other axis are taken for wobble.

/// Which way the ball rolled, as seen from the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}

impl Direction {
    const fn index(self) -> usize {
        self as usize
    }
    const fn opposite(self) -> Self {
        match self {
            Self::Up => Self::Down,
            Self::Down => Self::Up,
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
    const fn vertical(self) -> bool {
        matches!(self, Self::Up | Self::Down)
    }
}

/// Edges for one step until hardware says otherwise (checklist 6).
pub const DEFAULT_THRESHOLD: u8 = 2;
/// A pause this long starts the count over.
pub const IDLE_MS: u64 = 150;
/// How long after a step the other axis is ignored.
pub const AXIS_LOCK_MS: u64 = 120;

pub struct Trackball {
    threshold: u8,
    counts: [u8; 4],
    last_edge: Option<u64>,
    /// The axis of the last step, vertical or not, until when.
    lock: Option<(bool, u64)>,
}

impl Trackball {
    pub const fn new(threshold: u8) -> Self {
        Self {
            threshold: if threshold == 0 { 1 } else { threshold },
            counts: [0; 4],
            last_edge: None,
            lock: None,
        }
    }

    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// An edge on `direction`'s sensor at `now_ms`; the step it completes,
    /// if it does.
    pub fn edge(&mut self, direction: Direction, now_ms: u64) -> Option<Direction> {
        if self
            .last_edge
            .is_some_and(|last| now_ms.saturating_sub(last) >= IDLE_MS)
        {
            self.counts = [0; 4];
        }
        self.last_edge = Some(now_ms);
        if let Some((vertical, until)) = self.lock {
            if now_ms >= until {
                self.lock = None;
            } else if vertical != direction.vertical() {
                return None;
            }
        }
        // A roll back first takes back what was counted the other way.
        let opposite = &mut self.counts[direction.opposite().index()];
        if *opposite > 0 {
            *opposite -= 1;
            return None;
        }
        let count = &mut self.counts[direction.index()];
        *count += 1;
        if *count < self.threshold {
            return None;
        }
        self.counts = [0; 4];
        self.lock = Some((direction.vertical(), now_ms + AXIS_LOCK_MS));
        Some(direction)
    }
}

impl Default for Trackball {
    fn default() -> Self {
        Self::new(DEFAULT_THRESHOLD)
    }
}
