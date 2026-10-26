//! Locking: the interface locks once its panel has been dark a moment, or
//! when the board's lock button is pressed, and the lock screen stands in
//! for every other screen until it is unlocked.
//!
//! On a board with a wheel, unlocking takes two steps a pocket is unlikely
//! to make: turning the wheel down [`UNLOCK_STEPS`] detents, then pressing
//! it within [`UNLOCK_WINDOW_MS`]. Turning up takes steps back. On a board
//! whose press is hard to make by accident, such as a trackball's, a press
//! alone unlocks. Keys do nothing while locked; what was on screen is kept,
//! and unlocking returns to it, or opens first run on a device not yet set
//! up.

use buoyant::focus::FocusKey;

use crate::board::Unlock;
use crate::model::State;

/// How many detents down unlock.
pub const UNLOCK_STEPS: u8 = 5;
/// How long a press unlocks once the wheel has turned far enough, in
/// milliseconds.
pub const UNLOCK_WINDOW_MS: u64 = 2000;
/// How long the panel is dark before the interface locks, in milliseconds:
/// an input in that time lights it again unlocked.
pub const LOCK_GRACE_MS: u64 = 1000;

/// Whether the interface is locked, and how far it is toward unlocking.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lock {
    pub locked: bool,
    /// When the panel's going dark locks it, on the board's clock, while
    /// it is dark and not yet locked.
    at: Option<u64>,
    /// Detents turned toward unlocking, up to [`UNLOCK_STEPS`].
    pub steps: u8,
    /// Until when a press unlocks, once the steps are all turned.
    ready_until: Option<u64>,
    /// What was focused when it locked, for unlocking to return to.
    held: Option<FocusKey>,
}

impl Lock {
    /// Whether a press now unlocks.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready_until.is_some()
    }

    /// The next moment the lock changes by itself.
    pub(crate) fn deadline(&self) -> Option<u64> {
        match (self.at, self.ready_until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Starts over toward unlocking.
    fn reset(&mut self) {
        self.steps = 0;
        self.ready_until = None;
    }
}

impl State {
    /// The panel went dark at `now`. The interface locks once it has been
    /// dark for [`LOCK_GRACE_MS`].
    pub fn screen_off(&mut self, now: u64) {
        self.dark = true;
        if !self.lock.locked {
            self.lock.at = Some(now + LOCK_GRACE_MS);
        }
        self.uptime = now;
    }

    /// The panel lit at `now`: the lock screen, if it locked, starts over.
    pub fn screen_on(&mut self, now: u64) {
        self.dark = false;
        self.lock.at = None;
        self.lock.reset();
        self.uptime = now;
    }

    /// Locks the interface, keeping what is on screen for unlocking.
    pub fn lock(&mut self) {
        if self.lock.locked {
            return;
        }
        self.lock = Lock {
            locked: true,
            held: self.screen().focus().current(),
            ..Lock::default()
        };
        self.picker = None;
        self.banner = None;
        self.settle();
    }

    /// Unlocks, back to what was on screen, or into first run while the
    /// device has not been set up and it is not already under way.
    fn unlock(&mut self) {
        let held = self.lock.held;
        self.lock = Lock::default();
        self.arrived.clear();
        if !self.node.setup_complete() && !self.in_setup() {
            self.start_setup();
        } else if let Some(key) = held {
            self.focus().request(key);
        }
        self.settle();
    }

    /// Whether a press now unlocks: once the steps are turned, or always
    /// where a press alone unlocks.
    #[must_use]
    pub const fn unlock_ready(&self) -> bool {
        matches!(self.board.controls.unlock, Unlock::Press) || self.lock.ready()
    }

    /// The wheel turned `detents` on the lock screen at `now`: down toward
    /// unlocking, up away from it. Where a press alone unlocks, turning
    /// does nothing.
    pub fn turn_to_unlock(&mut self, detents: i8, now: u64) {
        if matches!(self.board.controls.unlock, Unlock::Press) {
            return;
        }
        let lock = &mut self.lock;
        lock.steps =
            (i16::from(lock.steps) + i16::from(detents)).clamp(0, i16::from(UNLOCK_STEPS)) as u8;
        if lock.steps < UNLOCK_STEPS {
            lock.ready_until = None;
        } else if lock.ready_until.is_none() {
            lock.ready_until = Some(now + UNLOCK_WINDOW_MS);
        }
    }

    /// The wheel was pressed on the lock screen at `now`: it unlocks if the
    /// steps were turned in time, or where a press alone unlocks. A press
    /// too late starts the bar over.
    pub fn press_to_unlock(&mut self, now: u64) {
        self.expire_lock(now);
        if self.unlock_ready() {
            self.unlock();
        }
    }

    /// Lets the lock's deadlines pass by `now`: going dark locks, and a
    /// window not pressed in starts over.
    pub(crate) fn expire_lock(&mut self, now: u64) {
        if self.lock.at.is_some_and(|at| at <= now) {
            self.lock();
        }
        if self.lock.ready_until.is_some_and(|until| until < now) {
            self.lock.reset();
        }
    }
}
