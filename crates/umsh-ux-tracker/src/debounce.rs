//! Debouncing a push button's level, ahead of
//! [`ButtonFsm`](crate::button::ButtonFsm), which wants clean edges.

/// Stable-level debounce: a new level counts once it has held for 15 ms.
pub struct Debounce {
    stable: bool,
    observed: bool,
    since: u64,
}
impl Debounce {
    pub const fn new(pressed: bool) -> Self {
        Self {
            stable: pressed,
            observed: pressed,
            since: 0,
        }
    }
    pub fn sample(&mut self, pressed: bool, now_ms: u64) -> Option<bool> {
        if pressed != self.observed {
            self.observed = pressed;
            self.since = now_ms;
        }
        if self.observed != self.stable && now_ms.saturating_sub(self.since) >= 15 {
            self.stable = self.observed;
            Some(self.stable)
        } else {
            None
        }
    }

    pub fn observed(&self) -> bool {
        self.observed
    }

    pub fn deadline(&self) -> Option<u64> {
        (self.observed != self.stable).then_some(self.since.saturating_add(15))
    }
}

/// A gesture begins at the first contact, and ends only after a stable
/// release, even if a bouncing press never became a debounced press.
#[derive(Default)]
pub struct PressLatch {
    active: bool,
    release_at: Option<u64>,
}
impl PressLatch {
    pub fn observe(&mut self, pressed: bool, now_ms: u64) -> bool {
        if pressed {
            self.release_at = None;
            let began = !self.active;
            self.active = true;
            began
        } else {
            if self.active {
                let at = *self.release_at.get_or_insert(now_ms.saturating_add(15));
                if now_ms >= at {
                    self.active = false;
                    self.release_at = None;
                }
            }
            false
        }
    }

    pub fn deadline(&self) -> Option<u64> {
        self.release_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_does_not_repeat_or_accept_bounce() {
        let mut b = Debounce::new(false);
        for (pressed, now) in [(true, 1), (false, 3), (true, 5), (true, 19)] {
            assert_eq!(b.sample(pressed, now), None);
        }
        assert_eq!(b.sample(true, 20), Some(true));
        assert_eq!(b.sample(true, 5000), None);
        assert_eq!(b.sample(false, 5010), None);
        assert_eq!(b.sample(false, 5025), Some(false));
    }

    #[test]
    fn wake_press_keeps_its_gate_through_bounce_and_hold() {
        let mut latch = PressLatch::default();
        assert!(latch.observe(true, 1));
        assert!(!latch.observe(false, 3));
        assert_eq!(latch.deadline(), Some(18));
        assert!(!latch.observe(true, 5));
        assert_eq!(latch.deadline(), None);
        assert!(!latch.observe(true, 5000));
        assert!(!latch.observe(false, 5001));
        assert!(!latch.observe(false, 5016));
        assert!(latch.observe(true, 5017));
    }
}
