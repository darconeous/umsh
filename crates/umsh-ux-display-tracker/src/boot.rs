//! One boot splash, timed from when the panel finishes displaying it.
//!
//! Independent of the menu: opening About never starts this timer. The
//! display task keeps input gated until the replacement frame is flushed.

/// Boot-only presentation state, driven by monotonic milliseconds.
#[derive(Clone, Copy, Debug)]
pub struct BootSplash {
    active: bool,
    deadline_ms: Option<u64>,
}

impl BootSplash {
    pub const fn new() -> Self {
        Self {
            active: true,
            deadline_ms: None,
        }
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Arm once, after the initial panel flush or refresh completes.
    pub fn shown(&mut self, now_ms: u64) {
        if self.active && self.deadline_ms.is_none() {
            self.deadline_ms = Some(now_ms.saturating_add(2_000));
        }
    }

    pub const fn next_deadline(&self) -> Option<u64> {
        self.deadline_ms
    }

    /// Returns true only when this call ends the splash.
    pub fn dismiss(&mut self) -> bool {
        self.deadline_ms = None;
        core::mem::replace(&mut self.active, false)
    }

    /// Returns true once, when the two visible seconds have elapsed.
    pub fn poll(&mut self, now_ms: u64) -> bool {
        if self.deadline_ms.is_some_and(|deadline| now_ms >= deadline) {
            self.dismiss()
        } else {
            false
        }
    }
}

impl Default for BootSplash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_visible_seconds_start_after_the_refresh() {
        let mut splash = BootSplash::new();
        assert!(!splash.poll(2_000));
        assert_eq!(splash.next_deadline(), None);
        splash.shown(2_000);
        assert_eq!(splash.next_deadline(), Some(4_000));
        assert!(!splash.poll(3_999));
        // An unrelated redraw cannot extend the dwell.
        splash.shown(3_999);
        assert!(splash.poll(4_000));
        assert!(!splash.is_active());
        assert!(!splash.poll(4_001));
        splash.shown(5_000);
        assert_eq!(splash.next_deadline(), None);
    }

    #[test]
    fn dismissal_is_final_even_before_the_initial_refresh_finishes() {
        for shown in [false, true] {
            let mut splash = BootSplash::new();
            if shown {
                splash.shown(100);
            }
            assert!(splash.dismiss());
            assert!(!splash.dismiss());
            splash.shown(200);
            assert!(!splash.is_active());
            assert_eq!(splash.next_deadline(), None);
            assert!(!splash.poll(10_000));
        }
    }
}
