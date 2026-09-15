//! Input/display handoff policy, independent of GPIO and the executor.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Interactive,
    Dark,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gesture {
    Navigate,
    Wake,
    Splash,
    Ignore,
}

pub struct InputPower {
    pub mode: Mode,
    pub epoch: u32,
    pub armed: bool,
    pub display_ready: bool,
    activity: u32,
    dark_activity: u32,
    waking: bool,
}

impl Default for InputPower {
    fn default() -> Self {
        Self::new()
    }
}

impl InputPower {
    pub const fn new() -> Self {
        Self {
            mode: Mode::Interactive,
            epoch: 0,
            armed: false,
            display_ready: false,
            activity: 0,
            dark_activity: 0,
            waking: false,
        }
    }

    pub fn activity(&self) -> u32 {
        self.activity
    }

    pub fn note_activity(&mut self) {
        self.activity = self.activity.wrapping_add(1);
    }

    /// A display-off operation may have yielded while an input arrived.
    pub fn dark(&mut self, before_display_off: u32) -> bool {
        if self.mode == Mode::Shutdown || self.activity != before_display_off || self.waking {
            return false;
        }
        self.mode = Mode::Dark;
        self.epoch = self.epoch.wrapping_add(1);
        self.armed = false;
        self.display_ready = false;
        self.dark_activity = self.activity;
        true
    }

    pub fn wake(&mut self) -> bool {
        if self.mode == Mode::Shutdown {
            return false;
        }
        if self.mode == Mode::Dark {
            self.mode = Mode::Interactive;
            self.epoch = self.epoch.wrapping_add(1);
        }
        self.armed = false;
        self.waking = true;
        self.display_ready = false;
        true
    }

    pub fn arm(&mut self, epoch: u32) -> bool {
        if self.mode != Mode::Dark || self.epoch != epoch || self.activity != self.dark_activity {
            return false;
        }
        self.armed = true;
        true
    }

    pub fn activity_since_dark(&self) -> bool {
        self.activity != self.dark_activity
    }

    pub fn shown(&mut self, epoch: u32) {
        if self.mode == Mode::Interactive && self.epoch == epoch {
            self.display_ready = true;
            self.waking = false;
        }
    }

    pub fn shutdown(&mut self) {
        self.mode = Mode::Shutdown;
        self.epoch = self.epoch.wrapping_add(1);
        self.armed = false;
        self.display_ready = false;
    }

    /// Latch at gesture start, not after debounce or display rendering.
    pub fn gesture(&mut self, splash: bool, faded: bool) -> Gesture {
        self.note_activity();
        if self.mode == Mode::Shutdown {
            Gesture::Ignore
        } else if splash {
            Gesture::Splash
        } else if self.mode == Mode::Dark || (faded && !self.waking) {
            self.wake();
            Gesture::Wake
        } else {
            Gesture::Navigate
        }
    }
}

/// Fixed-space qualification summary. No timers or extra acquisitions.
pub struct PowerWindow {
    pub count: u32,
    pub unlocked: u32,
    pub min_ma: i32,
    pub max_ma: i32,
    sum_ma: i64,
    first_ms: u64,
    last_ms: u64,
}
impl Default for PowerWindow {
    fn default() -> Self {
        Self::new()
    }
}
impl PowerWindow {
    pub const fn new() -> Self {
        Self {
            count: 0,
            unlocked: 0,
            min_ma: 0,
            max_ma: 0,
            sum_ma: 0,
            first_ms: 0,
            last_ms: 0,
        }
    }
    pub fn sample(&mut self, now_ms: u64, current_ma: i32, unlocked: bool) {
        if self.complete() {
            return;
        }
        if self.count == 0 {
            self.first_ms = now_ms;
            self.min_ma = current_ma;
            self.max_ma = current_ma;
        }
        self.last_ms = now_ms;
        self.count += 1;
        self.unlocked += u32::from(unlocked);
        self.min_ma = self.min_ma.min(current_ma);
        self.max_ma = self.max_ma.max(current_ma);
        self.sum_ma += i64::from(current_ma);
    }
    pub fn span_ms(&self) -> u64 {
        self.last_ms.saturating_sub(self.first_ms)
    }
    pub fn complete(&self) -> bool {
        self.count >= 300 && self.span_ms() >= 300_000
    }
    pub fn mean_ma(&self) -> i64 {
        self.sum_ma.checked_div(i64::from(self.count)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_window_requires_five_minutes_and_keeps_signed_current() {
        let mut w = PowerWindow::new();
        for i in 0..300 {
            w.sample(30_000 + i * 1000, -100, true);
        }
        assert!(!w.complete());
        w.sample(330_000, -200, false);
        assert!(w.complete());
        assert_eq!(w.count, 301);
        assert_eq!(w.unlocked, 300);
        assert_eq!((w.min_ma, w.max_ma), (-200, -100));
        assert_eq!(w.mean_ma(), -100);
        w.sample(331_000, 700, false);
        assert_eq!(w.count, 301);
    }

    #[test]
    fn activity_during_display_off_cancels_parking() {
        let mut p = InputPower::new();
        p.shown(0);
        let token = p.activity();
        p.note_activity();
        assert!(!p.dark(token));
        assert_eq!(p.mode, Mode::Interactive);
    }

    #[test]
    fn an_edge_after_dark_request_but_before_arming_cancels_sleep() {
        let mut p = InputPower::new();
        assert!(p.dark(p.activity()));
        p.note_activity();
        assert!(!p.arm(p.epoch));
        assert!(p.activity_since_dark());
    }

    #[test]
    fn wake_invalidates_arm_and_consumes_only_the_wake_gesture() {
        let mut p = InputPower::new();
        p.shown(0);
        assert!(p.dark(p.activity()));
        let stale = p.epoch;
        assert_eq!(p.gesture(false, true), Gesture::Wake);
        assert!(!p.arm(stale));
        assert_eq!(p.gesture(false, true), Gesture::Navigate);
        assert!(!p.display_ready);
        p.shown(stale);
        assert!(!p.display_ready);
        p.shown(p.epoch);
        assert!(p.display_ready);
    }

    #[test]
    fn dimming_consumes_a_gesture_without_allowing_sleep() {
        let mut p = InputPower::new();
        p.shown(0);
        assert_eq!(p.gesture(false, true), Gesture::Wake);
        assert_eq!(p.mode, Mode::Interactive);
        assert!(!p.arm(p.epoch));
        assert_eq!(p.gesture(false, true), Gesture::Navigate);
    }

    #[test]
    fn shutdown_wins_over_every_stale_ack_and_input() {
        let mut p = InputPower::new();
        let epoch = p.epoch;
        p.shutdown();
        assert!(!p.wake());
        assert!(!p.dark(p.activity()));
        assert!(!p.arm(epoch));
        p.shown(epoch);
        assert!(!p.display_ready);
        assert_eq!(p.gesture(false, false), Gesture::Ignore);
        assert_eq!(p.mode, Mode::Shutdown);
    }

    #[test]
    fn splash_disposition_survives_a_later_display_change() {
        let mut p = InputPower::new();
        let held = p.gesture(true, false);
        p.shown(0);
        assert_eq!(held, Gesture::Splash);
        assert_eq!(p.gesture(false, false), Gesture::Navigate);
    }
}
