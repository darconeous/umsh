//! Display-attention policy: when the device should stop assuming the
//! user is looking at it.
//!
//! Both panel technologies lapse after a period of inactivity; what
//! lapsing *does* differs, because their costs differ:
//!
//! - [`DisplayKind::Emissive`] (OLED) burns current for as long as it is
//!   lit, so lapsing turns the panel off — via a dimmed warning state
//!   first, so it reads as going to sleep rather than dying.
//! - [`DisplayKind::Persistent`] (e-paper) costs nothing to keep
//!   readable, so it stays visible. Lapsing instead collapses the menu
//!   back to its home page.
//!
//! The shared part is the one that matters to the user: after a while
//! away, the device forgets what you were in the middle of, and the next
//! press starts from a page whose meaning is visible. Both kinds
//! therefore send the menu home on [`Transition::Lapsed`] (see
//! [`crate::menu::UiModel::go_home`]); only emissive panels also cut
//! power.
//!
//! # Driving it
//!
//! 1. Call [`Attention::wake`] on every event that means "the user is
//!    here or wants to be": a button press (on the press edge, not the
//!    release), a BLE connection-state change, an opening pairing
//!    window, an alert, a low-battery notice.
//! 2. Call [`Attention::set_hold`] for conditions that must stay visible
//!    for as long as they last, such as a pairing window showing a PIN.
//! 3. Call [`Attention::poll`] when [`Attention::next_deadline`]
//!    elapses, and act on any [`Transition`] it returns.
//!
//! Content changes that are *not* the user's doing — a battery sample, a
//! bond count — must not call `wake`. Redraw them only while
//! [`Attention::accepts_redraw`] is true, or a board that samples its
//! battery on a timer will never let its panel sleep.

use core::time::Duration;

/// How the board's panel behaves when it is not being looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayKind {
    /// Lit panel (OLED). Costs power while visible; can be dimmed and
    /// switched off.
    Emissive,
    /// Bistable panel (e-paper). Readable at zero power; never switched
    /// off while the device is awake.
    Persistent,
}

/// Timing policy. Held by value so a board can adjust it at runtime —
/// the plumbing a future `PROP_DISPLAY_TIMEOUT` needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttentionConfig {
    /// Inactivity before attention lapses.
    pub timeout: Duration,
    /// How long before `timeout` an emissive panel dims as a warning.
    /// Zero (or anything at least as large as `timeout`) disables the
    /// dim state. Ignored for persistent panels.
    pub dim_margin: Duration,
}

impl AttentionConfig {
    /// OLED default: off after 10 s, dimmed for the last 3 s of that.
    pub const EMISSIVE: Self = Self {
        timeout: Duration::from_secs(10),
        dim_margin: Duration::from_secs(3),
    };

    /// E-paper default: menu returns home after 30 s. Longer than the
    /// emissive timeout because nothing is being spent to keep the
    /// screen readable — only stale menu context is at stake — and
    /// because each partial refresh is visible enough that a twitchy
    /// fallback would be an annoyance of its own.
    pub const PERSISTENT: Self = Self {
        timeout: Duration::from_secs(30),
        dim_margin: Duration::ZERO,
    };

    /// The instant, relative to the last activity, at which the panel
    /// should dim. `None` when this config has no dim state.
    fn dim_after(&self, kind: DisplayKind) -> Option<Duration> {
        if kind != DisplayKind::Emissive
            || self.dim_margin.is_zero()
            || self.dim_margin >= self.timeout
        {
            return None;
        }
        Some(self.timeout - self.dim_margin)
    }
}

/// A condition that pins the display awake for as long as it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldReason {
    /// A pairing window is open. Its PIN has to stay readable for the
    /// whole window.
    Pairing,
    /// A locate alert is running — the display is part of being found.
    Alert,
    /// A guided maintenance or update flow is on screen.
    Maintenance,
    /// A shutdown or power-off confirmation is counting down.
    Shutdown,
}

impl HoldReason {
    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// What the panel is currently doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayState {
    /// Being looked at: lit at full brightness, menu navigable.
    Active,
    /// Emissive only: still lit, dimmed, about to lapse.
    Dim,
    /// Attention has lapsed. Emissive panels are off; persistent panels
    /// are showing their home page.
    Lapsed,
}

/// A state change the owning task has to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// Attention regained. Emissive: draw the fresh frame *first*, then
    /// power the panel on (and restore full contrast if it was dimmed),
    /// so the user never catches a stale frame. Persistent: just redraw.
    Woke,
    /// Emissive only: drop to the dimmed contrast.
    Dimmed,
    /// Attention lapsed. Send the menu home, then — emissive only —
    /// power the panel off.
    Lapsed,
}

/// Display-attention state machine.
///
/// Pure logic driven by a monotonic millisecond clock: no timers, no
/// hardware. Every method that can change state takes `now_ms` so the
/// whole thing is testable with synthetic time.
#[derive(Clone, Copy, Debug)]
pub struct Attention {
    kind: DisplayKind,
    config: AttentionConfig,
    state: DisplayState,
    holds: u8,
    /// Timestamp the current inactivity window is measured from.
    since_ms: u64,
}

impl Attention {
    /// Start in [`DisplayState::Active`] — boot is itself a wake event.
    pub fn new(kind: DisplayKind, config: AttentionConfig, now_ms: u64) -> Self {
        Self {
            kind,
            config,
            state: DisplayState::Active,
            holds: 0,
            since_ms: now_ms,
        }
    }

    pub fn kind(&self) -> DisplayKind {
        self.kind
    }

    pub fn state(&self) -> DisplayState {
        self.state
    }

    pub fn config(&self) -> AttentionConfig {
        self.config
    }

    /// Replace the timing policy. The new timeout is measured from the
    /// existing activity mark, so shortening it below the time already
    /// elapsed lapses at the next [`poll`](Self::poll) rather than
    /// retroactively.
    pub fn set_config(&mut self, config: AttentionConfig) {
        self.config = config;
    }

    /// True once attention has lapsed.
    pub fn is_lapsed(&self) -> bool {
        matches!(self.state, DisplayState::Lapsed)
    }

    /// Whether the panel can show a redraw right now.
    ///
    /// False only for an emissive panel that has been powered off:
    /// pushing pixels at a dark panel wastes bus traffic and, on a
    /// board that samples its battery on a timer, would otherwise run
    /// forever. Persistent panels always accept a redraw — that is how
    /// their lapse is rendered.
    pub fn accepts_redraw(&self) -> bool {
        self.kind == DisplayKind::Persistent || !self.is_lapsed()
    }

    /// Whether any hold is currently pinning the display awake.
    pub fn held(&self) -> bool {
        self.holds != 0
    }

    /// Register user-driven activity.
    ///
    /// Returns [`Transition::Woke`] when this actually brought the panel
    /// back, so the caller can order its redraw and power-on correctly;
    /// returns `None` when the display was already active and only the
    /// inactivity timer moved.
    pub fn wake(&mut self, now_ms: u64) -> Option<Transition> {
        self.since_ms = now_ms;
        if matches!(self.state, DisplayState::Active) {
            return None;
        }
        self.state = DisplayState::Active;
        Some(Transition::Woke)
    }

    /// Assert or release a hold.
    ///
    /// Asserting one also counts as activity, so an event like a pairing
    /// window opening both wakes the panel and pins it. Releasing the
    /// last hold restarts the inactivity window from that moment, so the
    /// user gets a full timeout to read whatever the hold was showing.
    pub fn set_hold(
        &mut self,
        reason: HoldReason,
        active: bool,
        now_ms: u64,
    ) -> Option<Transition> {
        let before = self.holds;
        if active {
            self.holds |= reason.bit();
        } else {
            self.holds &= !reason.bit();
        }
        if self.holds == before {
            return None;
        }
        if active {
            return self.wake(now_ms);
        }
        if self.holds == 0 {
            self.since_ms = now_ms;
        }
        None
    }

    /// Advance time. Returns a transition when one becomes due.
    pub fn poll(&mut self, now_ms: u64) -> Option<Transition> {
        if self.held() || self.is_lapsed() {
            return None;
        }
        let idle = Duration::from_millis(now_ms.saturating_sub(self.since_ms));
        if idle >= self.config.timeout {
            self.state = DisplayState::Lapsed;
            return Some(Transition::Lapsed);
        }
        if matches!(self.state, DisplayState::Active)
            && let Some(dim_after) = self.config.dim_after(self.kind)
            && idle >= dim_after
        {
            self.state = DisplayState::Dim;
            return Some(Transition::Dimmed);
        }
        None
    }

    /// Absolute monotonic-millisecond deadline for the next
    /// [`poll`](Self::poll), if any is pending.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.held() || self.is_lapsed() {
            return None;
        }
        let after = match self.state {
            DisplayState::Active => self
                .config
                .dim_after(self.kind)
                .unwrap_or(self.config.timeout),
            DisplayState::Dim => self.config.timeout,
            DisplayState::Lapsed => return None,
        };
        Some(self.since_ms.saturating_add(after.as_millis() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oled() -> Attention {
        Attention::new(DisplayKind::Emissive, AttentionConfig::EMISSIVE, 0)
    }

    fn epaper() -> Attention {
        Attention::new(DisplayKind::Persistent, AttentionConfig::PERSISTENT, 0)
    }

    #[test]
    fn emissive_dims_then_lapses() {
        let mut a = oled();
        assert_eq!(a.next_deadline(), Some(7_000));
        assert_eq!(a.poll(6_999), None);
        assert_eq!(a.poll(7_000), Some(Transition::Dimmed));
        assert_eq!(a.state(), DisplayState::Dim);
        assert_eq!(a.next_deadline(), Some(10_000));
        assert_eq!(a.poll(9_999), None);
        assert_eq!(a.poll(10_000), Some(Transition::Lapsed));
        assert_eq!(a.state(), DisplayState::Lapsed);
        assert_eq!(a.next_deadline(), None);
    }

    #[test]
    fn lapse_fires_once() {
        let mut a = oled();
        a.poll(7_000);
        assert_eq!(a.poll(10_000), Some(Transition::Lapsed));
        assert_eq!(a.poll(20_000), None);
    }

    #[test]
    fn persistent_lapses_without_dimming() {
        let mut a = epaper();
        assert_eq!(a.next_deadline(), Some(30_000));
        assert_eq!(a.poll(29_999), None);
        assert_eq!(a.poll(30_000), Some(Transition::Lapsed));
        assert_eq!(a.state(), DisplayState::Lapsed);
    }

    #[test]
    fn persistent_always_accepts_redraw() {
        let mut a = epaper();
        assert!(a.accepts_redraw());
        a.poll(30_000);
        assert!(a.is_lapsed());
        assert!(a.accepts_redraw());
    }

    #[test]
    fn dark_emissive_panel_refuses_redraw() {
        let mut a = oled();
        assert!(a.accepts_redraw());
        a.poll(7_000);
        // Dimmed is still visible.
        assert!(a.accepts_redraw());
        a.poll(10_000);
        assert!(!a.accepts_redraw());
    }

    #[test]
    fn wake_from_lapsed_reports_the_transition() {
        let mut a = oled();
        a.poll(10_000);
        assert_eq!(a.wake(12_000), Some(Transition::Woke));
        assert_eq!(a.state(), DisplayState::Active);
        // Full timeout again, measured from the wake.
        assert_eq!(a.next_deadline(), Some(19_000));
    }

    #[test]
    fn wake_from_dim_restores_full_brightness() {
        let mut a = oled();
        a.poll(7_000);
        assert_eq!(a.state(), DisplayState::Dim);
        assert_eq!(a.wake(8_000), Some(Transition::Woke));
        assert_eq!(a.state(), DisplayState::Active);
    }

    #[test]
    fn wake_while_active_only_defers_the_deadline() {
        let mut a = oled();
        assert_eq!(a.wake(5_000), None);
        assert_eq!(a.next_deadline(), Some(12_000));
        assert_eq!(a.poll(10_000), None);
    }

    #[test]
    fn a_hold_pins_the_display_awake() {
        let mut a = oled();
        a.set_hold(HoldReason::Pairing, true, 1_000);
        assert_eq!(a.next_deadline(), None);
        assert_eq!(a.poll(60_000), None);
        assert_eq!(a.state(), DisplayState::Active);
    }

    #[test]
    fn asserting_a_hold_wakes_a_lapsed_panel() {
        let mut a = oled();
        a.poll(10_000);
        assert!(a.is_lapsed());
        assert_eq!(
            a.set_hold(HoldReason::Alert, true, 11_000),
            Some(Transition::Woke)
        );
        assert_eq!(a.state(), DisplayState::Active);
    }

    #[test]
    fn releasing_the_last_hold_restarts_the_full_timeout() {
        let mut a = oled();
        a.set_hold(HoldReason::Pairing, true, 1_000);
        assert_eq!(a.set_hold(HoldReason::Pairing, false, 60_000), None);
        assert_eq!(a.next_deadline(), Some(67_000));
        assert_eq!(a.poll(66_000), None);
        assert_eq!(a.poll(67_000), Some(Transition::Dimmed));
    }

    #[test]
    fn overlapping_holds_release_independently() {
        let mut a = oled();
        a.set_hold(HoldReason::Pairing, true, 1_000);
        a.set_hold(HoldReason::Alert, true, 2_000);
        a.set_hold(HoldReason::Pairing, false, 3_000);
        assert!(a.held());
        assert_eq!(a.poll(60_000), None);
        a.set_hold(HoldReason::Alert, false, 4_000);
        assert!(!a.held());
        assert_eq!(a.next_deadline(), Some(11_000));
    }

    #[test]
    fn redundant_hold_changes_do_not_move_the_clock() {
        let mut a = oled();
        a.set_hold(HoldReason::Pairing, true, 1_000);
        a.set_hold(HoldReason::Pairing, true, 5_000);
        a.set_hold(HoldReason::Pairing, false, 6_000);
        // Timer restarts from the real release, not the duplicate assert.
        assert_eq!(a.next_deadline(), Some(13_000));
    }

    #[test]
    fn releasing_a_hold_that_was_never_held_is_inert() {
        let mut a = oled();
        assert_eq!(a.set_hold(HoldReason::Maintenance, false, 5_000), None);
        assert_eq!(a.next_deadline(), Some(7_000));
    }

    #[test]
    fn zero_dim_margin_lapses_without_a_dim_state() {
        let config = AttentionConfig {
            timeout: Duration::from_secs(10),
            dim_margin: Duration::ZERO,
        };
        let mut a = Attention::new(DisplayKind::Emissive, config, 0);
        assert_eq!(a.next_deadline(), Some(10_000));
        assert_eq!(a.poll(9_999), None);
        assert_eq!(a.poll(10_000), Some(Transition::Lapsed));
    }

    #[test]
    fn dim_margin_at_or_over_the_timeout_disables_dimming() {
        let config = AttentionConfig {
            timeout: Duration::from_secs(10),
            dim_margin: Duration::from_secs(10),
        };
        let mut a = Attention::new(DisplayKind::Emissive, config, 0);
        assert_eq!(a.next_deadline(), Some(10_000));
        assert_eq!(a.poll(10_000), Some(Transition::Lapsed));
    }

    #[test]
    fn a_shorter_timeout_applies_from_the_existing_activity_mark() {
        let mut a = oled();
        a.set_config(AttentionConfig {
            timeout: Duration::from_secs(5),
            dim_margin: Duration::ZERO,
        });
        assert_eq!(a.next_deadline(), Some(5_000));
        assert_eq!(a.poll(5_000), Some(Transition::Lapsed));
    }

    #[test]
    fn a_timeout_already_exceeded_lapses_at_the_next_poll() {
        let mut a = oled();
        a.wake(100_000);
        a.set_config(AttentionConfig {
            timeout: Duration::from_secs(1),
            dim_margin: Duration::ZERO,
        });
        assert_eq!(a.poll(101_500), Some(Transition::Lapsed));
    }
}
