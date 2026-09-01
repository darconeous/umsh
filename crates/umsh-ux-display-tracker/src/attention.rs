//! Display-attention policy: when the device should stop assuming the
//! user is looking at it.
//!
//! Both panel technologies lapse after a period of inactivity; what
//! lapsing *does* differs, because their costs differ:
//!
//! - [`DisplayKind::Emissive`] (OLED) burns current for as long as it is
//!   lit, so lapsing turns the panel off — falling smoothly into a dimmed
//!   warning state first, so it reads as going to sleep rather than dying.
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

/// How often the fall into the dim state is stepped.
///
/// Twenty steps to a second, which on every panel in this class is one
/// three-byte contrast write apiece and no framebuffer traffic at all.
const RAMP_STEP_MS: u64 = 50;
const RAMP_STEP: Duration = Duration::from_millis(RAMP_STEP_MS);

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
    /// How long the fall from full brightness to the dim floor is drawn
    /// out over. Zero drops in a single step, which is what a persistent
    /// panel — and any board whose panel cannot be dimmed gradually —
    /// wants.
    pub dim_ramp: Duration,
}

impl AttentionConfig {
    /// OLED default: off after 30 s, dimmed for the last 10 s of that,
    /// falling into the dim over the first second of those ten.
    ///
    /// The numbers are what a panel a person is actually reading from
    /// needs: twenty seconds is long enough to walk to a menu entry,
    /// read it, and think about it, and ten dimmed seconds afterwards is
    /// long enough that the warning is a warning rather than the last
    /// moment before the screen is gone.
    pub const EMISSIVE: Self = Self {
        timeout: Duration::from_secs(30),
        dim_margin: Duration::from_secs(10),
        dim_ramp: Duration::from_secs(1),
    };

    /// E-paper default: menu returns home after 30 s. Longer than the
    /// emissive timeout because nothing is being spent to keep the
    /// screen readable — only stale menu context is at stake — and
    /// because each partial refresh is visible enough that a twitchy
    /// fallback would be an annoyance of its own.
    pub const PERSISTENT: Self = Self {
        timeout: Duration::from_secs(30),
        dim_margin: Duration::ZERO,
        dim_ramp: Duration::ZERO,
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

    /// How many [`RAMP_STEP`]s the fall into the dim state takes.
    ///
    /// Always at least one: a zero ramp is a single step change, which is
    /// the whole of what a panel that cannot fade gradually needs.
    fn ramp_steps(&self) -> u16 {
        let steps = self.dim_ramp.as_millis().div_ceil(u128::from(RAMP_STEP_MS));
        steps.clamp(1, u128::from(u16::MAX)) as u16
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
    /// Emissive only: still lit, falling to or resting at the dim floor,
    /// about to lapse. [`Attention::brightness_permille`] says which.
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
    ///
    /// A wake snaps straight back to full brightness. Only the fall is
    /// gradual — the user is waiting on the rise.
    Woke,
    /// Emissive only: apply [`Attention::brightness_permille`].
    ///
    /// One of these arrives per [`RAMP_STEP`] of the fall into the dim
    /// state, not one per lapse, so a caller that treats it as a single
    /// edge to a fixed contrast will draw a staircase of one step.
    Dimming,
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
    /// How many steps of the fall into the dim state have been reported.
    /// Zero outside [`DisplayState::Dim`].
    ramp_step: u16,
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
            ramp_step: 0,
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

    /// How far the panel sits between its dim floor and full brightness,
    /// in permille: 1000 while active, falling across
    /// [`AttentionConfig::dim_ramp`] once the dim state begins, and 0
    /// once it has settled there.
    ///
    /// Deliberately *not* an absolute brightness. Which two levels a
    /// panel's floor and full are is the board's business — an SH1106's
    /// dim contrast is an eighth of its normal one and an SSD1306's is
    /// half — and a policy that named either would be wrong on the other.
    /// All this says is where between them to sit.
    pub fn brightness_permille(&self) -> u16 {
        match self.state {
            DisplayState::Active => 1_000,
            DisplayState::Dim => {
                let steps = self.config.ramp_steps();
                let done = u32::from(self.ramp_step.min(steps));
                (1_000 - 1_000 * done / u32::from(steps)) as u16
            }
            DisplayState::Lapsed => 0,
        }
    }

    /// Register user-driven activity.
    ///
    /// Returns [`Transition::Woke`] when this actually brought the panel
    /// back, so the caller can order its redraw and power-on correctly;
    /// returns `None` when the display was already active and only the
    /// inactivity timer moved.
    ///
    /// Dropping the transition is how a panel gets stranded: the state
    /// machine moves to [`DisplayState::Active`] while the glass stays
    /// dark, and because every later wake then finds it already active,
    /// nothing can light it again. A caller that genuinely has nothing to
    /// do with a wake — a persistent panel has no power to restore —
    /// should say so with `let _ =`.
    #[must_use = "a wake that is not acted on leaves the panel dark while the policy calls it lit"]
    pub fn wake(&mut self, now_ms: u64) -> Option<Transition> {
        self.since_ms = now_ms;
        if matches!(self.state, DisplayState::Active) {
            return None;
        }
        self.state = DisplayState::Active;
        self.ramp_step = 0;
        Some(Transition::Woke)
    }

    /// Assert or release a hold.
    ///
    /// Asserting one also counts as activity, so an event like a pairing
    /// window opening both wakes the panel and pins it. Releasing the
    /// last hold restarts the inactivity window from that moment, so the
    /// user gets a full timeout to read whatever the hold was showing.
    ///
    /// The returned wake matters most exactly where it is easiest to
    /// overlook. A hold is often re-derived on a loop rather than
    /// received as an event, and an alert or a pairing window that
    /// arrives at a sleeping tracker has no press behind it — so this
    /// call is the only thing that will ever say to light the panel. See
    /// [`wake`](Self::wake) for what dropping it costs.
    #[must_use = "asserting a hold can be the wake that lights the panel"]
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
        let dim_after = self.config.dim_after(self.kind)?;
        if idle < dim_after {
            return None;
        }
        // Which step the fall has reached is derived from the clock rather
        // than counted, so a poll that arrives late — or several steps
        // late — lands on the brightness the elapsed time asks for instead
        // of walking there one call at a time.
        let steps = self.config.ramp_steps();
        let elapsed = (idle - dim_after).as_millis() as u64;
        let due = ((elapsed / RAMP_STEP_MS) + 1).min(u64::from(steps)) as u16;
        if matches!(self.state, DisplayState::Active) {
            self.state = DisplayState::Dim;
        } else if due <= self.ramp_step {
            return None;
        }
        self.ramp_step = due;
        Some(Transition::Dimming)
    }

    /// Absolute monotonic-millisecond deadline for the next
    /// [`poll`](Self::poll), if any is pending.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.held() || self.is_lapsed() {
            return None;
        }
        let lapse_at = self
            .since_ms
            .saturating_add(self.config.timeout.as_millis() as u64);
        let after = match self.state {
            DisplayState::Active => self
                .config
                .dim_after(self.kind)
                .unwrap_or(self.config.timeout),
            // Still falling: the next step of the ramp. Once it has
            // settled on the floor there is nothing left to do but lapse.
            DisplayState::Dim => match self.config.dim_after(self.kind) {
                Some(dim_after) if self.ramp_step < self.config.ramp_steps() => {
                    dim_after + RAMP_STEP * u32::from(self.ramp_step)
                }
                _ => return Some(lapse_at),
            },
            DisplayState::Lapsed => return None,
        };
        Some(
            self.since_ms
                .saturating_add(after.as_millis() as u64)
                .min(lapse_at),
        )
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

    /// Drive `a` the way a display task does: poll at each deadline up to
    /// `until_ms`. Returns how many steps of the fall came back and the
    /// first and last instant one did, asserting on the way through that
    /// nothing but a ramp step arrived.
    fn ramp(a: &mut Attention, until_ms: u64) -> (usize, u64, u64) {
        let (mut count, mut first, mut last) = (0, 0, 0);
        while let Some(deadline) = a.next_deadline() {
            if deadline > until_ms {
                break;
            }
            if let Some(transition) = a.poll(deadline) {
                assert_eq!(transition, Transition::Dimming, "at {deadline}");
                if count == 0 {
                    first = deadline;
                }
                last = deadline;
                count += 1;
            }
        }
        (count, first, last)
    }

    #[test]
    fn emissive_dims_then_lapses() {
        let mut a = oled();
        assert_eq!(a.next_deadline(), Some(20_000));
        assert_eq!(a.poll(19_999), None);
        assert_eq!(a.poll(20_000), Some(Transition::Dimming));
        assert_eq!(a.state(), DisplayState::Dim);

        // The ramp owns the next second; the lapse is the deadline after it.
        ramp(&mut a, 29_999);
        assert_eq!(a.brightness_permille(), 0);
        assert_eq!(a.next_deadline(), Some(30_000));
        assert_eq!(a.poll(29_999), None);
        assert_eq!(a.poll(30_000), Some(Transition::Lapsed));
        assert_eq!(a.state(), DisplayState::Lapsed);
        assert_eq!(a.next_deadline(), None);
    }

    /// The whole point of the ramp: a fall the eye reads as a fade rather
    /// than as the panel dropping a level.
    #[test]
    fn the_fall_into_the_dim_state_is_stepped() {
        let mut a = oled();
        let (count, first, last) = ramp(&mut a, 29_999);
        assert_eq!(count, 20, "one second of 50 ms steps");
        // First step at the dim instant, last one 950 ms later.
        assert_eq!(first, 20_000);
        assert_eq!(last, 20_950);
    }

    #[test]
    fn brightness_falls_monotonically_to_the_floor() {
        let mut a = oled();
        assert_eq!(a.brightness_permille(), 1_000);
        let mut previous = 1_000;
        while let Some(deadline) = a.next_deadline() {
            if deadline >= 30_000 {
                break;
            }
            a.poll(deadline);
            let now = a.brightness_permille();
            assert!(now < previous, "{now} is not below {previous}");
            previous = now;
        }
        assert_eq!(previous, 0);
        a.poll(30_000);
        assert_eq!(a.brightness_permille(), 0);
    }

    /// A task that misses several steps — a busy radio, a long flush —
    /// lands on the brightness the clock asks for rather than walking
    /// there one poll at a time.
    #[test]
    fn a_late_poll_catches_up_in_one_step() {
        let mut a = oled();
        assert_eq!(a.poll(20_500), Some(Transition::Dimming));
        assert_eq!(a.brightness_permille(), 450);
        assert_eq!(a.poll(20_950), Some(Transition::Dimming));
        assert_eq!(a.brightness_permille(), 0);
    }

    #[test]
    fn the_ramp_stops_at_the_floor() {
        let mut a = oled();
        ramp(&mut a, 29_999);
        assert_eq!(a.poll(25_000), None);
        assert_eq!(a.brightness_permille(), 0);
    }

    #[test]
    fn a_wake_mid_ramp_returns_to_full_brightness() {
        let mut a = oled();
        a.poll(20_200);
        assert_eq!(a.state(), DisplayState::Dim);
        assert!(a.brightness_permille() < 1_000);
        assert_eq!(a.wake(20_300), Some(Transition::Woke));
        assert_eq!(a.brightness_permille(), 1_000);
        assert_eq!(a.next_deadline(), Some(40_300));
    }

    #[test]
    fn a_panel_that_cannot_fade_drops_in_one_step() {
        let config = AttentionConfig {
            dim_ramp: Duration::ZERO,
            ..AttentionConfig::EMISSIVE
        };
        let mut a = Attention::new(DisplayKind::Emissive, config, 0);
        assert_eq!(a.poll(20_000), Some(Transition::Dimming));
        assert_eq!(a.brightness_permille(), 0);
        assert_eq!(a.next_deadline(), Some(30_000));
        assert_eq!(a.poll(25_000), None);
    }

    #[test]
    fn no_deadline_ever_overshoots_the_lapse() {
        // A ramp longer than the margin it has to fit inside.
        let config = AttentionConfig {
            timeout: Duration::from_secs(10),
            dim_margin: Duration::from_secs(1),
            dim_ramp: Duration::from_secs(5),
        };
        let mut a = Attention::new(DisplayKind::Emissive, config, 0);
        while let Some(deadline) = a.next_deadline() {
            assert!(deadline <= 10_000, "{deadline} is past the lapse");
            if a.poll(deadline) == Some(Transition::Lapsed) {
                break;
            }
        }
        assert!(a.is_lapsed());
    }

    #[test]
    fn lapse_fires_once() {
        let mut a = oled();
        a.poll(20_000);
        assert_eq!(a.poll(30_000), Some(Transition::Lapsed));
        assert_eq!(a.poll(40_000), None);
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
        a.poll(20_000);
        // Dimmed is still visible.
        assert!(a.accepts_redraw());
        a.poll(30_000);
        assert!(!a.accepts_redraw());
    }

    #[test]
    fn wake_from_lapsed_reports_the_transition() {
        let mut a = oled();
        a.poll(30_000);
        assert_eq!(a.wake(32_000), Some(Transition::Woke));
        assert_eq!(a.state(), DisplayState::Active);
        // Full timeout again, measured from the wake.
        assert_eq!(a.next_deadline(), Some(52_000));
    }

    #[test]
    fn wake_from_dim_restores_full_brightness() {
        let mut a = oled();
        a.poll(20_000);
        assert_eq!(a.state(), DisplayState::Dim);
        assert_eq!(a.wake(21_000), Some(Transition::Woke));
        assert_eq!(a.state(), DisplayState::Active);
        assert_eq!(a.brightness_permille(), 1_000);
    }

    #[test]
    fn wake_while_active_only_defers_the_deadline() {
        let mut a = oled();
        assert_eq!(a.wake(5_000), None);
        assert_eq!(a.next_deadline(), Some(25_000));
        assert_eq!(a.poll(20_000), None);
    }

    #[test]
    fn a_hold_pins_the_display_awake() {
        let mut a = oled();
        let _ = a.set_hold(HoldReason::Pairing, true, 1_000);
        assert_eq!(a.next_deadline(), None);
        assert_eq!(a.poll(60_000), None);
        assert_eq!(a.state(), DisplayState::Active);
    }

    #[test]
    fn asserting_a_hold_wakes_a_lapsed_panel() {
        let mut a = oled();
        a.poll(30_000);
        assert!(a.is_lapsed());
        assert_eq!(
            a.set_hold(HoldReason::Alert, true, 31_000),
            Some(Transition::Woke)
        );
        assert_eq!(a.state(), DisplayState::Active);
    }

    #[test]
    fn releasing_the_last_hold_restarts_the_full_timeout() {
        let mut a = oled();
        let _ = a.set_hold(HoldReason::Pairing, true, 1_000);
        assert_eq!(a.set_hold(HoldReason::Pairing, false, 60_000), None);
        assert_eq!(a.next_deadline(), Some(80_000));
        assert_eq!(a.poll(79_000), None);
        assert_eq!(a.poll(80_000), Some(Transition::Dimming));
    }

    #[test]
    fn overlapping_holds_release_independently() {
        let mut a = oled();
        let _ = a.set_hold(HoldReason::Pairing, true, 1_000);
        let _ = a.set_hold(HoldReason::Alert, true, 2_000);
        let _ = a.set_hold(HoldReason::Pairing, false, 3_000);
        assert!(a.held());
        assert_eq!(a.poll(60_000), None);
        let _ = a.set_hold(HoldReason::Alert, false, 4_000);
        assert!(!a.held());
        assert_eq!(a.next_deadline(), Some(24_000));
    }

    #[test]
    fn redundant_hold_changes_do_not_move_the_clock() {
        let mut a = oled();
        let _ = a.set_hold(HoldReason::Pairing, true, 1_000);
        let _ = a.set_hold(HoldReason::Pairing, true, 5_000);
        let _ = a.set_hold(HoldReason::Pairing, false, 6_000);
        // Timer restarts from the real release, not the duplicate assert.
        assert_eq!(a.next_deadline(), Some(26_000));
    }

    #[test]
    fn releasing_a_hold_that_was_never_held_is_inert() {
        let mut a = oled();
        assert_eq!(a.set_hold(HoldReason::Maintenance, false, 5_000), None);
        assert_eq!(a.next_deadline(), Some(20_000));
    }

    #[test]
    fn zero_dim_margin_lapses_without_a_dim_state() {
        let config = AttentionConfig {
            timeout: Duration::from_secs(10),
            dim_margin: Duration::ZERO,
            ..AttentionConfig::EMISSIVE
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
            ..AttentionConfig::EMISSIVE
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
            ..AttentionConfig::EMISSIVE
        });
        assert_eq!(a.next_deadline(), Some(5_000));
        assert_eq!(a.poll(5_000), Some(Transition::Lapsed));
    }

    #[test]
    fn a_timeout_already_exceeded_lapses_at_the_next_poll() {
        let mut a = oled();
        let _ = a.wake(100_000);
        a.set_config(AttentionConfig {
            timeout: Duration::from_secs(1),
            dim_margin: Duration::ZERO,
            ..AttentionConfig::EMISSIVE
        });
        assert_eq!(a.poll(101_500), Some(Transition::Lapsed));
    }
}
