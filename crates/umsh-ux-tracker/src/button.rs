//! Button event recognition state machine.
//!
//! Resolves a stream of raw [`ButtonEdge`] events plus a monotonic
//! millisecond clock into the high-level [`ButtonEvent`]s the UX is
//! defined in terms of: single, double, triple, and quadruple clicks,
//! plus long-press and an optional very-long-press.
//!
//! The machine is **pure logic** — no embassy, no hardware, no I/O — so
//! it can be exhaustively unit-tested with synthetic time. Callers are
//! expected to:
//!
//! 1. Call [`ButtonFsm::on_edge`] for each debounced press / release.
//! 2. Call [`ButtonFsm::poll`] when the deadline reported by
//!    [`ButtonFsm::next_deadline`] elapses.
//!
//! Both methods can produce a [`ButtonEvent`] when one becomes
//! resolvable.
//!
//! # Recognition rules
//!
//! - A "click" is a press-then-release where the hold duration is at
//!   most `max_click_hold`.
//! - One to four clicks within `inter_click_gap` of each other produce
//!   [`ButtonEvent::Single`], [`ButtonEvent::Double`],
//!   [`ButtonEvent::Triple`], or [`ButtonEvent::Quad`] respectively.
//!   Quad fires immediately on the fourth release without waiting for
//!   the gap; single / double / triple fire after the gap elapses with
//!   no further press.
//! - By default, holding the button continuously for `long_press` produces
//!   [`ButtonEvent::Long`] *while the button is still pressed* and consumes
//!   any clicks accumulated before the hold began.
//! - When `very_long_press` is configured, releasing between `long_press`
//!   and `very_long_press` produces [`ButtonEvent::Long`]. Remaining held
//!   through `very_long_press` produces [`ButtonEvent::VeryLong`] without
//!   first emitting `Long`. This supports a navigational hold plus a distinct
//!   always-available sleep hold.
//! - Releases longer than `max_click_hold` but shorter than
//!   `long_press` are *discarded clicks*; if there are accumulated
//!   prior clicks they are emitted, otherwise nothing fires. This
//!   matches the rule: a press that's "too long to be a click but too
//!   short to be a long-press" is a user error and should not silently
//!   become either.

use core::time::Duration;

/// Raw debounced button transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonEdge {
    /// Button transitioned from released to pressed.
    Press,
    /// Button transitioned from pressed to released.
    Release,
}

/// High-level button event recognized by the FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonEvent {
    Single,
    Double,
    Triple,
    Quad,
    Long,
    VeryLong,
}

/// Tunable timings. Defaults match the values in
/// `docs/firmware-plan-t1000e.md`; tune on real hardware.
#[derive(Debug, Clone, Copy)]
pub struct ButtonTimings {
    /// Longest hold that still counts as a click (rather than a discard
    /// or a long-press).
    pub max_click_hold: Duration,
    /// Maximum gap from a release to the next press to count as part of
    /// the same click sequence.
    pub inter_click_gap: Duration,
    /// Continuous hold duration that triggers [`ButtonEvent::Long`].
    pub long_press: Duration,
    /// Optional second hold threshold. When present, `Long` is emitted on
    /// release after `long_press`, while [`ButtonEvent::VeryLong`] fires at
    /// this deadline while the button remains held.
    pub very_long_press: Option<Duration>,
}

impl Default for ButtonTimings {
    fn default() -> Self {
        Self {
            max_click_hold: Duration::from_millis(500),
            inter_click_gap: Duration::from_millis(400),
            long_press: Duration::from_secs(3),
            very_long_press: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No press in progress, no pending click sequence.
    Idle,
    /// Button currently held. `pressed_at` is the press timestamp,
    /// `prior_clicks` is the count of completed clicks before this press.
    Pressed { pressed_at: u64, prior_clicks: u8 },
    /// Button released after a valid click, waiting to see whether the
    /// next press arrives within `inter_click_gap`.
    WaitingForNext { released_at: u64, clicks: u8 },
    /// Long-press has already fired; suppress everything until release.
    LongFired,
}

/// Button event recognition state machine.
#[derive(Debug)]
pub struct ButtonFsm {
    timings: ButtonTimings,
    state: State,
}

impl ButtonFsm {
    pub fn new(timings: ButtonTimings) -> Self {
        Self {
            timings,
            state: State::Idle,
        }
    }

    /// Feed a debounced edge. Returns an event if one is resolvable
    /// purely from the edge (without waiting for a timeout).
    pub fn on_edge(&mut self, edge: ButtonEdge, now_ms: u64) -> Option<ButtonEvent> {
        match (self.state, edge) {
            // First press of a new sequence.
            (State::Idle, ButtonEdge::Press) => {
                self.state = State::Pressed {
                    pressed_at: now_ms,
                    prior_clicks: 0,
                };
                None
            }

            // Subsequent press in an in-progress click chord.
            (State::WaitingForNext { clicks, .. }, ButtonEdge::Press) => {
                self.state = State::Pressed {
                    pressed_at: now_ms,
                    prior_clicks: clicks,
                };
                None
            }

            // Release after a press: classify the hold duration.
            (
                State::Pressed {
                    pressed_at,
                    prior_clicks,
                },
                ButtonEdge::Release,
            ) => self.classify_release(pressed_at, prior_clicks, now_ms),

            // Release after long-press: reset.
            (State::LongFired, ButtonEdge::Release) => {
                self.state = State::Idle;
                None
            }

            // Glitchy duplicate edges — ignore.
            (State::Pressed { .. }, ButtonEdge::Press) => None,
            (State::WaitingForNext { .. }, ButtonEdge::Release) => None,
            (State::Idle, ButtonEdge::Release) => None,
            (State::LongFired, ButtonEdge::Press) => None,
        }
    }

    /// Advance time without an edge. Returns an event if a timeout
    /// resolves one (long-press while held, or single/double after the
    /// inter-click gap).
    pub fn poll(&mut self, now_ms: u64) -> Option<ButtonEvent> {
        match self.state {
            State::Pressed { pressed_at, .. }
                if elapsed(pressed_at, now_ms)
                    >= self
                        .timings
                        .very_long_press
                        .unwrap_or(self.timings.long_press) =>
            {
                self.state = State::LongFired;
                Some(if self.timings.very_long_press.is_some() {
                    ButtonEvent::VeryLong
                } else {
                    ButtonEvent::Long
                })
            }

            State::WaitingForNext {
                released_at,
                clicks,
            } if elapsed(released_at, now_ms) >= self.timings.inter_click_gap => {
                self.state = State::Idle;
                click_count_to_event(clicks)
            }

            _ => None,
        }
    }

    /// Returns the absolute monotonic-millisecond deadline at which
    /// [`poll`](Self::poll) should next be called, if any.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.state {
            State::Pressed { pressed_at, .. } => {
                let deadline = self
                    .timings
                    .very_long_press
                    .unwrap_or(self.timings.long_press);
                Some(pressed_at + deadline.as_millis() as u64)
            }
            State::WaitingForNext { released_at, .. } => {
                Some(released_at + self.timings.inter_click_gap.as_millis() as u64)
            }
            State::Idle | State::LongFired => None,
        }
    }

    fn classify_release(
        &mut self,
        pressed_at: u64,
        prior_clicks: u8,
        now_ms: u64,
    ) -> Option<ButtonEvent> {
        let hold = elapsed(pressed_at, now_ms);

        if let Some(very_long) = self.timings.very_long_press {
            if hold >= very_long {
                // The deadline should normally fire from poll. Preserve the
                // event if the caller only observes the eventual release.
                self.state = State::Idle;
                return Some(ButtonEvent::VeryLong);
            }
            if hold >= self.timings.long_press {
                self.state = State::Idle;
                return Some(ButtonEvent::Long);
            }
        }

        if self.timings.very_long_press.is_none() && hold >= self.timings.long_press {
            // Long-press should have already fired in poll; on the off
            // chance it didn't (e.g. poll wasn't called), fire it now.
            self.state = State::Idle;
            return Some(ButtonEvent::Long);
        }

        if hold > self.timings.max_click_hold {
            // Held too long for a click, too short for a long-press.
            // Emit any accumulated prior clicks and reset.
            self.state = State::Idle;
            return click_count_to_event(prior_clicks);
        }

        // Valid click.
        let clicks = prior_clicks.saturating_add(1);
        if clicks >= 4 {
            self.state = State::Idle;
            return Some(ButtonEvent::Quad);
        }
        self.state = State::WaitingForNext {
            released_at: now_ms,
            clicks,
        };
        None
    }
}

fn elapsed(since_ms: u64, now_ms: u64) -> Duration {
    Duration::from_millis(now_ms.saturating_sub(since_ms))
}

fn click_count_to_event(clicks: u8) -> Option<ButtonEvent> {
    match clicks {
        1 => Some(ButtonEvent::Single),
        2 => Some(ButtonEvent::Double),
        3 => Some(ButtonEvent::Triple),
        4 => Some(ButtonEvent::Quad),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FSM with fixed test timings (500 ms click, 400 ms gap, 5 s long).
    ///
    /// Deliberately *not* `ButtonTimings::default()`: the assertions below
    /// hardcode thresholds derived from these numbers, and the product
    /// defaults are tuning knobs that have changed before (long-press
    /// 5 s → 3 s in commit 65d8d4e6, which silently broke this module's
    /// tests). Pinning the timings keeps the tests about the FSM's
    /// *logic*, not the current tuning.
    fn fsm() -> ButtonFsm {
        ButtonFsm::new(ButtonTimings {
            max_click_hold: Duration::from_millis(500),
            inter_click_gap: Duration::from_millis(400),
            long_press: Duration::from_secs(5),
            very_long_press: None,
        })
    }

    /// Simulate a press at `down_ms` and release at `up_ms` with no
    /// intervening polls. Returns the edge events plus the result of a
    /// final `poll` at `up_ms + 500ms` (which is past the inter-click
    /// gap, so any pending single/double/triple should fire).
    fn click(
        fsm: &mut ButtonFsm,
        down_ms: u64,
        up_ms: u64,
    ) -> (Option<ButtonEvent>, Option<ButtonEvent>) {
        let on_press = fsm.on_edge(ButtonEdge::Press, down_ms);
        let on_release = fsm.on_edge(ButtonEdge::Release, up_ms);
        (on_press, on_release)
    }

    #[test]
    fn idle_release_is_ignored() {
        let mut fsm = fsm();
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 0), None);
    }

    #[test]
    fn single_click_fires_after_gap() {
        let mut fsm = fsm();
        let (p, r) = click(&mut fsm, 0, 100);
        assert_eq!(p, None);
        assert_eq!(r, None);

        // Before the gap, nothing.
        assert_eq!(fsm.poll(300), None);

        // After the gap, single fires.
        assert_eq!(fsm.poll(600), Some(ButtonEvent::Single));
        assert_eq!(fsm.poll(700), None);
    }

    #[test]
    fn double_click_fires_after_gap() {
        let mut fsm = fsm();
        click(&mut fsm, 0, 100);
        click(&mut fsm, 200, 300);

        assert_eq!(fsm.poll(400), None);
        assert_eq!(fsm.poll(800), Some(ButtonEvent::Double));
    }

    #[test]
    fn triple_click_fires_after_gap() {
        // Since Quad was added, a triple no longer fires immediately on
        // the third release — the FSM must wait out the inter-click gap
        // in case a fourth click arrives.
        let mut fsm = fsm();
        click(&mut fsm, 0, 100);
        click(&mut fsm, 200, 300);
        let (_, third_release) = click(&mut fsm, 400, 500);
        assert_eq!(third_release, None);

        // Before the gap, nothing.
        assert_eq!(fsm.poll(700), None);

        // After the gap, triple fires.
        assert_eq!(fsm.poll(900), Some(ButtonEvent::Triple));
        assert_eq!(fsm.poll(1_000), None);
    }

    #[test]
    fn long_press_fires_while_held() {
        let mut fsm = fsm();
        assert_eq!(fsm.on_edge(ButtonEdge::Press, 0), None);

        // Before the threshold, nothing.
        assert_eq!(fsm.poll(4_999), None);

        // At the threshold, long fires.
        assert_eq!(fsm.poll(5_000), Some(ButtonEvent::Long));

        // Subsequent polls while still held don't re-fire.
        assert_eq!(fsm.poll(6_000), None);

        // Eventual release returns to idle without producing anything.
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 7_000), None);
        assert_eq!(fsm.poll(8_000), None);
    }

    #[test]
    fn long_press_consumes_prior_clicks() {
        let mut fsm = fsm();
        click(&mut fsm, 0, 100); // accumulate one click
        assert_eq!(fsm.on_edge(ButtonEdge::Press, 200), None);

        // Hold for 5 seconds → Long, prior click is lost.
        assert_eq!(fsm.poll(5_200), Some(ButtonEvent::Long));
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 5_300), None);
    }

    #[test]
    fn long_press_fires_on_release_if_poll_was_missed() {
        let mut fsm = fsm();
        fsm.on_edge(ButtonEdge::Press, 0);
        // No poll. Release after the long-press threshold.
        assert_eq!(
            fsm.on_edge(ButtonEdge::Release, 6_000),
            Some(ButtonEvent::Long)
        );
    }

    #[test]
    fn two_stage_hold_emits_long_on_release_without_firing_early() {
        let mut fsm = ButtonFsm::new(ButtonTimings {
            max_click_hold: Duration::from_millis(500),
            inter_click_gap: Duration::from_millis(400),
            long_press: Duration::from_secs(1),
            very_long_press: Some(Duration::from_secs(4)),
        });
        fsm.on_edge(ButtonEdge::Press, 0);

        // Crossing the navigation-hold threshold while still pressed does
        // not emit anything; the user can continue holding for sleep.
        assert_eq!(fsm.poll(1_000), None);
        assert_eq!(fsm.poll(2_500), None);
        assert_eq!(
            fsm.on_edge(ButtonEdge::Release, 2_500),
            Some(ButtonEvent::Long)
        );
    }

    #[test]
    fn two_stage_hold_emits_only_very_long_at_second_deadline() {
        let mut fsm = ButtonFsm::new(ButtonTimings {
            max_click_hold: Duration::from_millis(500),
            inter_click_gap: Duration::from_millis(400),
            long_press: Duration::from_secs(1),
            very_long_press: Some(Duration::from_secs(4)),
        });
        fsm.on_edge(ButtonEdge::Press, 0);

        assert_eq!(fsm.next_deadline(), Some(4_000));
        assert_eq!(fsm.poll(3_999), None);
        assert_eq!(fsm.poll(4_000), Some(ButtonEvent::VeryLong));
        assert_eq!(fsm.poll(5_000), None);
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 5_100), None);
    }

    #[test]
    fn two_stage_very_long_survives_a_missed_poll() {
        let mut fsm = ButtonFsm::new(ButtonTimings {
            max_click_hold: Duration::from_millis(500),
            inter_click_gap: Duration::from_millis(400),
            long_press: Duration::from_secs(1),
            very_long_press: Some(Duration::from_secs(4)),
        });
        fsm.on_edge(ButtonEdge::Press, 0);
        assert_eq!(
            fsm.on_edge(ButtonEdge::Release, 4_500),
            Some(ButtonEvent::VeryLong)
        );
    }

    #[test]
    fn hold_between_click_and_long_press_discards_click_with_no_priors() {
        let mut fsm = fsm();
        // Held 1 s — too long for a click, too short for long-press.
        fsm.on_edge(ButtonEdge::Press, 0);
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 1_000), None);
        assert_eq!(fsm.poll(2_000), None);
    }

    #[test]
    fn hold_between_click_and_long_press_emits_prior_clicks() {
        let mut fsm = fsm();
        // One valid click.
        click(&mut fsm, 0, 100);
        // Then a too-long second press: prior single should fire, second discarded.
        fsm.on_edge(ButtonEdge::Press, 200);
        let release = fsm.on_edge(ButtonEdge::Release, 1_500);
        assert_eq!(release, Some(ButtonEvent::Single));
    }

    #[test]
    fn next_deadline_tracks_long_press_while_held() {
        let mut fsm = fsm();
        fsm.on_edge(ButtonEdge::Press, 1_000);
        assert_eq!(fsm.next_deadline(), Some(6_000)); // 1_000 + 5_000
    }

    #[test]
    fn next_deadline_tracks_gap_while_waiting() {
        let mut fsm = fsm();
        click(&mut fsm, 0, 100);
        assert_eq!(fsm.next_deadline(), Some(500)); // released_at=100 + gap=400
    }

    #[test]
    fn next_deadline_is_none_when_idle() {
        let fsm = fsm();
        assert_eq!(fsm.next_deadline(), None);
    }

    #[test]
    fn duplicate_press_edges_are_ignored() {
        let mut fsm = fsm();
        assert_eq!(fsm.on_edge(ButtonEdge::Press, 0), None);
        assert_eq!(fsm.on_edge(ButtonEdge::Press, 50), None);
        // Release normally; should still register as a single click.
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 100), None);
        assert_eq!(fsm.poll(600), Some(ButtonEvent::Single));
    }

    #[test]
    fn glitch_release_in_idle_is_ignored() {
        let mut fsm = fsm();
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 0), None);
        assert_eq!(fsm.poll(1_000), None);
    }

    #[test]
    fn four_quick_clicks_resolve_as_quad_immediately() {
        // Quad is the highest click count, so it fires immediately on the
        // fourth release without waiting for the inter-click gap.
        let mut fsm = fsm();
        click(&mut fsm, 0, 50);
        click(&mut fsm, 100, 150);
        let (_, third) = click(&mut fsm, 200, 250);
        assert_eq!(third, None);
        let (_, quad) = click(&mut fsm, 300, 350);
        assert_eq!(quad, Some(ButtonEvent::Quad));

        // The sequence is consumed: nothing further fires.
        assert_eq!(fsm.poll(800), None);
        assert_eq!(fsm.next_deadline(), None);
    }
}
