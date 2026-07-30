//! Input gating: when a button gesture means something other than what
//! it would normally mean.
//!
//! Three conditions make a gesture unsafe to act on literally:
//!
//! - [`GateReason::ScreenOff`] — the user cannot see what they would be
//!   acting on, so the press only brings the display back.
//! - [`GateReason::AlertActive`] — a locate alert is running, and
//!   whoever just found the device meant to silence it, not to navigate
//!   its menus.
//! - [`GateReason::Refreshing`] — a persistent panel is mid-refresh, so
//!   the visible selection and the acted-on selection could differ.
//!
//! One gesture always passes through regardless:
//! [`ButtonEvent::VeryLong`], the power-off hold. It is deliberate
//! enough to mean it, it is the documented escape from every state, and
//! requiring a lit screen first would make a dark unresponsive device
//! impossible to turn off.
//!
//! # Latching
//!
//! The decision is latched at the **press** that starts a gesture, not
//! at the event that ends it. A double-click begun against a dark panel
//! resolves several hundred milliseconds later, by which time the panel
//! is lit again; without the latch it would both wake the display and
//! select something. Feed [`Gate::on_press`] on each press edge and
//! [`Gate::settle`] once the recognizer comes to rest, and the whole
//! chord is judged by the conditions that held when it began.

use umsh_ux_tracker::button::ButtonEvent;

/// A condition that changes what a gesture means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateReason {
    /// An emissive panel has been powered off.
    ScreenOff,
    /// A locate alert is running.
    AlertActive,
    /// A persistent panel has not finished drawing.
    Refreshing,
}

impl GateReason {
    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// What to do with a resolved gesture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Hand it to the menu.
    Deliver,
    /// Swallow it: the gesture began against a dark panel and has
    /// already done its job by waking it.
    ConsumedByWake,
    /// Swallow it and cancel the running locate alert instead.
    CancelAlert,
    /// Swallow it: the panel could not show what was being acted on.
    Discard,
}

/// Input gate.
///
/// Pure logic, no clock: the conditions are set by whoever owns them and
/// the latch is driven by the button recognizer's edges.
#[derive(Clone, Copy, Debug, Default)]
pub struct Gate {
    current: u8,
    latched: Option<u8>,
}

impl Gate {
    pub const fn new() -> Self {
        Self {
            current: 0,
            latched: None,
        }
    }

    /// Assert or release a condition.
    pub fn set(&mut self, reason: GateReason, active: bool) {
        if active {
            self.current |= reason.bit();
        } else {
            self.current &= !reason.bit();
        }
    }

    pub fn is_set(&self, reason: GateReason) -> bool {
        self.current & reason.bit() != 0
    }

    /// Whether any condition currently gates input.
    pub fn is_gating(&self) -> bool {
        self.current != 0
    }

    /// Latch the current conditions at the start of a gesture.
    ///
    /// Call on every debounced press edge; presses that continue an
    /// in-progress chord are ignored, so the first one decides.
    pub fn on_press(&mut self) {
        if self.latched.is_none() {
            self.latched = Some(self.current);
        }
    }

    /// Release the latch once the recognizer is at rest.
    ///
    /// Pass `umsh_ux_tracker::button::ButtonFsm::next_deadline().is_none()`.
    /// This covers gestures that end without producing an event — a hold
    /// too long to be a click and too short to be a long-press — which
    /// would otherwise strand the latch and swallow the *next* gesture.
    pub fn settle(&mut self, resting: bool) {
        if resting {
            self.latched = None;
        }
    }

    /// Decide what a resolved gesture means.
    ///
    /// Judged against the latched conditions when a gesture is in
    /// progress, and against the live ones otherwise.
    pub fn disposition(&self, event: ButtonEvent) -> Disposition {
        if matches!(event, ButtonEvent::VeryLong) {
            return Disposition::Deliver;
        }
        let reasons = self.latched.unwrap_or(self.current);
        if reasons & GateReason::AlertActive.bit() != 0 {
            Disposition::CancelAlert
        } else if reasons & GateReason::ScreenOff.bit() != 0 {
            Disposition::ConsumedByWake
        } else if reasons & GateReason::Refreshing.bit() != 0 {
            Disposition::Discard
        } else {
            Disposition::Deliver
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ungated_gesture_is_delivered() {
        let mut g = Gate::new();
        g.on_press();
        assert_eq!(g.disposition(ButtonEvent::Single), Disposition::Deliver);
        assert!(!g.is_gating());
    }

    #[test]
    fn a_gesture_begun_against_a_dark_panel_only_wakes_it() {
        let mut g = Gate::new();
        g.set(GateReason::ScreenOff, true);
        g.on_press();
        assert_eq!(
            g.disposition(ButtonEvent::Single),
            Disposition::ConsumedByWake
        );
    }

    #[test]
    fn the_whole_chord_is_judged_by_its_first_press() {
        let mut g = Gate::new();
        g.set(GateReason::ScreenOff, true);
        g.on_press();
        // The press woke the panel, so the condition clears mid-gesture.
        g.set(GateReason::ScreenOff, false);
        g.on_press(); // second press of a double-click
        assert_eq!(
            g.disposition(ButtonEvent::Double),
            Disposition::ConsumedByWake
        );
    }

    #[test]
    fn the_next_gesture_is_judged_afresh() {
        let mut g = Gate::new();
        g.set(GateReason::ScreenOff, true);
        g.on_press();
        assert_eq!(
            g.disposition(ButtonEvent::Single),
            Disposition::ConsumedByWake
        );
        g.set(GateReason::ScreenOff, false);
        g.settle(true);

        g.on_press();
        assert_eq!(g.disposition(ButtonEvent::Single), Disposition::Deliver);
    }

    #[test]
    fn a_gesture_that_resolves_to_nothing_does_not_strand_the_latch() {
        let mut g = Gate::new();
        g.set(GateReason::ScreenOff, true);
        g.on_press();
        // Held too long for a click, too short for a long-press: the
        // recognizer returns to rest without emitting anything.
        g.set(GateReason::ScreenOff, false);
        g.settle(true);

        g.on_press();
        assert_eq!(g.disposition(ButtonEvent::Single), Disposition::Deliver);
    }

    #[test]
    fn settle_while_a_chord_is_pending_keeps_the_latch() {
        let mut g = Gate::new();
        g.set(GateReason::ScreenOff, true);
        g.on_press();
        g.set(GateReason::ScreenOff, false);
        // Recognizer still waiting for a possible second click.
        g.settle(false);
        assert_eq!(
            g.disposition(ButtonEvent::Double),
            Disposition::ConsumedByWake
        );
    }

    #[test]
    fn an_alert_turns_every_gesture_into_a_cancel() {
        let mut g = Gate::new();
        g.set(GateReason::AlertActive, true);
        g.on_press();
        for event in [
            ButtonEvent::Single,
            ButtonEvent::Double,
            ButtonEvent::Triple,
            ButtonEvent::Quad,
            ButtonEvent::Long,
        ] {
            assert_eq!(g.disposition(event), Disposition::CancelAlert);
        }
    }

    #[test]
    fn power_off_always_passes_through() {
        let mut g = Gate::new();
        for reason in [
            GateReason::ScreenOff,
            GateReason::AlertActive,
            GateReason::Refreshing,
        ] {
            g.set(reason, true);
        }
        g.on_press();
        assert_eq!(g.disposition(ButtonEvent::VeryLong), Disposition::Deliver);
    }

    #[test]
    fn a_refreshing_panel_discards_input() {
        let mut g = Gate::new();
        g.set(GateReason::Refreshing, true);
        g.on_press();
        assert_eq!(g.disposition(ButtonEvent::Single), Disposition::Discard);
    }

    #[test]
    fn cancelling_an_alert_outranks_a_dark_panel() {
        let mut g = Gate::new();
        g.set(GateReason::ScreenOff, true);
        g.set(GateReason::AlertActive, true);
        g.on_press();
        assert_eq!(g.disposition(ButtonEvent::Single), Disposition::CancelAlert);
    }

    #[test]
    fn an_unlatched_gesture_falls_back_to_live_conditions() {
        let mut g = Gate::new();
        g.set(GateReason::AlertActive, true);
        assert_eq!(g.disposition(ButtonEvent::Single), Disposition::CancelAlert);
    }
}
