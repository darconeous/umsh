#![no_std]

//! UX mechanism for display-tracker-class UMSH boards.
//!
//! This crate is the user-experience layer for boards whose physical UX
//! is a small display plus a button — optionally with a D-pad — and no
//! keyboard: T-Echo, Heltec LoRa32 V3, Wio Tracker L1, T-Beam Supreme.
//! They differ in panel technology and input richness, but a user who
//! learns one should already know the others, so the interaction model
//! lives here rather than in each firmware.
//!
//! Like [`umsh_ux_tracker`], this crate provides only **mechanism**:
//!
//! - [`menu`] — the on-screen menu: a wrapping item list narrowed
//!   per-board, with confirmation in front of the destructive entries.
//! - [`attention`] — when to stop assuming the user is looking, and what
//!   that means for an emissive panel (power it off) versus a persistent
//!   one (send the menu home).
//! - [`gate`] — what a gesture means when the screen is dark, an alert
//!   is running, or the panel is mid-refresh.
//! - [`screen`] — what a frame looks like: the rows, what they say, and
//!   the battery indicator every frame carries. Behind the `screen`
//!   feature, since two boards in this family have no panel.
//!
//! Button gestures themselves come from
//! [`umsh_ux_tracker::button::ButtonFsm`]; this crate adds only the
//! shared timing policy, [`button_timings`]. Policy that depends on the
//! board — which effects the menu items map to, what shutting down
//! entails — belongs in the firmware.
//!
//! Rendering used to belong there too, on the theory that a 128×64 OLED
//! and a 200×200 e-paper have too little in common to share a layout.
//! They have more in common than they have pixels: [`screen`] takes a
//! per-board [`screen::Layout`] and draws the rest once, so the class
//! agrees on what a status page is rather than on how tall it is.
//!
//! See `docs/ux/` for the user-facing rules these modules encode and
//! `docs/firmware-architecture.md` for the BSP / UX / App / Binary
//! layering.

pub mod attention;
pub mod gate;
pub mod menu;
#[cfg(feature = "screen")]
pub mod screen;

use core::time::Duration;
use umsh_ux_tracker::button::ButtonTimings;

/// The gesture timing shared by every display tracker.
///
/// One set of numbers across the class is the point: the same hold
/// powers off a T-Echo and a Heltec V3, and muscle memory carries.
///
/// A click is at most 500 ms; a chord continues while presses are within
/// 400 ms of each other. Holding for 1 s and releasing is Back; holding
/// through 4 s powers off without waiting for the release, so the
/// gesture confirms itself while the user is still committing to it.
pub fn button_timings() -> ButtonTimings {
    ButtonTimings {
        max_click_hold: Duration::from_millis(500),
        inter_click_gap: Duration::from_millis(400),
        long_press: Duration::from_secs(1),
        very_long_press: Some(Duration::from_secs(4)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm};

    /// The class vocabulary, end to end through the real recognizer:
    /// single = Forward, double = Select, 1 s hold-release = Back,
    /// 4 s hold = power off.
    #[test]
    fn the_shared_timings_recognize_the_class_vocabulary() {
        let t = button_timings();

        let mut fsm = ButtonFsm::new(t);
        fsm.on_edge(ButtonEdge::Press, 0);
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 100), None);
        assert_eq!(fsm.poll(500), Some(ButtonEvent::Single));

        let mut fsm = ButtonFsm::new(t);
        fsm.on_edge(ButtonEdge::Press, 0);
        fsm.on_edge(ButtonEdge::Release, 100);
        fsm.on_edge(ButtonEdge::Press, 300);
        assert_eq!(fsm.on_edge(ButtonEdge::Release, 400), None);
        assert_eq!(fsm.poll(800), Some(ButtonEvent::Double));

        let mut fsm = ButtonFsm::new(t);
        fsm.on_edge(ButtonEdge::Press, 0);
        assert_eq!(
            fsm.on_edge(ButtonEdge::Release, 1_500),
            Some(ButtonEvent::Long)
        );

        let mut fsm = ButtonFsm::new(t);
        fsm.on_edge(ButtonEdge::Press, 0);
        // Fires while still held, before any release.
        assert_eq!(fsm.poll(4_000), Some(ButtonEvent::VeryLong));
    }

    /// A hold released between Back and power-off must not power off.
    #[test]
    fn releasing_before_the_power_off_threshold_is_only_back() {
        let mut fsm = ButtonFsm::new(button_timings());
        fsm.on_edge(ButtonEdge::Press, 0);
        assert_eq!(fsm.poll(3_999), None);
        assert_eq!(
            fsm.on_edge(ButtonEdge::Release, 3_999),
            Some(ButtonEvent::Long)
        );
    }
}
