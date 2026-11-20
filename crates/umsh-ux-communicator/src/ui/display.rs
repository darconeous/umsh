//! Display: the screen's brightness, which pressing lets turning change
//! until it is pressed again, Auto-Lock, with its choices, and the gamma
//! chart.

use buoyant::match_view;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::setting::{End, level_row, marked_row, page, row};
use crate::board::Metrics;
use crate::model::{AUTO_LOCK_CHOICES, State, brightness_level};
use crate::nav::{DevicePage, keys};

const ROW: u32 = 36;

/// What Auto-Lock's choices are called, in the order they are listed.
const NAMES: [&str; AUTO_LOCK_CHOICES.len()] =
    ["Never", "30 seconds", "1 minute", "2 minutes", "5 minutes"];

/// Display, or a screen it opens.
pub fn screen(state: &State, page: &DevicePage) -> impl View<Rgb565, State> + use<> {
    match_view!(page, {
        DevicePage::AutoLock => auto_lock(state),
        DevicePage::Gamma { test } => super::gamma::view(state, *test),
        _ => view(state),
    })
}

/// Brightness, Auto-Lock, and Gamma.
fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let level = brightness_level(state.node.brightness());
    let active = state.adjusting_brightness();
    let auto_lock = auto_lock_name(state.node.auto_lock());
    page(
        m,
        "Display",
        VStack::new((
            level_row(
                m,
                "Brightness",
                keys::BRIGHTNESS,
                State::press_brightness,
                level,
                active,
                |s, steps| _ = s.step_brightness(steps),
                State::set_brightness_level,
                ROW,
            ),
            row(
                m,
                "Auto-Lock",
                keys::AUTO_LOCK,
                State::open_auto_lock,
                End::value_chevron(&auto_lock),
                false,
                ROW,
            ),
            row(
                m,
                "Gamma",
                keys::GAMMA,
                State::open_gamma,
                End::Chevron,
                false,
                ROW,
            ),
        ))
        .with_spacing(0),
    )
}

/// Auto-Lock's choices, the one in force checked. Pressing one sets it.
fn auto_lock(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let current = state.node.auto_lock();
    page(
        m,
        "Auto-Lock",
        VStack::new((
            choice(m, 0, current),
            choice(m, 1, current),
            choice(m, 2, current),
            choice(m, 3, current),
            choice(m, 4, current),
        ))
        .with_spacing(0),
    )
}

/// The choice at `index`, checked when it is `current`.
fn choice(m: &'static Metrics, index: usize, current: u16) -> impl View<Rgb565, State> + use<> {
    let seconds = AUTO_LOCK_CHOICES[index];
    marked_row(
        m,
        NAMES[index],
        keys::auto_lock_choice(index),
        move |s: &mut State| s.choose_auto_lock(seconds),
        End::Nothing,
        false,
        ROW,
        Some(current == seconds),
    )
}

/// What Auto-Lock at `seconds` is called: as its choice is, or in whole
/// minutes or seconds when it is none of them.
fn auto_lock_name(seconds: u16) -> String<16> {
    let mut name = String::new();
    if let Some(index) = AUTO_LOCK_CHOICES.iter().position(|&c| c == seconds) {
        _ = name.push_str(NAMES[index]);
    } else if seconds.is_multiple_of(60) {
        _ = core::fmt::write(&mut name, format_args!("{} minutes", seconds / 60));
    } else {
        _ = core::fmt::write(&mut name, format_args!("{seconds} seconds"));
    }
    name
}

#[cfg(test)]
mod tests {
    use super::auto_lock_name;

    #[test]
    fn auto_lock_is_named_as_its_choice_or_in_whole_units() {
        assert_eq!(auto_lock_name(0), "Never");
        assert_eq!(auto_lock_name(60), "1 minute");
        assert_eq!(auto_lock_name(600), "10 minutes");
        assert_eq!(auto_lock_name(45), "45 seconds");
    }
}
