//! Device: the settings' categories, each with what it is set to, and the
//! Radio screen one of them opens. Changes apply at once; Backspace goes
//! back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::match_view;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::setting::{End, card, choice, row};
use crate::board::Metrics;
use crate::model::{BatteryReading, Bluetooth, ChatKind, RadioSettings, State};
use crate::nav::{DevicePage, Screen, keys};
use crate::theme;

const ROW: u32 = 36;
/// Shut down's confirmation.
const CONFIRM_WIDTH: u32 = 220;

/// The categories, beside the rail.
pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let channels = state
        .chats
        .iter()
        .filter(|c| matches!(c.kind, ChatKind::Channel { .. }))
        .count();
    let confirm = matches!(
        state.screen(),
        Screen::Chats {
            confirm_shut_down: true,
            ..
        }
    );
    let battery = state.battery.percent.map(super::battery::percent_text);
    let mut joined: String<24> = String::new();
    _ = core::fmt::write(&mut joined, format_args!("{channels} joined"));
    let category = |name, key, act: fn(&mut State), value: &str| {
        let end = if value.is_empty() {
            End::Chevron
        } else {
            End::value_chevron(value)
        };
        row(m, name, key, act, end, false, ROW)
    };
    super::list(
        VStack::new((
            category(
                "Identity",
                keys::IDENTITY,
                State::open_share,
                &state.status.device_name,
            ),
            category("Channels", keys::CHANNELS, State::open_channels, &joined),
            category(
                "Radio",
                keys::RADIO,
                State::open_radio,
                state.profile_name(&state.node.radio()),
            ),
            category("Display", keys::DISPLAY, State::open_display, ""),
            category("Keyboard", keys::KEYBOARD, State::open_keyboard, ""),
            category(
                "Clock",
                keys::CLOCK,
                State::open_clock,
                super::clock::summary(state),
            ),
            VStack::new((
                state.node.bluetooth_enabled().map(|_| {
                    category(
                        "Bluetooth",
                        keys::BLUETOOTH,
                        State::open_bluetooth,
                        if state.status.bluetooth == Some(Bluetooth::Connected) {
                            "Connected"
                        } else {
                            ""
                        },
                    )
                }),
                state
                    .node
                    .gnss_enabled()
                    .map(|_| category("GNSS", keys::GNSS, State::open_gnss, "")),
                (state.battery != BatteryReading::default()).then(|| {
                    category(
                        "Battery",
                        keys::BATTERY,
                        State::open_battery,
                        &battery.unwrap_or_default(),
                    )
                }),
            ))
            .with_spacing(0),
            category("Statistics", keys::STATISTICS, State::open_statistics, ""),
            category("About", keys::ABOUT, State::open_about, ""),
            row(
                m,
                "Shut down",
                keys::SHUT_DOWN,
                State::ask_shut_down,
                End::Nothing,
                false,
                ROW,
            ),
        ))
        .with_spacing(0),
    )
    .with_scroll_step(ROW)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        // Back, or the arrow toward the rail.
        Key::Backspace | Key::LeftArrow => {
            s.focus_rail();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
    .popover(confirm.then_some(()).as_ref(), |()| {
        shut_down_confirmation(m)
    })
    // A tap outside is Cancel.
    .on_blur(|s: &mut State| {
        s.cancel_shut_down();
        Dismissal::Dismiss
    })
}

/// Shut down, confirmed, or Cancel, which is focused.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
fn shut_down_confirmation(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| String::try_from(text).unwrap_or_default();
    card(
        m,
        VStack::new((
            choice(
                m,
                text("Shut down"),
                keys::SHUT_DOWN_CONFIRM,
                State::shut_down,
                theme::TEXT,
                None,
            ),
            choice(
                m,
                text("Cancel"),
                keys::SHUT_DOWN_CANCEL,
                State::cancel_shut_down,
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        CONFIRM_WIDTH,
        HorizontalAlignment::Center,
        State::cancel_shut_down,
    )
}

/// A screen under Device.
pub fn page(state: &State, page: &DevicePage) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    match_view!(page, {
        DevicePage::Radio { settings } => radio(m, settings, state.profile_name(settings)),
        DevicePage::Share => super::share::view(state),
        DevicePage::Channels => super::channels::view(state),
        DevicePage::AddChannel { text } => super::add_channel::view(state, text),
        DevicePage::Profiles => super::profile::view(state, "Profile"),
        DevicePage::Keyboard { settings } => super::typing::settings(m, settings),
        DevicePage::TransmitPower { text } => super::typing::transmit_power(m, text),
        DevicePage::Clock { page } => super::clock::page(state, page),
        DevicePage::Bluetooth { .. }
        | DevicePage::Gnss
        | DevicePage::Battery
        | DevicePage::Display { .. }
        | DevicePage::AutoLock
        | DevicePage::Statistics
        | DevicePage::About
        | DevicePage::Credits => board_page(state, page),
    })
}

/// A screen about the board: its links, its battery, its screen, its
/// counters, and what it is and runs. Apart from [`page`], whose arms `match_view!` limits.
fn board_page(state: &State, page: &DevicePage) -> impl View<Rgb565, State> + use<> {
    match_view!(page, {
        DevicePage::Bluetooth { confirm } => super::links::bluetooth(state, *confirm),
        DevicePage::Gnss => super::links::gnss(state),
        DevicePage::Battery => super::battery::view(state),
        DevicePage::Display { .. } => super::display::view(state),
        DevicePage::AutoLock => super::display::auto_lock(state),
        DevicePage::Statistics => super::statistics::view(state),
        DevicePage::About => super::about::view(state),
        // Credits, the only other `page` sends here.
        _ => super::about::credits(state),
    })
}

/// The radio's settings, on the radio profile called `profile`.
fn radio(
    m: &'static Metrics,
    settings: &RadioSettings,
    profile: &str,
) -> impl View<Rgb565, State> + use<> {
    let mut airtime: String<24> = String::new();
    _ = core::fmt::write(
        &mut airtime,
        format_args!("{}% this hour", settings.airtime),
    );
    let mut power: String<24> = String::new();
    _ = core::fmt::write(&mut power, format_args!("{} dBm", settings.transmit_power));
    VStack::new((
        header(m, "Radio", None, None),
        super::list(
            VStack::new((
                row(
                    m,
                    "Radio",
                    keys::RADIO_ENABLED,
                    State::toggle_radio,
                    End::Switch(settings.enabled),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Profile",
                    keys::PROFILE,
                    State::open_profiles,
                    End::value_chevron(profile),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Transmit power",
                    keys::TRANSMIT_POWER,
                    State::open_transmit_power,
                    End::value_chevron(&power),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Forwarding",
                    keys::FORWARDING,
                    State::toggle_forwarding,
                    End::Switch(settings.forwarding),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Share location",
                    keys::SHARE_LOCATION,
                    State::toggle_share_location,
                    End::Switch(settings.share_location),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Airtime",
                    keys::AIRTIME,
                    |_| {},
                    End::value(&airtime),
                    false,
                    ROW,
                ),
            ))
            .with_spacing(0),
        )
        .with_scroll_step(ROW),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}
