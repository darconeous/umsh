//! Device › Clock: its settings, the date and time set by hand, and the
//! time zones, which first run shows too. Backspace goes back; on the time
//! zones, it first takes back a letter typed.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::match_view;
use buoyant::view::LazyForEach;
use buoyant::view::lazy_foreach::Extent;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::setting::{End, marked_row, readout, row};
use super::{label, line};
use crate::board::Metrics;
use crate::clock_settings::{ClockPage, DateParts, Part, ZoneFind, matching};
use crate::model::{ClockSource, State, age};
use crate::nav::keys;
use crate::zones::{self, ZONES};
use crate::{font, icon, theme};

const ROW: u32 = 36;
/// The parts of the date and time: their height, and the room each takes.
const PART: u32 = 40;
const PART_GAP: u32 = 6;
const GROUP_GAP: u32 = 26;
const PART_TOP: u32 = 30;
/// The colon between the hour and the minute, about as wide as drawn.
const COLON: u32 = 8;
/// The least room left at the screen's edges.
const INSET: u32 = 8;
/// The most zones the list builds at once: those the view shows and some
/// way beyond, wherever it is scrolled to.
const ZONE_ROWS: usize = 16;
pub fn page(state: &State, page: &ClockPage) -> impl View<Rgb565, State> + use<> {
    match_view!(page, {
        ClockPage::Main => main(state),
        ClockPage::SetTime { parts, editing, .. } => set_time(state, parts, *editing),
        ClockPage::Zones { find } => zone_list(state, find, "Time zone"),
    })
}

/// What Device's Clock row says: where the time comes from.
#[must_use]
pub fn summary(state: &State) -> &'static str {
    match state.clock.automatic {
        Some(true) => "GNSS",
        _ => "Manual",
    }
}

/// The settings.
fn main(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let clock = state.clock;
    let hour24 = clock.hour24;
    let mut now: String<32> = String::new();
    match state.wall_time.map(|time| state.local(time)) {
        Some(local) => {
            _ = core::fmt::write(
                &mut now,
                format_args!("{}, {}", local.short_date(), local.time(hour24)),
            );
        }
        None => _ = now.push_str("Not set"),
    }
    let automatic = clock.automatic == Some(true);
    let source = state.node.clock_source().map(|(source, at)| {
        let mut text: String<32> = String::new();
        let from = match source {
            ClockSource::Manual => "Manual",
            ClockSource::Gnss => "GNSS",
            ClockSource::Rtc => "Real-time clock",
        };
        let ago = age(
            Some((at / 1000) as u32),
            Some((state.uptime.max(at) / 1000) as u32),
        );
        if ago.as_str() == "now" {
            _ = core::fmt::write(&mut text, format_args!("{from}, just now"));
        } else {
            _ = core::fmt::write(&mut text, format_args!("{from}, {ago} ago"));
        }
        text
    });
    let zone = zones::name(&clock.zone);
    VStack::new((
        header(m, "Clock", None, None),
        super::list(
            VStack::new((
                clock.automatic.map(|on| {
                    row(
                        m,
                        "Set automatically",
                        keys::CLOCK_AUTOMATIC,
                        State::toggle_clock_automatic,
                        End::Switch(on),
                        false,
                        ROW,
                    )
                }),
                row(
                    m,
                    "Date and time",
                    keys::CLOCK_TIME,
                    State::open_set_time,
                    if automatic {
                        End::value(&now)
                    } else {
                        End::value_chevron(&now)
                    },
                    false,
                    ROW,
                ),
                row(
                    m,
                    "Time zone",
                    keys::CLOCK_ZONE,
                    State::open_zones,
                    End::value_chevron(&zone),
                    false,
                    ROW,
                ),
                row(
                    m,
                    "24-hour time",
                    keys::CLOCK_24H,
                    State::toggle_hour24,
                    End::Switch(hour24),
                    false,
                    ROW,
                ),
                source.map(|source| readout(m, "Last set from", &source, ROW)),
            ))
            .with_spacing(0),
        )
        .with_scroll_step(ROW),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(back)
}

fn back(key: Key, s: &mut State) -> KeyResponse {
    match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    }
}

/// The date and time, set a part at a time, in the zone named under them.
fn set_time(state: &State, parts: &DateParts, editing: bool) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let hour24 = state.clock.hour24;
    let focused = state.screen().focus().current().and_then(keys::part_of);
    let text = |value: core::fmt::Arguments| {
        let mut s: String<6> = String::new();
        _ = core::fmt::write(&mut s, value);
        s
    };
    let hour = if hour24 {
        parts.hour
    } else {
        match parts.hour % 12 {
            0 => 12,
            hour => hour,
        }
    };
    // The parts' widths, in the Pager's pixels at its size of 26.
    let scaled = |width: u32| width * m.title / 26;
    let part = |p: Part, value: String<6>, width: u32| {
        part_button(
            m,
            p,
            value,
            scaled(width),
            focused == Some(p),
            editing && focused == Some(p),
        )
    };
    let mut zone: String<40> = String::new();
    let offset = state
        .clock
        .zone
        .offset_at(state.clock.zone.to_utc(parts.local_seconds()));
    _ = core::fmt::write(
        &mut zone,
        format_args!(
            "{}, {}",
            zones::name(&state.clock.zone),
            zones::offset_text(offset)
        ),
    );
    let date = HStack::new((
        part(
            Part::Month,
            text(format_args!(
                "{}",
                crate::clock::MONTHS[usize::from(parts.month) - 1]
            )),
            66,
        ),
        part(Part::Day, text(format_args!("{}", parts.day)), 50),
        part(Part::Year, text(format_args!("{}", parts.year)), 78),
    ))
    .with_spacing(PART_GAP);
    let time = HStack::new((
        part(
            Part::Hour,
            if hour24 {
                text(format_args!("{hour:02}"))
            } else {
                text(format_args!("{hour}"))
            },
            50,
        ),
        line(":", &font::BOLD, m.title, theme::TEXT_SECONDARY),
        part(Part::Minute, text(format_args!("{:02}", parts.minute)), 50),
        (!hour24).then(|| {
            part(
                Part::Half,
                text(format_args!(
                    "{}",
                    if parts.hour < 12 { "AM" } else { "PM" }
                )),
                58,
            )
        }),
    ))
    .with_spacing(PART_GAP);
    // The time beside the date where both fit across, and under it where
    // they do not.
    let across = scaled(66 + 50 + 78 + 50 + 50 + if hour24 { 0 } else { 58 })
        + PART_GAP * if hour24 { 6 } else { 7 }
        + COLON
        + GROUP_GAP;
    let (beside, under) = if across <= m.width - 2 * INSET {
        (Some(time), None)
    } else {
        (None, Some(time))
    };
    VStack::new((
        header(m, "Date and time", None, None),
        VStack::new((HStack::new((date, beside)).with_spacing(GROUP_GAP), under))
            .with_spacing(PART_GAP)
            .flex_infinite_width(HorizontalAlignment::Center)
            .padding(Edges::Top, PART_TOP),
        label::<40>(&zone, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY)
            .flex_infinite_width(HorizontalAlignment::Center)
            .padding(Edges::Top, 22),
        Spacer::default(),
        row(
            m,
            "Set",
            keys::SET_TIME,
            State::submit_set_time,
            End::Nothing,
            false,
            ROW,
        ),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Character(c) if c.is_ascii_digit() => {
            s.type_time_digit(c as u8 - b'0');
            KeyResponse::Handled
        }
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// One part: framed, outlined while focused, and with the way to turn over
/// and under it while turning changes it.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
fn part_button(
    m: &'static Metrics,
    part: Part,
    value: String<6>,
    width: u32,
    focused: bool,
    editing: bool,
) -> impl View<Rgb565, State> + use<> {
    Button::new(
        move |s: &mut State| s.press_part(part),
        move |_| {
            let arrow = |image| {
                Image::new(image)
                    .as_template()
                    .foreground_color(if editing {
                        theme::ACCENT
                    } else {
                        theme::BACKGROUND
                    })
            };
            VStack::new((
                arrow(&icon::UP),
                line(value.clone(), &font::BOLD, m.title, theme::TEXT)
                    .hint_background_color(if focused { theme::FOCUS } else { theme::PANEL })
                    .frame_sized(width, PART * m.title / 26)
                    .background(
                        Alignment::Center,
                        ZStack::new((
                            RoundedRectangle::new(9).foreground_color(if focused {
                                theme::FOCUS
                            } else {
                                theme::PANEL
                            }),
                            RoundedRectangle::new(9)
                                .stroked(if focused { 2 } else { 1 })
                                .foreground_color(if focused {
                                    theme::ACCENT
                                } else {
                                    theme::LINE
                                }),
                        )),
                    ),
                arrow(&icon::DOWN),
            ))
            .with_spacing(2)
        },
    )
    .focus_key(keys::time_part(part))
}

/// The time zones under `title`, narrowed by the letters typed, the one set
/// checked. Pressing one sets it.
pub fn zone_list(
    state: &State,
    find: &ZoneFind,
    title: &'static str,
) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let shown = matching(find);
    let keyed = shown.clone();
    let current = zones::find(&state.clock.zone);
    let now = state.wall_time.map_or(0, i64::from);
    let find = find.clone();
    VStack::new((
        header(m, title, None, None),
        (!find.is_empty()).then(|| {
            label::<16>(&find, &font::BOLD, m.secondary, theme::ACCENT)
                .padding(Edges::Leading, 12)
                .flex_infinite_width(HorizontalAlignment::Leading)
                .frame()
                .with_height(24)
        }),
        super::list(
            LazyForEach::<ZONE_ROWS>::new_vertical(shown.len(), Extent::Fixed(ROW), move |i| {
                let index = usize::from(shown[i]);
                let zone = &ZONES[index];
                let offset = if zone.named_by_offset() {
                    String::<12>::new()
                } else {
                    zones::offset_text(zone.read().offset_at(now))
                };
                marked_row(
                    m,
                    zone.name,
                    keys::zone(index),
                    move |s: &mut State| s.choose_zone(index),
                    End::value(&offset),
                    false,
                    ROW,
                    Some(current == Some(index)),
                )
            })
            .keyed(move |i| keys::zone(usize::from(keyed[i]))),
        )
        .with_scroll_step(ROW),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Character(c) if c.is_alphabetic() || c == ' ' => {
            s.find_zone(c);
            KeyResponse::Handled
        }
        Key::Backspace => {
            if !s.unfind_zone() {
                s.back();
            }
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}
