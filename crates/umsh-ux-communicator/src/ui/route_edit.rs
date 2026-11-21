//! The rows of a route to a saved peer chosen by hand, edited in place of
//! the Route screen, and what opens over them. [`super::sheet`] lays them
//! out: this device, the hops, how far it floods past them, and the peer,
//! then Ping along route, Hold for, and Save. A press on a hop opens Move
//! and Remove; a lifted hop rides the wheel until a press puts it down.
//! Then flood and Hold for change by turning once pressed. Nothing reaches
//! the node before Save, and Backspace with changes asks.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::details::{AVATAR, INSET, NAME_X};
use super::line;
use super::member::action_look;
use super::path::{Half, NODE, halves, rail};
use super::setting::{card, choice};
use crate::board::Metrics;
use crate::model::{Repeater, State, flood_text};
use crate::nav::{EditOver, HOLD_CHOICES, keys};
use crate::{font, icon, theme};

/// What Hold for reads, by [`HOLD_CHOICES`].
pub const HOLD_LABELS: [&str; HOLD_CHOICES.len()] =
    ["30 min", "1 hour", "4 hours", "12 hours", "1 day"];
const MENU_WIDTH: u32 = 220;
/// What leaving with changes asks, which says more.
const LEAVE_WIDTH: u32 = 300;
/// The hollow dots of the flood row.
const DOT: u32 = 6;
/// Add hop's plus.
const PLUS: u32 = 24;

/// How the latest ping along the route went, as its row says.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pinged {
    /// None went along it as it stands.
    Not,
    Waiting,
    NoReply,
    /// Answered, in this many milliseconds.
    Reply(u32),
    /// Answered, but only by flooding once the route failed.
    Flooded,
}

/// What a row of the editor reads at its end, formatted as it is drawn.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Value {
    None,
    /// Add hop's plus, on the rail.
    Add,
    Flood(u8),
    /// Which of [`HOLD_CHOICES`].
    Hold(u8),
    Ping(Pinged),
}

/// A row of the editor past its hops.
#[derive(Clone, Copy)]
pub(super) struct Look {
    pub(super) label: &'static str,
    pub(super) value: Value,
    /// Turning changes its value.
    pub(super) active: bool,
    pub(super) focused: bool,
    /// Its label is in the accent: what the editor is for.
    pub(super) accent: bool,
    pub(super) m: &'static Metrics,
}

/// A row past the hops. Built each time it is drawn, as every row is.
pub(super) fn row_look((look, on_rail): &(Look, bool)) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let face = if look.focused || look.accent {
        &font::BOLD
    } else {
        &font::REGULAR
    };
    let color = if look.accent {
        theme::ACCENT
    } else {
        theme::TEXT
    };
    let mut value: String<16> = String::new();
    let mut value_color = theme::TEXT_SECONDARY;
    let mut check = false;
    let mut chevron = false;
    match look.value {
        Value::None | Value::Add => {}
        Value::Flood(hops) => _ = value.push_str(&flood_text(hops)),
        Value::Hold(hold) => {
            _ = value.push_str(HOLD_LABELS[usize::from(hold).min(HOLD_LABELS.len() - 1)]);
        }
        Value::Ping(Pinged::Not | Pinged::Waiting) => chevron = true,
        Value::Ping(Pinged::NoReply) => {
            _ = value.push_str("No reply");
            value_color = theme::RED;
        }
        Value::Ping(Pinged::Flooded) => {
            _ = value.push_str("Flooded");
            value_color = theme::AMBER;
        }
        Value::Ping(Pinged::Reply(ms)) => {
            _ = core::fmt::write(
                &mut value,
                format_args!("{}.{} s", ms / 1000, ms % 1000 / 100),
            );
            value_color = theme::GREEN;
            check = true;
        }
    }
    let flooding = matches!(look.value, Value::Flood(1..));
    let add = matches!(look.value, Value::Add);
    let dot = move || {
        Circle
            .stroked(1)
            .foreground_color(if flooding {
                theme::TEXT_TERTIARY
            } else {
                theme::LINE
            })
            .frame_sized(DOT, DOT)
    };
    let (value_face, value_color) = if look.active {
        (&font::BOLD, theme::TEXT)
    } else {
        (&font::REGULAR, value_color)
    };
    action_look(
        HStack::new((
            line(look.label, face, m.body, color),
            Spacer::default(),
            look.active.then(|| {
                VStack::new((
                    Image::new(&icon::UP).as_template(),
                    Image::new(&icon::DOWN).as_template(),
                ))
                .with_spacing(0)
                .foreground_color(theme::ACCENT)
            }),
            check.then(|| {
                Image::new(&icon::CHECK)
                    .as_template()
                    .foreground_color(theme::GREEN)
            }),
            (!value.is_empty()).then(|| line(value, value_face, m.secondary, value_color)),
            chevron.then(|| {
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY)
            }),
        ))
        .with_spacing(8)
        .padding(
            Edges::Leading,
            if *on_rail { NAME_X - 4 } else { INSET - 4 },
        )
        // The flood past the last hop: dots on the rail, one when off;
        // or Add hop's plus.
        .overlay(
            Alignment::Leading,
            on_rail.then(|| {
                HStack::new((
                    (!add).then(|| {
                        VStack::new((dot(), flooding.then(dot), flooding.then(dot))).with_spacing(2)
                    }),
                    add.then(|| {
                        ZStack::new((
                            Circle.foreground_color(theme::BACKGROUND),
                            Image::new(&icon::ADD_HOP)
                                .as_template()
                                .foreground_color(theme::ACCENT),
                        ))
                        .frame_sized(PLUS, PLUS)
                    }),
                ))
                .frame()
                .with_width(AVATAR)
                .padding(Edges::Leading, INSET - 4)
            }),
        ),
        look.focused,
    )
    .background(
        Alignment::Leading,
        on_rail.then(|| halves(NODE, Half::On, Half::flood(flooding))),
    )
}

/// A hop of the route: the node it most plausibly is, on the rail, and a
/// grip, or arrows while it is lifted. Built each time it is drawn.
pub(super) fn hop_look(
    (repeater, focused, lifted, m): &(Option<Repeater>, bool, bool, &'static Metrics),
) -> impl View<Rgb565, ()> + use<> {
    let face = if *focused || *lifted {
        &font::SEMIBOLD
    } else {
        &font::REGULAR
    };
    let name = repeater.as_ref().map(|r| r.name.clone());
    let avatar = repeater.as_ref().map(|r| r.avatar.clone());
    action_look(
        HStack::new((
            name.map(|name| line(name, face, m.body, theme::TEXT)),
            Spacer::default(),
            (!*lifted).then(|| {
                Image::new(&icon::GRIP)
                    .as_template()
                    .foreground_color(if *focused {
                        theme::TEXT_TERTIARY
                    } else {
                        theme::LINE
                    })
            }),
            lifted.then(|| {
                VStack::new((
                    Image::new(&icon::UP).as_template(),
                    Image::new(&icon::DOWN).as_template(),
                ))
                .with_spacing(0)
                .foreground_color(theme::ACCENT)
            }),
        ))
        .with_spacing(8)
        .padding(Edges::Leading, NAME_X - 4)
        .overlay(
            Alignment::Leading,
            avatar.map(|avatar| {
                super::avatar::view(&avatar, AVATAR).padding(Edges::Leading, INSET - 4)
            }),
        ),
        *focused || *lifted,
    )
    .background(Alignment::Leading, rail(NODE, true, true))
}

/// What is open over the editor: a hop's Move and Remove, by the hop; or,
/// leaving with changes, Save, Discard changes and Keep editing, Save
/// focused. Backspace closes either.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
pub(super) fn over_view(m: &'static Metrics, over: EditOver) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| String::try_from(text).unwrap_or_default();
    let (first, second, third, width, alignment) = match over {
        EditOver::Hop(_) => (
            choice(
                m,
                text("Move"),
                keys::HOP_MOVE,
                State::move_hop,
                theme::TEXT,
                None,
            ),
            choice(
                m,
                text("Remove"),
                keys::HOP_REMOVE,
                State::remove_hop,
                theme::RED,
                None,
            ),
            None,
            MENU_WIDTH,
            HorizontalAlignment::Trailing,
        ),
        EditOver::Leave => (
            choice(
                m,
                text("Save"),
                keys::LEAVE_SAVE,
                State::save_route,
                theme::TEXT,
                None,
            ),
            choice(
                m,
                text("Discard changes"),
                keys::LEAVE_DISCARD,
                State::discard_route,
                theme::RED,
                None,
            ),
            Some(choice(
                m,
                text("Keep editing"),
                keys::LEAVE_KEEP,
                State::close_route_over,
                theme::TEXT,
                None,
            )),
            LEAVE_WIDTH,
            HorizontalAlignment::Center,
        ),
    };
    card(
        m,
        VStack::new((first, second, third)).with_spacing(0),
        width,
        alignment,
        State::close_route_over,
    )
}
