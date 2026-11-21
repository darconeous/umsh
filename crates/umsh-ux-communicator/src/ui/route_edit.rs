//! A route to a saved peer chosen by hand, edited in place of the Route
//! screen: this device, the hops, how far it floods past them, and the
//! peer, then Ping along route, Hold for, and Save. A press on a hop opens
//! Move and Remove; a lifted hop rides the wheel until a press puts it
//! down. Then flood and Hold for change by turning once pressed. Nothing
//! reaches the node before Save, and Backspace with changes asks.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::Lazy;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::titled;
use super::details::{AVATAR, INSET, NAME_X};
use super::line;
use super::member::action_look;
use super::path::{self, Half, NODE, halves, rail};
use super::setting::{card, choice};
use crate::board::Metrics;
use crate::model::{MAX_PATH, PeerId, PeerSummary, PingView, Repeater, State, flood_text};
use crate::nav::{Adjust, EditOver, HOLD_CHOICES, RouteDraft, keys};
use crate::{font, icon, theme};

/// What Hold for reads, by [`HOLD_CHOICES`].
pub const HOLD_LABELS: [&str; HOLD_CHOICES.len()] =
    ["30 min", "1 hour", "4 hours", "12 hours", "1 day"];
const MENU_WIDTH: u32 = 220;
/// What leaving with changes asks, which says more.
const LEAVE_WIDTH: u32 = 300;
/// The hollow dots of the flood row.
const DOT: u32 = 6;

static INDICES: [usize; MAX_PATH] = {
    let mut a = [0; MAX_PATH];
    let mut i = 0;
    while i < MAX_PATH {
        a[i] = i;
        i += 1;
    }
    a
};

/// The route to the saved peer `id`, `peer`, as `draft` has it.
// Out of line, as every page of `peer_or_channel` is.
#[inline(never)]
pub fn view(
    state: &State,
    id: PeerId,
    peer: &PeerSummary,
    draft: &RouteDraft,
) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let focused = state.screen().focus().current();
    let adjusting = state.adjusting_route();
    // Only the hints are kept: each row names its repeater as it is laid
    // out, so that the view holds no repeater.
    let node = state.node;
    let hints: [[u8; 2]; MAX_PATH] = {
        let mut hints = [[0; 2]; MAX_PATH];
        hints[..draft.hints().len()].copy_from_slice(draft.hints());
        hints
    };
    let count = draft.hints().len();
    let lifted = draft.lifted.map(|(now, _)| usize::from(now));
    let pinged = if draft.pinged {
        match state.node.ping_view(id) {
            Some(PingView::Reply(reply)) if reply.flooded => Pinged::Flooded,
            Some(PingView::Reply(reply)) => Pinged::Reply(reply.round_trip_ms),
            Some(PingView::NoReply) => Pinged::NoReply,
            Some(PingView::Waiting) | None => Pinged::Waiting,
        }
    } else {
        Pinged::Not
    };
    let look = move |label, value, key, accent| Look {
        label,
        value,
        active: false,
        focused: focused == Some(key),
        accent,
        m,
    };
    let flood = Look {
        label: if count == 0 { "Flood" } else { "Then flood" },
        active: adjusting == Some(Adjust::Flood),
        ..look("", Value::Flood(draft.flood), keys::ROUTE_FLOOD, false)
    };
    let ping = look(
        "Ping along route",
        Value::Ping(pinged),
        keys::ROUTE_PING_ALONG,
        false,
    );
    let hold = Look {
        active: adjusting == Some(Adjust::Hold),
        ..look("Hold for", Value::Hold(draft.hold), keys::ROUTE_HOLD, false)
    };
    let save = look("Save", Value::None, keys::ROUTE_SAVE, true);
    let mut name: String<32> = String::new();
    _ = name.push_str(umsh_grapheme::cut(peer.name.as_str(), 32));
    VStack::new((
        titled(m, "Edit route", theme::TEXT, None, peer.name.as_str()),
        super::list(
            VStack::new((
                path::you(m),
                ForEach::<MAX_PATH>::new_vertical(&INDICES[..count], move |&i| {
                    let repeater = node.repeater(hints[i]);
                    let lifted = lifted == Some(i);
                    Button::new(
                        move |s: &mut State| s.press_hop(i),
                        move |button: ButtonState| {
                            Lazy::new((repeater.clone(), button.is_focused(), lifted, m), hop_look)
                        },
                    )
                })
                .keyed(|&i| keys::path(i))
                .with_spacing(0),
                row(flood, true, State::press_flood).focus_key(keys::ROUTE_FLOOD),
                path::end(m, peer.avatar.clone(), name, false, draft.flood > 0),
                row(ping, false, State::ping_along).focus_key(keys::ROUTE_PING_ALONG),
                row(hold, false, State::press_hold).focus_key(keys::ROUTE_HOLD),
                row(save, false, State::save_route).focus_key(keys::ROUTE_SAVE),
            ))
            .with_spacing(0),
        )
        .with_scroll_step(NODE),
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
    .popover(draft.over.as_ref(), move |over| over_view(m, *over))
    // A tap outside closes it, as Backspace does.
    .on_blur(|s: &mut State| {
        s.close_route_over();
        Dismissal::Dismiss
    })
}

/// How the latest ping along the route went, as its row says.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pinged {
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
enum Value {
    None,
    Flood(u8),
    /// Which of [`HOLD_CHOICES`].
    Hold(u8),
    Ping(Pinged),
}

/// A row of the editor past its hops.
#[derive(Clone, Copy)]
struct Look {
    label: &'static str,
    value: Value,
    /// Turning changes its value.
    active: bool,
    focused: bool,
    /// Its label is in the accent: what the editor is for.
    accent: bool,
    m: &'static Metrics,
}

/// A row that does `act`, drawn by `look`; `on_rail` when it sits on the
/// path, as the flood past the last hop does.
fn row(look: Look, on_rail: bool, act: fn(&mut State)) -> impl View<Rgb565, State> + use<> {
    Button::new(act, move |button: ButtonState| {
        Lazy::new(
            (
                Look {
                    focused: button.is_focused(),
                    ..look
                },
                on_rail,
            ),
            row_look,
        )
    })
}

/// A row past the hops. Built each time it is drawn, as every row is.
fn row_look((look, on_rail): &(Look, bool)) -> impl View<Rgb565, ()> + use<> {
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
        Value::None => {}
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
        // The flood past the last hop: dots on the rail, one when off.
        .overlay(
            Alignment::Leading,
            on_rail.then(|| {
                VStack::new((dot(), flooding.then(dot), flooding.then(dot)))
                    .with_spacing(2)
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
fn hop_look(
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
fn over_view(m: &'static Metrics, over: EditOver) -> impl View<Rgb565, State> + use<> {
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
