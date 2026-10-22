//! The screens, as Buoyant views over [`State`].
//!
//! Views own what they draw: Buoyant keeps the previous frame's render tree
//! to animate from, so nothing in it may borrow the state that changed.

use crate::typeface::Typeface;
use buoyant::app::App;
use buoyant::focus::{DefaultFocus, Role};
use buoyant::match_view;
use buoyant::render::AnimatedJoin;
use buoyant::view::ViewMarker;
use buoyant::view::prelude::*;
use buoyant::view::scroll_view::ScrollBarVisibility;
use embedded_graphics::pixelcolor::Rgb565;

use crate::board::Metrics;
use crate::model::{ChatKind, Ending, Overlay, Section, State};
use crate::nav::{MemberFrom, Screen, keys};
use crate::{font, theme};

mod add_channel;
mod avatar;
mod banner;
mod channels;
mod chats;
mod clock;
mod conversation;
mod details;
mod device;
mod enter_address;
mod exchange;
mod find;
mod join;
mod links;
mod lock;
mod member;
mod nearby;
mod peer;
mod peers;
mod profile;
mod rail;
mod setting;
mod setup;
mod share;
mod share_contact;
mod status;
mod typing;

pub use typing::picker_columns;

/// How much of the content past the focused row a list keeps in view, so
/// that the next row shows cut by the edge where there is one.
const LOOK_AHEAD: u32 = 12;

/// A list that scrolls with focus, with no bar: the next row showing past
/// the focused one says there is more.
fn list<V: ViewMarker>(content: V) -> ScrollView<V> {
    ScrollView::new(content)
        .with_bar_visibility(ScrollBarVisibility::Never)
        .with_focus_margin(LOOK_AHEAD)
}

/// The card that says the board is shutting down.
const SHUTTING_DOWN_WIDTH: u32 = 220;

/// Readies an app over [`root_view`]: what can take focus, and where focus
/// is kept.
pub fn bind<V, F>(app: &mut App<V, State, F>)
where
    V: buoyant::view::ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    app.set_roles(Role::Button | Role::TextEntry);
    app.set_focus_binding(State::focus);
    if let Some(side) = app.state().metrics().touch_target {
        app.set_min_touch_target(buoyant::primitives::Size::new(side, side));
    }
    // Focus settles where the state asks, before the first input.
    app.finalize_view();
}

/// The whole screen for `state`.
///
/// The screen's parts have fixed places, so they are laid over one another
/// and inset rather than stacked: a stack lays each child out several times
/// to learn how flexible it is, nested stacks multiply that, and on the
/// device layout is the larger part of a frame.
#[must_use]
pub fn root_view(state: &State) -> impl View<Rgb565, State> + use<> {
    ZStack::new((
        // Locked, the lock screen stands in for everything else, which is
        // not built at all until it unlocks.
        match_view!(state.lock.locked, {
            true => lock::view(state),
            false => screens(state),
        }),
        // Over everything: one slot, the topmost of what could be here.
        state.overlay().map(|overlay| overlay_view(state, overlay)),
    ))
    .with_alignment(Alignment::TopLeading)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .flex_infinite_height(VerticalAlignment::Top)
    .background_color(theme::BACKGROUND, Rectangle)
}

/// The strip and the screen on top, while unlocked.
fn screens(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    ZStack::new((
        status::view(
            m,
            &state.status,
            state.in_setup(),
            state.keyboard.latches(),
            state
                .wall_time
                .map(|time| state.local(time).time(state.hour24())),
        ),
        match_view!(state.screen(), {
            Screen::Chats { .. } => chats_screen(state),
            Screen::Conversation { chat, .. } => conversation::view(state, *chat),
            Screen::Details { message, details, .. } => details::view(m,
                details,
                state.inbound(*message),
                state
                    .conversation
                    .as_ref()
                    .and_then(|c| state.chat(c.chat))
                    .is_some_and(|s| matches!(s.kind, ChatKind::Peer { .. })),
                details
                    .time
                    .map(|time| state.local(time).time(state.hour24())),
            ),
            Screen::Member {
                from,
                member,
                requested,
                ..
            } => member::view(m,
                member,
                *requested,
                match from {
                    MemberFrom::Message(_) => Some(
                        state
                            .conversation
                            .as_ref()
                            .and_then(|c| state.chat(c.chat))
                            .map_or("", |s| s.name.as_str()),
                    ),
                    MemberFrom::Chat(_) | MemberFrom::Known => None,
                },
            ),
            Screen::Join { invite, name, .. } => join::view(m, invite, name),
            Screen::Nearby { .. } | Screen::Exchange { .. } | Screen::EnterAddress { .. } =>
                add_peer(state),
            Screen::Peer {
                peer,
                detail,
                confirm,
                requested,
                ..
            } => state
                .peer(*peer)
                .map(|summary| peer::view(m, summary, detail, *confirm, *requested)),
            Screen::ShareContact { peer, .. } => state
                .peer(*peer)
                .map(|summary| share_contact::view(state, &summary.name)),
            Screen::Device { page, .. } => device::page(state, page),
            Screen::Setup { page, .. } => setup::view(state, page),
        })
        .padding(Edges::Top, m.strip),
    ))
    .with_alignment(Alignment::TopLeading)
}

/// Add peer's screens: Nearby, an exchange in its place, and Enter an
/// address.
fn add_peer(state: &State) -> impl View<Rgb565, State> + use<> {
    match_view!(state.screen(), {
        Screen::Exchange { .. } => exchange::view(state),
        Screen::EnterAddress { text, .. } => enter_address::view(state, text),
        _ => nearby::view(state),
    })
}

/// What lies over the screen: a banner, a glance, or the character
/// picker, none of which takes focus; or, over even the strip, what the
/// screen says as the board turns off.
fn overlay_view(state: &State, overlay: Overlay) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    match_view!(overlay, {
        Overlay::Ending(end) => ending(state.metrics(), end),
        Overlay::Picker(at) => typing::picker(state, at),
        Overlay::Glance(glance) => typing::glance(m, glance),
        Overlay::Banner(notice) => banner::view(state, notice),
    })
}

/// What the screen says as the board turns off.
fn ending(m: &'static Metrics, ending: Ending) -> impl View<Rgb565, State> + use<> {
    match_view!(ending, {
        Ending::ShuttingDown => shutting_down(m),
        Ending::BatteryEmpty { lit } => empty_battery(lit),
    })
}

/// A card over the screen, as the board turns off as asked.
fn shutting_down(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    VStack::new((
        Image::new(&crate::icon::POWER)
            .as_template()
            .foreground_color(theme::TEXT_SECONDARY),
        line("Shutting down", &font::SEMIBOLD, m.body, theme::TEXT),
    ))
    .with_spacing(10)
    .padding(Edges::Vertical, 20)
    .frame()
    .with_width(SHUTTING_DOWN_WIDTH)
    .background(
        Alignment::Center,
        ZStack::new((
            RoundedRectangle::new(12)
                .foreground_color(Rgb565::new(0, 0, 0))
                .offset(1, 3),
            RoundedRectangle::new(12).foreground_color(theme::MENU),
            RoundedRectangle::new(12)
                .stroked(1)
                .foreground_color(theme::MENU_LINE),
        )),
    )
    .flex_infinite_width(HorizontalAlignment::Center)
    .flex_infinite_height(VerticalAlignment::Center)
}

/// The empty battery, alone on the screen, `lit` or not as it blinks. No
/// words to translate, and no controls.
fn empty_battery(lit: bool) -> impl View<Rgb565, State> + use<> {
    lit.then(|| {
        Image::new(&crate::icon::BATTERY_EMPTY)
            .as_template()
            .foreground_color(theme::RED)
    })
    .flex_infinite_width(HorizontalAlignment::Center)
    .flex_infinite_height(VerticalAlignment::Center)
    .background_color(theme::BACKGROUND, Rectangle)
}

/// The rail and the list beside it. Turning on the rail shows each section
/// as it is reached; Find, while it is open, takes the Chats list's place.
fn chats_screen(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let focus = state.screen().focus().current();
    let shown = focus.and_then(keys::section).unwrap_or(state.section);
    let find = match state.screen() {
        Screen::Chats { find, .. } => find.as_ref().filter(|_| shown == Section::Chats),
        _ => None,
    };
    let menu = match state.screen() {
        Screen::Chats { menu, .. } => *menu,
        _ => None,
    };
    let list = match (shown, find) {
        (Section::Chats, Some(_)) => List::Find,
        (Section::Chats, None) => List::Chats,
        (Section::Peers, _) => List::Peers,
        (Section::Device, _) => List::Device,
    };
    ZStack::new((
        rail::view(m, shown, state.unread_chats()),
        match_view!(list, {
            List::Chats => chats::view(m, &state.chats, state.wall_time, menu),
            List::Find => find.map(|text| find::view(state, text)),
            List::Peers => peers::view(m, &state.peers),
            List::Device => device::view(state),
        })
        .padding(Edges::Leading, m.rail),
    ))
    .with_alignment(Alignment::TopLeading)
}

/// What shows beside the rail.
#[derive(Clone, Copy, PartialEq, Eq)]
enum List {
    Chats,
    Find,
    Peers,
    Device,
}

/// One line of text, cut short with an ellipsis when it does not fit, and
/// owned so the view borrows nothing.
fn label<const N: usize>(
    s: &str,
    face: &'static Typeface,
    size: u32,
    color: Rgb565,
) -> impl View<Rgb565, State> + use<N> {
    let mut owned: heapless::String<N> = heapless::String::new();
    _ = owned.push_str(umsh_grapheme::cut(s, N));
    line(owned, face, size, color)
}

/// One line of `text`, which the view holds as it is given: shared text
/// is shown without being copied.
fn line<T: AsRef<str> + Clone, C>(
    text: T,
    face: &'static Typeface,
    size: u32,
    color: Rgb565,
) -> impl View<Rgb565, C> + use<T, C> {
    Text::new(text, face)
        .with_font_size(size)
        .with_line_limit(1)
        .foreground_color(color)
}

/// An address, in the fewest lines of equal length that each fit in
/// `width`, each line `height` tall: whole on a wide screen, and broken
/// evenly where it does not fit.
fn address(
    text: &str,
    face: &'static Typeface,
    size: u32,
    color: Rgb565,
    width: u32,
    height: u32,
) -> impl View<Rgb565, State> + use<> {
    const MOST: usize = 3;
    let glyphs = face.face(size);
    let advance = |s: &str| -> u32 {
        s.chars()
            .map(|c| glyphs.glyph(c).map_or(0, |g| u32::from(g.advance)))
            .sum()
    };
    let count = text.chars().count();
    let split = |lines: usize| {
        let each = count.div_ceil(lines).max(1);
        let mut parts: heapless::Vec<heapless::String<44>, MOST> = heapless::Vec::new();
        let mut chars = text.chars();
        for _ in 0..lines {
            let part: heapless::String<44> = chars.by_ref().take(each).collect();
            if !part.is_empty() {
                _ = parts.push(part);
            }
        }
        parts
    };
    let mut parts = split(1);
    for lines in 2..=MOST {
        if parts.iter().all(|p| advance(p) <= width) {
            break;
        }
        parts = split(lines);
    }
    let part = |i: usize| {
        parts.get(i).cloned().map(|p| {
            line(p, face, size, color)
                .flex_infinite_width(HorizontalAlignment::Leading)
                .frame()
                .with_height(height)
        })
    };
    VStack::new((part(0), part(1), part(2))).with_spacing(0)
}
