//! The Peers list: Add peer, then two lines per saved peer, most recently
//! heard first. Backspace moves to the rail.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::Vec;

use super::line;
use crate::board::Metrics;
use crate::model::{MAX_PEERS, PeerSummary, State, hops_text};
use crate::nav::keys;
use crate::{font, icon, theme};

pub(super) const ROW: u32 = 44;
const NAME_LINE: u32 = 24;
const ROUTE_LINE: u32 = ROW - NAME_LINE;
pub(super) const AVATAR: u32 = 34;
/// From the list's leading edge to the text.
pub(super) const TEXT_X: u32 = 51;
/// The signal bars: each one's width, the space between them, and the
/// shortest one's height and how much taller each next one is.
const BAR: u32 = 3;
const BAR_GAP: u32 = 2;
const BAR_BASE: u32 = 4;
const BAR_STEP: u32 = 3;

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; MAX_PEERS] = {
    let mut a = [0; MAX_PEERS];
    let mut i = 0;
    while i < MAX_PEERS {
        a[i] = i;
        i += 1;
    }
    a
};

pub fn view(
    m: &'static Metrics,
    peers: &Vec<PeerSummary, MAX_PEERS>,
) -> impl View<Rgb565, State> + use<> {
    let rows = peers.clone();
    let ids: Vec<u32, MAX_PEERS> = peers.iter().map(|p| p.id).collect();
    let count = rows.len();
    super::list(
        VStack::new((
            add_row(
                m,
                "Add peer",
                State::open_add_peer,
                keys::ADD_PEER,
                m.beside_rail(),
            ),
            ForEach::<MAX_PEERS>::new_vertical(&INDICES[..count], move |&i| row(m, &rows[i]))
                .keyed(move |&i| keys::peer(ids[i])),
        ))
        .with_spacing(0),
    )
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        // Back, or the arrow toward the rail.
        Key::Backspace | Key::LeftArrow => {
            s.focus_rail();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// A row's focused look, under its content: filled, with the accent at its
/// leading edge, as the Chats list's rows are. `width` is the list's.
pub(super) fn focused_row<C, V: View<Rgb565, C>>(
    content: V,
    focused: bool,
    width: u32,
) -> impl View<Rgb565, C> + use<C, V> {
    content
        .hint_background_color(if focused {
            theme::FOCUS
        } else {
            theme::BACKGROUND
        })
        .background(
            Alignment::Center,
            focused.then(|| Rectangle.foreground_color(theme::FOCUS)),
        )
        .overlay(
            Alignment::Leading,
            focused.then(|| {
                Rectangle
                    .foreground_color(theme::ACCENT)
                    .frame_sized(4, ROW)
            }),
        )
        .overlay(
            Alignment::BottomTrailing,
            (!focused).then(|| {
                Rectangle
                    .foreground_color(theme::LINE)
                    .frame_sized(width - TEXT_X, 1)
            }),
        )
}

/// The row heading a list that adds to it.
pub(super) fn add_row(
    m: &'static Metrics,
    name: &'static str,
    act: fn(&mut State),
    key: buoyant::focus::FocusKey,
    width: u32,
) -> impl View<Rgb565, State> + use<> {
    Button::new(act, move |button: ButtonState| {
        focused_row(
            super::line(name, &font::SEMIBOLD, m.body, theme::ACCENT)
                .padding(Edges::Leading, TEXT_X)
                .flex_infinite_width(HorizontalAlignment::Leading)
                .frame()
                .with_height(ROW)
                .overlay(
                    Alignment::Leading,
                    Image::new(&icon::ADD)
                        .as_template()
                        .foreground_color(theme::ACCENT)
                        .frame()
                        .with_width(TEXT_X),
                ),
            button.is_focused(),
            width,
        )
    })
    .focus_key(key)
}

fn row(m: &'static Metrics, peer: &PeerSummary) -> impl View<Rgb565, State> + use<> {
    let peer = peer.clone();
    let id = peer.id;
    Button::new(
        move |s: &mut State| s.open_peer(id),
        move |button: ButtonState| Lazy::new((peer.clone(), button.is_focused(), m), row_look),
    )
}

/// A peer's row: their avatar, then their name over how far away they are.
///
/// Built from the peer each time it is drawn ([`Lazy`]): kept in the
/// render trees, every row's would outweigh the rest of the screen.
fn row_look(
    (peer, focused, m): &(PeerSummary, bool, &'static Metrics),
) -> impl View<Rgb565, ()> + use<> {
    focused_row(
        VStack::new((
            HStack::new((
                line(peer.name.clone(), &font::SEMIBOLD, m.body, theme::TEXT),
                Spacer::default(),
                line(
                    peer.heard.clone(),
                    &font::SEMIBOLD,
                    m.small,
                    theme::TEXT_TERTIARY,
                )
                .fixed_size(true, false),
            ))
            .with_spacing(4)
            .padding(Edges::Trailing, 10)
            .frame()
            .with_height(NAME_LINE),
            // A peer not known to be anywhere has its name alone, in the
            // middle.
            peer.hops
                .is_some()
                .then(|| route_line(m, peer).frame().with_height(ROUTE_LINE)),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading)
        .padding(Edges::Leading, TEXT_X)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(ROW)
        .overlay(
            Alignment::Leading,
            super::avatar::view(&peer.avatar, AVATAR)
                .frame()
                .with_width(TEXT_X),
        ),
        *focused,
        m.beside_rail(),
    )
}

/// How far away the peer is, with how strongly they are heard when direct.
fn route_line(m: &Metrics, peer: &PeerSummary) -> impl View<Rgb565, ()> + use<> {
    let route = peer.hops.map(hops_text).unwrap_or_default();
    HStack::new((
        peer.signal.filter(|_| peer.hops == Some(1)).map(bars),
        line(route, &font::REGULAR, m.secondary, theme::TEXT_TERTIARY),
    ))
    .with_spacing(6)
    .with_alignment(VerticalAlignment::Center)
}

/// `lit` of four bars, rising.
fn bars(lit: u8) -> impl View<Rgb565, ()> + use<> {
    let bar = move |i: u8| {
        RoundedRectangle::new(1)
            .foreground_color(if i < lit {
                theme::GREEN
            } else {
                theme::TEXT_TERTIARY
            })
            .frame_sized(BAR, BAR_BASE + u32::from(i) * BAR_STEP)
    };
    HStack::new((bar(0), bar(1), bar(2), bar(3)))
        .with_spacing(BAR_GAP)
        .with_alignment(VerticalAlignment::Bottom)
}
