//! The repeaters one router reports hearing, as last read: each one's
//! name, how the router heard it and how long ago, and how far from the
//! router, then Load more and Refresh. Opening asks for nothing; every
//! page is one exchange across the mesh. A known node's row opens its
//! page; a bare hint's asks who it is. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::Lazy;
use buoyant::view::LazyForEach;
use buoyant::view::lazy_foreach::Extent;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::titled;
use super::details::{AVATAR, INSET, NAME_X, spinner};
use super::line;
use super::path::{bar_color, lit};
use super::peers::bars;
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{Listing, ListingAsk, MAX_LISTED, Signal, State, age};
use crate::nav::keys;
use crate::{font, icon, theme};

/// A repeater's row: its name, then how the router heard it.
const NEIGHBOR: u32 = 44;
/// The label over the list.
const LABEL: u32 = 26;
/// How long a repeater goes unheard before its row fades, in minutes.
const STALE_MIN: u16 = 6 * 60;

/// What the router at `router` reports hearing.
// Out of line, as every page of `peer_or_channel` is.
#[inline(never)]
pub fn view(state: &State, router: &str) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let node = state.node;
    let listing = node.listing(router);
    let name = node
        .known_member(router)
        .map(|member| member.sender.name)
        .unwrap_or_default();
    let identifying = state.identifying();
    let phase = state.spinner_phase();
    let count = listing
        .as_ref()
        .map_or(0, |listing| usize::from(listing.count));
    let read = listing.as_ref().and_then(|listing| listing.read_ms_ago);
    let asking = listing.as_ref().and_then(|listing| listing.asking);
    let no_answer = listing.as_ref().is_some_and(|listing| listing.no_answer);
    let shown: String<44> = String::try_from(router).unwrap_or_default();
    let text_row = move |label, key, act: fn(&mut State), busy, count| {
        Button::new(act, move |button: ButtonState| {
            Lazy::new(
                TextLook {
                    label,
                    count,
                    busy,
                    phase,
                    focused: button.is_focused(),
                    m,
                },
                text_look,
            )
        })
        .focus_key(key)
    };
    let more = listing
        .as_ref()
        .filter(|listing| listing.more)
        .map(|listing: &Listing| (listing.count, listing.total));
    VStack::new((
        titled(m, "Neighbors", theme::TEXT, None, &name),
        super::list(
            VStack::new((
                read.map(|ms| read_label(m, ms)),
                read.is_none()
                    .then(|| note(m, "Not read", None, theme::TEXT_TERTIARY)),
                LazyForEach::<MAX_LISTED>::new_vertical(count, Extent::Fixed(NEIGHBOR), move |i| {
                    let listed = node.listed(&shown, i)?;
                    let look = NeighborLook {
                        known: listed.address.is_some(),
                        waiting: listed.address.is_none() && identifying.contains(&listed.hint),
                        name: listed.name,
                        avatar: listed.avatar,
                        signal: listed.signal,
                        heard_min: listed.heard_min,
                        distance_m: listed.distance_m,
                        phase,
                        focused: false,
                        m,
                    };
                    Some(Button::new(
                        move |s: &mut State| s.press_neighbor(i),
                        move |button: ButtonState| {
                            Lazy::new(
                                NeighborLook {
                                    focused: button.is_focused(),
                                    ..look.clone()
                                },
                                neighbor_look,
                            )
                        },
                    ))
                })
                .keyed(keys::neighbor),
                no_answer.then(|| {
                    note(
                        m,
                        "No answer",
                        Some("Out of reach, or it keeps no neighbor list"),
                        theme::AMBER,
                    )
                }),
                (read.is_some() && count == 0 && !no_answer && asking.is_none())
                    .then(|| note(m, "None", None, theme::TEXT_TERTIARY)),
                more.map(|more| {
                    text_row(
                        "Load more",
                        keys::NEIGHBORS_MORE,
                        State::more_neighbors,
                        asking == Some(ListingAsk::More),
                        Some(more),
                    )
                }),
                text_row(
                    "Refresh",
                    keys::NEIGHBORS_REFRESH,
                    State::refresh_neighbors,
                    asking == Some(ListingAsk::Top),
                    None,
                ),
            ))
            .with_spacing(0),
        )
        .with_scroll_step(NEIGHBOR),
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

/// When the listing was read, over it.
fn read_label(m: &'static Metrics, ms: u64) -> impl View<Rgb565, State> + use<> {
    let ago = age(Some(0), Some((ms / 1000).min(u64::from(u32::MAX)) as u32));
    let mut text: String<24> = String::new();
    if ago == "now" {
        _ = text.push_str("Read just now");
    } else {
        _ = core::fmt::write(&mut text, format_args!("Read {ago} ago"));
    }
    line(text, &font::BOLD, m.small, theme::TEXT_SECONDARY)
        .padding(Edges::Leading, INSET)
        .padding(Edges::Top, 6)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(LABEL)
}

/// What the listing says in place of rows: that it was never read, that
/// the router listed nobody, or that it did not answer and why.
fn note(
    m: &'static Metrics,
    title: &'static str,
    why: Option<&'static str>,
    color: Rgb565,
) -> impl View<Rgb565, State> + use<> {
    VStack::new((
        line(
            title,
            if why.is_some() {
                &font::BOLD
            } else {
                &font::REGULAR
            },
            m.body,
            color,
        ),
        why.map(|why| line(why, &font::REGULAR, m.small, theme::TEXT_TERTIARY)),
    ))
    .with_spacing(2)
    .with_alignment(HorizontalAlignment::Leading)
    .padding(Edges::Leading, NAME_X)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .frame()
    .with_height(NEIGHBOR)
    .overlay(
        Alignment::Bottom,
        Rectangle
            .foreground_color(theme::LINE)
            .frame()
            .with_height(1)
            .padding(Edges::Leading, NAME_X),
    )
}

/// A repeater the router reported, as its row draws it.
#[derive(Clone)]
struct NeighborLook {
    name: String<24>,
    avatar: AvatarStyle,
    /// A known node, whose page a press opens; else a bare hint.
    known: bool,
    /// Who the bare hint is was asked, and is waited for.
    waiting: bool,
    signal: Option<Signal>,
    heard_min: Option<u16>,
    distance_m: Option<u32>,
    phase: u8,
    focused: bool,
    m: &'static Metrics,
}

/// A repeater's row: its avatar and name, then the bars and the reading
/// (or that a bridge carried it), how long ago, and how far from the
/// router. Built each time it is drawn.
fn neighbor_look(look: &NeighborLook) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let stale = look.heard_min.is_some_and(|min| min >= STALE_MIN);
    let face = if look.focused {
        &font::SEMIBOLD
    } else {
        &font::REGULAR
    };
    let lit = look.signal.map(lit);
    VStack::new((
        line(
            look.name.clone(),
            face,
            m.body,
            if stale {
                theme::TEXT_TERTIARY
            } else {
                theme::TEXT
            },
        ),
        HStack::new((
            lit.map(|lit| {
                bars(
                    lit,
                    if stale {
                        theme::TEXT_TERTIARY
                    } else {
                        bar_color(lit)
                    },
                )
            }),
            line(reading(look), &font::REGULAR, m.small, theme::TEXT_TERTIARY),
        ))
        .with_spacing(6)
        .with_alignment(VerticalAlignment::Center),
    ))
    .with_spacing(2)
    .with_alignment(HorizontalAlignment::Leading)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .overlay(
        Alignment::Trailing,
        HStack::new((
            look.known.then(|| {
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY)
            }),
            (!look.known && !look.waiting).then(|| {
                Image::new(&icon::SEARCH)
                    .as_template()
                    .foreground_color(theme::ACCENT)
            }),
            (!look.known && look.waiting).then(|| spinner(look.phase)),
        )),
    )
    .padding(Edges::Leading, NAME_X - 4)
    .overlay(
        Alignment::Leading,
        super::avatar::view(&look.avatar, AVATAR).padding(Edges::Leading, INSET - 4),
    )
    .padding(Edges::Trailing, 10)
    .hint_background_color(if look.focused {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    })
    .frame()
    .with_height(NEIGHBOR - 2)
    .background(
        Alignment::Center,
        look.focused.then(|| {
            ZStack::new((
                RoundedRectangle::new(8).foreground_color(theme::FOCUS),
                RoundedRectangle::new(8)
                    .stroked(2)
                    .foreground_color(theme::ACCENT),
            ))
        }),
    )
    .padding(Edges::Horizontal, 4)
    .padding(Edges::Vertical, 1)
    .overlay(
        Alignment::Bottom,
        (!look.focused).then(|| {
            Rectangle
                .foreground_color(theme::LINE)
                .frame()
                .with_height(1)
                .padding(Edges::Leading, NAME_X)
        }),
    )
}

/// How the router heard a repeater, how long ago, and how far from it,
/// such as `−101 dBm · SNR 1.5 · 6m · 6.1 km`.
fn reading(look: &NeighborLook) -> String<48> {
    let minus = |negative: bool| if negative { "\u{2212}" } else { "" };
    let mut text: String<48> = String::new();
    match look.signal {
        Some(signal) => {
            let snr = signal.snr.unsigned_abs();
            _ = core::fmt::write(
                &mut text,
                format_args!(
                    "{}{} dBm \u{B7} SNR {}{}.{}",
                    minus(signal.rssi < 0),
                    signal.rssi.unsigned_abs(),
                    minus(signal.snr < 0),
                    snr / 10,
                    snr % 10,
                ),
            );
        }
        // Heard over a link, not the air.
        None => _ = text.push_str("Bridged"),
    }
    if let Some(min) = look.heard_min {
        let ago = age(Some(0), Some(u32::from(min) * 60));
        _ = core::fmt::write(&mut text, format_args!(" \u{B7} {ago}"));
    }
    if let Some(m) = look.distance_m {
        _ = match m {
            0..1_000 => core::fmt::write(&mut text, format_args!(" \u{B7} {m} m")),
            1_000..10_000 => core::fmt::write(
                &mut text,
                format_args!(" \u{B7} {}.{} km", m / 1000, m % 1000 / 100),
            ),
            _ => core::fmt::write(&mut text, format_args!(" \u{B7} {} km", m / 1000)),
        };
    }
    text
}

/// Load more or Refresh, as its row draws it.
#[derive(Clone, Copy)]
struct TextLook {
    label: &'static str,
    /// How many are held, of how many the router said it hears.
    count: Option<(u8, Option<u8>)>,
    /// What it asked for is waited for.
    busy: bool,
    phase: u8,
    focused: bool,
    m: &'static Metrics,
}

fn text_look(look: &TextLook) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let mut count: String<12> = String::new();
    if let Some((held, total)) = look.count {
        _ = match total {
            Some(total) => core::fmt::write(&mut count, format_args!("{held} of {total}")),
            None => core::fmt::write(&mut count, format_args!("{held}")),
        };
    }
    super::member::action_look(
        HStack::new((
            line(
                look.label,
                if look.focused {
                    &font::BOLD
                } else {
                    &font::SEMIBOLD
                },
                m.body,
                theme::ACCENT,
            ),
            Spacer::default(),
            look.busy.then(|| spinner(look.phase)),
            (!look.busy && !count.is_empty())
                .then(|| line(count, &font::REGULAR, m.small, theme::TEXT_TERTIARY)),
        ))
        .with_spacing(8)
        .padding(Edges::Leading, NAME_X - 4),
        look.focused,
    )
}
