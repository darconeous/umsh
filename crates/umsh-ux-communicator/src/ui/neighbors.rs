//! The rows of a router's Neighbors, what it reports hearing as last read,
//! which [`super::sheet`] lays out: each repeater's name, how the router
//! heard it and how long ago, and how far from the router, then Load more
//! and Refresh. Opening asks for nothing; every page is one exchange across
//! the mesh. A known node's row opens its page; a bare hint's asks who it
//! is. Backspace goes back.
//!
//! Add hop lists in the same rows, and adds the known repeaters and the
//! router hints typed text fixes in rows of their own.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::details::{AVATAR, INSET, NAME_X, spinner};
use super::line;
use super::path::{bar_color, lit};
use super::peers::bars;
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{Signal, age};
use crate::{font, icon, theme};

/// A repeater's row: its name, then how the router heard it.
pub(super) const NEIGHBOR: u32 = 44;
/// The label over the list.
const LABEL: u32 = 26;
/// How long a repeater goes unheard before its row fades, in minutes.
const STALE_MIN: u16 = 6 * 60;
/// The room a name leaves for the words at its end.
const END_WORDS: u32 = 96;

/// A known repeater's row, or a router hint's.
pub(super) const NODE: u32 = super::path::NODE;
/// Add hop's field, while text is typed into it.
const FIELD: u32 = 28;
const FIELD_RADIUS: u16 = 14;

/// What the listing says around its rows: a label over them, such as when
/// it was read, with what it says at its end; or in their place, that it
/// was never read, that the router listed nobody, or that it did not
/// answer and why.
#[derive(Clone)]
pub(super) enum Caption {
    Label(String<32>, Option<String<24>>),
    Note(&'static str, Option<&'static str>, Rgb565),
}

/// When the listing was read, such as `Read 12m ago`.
pub(super) fn read_text(ms: u64) -> String<24> {
    let ago = age(Some(0), Some((ms / 1000).min(u64::from(u32::MAX)) as u32));
    let mut text: String<24> = String::new();
    if ago == "now" {
        _ = text.push_str("Read just now");
    } else {
        _ = core::fmt::write(&mut text, format_args!("Read {ago} ago"));
    }
    text
}

/// A caption's look. Built each time it is drawn ([`Lazy`]): kept in the
/// view tree, each would be compiled into every pass over it.
pub(super) fn caption_look(
    (said, m): &(Caption, &'static Metrics),
) -> impl View<Rgb565, ()> + use<> {
    let (label, end, title, why, color) = match said {
        Caption::Label(text, end) => (
            Some(text.clone()),
            end.clone(),
            "",
            None,
            theme::TEXT_SECONDARY,
        ),
        Caption::Note(title, why, color) => (None, None, *title, *why, *color),
    };
    let note = label.is_none();
    VStack::new((
        label.map(|text| {
            HStack::new((
                line(text, &font::BOLD, m.small, color),
                Spacer::default(),
                end.map(|end| line(end, &font::REGULAR, m.small, theme::TEXT_TERTIARY)),
            ))
            .padding(Edges::Trailing, 14)
        }),
        note.then(|| {
            line(
                title,
                if why.is_some() {
                    &font::BOLD
                } else {
                    &font::REGULAR
                },
                m.body,
                color,
            )
        }),
        why.map(|why| line(why, &font::REGULAR, m.small, theme::TEXT_TERTIARY)),
    ))
    .with_spacing(2)
    .with_alignment(HorizontalAlignment::Leading)
    .padding(Edges::Leading, if note { NAME_X } else { INSET })
    .padding(Edges::Top, if note { 0 } else { 6 })
    .flex_infinite_width(HorizontalAlignment::Leading)
    .frame()
    .with_height(if note { NEIGHBOR } else { LABEL })
    .overlay(
        Alignment::Bottom,
        note.then(|| {
            Rectangle
                .foreground_color(theme::LINE)
                .frame()
                .with_height(1)
                .padding(Edges::Leading, NAME_X)
        }),
    )
}

/// A repeater the router reported, as its row draws it.
#[derive(Clone)]
pub(super) struct NeighborLook {
    pub(super) name: String<24>,
    pub(super) avatar: AvatarStyle,
    pub(super) end: End,
    pub(super) signal: Option<Signal>,
    pub(super) heard_min: Option<u16>,
    pub(super) distance_m: Option<u32>,
    pub(super) phase: u8,
    /// What Enter in Add hop's field adds.
    pub(super) tint: bool,
    pub(super) focused: bool,
    pub(super) m: &'static Metrics,
}

/// What a repeater's row shows at its end.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum End {
    /// A known node, whose page a press opens.
    Open,
    /// A bare hint, which a press asks who it is.
    Lookup,
    /// Who the bare hint is was asked, and is waited for.
    Asking,
    /// Add hop's peer, beside whom the route ends.
    Finish,
    /// Already a hop of the route being edited.
    InPath,
    Nothing,
}

/// A repeater's row: its avatar and name, then the bars and the reading
/// (or that a bridge carried it), how long ago, and how far from the
/// router. Built each time it is drawn.
pub(super) fn neighbor_look(look: &NeighborLook) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let stale = look.heard_min.is_some_and(|min| min >= STALE_MIN) || look.end == End::InPath;
    let face = if look.focused {
        &font::SEMIBOLD
    } else {
        &font::REGULAR
    };
    let lit = look.signal.map(lit);
    // "Finish here" and "In path" sit on the name's line, which keeps
    // clear of them; the icons sit centered across both lines.
    let worded = matches!(look.end, End::Finish | End::InPath);
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
        )
        .padding(Edges::Trailing, if worded { END_WORDS } else { 0 }),
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
        if worded {
            Alignment::TopTrailing
        } else {
            Alignment::Trailing
        },
        end_view(look.end, look.phase, m).padding(Edges::Top, if worded { 2 } else { 0 }),
    )
    .padding(Edges::Leading, NAME_X - 4)
    .overlay(
        Alignment::Leading,
        super::avatar::view(&look.avatar, AVATAR).padding(Edges::Leading, INSET - 4),
    )
    .padding(Edges::Trailing, 10)
    .hint_background_color(if look.focused || look.tint {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    })
    .frame()
    .with_height(NEIGHBOR - 2)
    .background(
        Alignment::Center,
        (look.focused || look.tint).then(|| {
            ZStack::new((
                RoundedRectangle::new(8).foreground_color(theme::FOCUS),
                look.focused.then(|| {
                    RoundedRectangle::new(8)
                        .stroked(2)
                        .foreground_color(theme::ACCENT)
                }),
            ))
        }),
    )
    .padding(Edges::Horizontal, 4)
    .padding(Edges::Vertical, 1)
    .overlay(
        Alignment::Bottom,
        (!look.focused && !look.tint).then(|| {
            Rectangle
                .foreground_color(theme::LINE)
                .frame()
                .with_height(1)
                .padding(Edges::Leading, NAME_X)
        }),
    )
}

/// What a row shows at its end, by [`End`].
fn end_view(end: End, phase: u8, m: &'static Metrics) -> impl View<Rgb565, ()> + use<> {
    let (text, color) = match end {
        End::Finish => ("Finish here", theme::ACCENT),
        End::InPath => ("In path", theme::TEXT_TERTIARY),
        _ => ("", theme::TEXT_TERTIARY),
    };
    HStack::new((
        (end == End::Open).then(|| {
            Image::new(&icon::CHEVRON)
                .as_template()
                .foreground_color(theme::TEXT_TERTIARY)
        }),
        (end == End::Lookup).then(|| {
            Image::new(&icon::SEARCH)
                .as_template()
                .foreground_color(theme::ACCENT)
        }),
        (end == End::Asking).then(|| spinner(phase)),
        (!text.is_empty()).then(|| line(text, &font::BOLD, m.secondary, color)),
    ))
}

/// A known repeater, or a router hint typed text fixes, as its row draws
/// it in Add hop.
#[derive(Clone)]
pub(super) struct NodeLook {
    pub(super) name: String<24>,
    pub(super) avatar: AvatarStyle,
    /// What follows the name, such as how the hint was read.
    pub(super) about: String<24>,
    /// How long ago it was heard, such as `2h`.
    pub(super) age: String<6>,
    /// Named by its hint, in the face addresses are written in.
    pub(super) hint: bool,
    pub(super) in_path: bool,
    /// What Enter adds, while text is typed.
    pub(super) tint: bool,
    pub(super) focused: bool,
    pub(super) m: &'static Metrics,
}

/// A known repeater's row, or a router hint's: its avatar and name, what
/// follows it, and how long ago it was heard, or that it is already on the
/// route. Built each time it is drawn.
pub(super) fn node_look(look: &NodeLook) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let face = match (look.hint, look.focused) {
        (true, true) => &font::MONO_BOLD,
        (true, false) => &font::MONO,
        (false, true) => &font::SEMIBOLD,
        (false, false) => &font::REGULAR,
    };
    let fill = if look.focused || look.tint {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    };
    HStack::new((
        line(
            look.name.clone(),
            face,
            m.body,
            if look.in_path {
                theme::TEXT_TERTIARY
            } else {
                theme::TEXT
            },
        )
        .fixed_size(true, false),
        (!look.about.is_empty()).then(|| {
            line(
                look.about.clone(),
                &font::REGULAR,
                m.small,
                theme::TEXT_TERTIARY,
            )
        }),
        Spacer::default(),
        (!look.in_path && !look.age.is_empty()).then(|| {
            line(
                look.age.clone(),
                &font::MEDIUM,
                m.small,
                theme::TEXT_TERTIARY,
            )
        }),
        look.in_path.then(|| end_view(End::InPath, 0, m)),
    ))
    .with_spacing(8)
    .padding(Edges::Leading, NAME_X - 4)
    .overlay(
        Alignment::Leading,
        super::avatar::view(&look.avatar, AVATAR).padding(Edges::Leading, INSET - 4),
    )
    .padding(Edges::Trailing, 10)
    .hint_background_color(fill)
    .frame()
    .with_height(NODE - 2)
    .background(
        Alignment::Center,
        (look.focused || look.tint).then(|| {
            ZStack::new((
                RoundedRectangle::new(8).foreground_color(theme::FOCUS),
                look.focused.then(|| {
                    RoundedRectangle::new(8)
                        .stroked(2)
                        .foreground_color(theme::ACCENT)
                }),
            ))
        }),
    )
    .padding(Edges::Horizontal, 4)
    .padding(Edges::Vertical, 1)
    .overlay(
        Alignment::Bottom,
        (!look.focused && !look.tint).then(|| {
            Rectangle
                .foreground_color(theme::LINE)
                .frame()
                .with_height(1)
                .padding(Edges::Leading, NAME_X)
        }),
    )
}

/// Add hop's field, while text is typed into it: what is typed, and how
/// many rows match it.
#[derive(Clone)]
pub(super) struct FieldLook {
    pub(super) text: String<16>,
    pub(super) found: usize,
    pub(super) m: &'static Metrics,
}

/// The field: a magnifier, what is typed and the caret, and how many rows
/// it finds. Built each time it is drawn.
pub(super) fn field_look(look: &FieldLook) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let mut found: String<12> = String::new();
    _ = core::fmt::write(&mut found, format_args!("{} found", look.found));
    HStack::new((
        Image::new(&icon::SEARCH)
            .as_template()
            .foreground_color(theme::TEXT_SECONDARY),
        line(look.text.clone(), &font::MONO, m.body, theme::TEXT).fixed_size(true, false),
        Rectangle
            .foreground_color(theme::ACCENT)
            .frame_sized(2, m.body),
        Spacer::default(),
        line(found, &font::MEDIUM, m.small, theme::TEXT_TERTIARY),
    ))
    .with_spacing(6)
    .hint_background_color(theme::ACTIVE_FIELD)
    .padding(Edges::Leading, 6)
    .padding(Edges::Trailing, 12)
    .frame()
    .with_height(FIELD)
    .background(
        Alignment::Center,
        RoundedRectangle::new(FIELD_RADIUS).foreground_color(theme::ACTIVE_FIELD),
    )
    .overlay(
        Alignment::Center,
        RoundedRectangle::new(FIELD_RADIUS)
            .stroked(2)
            .foreground_color(theme::ACCENT),
    )
    .padding(Edges::Horizontal, 8)
    .padding(Edges::Vertical, 3)
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
pub(super) struct TextLook {
    pub(super) label: &'static str,
    /// How many are held, of how many the router said it hears.
    pub(super) count: Option<(u8, Option<u8>)>,
    /// What it asked for is waited for.
    pub(super) busy: bool,
    pub(super) phase: u8,
    pub(super) focused: bool,
    pub(super) m: &'static Metrics,
}

pub(super) fn text_look(look: &TextLook) -> impl View<Rgb565, ()> + use<> {
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
