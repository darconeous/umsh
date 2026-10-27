//! How a message reached this device, or which repeaters carried mine:
//! the rows of the iOS details sheet that a reader on a communicator needs,
//! and who reacted to it. The wheel scrolls through them, and stops on each
//! repeater, which a press opens or asks who it is; Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::header;
use super::member::action_look;
use super::{label, line};
use crate::board::Metrics;
use crate::model::{Details, MAX_REACTORS, MAX_REPEATERS, Reactor, Repeater, State};
use crate::nav::{SPIN_PHASES, keys};
use crate::{font, icon, theme};

const ROW: u32 = 36;
pub(super) const INSET: u32 = 12;
/// The caption over the reactions.
const CAPTION: u32 = 30;
pub(super) const AVATAR: u32 = 26;
/// A reactor's name, past their avatar.
pub(super) const NAME_X: u32 = INSET + AVATAR + 10;

// The repeaters are counted off the same indices.
const _: () = assert!(MAX_REPEATERS <= MAX_REACTORS);

static INDICES: [usize; MAX_REACTORS] = {
    let mut a = [0; MAX_REACTORS];
    let mut i = 0;
    while i < MAX_REACTORS {
        a[i] = i;
        i += 1;
    }
    a
};

/// The spinner of a repeater asked who it is: its dots' ring, and each
/// dot's size.
const SPINNER: i32 = 8;
const SPINNER_DOT: u32 = 4;
/// The ring's diagonal places, along each axis.
const SPINNER_DIAGONAL: i32 = 6;

/// `time` is when the message was sent or received, in local time. A
/// message in a direct chat (`direct`) says whether it had forward secrecy;
/// one received in a channel, that its sender is not verified. The
/// repeaters `identifying` were asked who they are, and spin at `phase`.
pub fn view(
    m: &'static Metrics,
    details: &Details,
    inbound: bool,
    direct: bool,
    time: Option<String<8>>,
    identifying: &[[u8; 2]],
    phase: u8,
) -> impl View<Rgb565, State> + use<> {
    // The rows above the repeaters' have no need of them.
    let mut details = details.clone();
    let repeaters = core::mem::take(&mut details.repeaters);
    let waiting: Vec<bool, MAX_REPEATERS> = repeaters
        .iter()
        .map(|repeater| identifying.contains(&repeater.hint))
        .collect();
    let anonymous = details.anonymous;
    // A name matched by a hint may be another node's.
    let matched = repeaters.iter().any(|repeater| repeater.address.is_some());
    let repeated = !repeaters.is_empty() || anonymous > 0;
    VStack::new((
        header(m, "Message details", None, None),
        super::list(
            VStack::new((
                // One focusable block, which the wheel scrolls a row at a
                // time.
                Button::new(
                    |_: &mut State| {},
                    move |_| rows(m, &details, inbound, direct, repeated, time.as_ref()),
                )
                .focus_key(keys::DETAIL_LIST),
                ForEach::<MAX_REPEATERS>::new_vertical(&INDICES[..repeaters.len()], move |&i| {
                    repeater(m, i, &repeaters[i], waiting[i], phase)
                })
                .keyed(|&i| keys::repeater(i))
                .with_spacing(0),
                (anonymous > 0 || matched).then(|| {
                    Button::new(|_: &mut State| {}, move |_| unnamed(m, anonymous, matched))
                        .focus_key(keys::DETAIL_NOTE)
                }),
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

/// The rows for what is known, captioned for the repeaters under them
/// when mine was `repeated`.
fn rows(
    m: &'static Metrics,
    details: &Details,
    inbound: bool,
    direct: bool,
    repeated: bool,
    time: Option<&String<8>>,
) -> impl View<Rgb565, State> + use<> {
    let text = |value: core::fmt::Arguments| {
        let mut s: String<24> = String::new();
        _ = core::fmt::write(&mut s, value);
        s
    };
    // A true minus, as the mockup sets it.
    let minus = |negative: bool| if negative { "\u{2212}" } else { "" };
    VStack::new((
        time.map(|time| row(m, if inbound { "Received" } else { "Sent" }, time, false)),
        details
            .hops
            .map(|hops| row(m, "Hops", &text(format_args!("{hops}")), false)),
        (!details.route.is_empty())
            .then(|| row(m, "Route", &text(format_args!("{}", details.route)), false)),
        details.rssi.map(|rssi| {
            let value = text(format_args!(
                "{}{} dBm",
                minus(rssi < 0),
                rssi.unsigned_abs()
            ));
            row(m, "Signal", &value, false)
        }),
        details.snr.map(|tenths| {
            let (sign, tenths) = (minus(tenths < 0), tenths.unsigned_abs());
            let value = text(format_args!("{sign}{}.{} dB", tenths / 10, tenths % 10));
            row(m, "Signal-to-noise", &value, false)
        }),
        // A channel message only claims its sender: anyone who holds the
        // channel's key could have sent it.
        (inbound && !direct).then(|| row(m, "Sender", "Not verified", false)),
        direct.then(|| {
            row(
                m,
                "Forward secrecy",
                if details.forward_secret { "Yes" } else { "No" },
                false,
            )
        }),
        (!details.reactors.is_empty()).then(|| caption(m, "Reactions")),
        {
            let reactors = details.reactors.clone();
            ForEach::<MAX_REACTORS>::new_vertical(&INDICES[..reactors.len()], move |&i| {
                reactor(m, &reactors[i])
            })
            .with_spacing(0)
        },
        repeated.then(|| caption(m, "Repeated by")),
    ))
    .with_spacing(0)
    // The whole block, so it scrolls from its first row's top.
    .content_shape(Rectangle)
}

/// The caption over a section of rows.
fn caption(m: &'static Metrics, text: &'static str) -> impl View<Rgb565, State> + use<> {
    label::<16>(text, &font::BOLD, m.small, theme::TEXT_SECONDARY)
        .padding(Edges::Leading, INSET)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(CAPTION)
        .with_alignment(Alignment::BottomLeading)
}

/// A repeater heard carrying mine, the `index`th: a press opens the node it
/// most plausibly is, or asks who it is when none is known. It spins while
/// `waiting` on the answer.
fn repeater(
    m: &'static Metrics,
    index: usize,
    repeater: &Repeater,
    waiting: bool,
    phase: u8,
) -> impl View<Rgb565, State> + use<> {
    let repeater = repeater.clone();
    Button::new(
        move |s: &mut State| s.open_repeater(index),
        move |button: ButtonState| {
            Lazy::new(
                (repeater.clone(), button.is_focused(), waiting, phase, m),
                repeater_look,
            )
        },
    )
}

/// A repeater's row: its avatar and name, as a reactor's are, and at its
/// end where a press goes.
///
/// Built from the repeater each time it is drawn ([`Lazy`]): kept in the
/// render trees, every row's would outweigh the rest of the screen.
pub(super) fn repeater_look(
    (repeater, focused, waiting, phase, m): &(Repeater, bool, bool, u8, &'static Metrics),
) -> impl View<Rgb565, ()> + use<> {
    let known = repeater.address.is_some();
    let face = if *focused {
        &font::SEMIBOLD
    } else {
        &font::REGULAR
    };
    action_look(
        HStack::new((
            line(repeater.name.clone(), face, m.body, theme::TEXT),
            Spacer::default(),
            known.then(|| {
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY)
            }),
            (!known && !*waiting).then(|| {
                Image::new(&icon::SEARCH)
                    .as_template()
                    .foreground_color(theme::ACCENT)
            }),
            (!known && *waiting).then(|| spinner(*phase)),
        ))
        .with_spacing(8)
        .padding(Edges::Leading, NAME_X - 4)
        .overlay(
            Alignment::Leading,
            super::avatar::view(&repeater.avatar, AVATAR).padding(Edges::Leading, INSET - 4),
        ),
        *focused,
    )
}

/// A ring of dots, the one at `phase` lit and the two before it fading.
pub(super) fn spinner<C>(phase: u8) -> impl View<Rgb565, C> + use<C> {
    // Each dot's place on the ring, clockwise from the top.
    const AT: [(i32, i32); SPIN_PHASES as usize] = [
        (0, -SPINNER),
        (SPINNER_DIAGONAL, -SPINNER_DIAGONAL),
        (SPINNER, 0),
        (SPINNER_DIAGONAL, SPINNER_DIAGONAL),
        (0, SPINNER),
        (-SPINNER_DIAGONAL, SPINNER_DIAGONAL),
        (-SPINNER, 0),
        (-SPINNER_DIAGONAL, -SPINNER_DIAGONAL),
    ];
    let dot = move |i: u8| {
        let behind = (phase + SPIN_PHASES - i) % SPIN_PHASES;
        let color = match behind {
            0 => theme::ACCENT,
            1 | 2 => theme::TEXT_SECONDARY,
            _ => theme::TEXT_TERTIARY,
        };
        let (x, y) = AT[usize::from(i)];
        Circle
            .foreground_color(color)
            .frame_sized(SPINNER_DOT, SPINNER_DOT)
            .offset(x, y)
    };
    ZStack::new((
        dot(0),
        dot(1),
        dot(2),
        dot(3),
        dot(4),
        dot(5),
        dot(6),
        dot(7),
    ))
    .frame_sized(
        2 * SPINNER as u32 + SPINNER_DOT,
        2 * SPINNER as u32 + SPINNER_DOT,
    )
}

/// What is said under the repeaters: how many named none, and that a
/// `matched` name may be another node's.
fn unnamed(m: &'static Metrics, anonymous: u16, matched: bool) -> impl View<Rgb565, State> + use<> {
    let mut count: String<8> = String::new();
    _ = core::fmt::write(&mut count, format_args!("{anonymous}"));
    VStack::new((
        (anonymous > 0).then(|| row(m, "Unidentified", &count, false)),
        matched.then(|| {
            label::<48>(
                "Names are matched by hint and may be wrong.",
                &font::REGULAR,
                m.small,
                theme::TEXT_TERTIARY,
            )
            .padding(Edges::Leading, INSET)
            .flex_infinite_width(HorizontalAlignment::Leading)
            .frame()
            .with_height(CAPTION)
        }),
    ))
    .with_spacing(0)
    .content_shape(Rectangle)
}

/// Someone's reaction: who, and the glyph for it.
fn reactor(m: &'static Metrics, reactor: &Reactor) -> impl View<Rgb565, State> + use<> {
    let name = |text| line(text, &font::REGULAR, m.body, theme::TEXT);
    HStack::new((
        reactor.name.clone().map(name),
        reactor
            .name
            .is_none()
            .then(|| line("You", &font::REGULAR, m.body, theme::TEXT)),
        Spacer::default(),
        super::conversation::face(reactor.reaction, m.body, theme::BACKGROUND),
    ))
    .with_spacing(8)
    .padding(Edges::Leading, NAME_X)
    .padding(Edges::Trailing, 14)
    .frame()
    .with_height(ROW)
    .overlay(
        Alignment::Leading,
        super::avatar::view(&reactor.avatar, AVATAR).padding(Edges::Leading, INSET),
    )
}

/// A labeled value, with a rule under it. A `muted` label is for a value
/// not known yet.
pub(super) fn row(
    m: &'static Metrics,
    name: &'static str,
    value: &str,
    muted: bool,
) -> impl View<Rgb565, State> + use<> {
    let color = if muted {
        theme::TEXT_TERTIARY
    } else {
        theme::TEXT
    };
    HStack::new((
        label::<16>(name, &font::REGULAR, m.body, color),
        Spacer::default(),
        label::<48>(value, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY),
    ))
    .with_spacing(8)
    .padding(Edges::Leading, INSET)
    .padding(Edges::Trailing, 14)
    .frame()
    .with_height(ROW)
    .overlay(
        Alignment::Bottom,
        Rectangle
            .foreground_color(theme::LINE)
            .frame()
            .with_height(1)
            .padding(Edges::Leading, INSET),
    )
}
