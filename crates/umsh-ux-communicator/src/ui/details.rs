//! How a message reached this device: the rows of the iOS details sheet
//! that a reader on a communicator needs, and who reacted to it. The wheel
//! scrolls through them; Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::{label, line};
use crate::board::Metrics;
use crate::model::{Details, MAX_REACTORS, Reactor, State};
use crate::nav::keys;
use crate::{font, icon, theme};

const ROW: u32 = 36;
const INSET: u32 = 12;
/// The caption over the reactions.
const CAPTION: u32 = 30;
const AVATAR: u32 = 26;
/// A reactor's name, past their avatar.
const NAME_X: u32 = INSET + AVATAR + 10;

static INDICES: [usize; MAX_REACTORS] = {
    let mut a = [0; MAX_REACTORS];
    let mut i = 0;
    while i < MAX_REACTORS {
        a[i] = i;
        i += 1;
    }
    a
};

/// `time` is when the message was sent or received, in local time.
pub fn view(
    m: &'static Metrics,
    details: &Details,
    inbound: bool,
    time: Option<String<8>>,
) -> impl View<Rgb565, State> + use<> {
    let details = details.clone();
    VStack::new((
        header(m, "Message details", None, None),
        super::list(
            // One focusable block, which the wheel scrolls a row at a time.
            Button::new(
                |_: &mut State| {},
                move |_| rows(m, &details, inbound, time.as_ref()),
            )
            .focus_key(keys::DETAIL_LIST),
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

/// The rows for what is known.
fn rows(
    m: &'static Metrics,
    details: &Details,
    inbound: bool,
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
        inbound.then(|| {
            let source = if details.authenticated {
                "Authenticated"
            } else {
                "Not authenticated"
            };
            row(m, "Source", source, false)
        }),
        (!details.reactors.is_empty()).then(|| {
            label::<16>("Reactions", &font::BOLD, m.small, theme::TEXT_SECONDARY)
                .padding(Edges::Leading, INSET)
                .flex_infinite_width(HorizontalAlignment::Leading)
                .frame()
                .with_height(CAPTION)
                .with_alignment(Alignment::BottomLeading)
        }),
        {
            let reactors = details.reactors.clone();
            ForEach::<MAX_REACTORS>::new_vertical(&INDICES[..reactors.len()], move |&i| {
                reactor(m, &reactors[i])
            })
            .with_spacing(0)
        },
    ))
    .with_spacing(0)
    // The whole block, so it scrolls from its first row's top.
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
        Image::new(icon::reaction(reactor.reaction, icon::Pad::Screen)),
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
