//! A contact exchange with a device from Nearby, in Nearby's place: the
//! code both holders compare, Same and Different, waiting for the other
//! holder, and how it ended. Backspace backs out.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, FocusKey};
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::{ARROW_GAP, back};
use super::label;
use super::nearby::{glyph, model_name};
use crate::board::Metrics;
use crate::model::{Exchange, ExchangeEnd, NearbyDevice, State};
use crate::nav::keys;
use crate::{font, icon, theme};

/// The header's glyph of the other device.
const GLYPH: u32 = 26;
const LEADING: u32 = 10;
/// The two buttons side by side: each at most this wide, this tall, and
/// this far apart.
const BUTTON: u32 = 180;
const BUTTON_HEIGHT: u32 = 36;
const BUTTON_GAP: u32 = 16;
const RADIUS: u16 = 10;
/// The waiting dots.
const DOT: u32 = 5;

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let with = state.meet.with;
    let name = with.map_or("", |device| model_name(device.model));
    let body = match &state.meet.exchange {
        Exchange::Asking(_) | Exchange::Accepted(_) => Body::Waiting,
        Exchange::Comparing { code, sent, .. } => Body::Code {
            code: *code,
            sent: *sent,
        },
        Exchange::Ended(ExchangeEnd::Different) => Body::Ended("Codes differ. Nothing saved."),
        Exchange::Ended(_) => Body::Ended("Not exchanged. Nothing saved."),
        Exchange::Closed
        | Exchange::Opening
        | Exchange::Idle
        | Exchange::Asked(_)
        | Exchange::Exchanged(_) => Body::Nothing,
    };
    VStack::new((
        device_header(m, with),
        buoyant::match_view!(body, {
            Body::Waiting => waiting(m, name)
                .flex_infinite_height(VerticalAlignment::Center),
            Body::Code { code, sent } => compare(m, code, sent, name),
            Body::Ended(text) => ended(m, text),
            Body::Nothing => Spacer::default(),
        }),
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

#[derive(Clone, Copy)]
enum Body {
    Waiting,
    Code { code: u32, sent: bool },
    Ended(&'static str),
    Nothing,
}

/// The other device, by its color and model, exchanging.
fn device_header(
    m: &'static Metrics,
    with: Option<NearbyDevice>,
) -> impl View<Rgb565, State> + use<> {
    HStack::new((
        back(m, |s| _ = s.back()),
        HStack::new((
            with.map(|device| glyph(device.hue, GLYPH)),
            with.map(|device| {
                label::<16>(model_name(device.model), &font::BOLD, m.body, theme::TEXT)
                    .fixed_size(true, false)
            }),
            label::<16>("Exchanging", &font::MEDIUM, m.small, theme::TEXT_TERTIARY),
            Spacer::default(),
        ))
        .with_spacing(6),
    ))
    .with_spacing(ARROW_GAP)
    .padding(Edges::Leading, if m.back { 0 } else { LEADING })
    .frame()
    .with_height(m.header)
    .overlay(
        Alignment::Bottom,
        Rectangle
            .foreground_color(theme::LINE)
            .frame()
            .with_height(1),
    )
}

/// The code, the question, and Same and Different, or once Same is
/// pressed, that the other holder is awaited.
fn compare(
    m: &'static Metrics,
    code: u32,
    sent: bool,
    name: &'static str,
) -> impl View<Rgb565, State> + use<> {
    let mut digits: String<8> = String::new();
    _ = core::fmt::write(
        &mut digits,
        format_args!("{:03} {:03}", code / 1000, code % 1000),
    );
    VStack::new((
        Spacer::default(),
        Text::new(digits, &font::CODE)
            .with_font_size(code_size(m))
            .with_line_limit(1)
            .foreground_color(theme::TEXT),
        label::<32>(
            "Same code on the other screen?",
            &font::MEDIUM,
            m.secondary,
            theme::TEXT_SECONDARY,
        ),
        Spacer::default(),
        buoyant::match_view!(sent, {
            false => buttons(
                m,
                ("Same", keys::SAME, |s| s.confirm_code(true)),
                ("Different", keys::DIFFERENT, |s| s.confirm_code(false)),
            ),
            true => HStack::new((
                Image::new(&icon::CHECK)
                    .as_template()
                    .foreground_color(theme::GREEN),
                label::<8>("Same", &font::BOLD, m.body, theme::GREEN),
                Spacer::default().frame().with_width(BUTTON_GAP),
                waiting(m, name),
            ))
            .with_spacing(4)
            .frame()
            .with_height(BUTTON_HEIGHT),
        }),
    ))
    .with_spacing(4)
    .padding(Edges::Bottom, 10)
}

/// Waiting for the other device, with the dots of something under way.
fn waiting(m: &'static Metrics, name: &'static str) -> impl View<Rgb565, State> + use<> {
    let mut text: String<32> = String::new();
    _ = text.push_str("Waiting for ");
    _ = text.push_str(name);
    let dot = |color| Circle.foreground_color(color).frame_sized(DOT, DOT);
    HStack::new((
        label::<32>(&text, &font::MEDIUM, m.body, theme::TEXT_SECONDARY),
        HStack::new((
            dot(theme::TEXT_SECONDARY),
            dot(theme::TEXT_SECONDARY),
            dot(theme::NEAR_UNLIT),
        ))
        .with_spacing(4),
    ))
    .with_spacing(10)
}

/// How an exchange ended without contacts crossing, with Try again and
/// Done.
fn ended(m: &'static Metrics, text: &'static str) -> impl View<Rgb565, State> + use<> {
    VStack::new((
        Spacer::default(),
        Image::new(&icon::WARNING_LARGE)
            .as_template()
            .foreground_color(theme::RED),
        label::<32>(text, &font::SEMIBOLD, m.body, theme::TEXT),
        Spacer::default(),
        buttons(
            m,
            ("Try again", keys::TRY_AGAIN, State::try_again),
            ("Done", keys::DONE, |s| _ = s.back()),
        ),
    ))
    .with_spacing(6)
    .padding(Edges::Bottom, 10)
}

/// Two choices side by side; turning moves between them.
fn buttons(
    m: &'static Metrics,
    first: (&'static str, FocusKey, fn(&mut State)),
    second: (&'static str, FocusKey, fn(&mut State)),
) -> impl View<Rgb565, State> + use<> {
    let width = BUTTON.min((m.width - 3 * BUTTON_GAP) / 2);
    HStack::new((button(m, first, width), button(m, second, width))).with_spacing(BUTTON_GAP)
}

fn button(
    m: &'static Metrics,
    (text, key, act): (&'static str, FocusKey, fn(&mut State)),
    width: u32,
) -> impl View<Rgb565, State> + use<> {
    Button::new(act, move |button: ButtonState| {
        let focused = button.is_focused();
        let (fill, ring, stroke, color, face) = if focused {
            (theme::FOCUS, theme::ACCENT, 2, theme::ACCENT, &font::BOLD)
        } else {
            (
                theme::FIELD,
                theme::MENU_LINE,
                1,
                theme::TEXT_SECONDARY,
                &font::MEDIUM,
            )
        };
        label::<16>(text, face, m.body, color)
            .hint_background_color(fill)
            .frame()
            .with_width(width)
            .with_height(BUTTON_HEIGHT)
            .background(
                Alignment::Center,
                ZStack::new((
                    RoundedRectangle::new(RADIUS).foreground_color(fill),
                    RoundedRectangle::new(RADIUS)
                        .stroked(stroke)
                        .foreground_color(ring),
                )),
            )
    })
    .focus_key(key)
}

/// The code's size: the T-Deck's, or the Pager's on its finer panel.
const fn code_size(m: &Metrics) -> u32 {
    if m.title >= 26 { 42 } else { 32 }
}
