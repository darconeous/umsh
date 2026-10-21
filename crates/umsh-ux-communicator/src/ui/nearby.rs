//! Add peer's Nearby: the devices that have Add peer open too, each by its
//! model and its color for this visit and nothing of whose it is, then
//! Enter an address and Show my code. The header shows this device's own
//! color. A device that asks to exchange opens a card over the list.
//! Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::header;
use super::label;
use super::member::{End, action};
use super::peers::{AVATAR, ROW, TEXT_X, focused_row};
use super::setting::{card, choice};
use crate::avatar::{Outline, PeerShape};
use crate::board::Metrics;
use crate::model::{Exchange, MAX_NEARBY, NearbyDevice, State};
use crate::nav::keys;
use crate::{font, icon, models, theme};

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; MAX_NEARBY] = {
    let mut a = [0; MAX_NEARBY];
    let mut i = 0;
    while i < MAX_NEARBY {
        a[i] = i;
        i += 1;
    }
    a
};

/// The header's glyph of this device, and the card's.
const SMALL: u32 = 26;
/// The section label's height, and how far it and the You mark sit in.
const LABEL: u32 = 26;
const INSET: u32 = 12;
/// The card asking to exchange.
const CARD_WIDTH: u32 = 330;
const CARD_HEAD: u32 = 56;

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let devices: Vec<NearbyDevice, MAX_NEARBY> = state.meet.devices.clone();
    let keys_of: Vec<_, MAX_NEARBY> = devices.iter().map(|d| keys::nearby(d.id)).collect();
    let count = devices.len();
    let asked = match state.meet.exchange {
        Exchange::Asked(device) => Some(device),
        _ => None,
    };
    VStack::new((
        header(m, "Add peer", None, None).overlay(
            Alignment::Trailing,
            state.meet.own_hue.map(|hue| you(m, hue)),
        ),
        label::<8>("Nearby", &font::BOLD, m.small, theme::TEXT_SECONDARY)
            .padding(Edges::Leading, INSET)
            .flex_infinite_width(HorizontalAlignment::Leading)
            .frame()
            .with_height(LABEL),
        super::list(
            VStack::new((
                ForEach::<MAX_NEARBY>::new_vertical(&INDICES[..count], move |&i| {
                    row(m, devices[i])
                })
                .keyed(move |&i| keys_of[i]),
                action(
                    m,
                    "Enter an address",
                    keys::ENTER_ADDRESS,
                    State::open_enter_address,
                    End::Chevron,
                ),
                action(
                    m,
                    "Show my code",
                    keys::SHOW_MY_CODE,
                    State::show_my_code,
                    End::Chevron,
                ),
            ))
            .with_spacing(0),
        ),
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
    .popover(asked.as_ref(), move |device| asked_card(m, *device))
    // A tap outside answers as Not now does.
    .on_blur(|s: &mut State| {
        s.answer_exchange(false);
        Dismissal::Dismiss
    })
}

/// This device's color for this visit, beside You.
fn you(m: &'static Metrics, hue: u8) -> impl View<Rgb565, State> + use<> {
    HStack::new((
        label::<4>("You", &font::SEMIBOLD, m.secondary, theme::TEXT_TERTIARY),
        glyph(hue, SMALL),
    ))
    .with_spacing(6)
    .padding(Edges::Trailing, INSET)
}

fn row(m: &'static Metrics, device: NearbyDevice) -> impl View<Rgb565, State> + use<> {
    let id = device.id;
    Button::new(
        move |s: &mut State| s.ask_to_exchange(id),
        move |button: ButtonState| {
            let focused = button.is_focused();
            focused_row(
                HStack::new((
                    label::<16>(
                        model_name(device.model),
                        if focused {
                            &font::BOLD
                        } else {
                            &font::SEMIBOLD
                        },
                        m.body,
                        theme::TEXT,
                    ),
                    Spacer::default(),
                    device.nearness.map(nearness),
                ))
                .with_spacing(8)
                .padding(Edges::Leading, TEXT_X)
                .padding(Edges::Trailing, 10)
                .frame()
                .with_height(ROW)
                .overlay(
                    Alignment::Leading,
                    glyph(device.hue, AVATAR).frame().with_width(TEXT_X),
                ),
                focused,
                m.width,
            )
        },
    )
}

/// The card a device asking to exchange opens: its model and color, and
/// the answers.
fn asked_card(m: &'static Metrics, device: NearbyDevice) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| String::try_from(text).unwrap_or_default();
    card(
        m,
        VStack::new((
            HStack::new((
                glyph(device.hue, AVATAR),
                VStack::new((
                    label::<16>(model_name(device.model), &font::BOLD, m.body, theme::TEXT),
                    label::<24>(
                        "Exchange contacts?",
                        &font::REGULAR,
                        m.secondary,
                        theme::TEXT_SECONDARY,
                    ),
                ))
                .with_alignment(HorizontalAlignment::Leading)
                .with_spacing(0),
                Spacer::default(),
            ))
            .with_spacing(10)
            .padding(Edges::Horizontal, INSET)
            .frame()
            .with_height(CARD_HEAD),
            choice(
                m,
                text("Exchange"),
                keys::EXCHANGE_ACCEPT,
                |s| s.answer_exchange(true),
                theme::TEXT,
                None,
            ),
            choice(
                m,
                text("Not now"),
                keys::EXCHANGE_DECLINE,
                |s| s.answer_exchange(false),
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        CARD_WIDTH,
        HorizontalAlignment::Center,
        |s| s.answer_exchange(false),
    )
}

/// What a device is called by its model.
pub(super) fn model_name(model: u16) -> &'static str {
    models::name(model).unwrap_or("Device")
}

/// A device before anything is exchanged: its color for this visit, and
/// the outline of a handheld, never an avatar. `size` is a row's avatar or
/// a header's.
pub(super) fn glyph(hue: u8, size: u32) -> impl View<Rgb565, State> + use<> {
    let outline = if size == AVATAR {
        &icon::HANDHELD_34
    } else {
        &icon::HANDHELD_26
    };
    ZStack::new((
        Outline::Peer(PeerShape::Circle).mask(size).map(|mask| {
            Image::new(mask)
                .as_template()
                .foreground_color(theme::session(hue))
        }),
        Image::new(outline)
            .as_template()
            .foreground_color(theme::BACKGROUND),
    ))
    .frame()
    .with_width(size)
    .with_height(size)
}

/// How near a device seems: the arcs lit from the inside out, `near` of
/// three.
fn nearness(near: u8) -> impl View<Rgb565, State> + use<> {
    let arc = |shown: u8| {
        if near >= shown {
            theme::ACCENT
        } else {
            theme::NEAR_UNLIT
        }
    };
    ZStack::new((
        Image::new(&icon::NEAR_DOT)
            .as_template()
            .foreground_color(theme::ACCENT),
        Image::new(&icon::NEAR_1)
            .as_template()
            .foreground_color(arc(1)),
        Image::new(&icon::NEAR_2)
            .as_template()
            .foreground_color(arc(2)),
        Image::new(&icon::NEAR_3)
            .as_template()
            .foreground_color(arc(3)),
    ))
}
