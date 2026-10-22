//! Share: the code for this node or a joined channel, with what it is
//! beside it. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::label;
use crate::board::Metrics;
use crate::model::{ChatKind, Shareable, State};
use crate::nav::keys;
use crate::qr::{Owned, QrImage};
use crate::{font, theme};

/// The room the code takes: the screen's height below the header, less
/// what the name and its lines take beside it. The quiet zone is in
/// modules.
const fn room(m: &Metrics) -> u32 {
    let tall = below_header(m) - 8;
    let wide = m.width - INSET - GAP - TRAILING - COLUMN;
    if tall < wide { tall } else { wide }
}
const fn below_header(m: &Metrics) -> u32 {
    m.below_strip() - header(m)
}
/// The header, with the way back, on a board with touch: the keys' Back
/// is no sign of one on screen.
const fn header(m: &Metrics) -> u32 {
    if m.back { m.header } else { 0 }
}
const QUIET: u32 = 2;
const INSET: u32 = 8;
const GAP: u32 = 12;
const TRAILING: u32 = 4;
/// The least the name and its lines take beside the code.
const COLUMN: u32 = 156;
/// The name, and each line under it.
const NAME: u32 = 40;
const LINE: u32 = 20;

pub fn view(state: &State, shown: Shareable) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let mut name: String<32> = String::new();
    let mut lines: Vec<String<24>, 2> = Vec::new();
    match shown {
        Shareable::Identity => {
            _ = name.push_str(&state.status.device_name);
            let address = state.node.address();
            let (first, second) = address.split_at(address.len().min(22));
            _ = lines.push(String::try_from(first).unwrap_or_default());
            _ = lines.push(String::try_from(second).unwrap_or_default());
        }
        Shareable::Channel(chat) => {
            if let Some(chat) = state.chat(chat) {
                _ = name.push_str(&chat.name);
                if let ChatKind::Channel { access } = chat.kind {
                    _ = lines
                        .push(String::try_from(super::channel::kind(access)).unwrap_or_default());
                }
            }
        }
    }
    let code = state
        .node
        .share_uri(shown)
        .and_then(|uri| QrImage::encode(&uri, room(m), QUIET));
    let mono = matches!(shown, Shareable::Identity);
    VStack::new((
        m.back
            .then(|| super::conversation::header(m, "Share", None, None)),
        HStack::new((
            card(m, code),
            VStack::new((
                // Where focus rests, so the keys reach the screen.
                Button::new(
                    |_: &mut State| {},
                    move |_| {
                        label::<32>(&name, &font::BOLD, m.body, theme::TEXT)
                            .flex_infinite_width(HorizontalAlignment::Leading)
                            .frame()
                            .with_height(NAME)
                    },
                )
                .focus_key(keys::SHARE_CODE),
                lines.first().map(|line| about(m, line, mono)),
                lines.get(1).map(|line| about(m, line, mono)),
            ))
            .with_spacing(0)
            .with_alignment(HorizontalAlignment::Leading)
            .flex_infinite_width(HorizontalAlignment::Leading),
        ))
        .with_spacing(GAP)
        .with_alignment(VerticalAlignment::Top)
        .padding(Edges::Leading, INSET)
        .padding(Edges::Trailing, TRAILING),
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

/// A line under the name: the address, set in monospace so its two halves
/// line up, or what kind of channel it is.
fn about(m: &'static Metrics, line: &str, mono: bool) -> impl View<Rgb565, State> + use<> {
    label::<24>(
        line,
        if mono { &font::MONO } else { &font::REGULAR },
        m.small,
        theme::TEXT_SECONDARY,
    )
    .frame()
    .with_height(LINE)
}

/// The code on its light card, centered in the room it has.
fn card(m: &'static Metrics, code: Option<QrImage>) -> impl View<Rgb565, State> + use<> {
    code.map(|code| {
        let quiet = QUIET * code.scale();
        Image::new(Owned(code))
            .padding(Edges::All, quiet)
            .background(
                Alignment::Center,
                RoundedRectangle::new(4).foreground_color(Rgb565::new(31, 63, 31)),
            )
    })
    .frame()
    .with_width(room(m))
    .with_height(below_header(m))
}
