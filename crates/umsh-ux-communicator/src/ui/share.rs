//! Share: the code for this node or a joined channel, with what it is
//! beside it, over the whole screen. A tap anywhere, a press, or Backspace
//! goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::label;
use crate::board::Metrics;
use crate::model::{ChatKind, Shareable, State};
use crate::nav::keys;
use crate::qr::{Owned, QrImage};
use crate::{font, theme};

/// The room the code takes: the screen's height below the strip, less what
/// the name and its lines take beside it. The quiet zone is in modules.
const fn room(m: &Metrics) -> u32 {
    let tall = m.below_strip() - 2 * MARGIN;
    let wide = m.width - INSET - GAP - TRAILING - COLUMN;
    if tall < wide { tall } else { wide }
}
/// The column beside the code.
const fn column(m: &Metrics) -> u32 {
    m.width - INSET - room(m) - GAP - TRAILING
}
const QUIET: u32 = 2;
/// The code's least margin above and below.
const MARGIN: u32 = 4;
const INSET: u32 = 8;
const GAP: u32 = 12;
const TRAILING: u32 = 4;
/// The least the name and its lines take beside the code: an address in
/// three lines.
const COLUMN: u32 = 100;
/// The name, and each line under it.
const NAME: u32 = 40;
const LINE: u32 = 20;

pub fn view(state: &State, shown: Shareable) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let mut name: String<32> = String::new();
    let mut address = None;
    let mut kind = None;
    match shown {
        Shareable::Identity => {
            _ = name.push_str(&state.status.device_name);
            address = Some(state.node.address());
        }
        Shareable::Channel(chat) => {
            if let Some(chat) = state.chat(chat) {
                _ = name.push_str(&chat.name);
                if let ChatKind::Channel { access } = chat.kind {
                    kind = Some(super::channel::kind(access));
                }
            }
        }
    }
    let code = state
        .node
        .share_uri(shown)
        .and_then(|uri| QrImage::encode(&uri, room(m), QUIET));
    // One button over the whole screen, which focus rests on.
    Button::new(
        |s: &mut State| {
            s.back();
        },
        move |_| {
            HStack::new((
                card(m, code.clone()),
                VStack::new((
                    label::<32>(&name, &font::BOLD, m.body, theme::TEXT)
                        .frame()
                        .with_height(NAME),
                    address.as_ref().map(|address| {
                        super::address(
                            address,
                            &font::MONO,
                            m.small,
                            theme::TEXT_SECONDARY,
                            column(m),
                            LINE,
                        )
                    }),
                    kind.map(|kind| {
                        label::<24>(kind, &font::REGULAR, m.small, theme::TEXT_SECONDARY)
                            .frame()
                            .with_height(LINE)
                    }),
                ))
                .with_spacing(0)
                .with_alignment(HorizontalAlignment::Leading)
                .flex_infinite_width(HorizontalAlignment::Leading),
            ))
            .with_spacing(GAP)
            .with_alignment(VerticalAlignment::Center)
            .padding(Edges::Leading, INSET)
            .padding(Edges::Trailing, TRAILING)
            .flex_infinite_width(HorizontalAlignment::Leading)
            .flex_infinite_height(VerticalAlignment::Center)
            // All of it takes the touch.
            .content_shape(Rectangle)
        },
    )
    .focus_key(keys::SHARE_CODE)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
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
    .with_height(m.below_strip())
}
