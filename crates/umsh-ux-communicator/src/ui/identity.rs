//! This node: its title, as a chat's header shows a peer, over its whole
//! address, its name, which pressing edits in place, and its code. The
//! title stays as the rest scrolls under it. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use super::conversation::titled;
use super::join::edited_name;
use super::setting::{End, row};
use crate::model::State;
use crate::nav::{NameText, keys};
use crate::{font, theme};

const ROW: u32 = 36;
const ADDRESS: u32 = 22;
/// The address's inset from the screen's edges, and its room above.
const INSET: u32 = 10;
const GAP: u32 = 6;

pub fn view(state: &State, name: &NameText) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let called = state.status.device_name.as_str();
    VStack::new((
        titled(
            m,
            if called.is_empty() { "No name" } else { called },
            theme::TEXT,
            Some(&state.node.avatar()),
            "This device",
        ),
        super::list(
            VStack::new((
                super::address(
                    &state.node.address(),
                    &font::REGULAR,
                    m.small,
                    theme::TEXT_SECONDARY,
                    m.width - 2 * INSET,
                    ADDRESS,
                )
                .padding(Edges::Leading, INSET)
                .padding(Edges::Top, GAP),
                edited_name(
                    m,
                    name,
                    State::identity_name_mut,
                    State::identity_name_active,
                    keys::IDENTITY_NAME,
                ),
                row(
                    m,
                    "View QR code",
                    keys::IDENTITY_CODE,
                    State::open_identity_code,
                    End::Chevron,
                    false,
                    ROW,
                ),
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
