//! This node: who it is and its whole address, then its name, which
//! pressing edits in place, and its code. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use super::join::edited_name;
use super::member::detail_head;
use super::setting::{End, row};
use crate::model::State;
use crate::nav::{NameText, keys};
use crate::{font, theme};

const ROW: u32 = 36;
const ADDRESS: u32 = 22;
/// The address's inset from the screen's edges.
const INSET: u32 = 10;

pub fn view(state: &State, name: &NameText) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let called = state.status.device_name.as_str();
    super::list(
        VStack::new((
            detail_head(
                m,
                &state.node.avatar(),
                if called.is_empty() { "No name" } else { called },
                "This device",
                true,
            ),
            super::address(
                &state.node.address(),
                &font::REGULAR,
                m.small,
                theme::TEXT_SECONDARY,
                m.width - 2 * INSET,
                ADDRESS,
            )
            .padding(Edges::Leading, INSET),
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
    .with_scroll_step(ROW)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}
