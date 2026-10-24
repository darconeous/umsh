//! The radio profiles the radio can be set to, one to a row. Pressing one
//! sets it; Backspace goes back. First run and Device › Radio › Profile
//! both show this list.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::LazyForEach;
use buoyant::view::lazy_foreach::Extent;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use super::conversation::header;
use super::setting::{End, row};
use crate::model::State;
use crate::nav::keys;

const ROW: u32 = 36;
/// The most rows the list builds at once: those the view shows and some
/// way beyond, wherever it is scrolled to.
const PROFILE_ROWS: usize = 16;

/// The list under `title`.
pub fn view(state: &State, title: &'static str) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let node = state.node;
    VStack::new((
        header(m, title, None, None),
        super::list(
            LazyForEach::<PROFILE_ROWS>::new_vertical(
                node.profile_count(),
                Extent::Fixed(ROW),
                move |index| {
                    row(
                        m,
                        node.profile(index).unwrap_or_default(),
                        keys::profile(index),
                        move |s: &mut State| s.choose_profile(index),
                        End::Nothing,
                        false,
                        ROW,
                    )
                },
            )
            .keyed(keys::profile),
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
