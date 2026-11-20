//! Trackball: whether rolling it up and down, and left and right, acts.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use crate::model::State;

#[cfg(feature = "directional")]
const ROW: u32 = 36;

#[cfg(feature = "directional")]
pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    use super::setting::{End, page, row};
    use crate::model::Directions;
    use crate::nav::keys;

    let m = state.metrics();
    let directions = state.node.directions();
    page(
        m,
        "Trackball",
        VStack::new((
            row(
                m,
                "Up and Down",
                keys::TRACKBALL_VERTICAL,
                State::toggle_trackball_vertical,
                End::Switch(directions.contains(Directions::VERTICAL)),
                false,
                ROW,
            ),
            row(
                m,
                "Left and Right",
                keys::TRACKBALL_HORIZONTAL,
                State::toggle_trackball_horizontal,
                End::Switch(directions.contains(Directions::HORIZONTAL)),
                false,
                ROW,
            ),
        ))
        .with_spacing(0),
    )
}

/// Nothing: a build without a trackball has no row that opens it.
#[cfg(not(feature = "directional"))]
pub fn view(_state: &State) -> impl View<Rgb565, State> + use<> {
    EmptyView
}
