//! Sounds: whether the device plays them, and how loud, which pressing
//! Volume lets turning change until it is pressed again.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use super::setting::{End, page, row};
use crate::model::{State, volume_level};
use crate::nav::keys;

const ROW: u32 = 36;

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let on = state.node.sound_enabled().unwrap_or(false);
    let level = volume_level(state.node.sound_volume());
    let active = state.adjusting_volume();
    page(
        m,
        "Sounds",
        VStack::new((
            row(
                m,
                "Sounds",
                keys::SOUNDS_ENABLED,
                State::toggle_sound,
                End::Switch(on),
                false,
                ROW,
            ),
            row(
                m,
                "Volume",
                keys::VOLUME,
                State::press_volume,
                End::Level {
                    level,
                    active,
                    step: State::step_volume,
                },
                false,
                ROW,
            ),
        ))
        .with_spacing(0),
    )
}
