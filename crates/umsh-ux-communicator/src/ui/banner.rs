//! A card lying on the header and narrower than it, so the screen under it
//! still shows at both ends: a message that arrived in another chat, or
//! that the battery is low. It takes no input and goes by itself.

use buoyant::match_view;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::RgbColor;

use super::label;
use crate::board::Metrics;
use crate::model::{ChatSummary, Notice, State};
use crate::{font, icon, theme};

const WIDTH: u32 = 330;
/// The battery's card, which has less to say.
const BATTERY_WIDTH: u32 = 250;
const HEIGHT: u32 = 32;
/// The least margin from the screen's edges.
const MARGIN: u32 = 8;
const RADIUS: u16 = 11;
/// The size the header draws avatars at.
const AVATAR: u32 = 26;

/// What `notice` says.
pub fn view(state: &State, notice: Notice) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    match_view!(notice, {
        Notice::Message(chat) => state.chat(chat).map(|summary| message(m, summary)),
        Notice::BatteryLow { percent } => battery(m, percent),
    })
}

/// The chat as the list shows it: its name and last message.
fn message(m: &'static Metrics, summary: &ChatSummary) -> impl View<Rgb565, State> + use<> {
    card(
        m,
        HStack::new((
            super::avatar::view(&summary.avatar, AVATAR),
            HStack::new((
                super::line(summary.title(), &font::BOLD, m.secondary, theme::TEXT)
                    .fixed_size(true, false),
                label::<64>(
                    &summary.preview,
                    &font::REGULAR,
                    m.secondary,
                    theme::TEXT_SECONDARY,
                ),
                Spacer::default(),
            ))
            .with_spacing(8),
        ))
        .with_spacing(6),
        WIDTH,
    )
}

/// The battery is low, at `percent`.
fn battery(m: &'static Metrics, percent: u8) -> impl View<Rgb565, State> + use<> {
    let mut charge: heapless::String<4> = heapless::String::new();
    _ = core::fmt::write(&mut charge, format_args!("{percent}%"));
    card(
        m,
        HStack::new((
            Image::new(&icon::BATTERY_LOW)
                .as_template()
                .foreground_color(theme::AMBER),
            label::<16>("Battery low", &font::BOLD, m.secondary, theme::AMBER)
                .fixed_size(true, false),
            label::<4>(&charge, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY),
            Spacer::default(),
        ))
        .with_spacing(6),
        BATTERY_WIDTH,
    )
}

/// `content` on the card, `width` wide, centered on the header.
fn card<V: View<Rgb565, State>>(
    m: &'static Metrics,
    content: V,
    width: u32,
) -> impl View<Rgb565, State> + use<V> {
    content
        .padding(Edges::Leading, 4)
        .padding(Edges::Trailing, 10)
        .hint_background_color(theme::BANNER)
        .frame_sized(width.min(m.width - 2 * MARGIN), HEIGHT)
        .background(
            Alignment::Center,
            ZStack::new((
                RoundedRectangle::new(RADIUS)
                    .foreground_color(Rgb565::BLACK)
                    .offset(1, 2),
                RoundedRectangle::new(RADIUS).foreground_color(theme::BANNER),
                RoundedRectangle::new(RADIUS)
                    .stroked(1)
                    .foreground_color(theme::BANNER_LINE),
            )),
        )
        .padding(Edges::Top, m.strip + 1)
        .flex_infinite_width(HorizontalAlignment::Center)
        .flex_infinite_height(VerticalAlignment::Top)
}
