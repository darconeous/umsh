//! The status strip: device name, time, and the few indicators worth a
//! permanent place.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::label;
use crate::board::Metrics;
use crate::keyboard::Latch;
use crate::model::{Bluetooth, Gnss, State, StatusStrip, Wifi};
use crate::{font, icon, theme};

/// The strip; on first run, the battery alone, there being no name or
/// time yet to show. The battery shows only where its charge is known.
/// Shift's and Alt's states come first among the indicators, in the
/// keyboard's order. The time is the local time, while
/// the clock is known; the lock screen leaves it out to show it larger.
pub fn view(
    m: &'static Metrics,
    s: &StatusStrip,
    setup: bool,
    (shift, alt): (Latch, Latch),
    time: Option<String<8>>,
) -> impl View<Rgb565, State> + use<> {
    let shown = !setup;
    ZStack::new((
        // One stack, not a stack of indicators inside it: see `root_view`.
        HStack::new((
            shown.then(|| {
                label::<24>(
                    &s.device_name,
                    &font::SEMIBOLD,
                    m.small,
                    theme::TEXT_SECONDARY,
                )
            }),
            Spacer::default(),
            modifier(alt, &icon::ALT_ONCE, &icon::ALT_LOCK, theme::ALT),
            modifier(shift, &icon::SHIFT_ONCE, &icon::SHIFT_LOCK, theme::TEXT),
            (shown && s.silent).then(|| indicator(&icon::BELL_SLASH)),
            s.wifi.filter(|_| shown).map(|wifi| {
                indicator(match wifi {
                    Wifi::Disconnected => &icon::WIFI_LOST,
                    Wifi::Joining => &icon::WIFI_JOINING,
                    Wifi::Connected => &icon::WIFI,
                })
            }),
            s.bluetooth.filter(|_| shown).map(bluetooth),
            s.gnss.filter(|_| shown).map(|gnss| {
                indicator(match gnss {
                    Gnss::Searching => &icon::GNSS_SEARCHING,
                    Gnss::Fixed => &icon::GNSS,
                })
            }),
            s.charging.then(|| indicator(&icon::BOLT)),
            // Only a charge that can be told: charging without one shows
            // the bolt alone.
            s.battery_percent
                .map(|_| battery(s.battery_segments, s.battery_low)),
        ))
        .with_spacing(3)
        .padding(Edges::Horizontal, 8),
        time.filter(|_| shown)
            .map(|time| label::<8>(&time, &font::BOLD, m.small, theme::TEXT)),
    ))
    .frame()
    .with_height(m.strip)
    .background_color(theme::CHROME, Rectangle)
}

type Mask = embedded_graphics::image::ImageRaw<'static, embedded_graphics::pixelcolor::Gray4>;

/// A modifier armed for one key, or locked.
fn modifier(
    latch: Latch,
    once: &'static Mask,
    locked: &'static Mask,
    color: Rgb565,
) -> Option<impl View<Rgb565, State> + use<>> {
    let image = match latch {
        Latch::Off => return None,
        Latch::Once => once,
        Latch::Locked => locked,
    };
    Some(Image::new(image).as_template().foreground_color(color))
}

fn indicator(image: &'static Mask) -> impl View<Rgb565, State> + use<> {
    Image::new(image)
        .as_template()
        .foreground_color(theme::TEXT_SECONDARY)
}

/// The rune, flanked while a phone is connected, and in the accent color
/// while a pairing window is open.
fn bluetooth(state: Bluetooth) -> impl View<Rgb565, State> + use<> {
    let (image, color) = match state {
        Bluetooth::Waiting => (&icon::BLUETOOTH, theme::TEXT_SECONDARY),
        Bluetooth::Connected => (&icon::BLUETOOTH_LINKED, theme::TEXT_SECONDARY),
        Bluetooth::Pairing => (&icon::BLUETOOTH, theme::ACCENT),
    };
    Image::new(image).as_template().foreground_color(color)
}

/// A battery outline with up to three charge segments, and its terminal,
/// amber while the charge is `low`. The segments keep [`CELL_GAP`] from
/// the outline's inside on every side, and from each other; the terminal
/// stands level with them.
fn battery(segments: u8, low: bool) -> impl View<Rgb565, State> + use<> {
    let outline = if low {
        theme::AMBER
    } else {
        theme::TEXT_SECONDARY
    };
    let segment = move |i: u8| {
        Rectangle
            .foreground_color(if segments > i {
                theme::TEXT
            } else {
                theme::CHROME
            })
            .frame_sized(CELL_WIDTH, CELL_HEIGHT)
            .offset(
                (1 + CELL_GAP + (CELL_WIDTH + CELL_GAP) * u32::from(i)) as i32,
                0,
            )
    };
    ZStack::new((
        RoundedRectangle::new(3)
            .stroked(1)
            .foreground_color(outline)
            .frame_sized(BATTERY_WIDTH, BATTERY_HEIGHT),
        segment(0),
        segment(1),
        segment(2),
        Rectangle
            .foreground_color(outline)
            .frame_sized(2, CELL_HEIGHT)
            .offset(BATTERY_WIDTH as i32 + 1, 0),
    ))
    .with_alignment(Alignment::Leading)
    .frame_sized(BATTERY_WIDTH + 3, BATTERY_HEIGHT)
}

/// The battery's outline, its stroke included.
const BATTERY_WIDTH: u32 = 1 + 3 * CELL_WIDTH + 4 * CELL_GAP + 1;
const BATTERY_HEIGHT: u32 = 1 + CELL_GAP + CELL_HEIGHT + CELL_GAP + 1;
const CELL_WIDTH: u32 = 5;
const CELL_HEIGHT: u32 = 6;
/// Around the charge segments, and between them.
const CELL_GAP: u32 = 2;
