//! About: what the device is and runs, and the credits for what its
//! firmware is built from.

use buoyant::focus::FocusKey;
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::setting::{End, page, row};
use crate::board::Metrics;
use crate::model::State;
use crate::nav::keys;
use crate::{font, models, theme};

const ROW: u32 = 36;
const INSET: u32 = 12;
const RADIUS: u16 = 8;

/// The firmware's parts, each with its license, ahead of the crates.
const PARTS: [(&str, &str); 4] = [
    ("UMSH", "MIT OR Apache-2.0\numsh.dev"),
    (
        "Twemoji",
        "\u{A9} 2014\u{2013}2021 Twitter\n\
         \u{A9} 2022\u{2013}present Jason Sofonia & Justine De Caires\n\
         CC BY 4.0\n\
         Rasterized, color-reduced, and compressed\n\
         creativecommons.org/licenses/by/4.0",
    ),
    (
        "M PLUS 1, M PLUS Code",
        "\u{A9} 2021 The M+ FONTS Project Authors\nSIL Open Font License 1.1",
    ),
    (
        "Unicode emoji data and character names",
        "\u{A9} 2025 Unicode, Inc.\nUnicode License v3",
    ),
];

/// The crates the firmware links, by license: lines of a license, a
/// colon, and the crates under it. `make crate-notices` writes it.
const CRATES: &str = include_str!("../../crates.txt");

/// The most licenses [`CRATES`] can name.
const LICENSES: usize = 16;

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; LICENSES] = {
    let mut a = [0; LICENSES];
    let mut i = 0;
    while i < a.len() {
        a[i] = i;
        i += 1;
    }
    a
};

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let about = state.node.about();
    let mut storage: String<24> = String::new();
    _ = core::fmt::write(
        &mut storage,
        format_args!("{} of {}", size(about.stored), size(about.quota)),
    );
    let readout = |name, key, value: &str| row(m, name, key, |_| {}, End::value(value), false, ROW);
    page(
        m,
        "About",
        VStack::new((
            readout("Name", keys::ABOUT_NAME, &state.status.device_name),
            readout(
                "Model",
                keys::ABOUT_MODEL,
                models::name(state.board.model).unwrap_or_default(),
            ),
            readout("Firmware", keys::ABOUT_FIRMWARE, state.firmware),
            readout("Storage", keys::ABOUT_STORAGE, &storage),
            row(
                m,
                "Credits",
                keys::CREDITS,
                State::open_credits,
                End::Chevron,
                false,
                ROW,
            ),
        ))
        .with_spacing(0),
    )
}

/// The firmware's parts and the crates it links, each with its license.
pub fn credits(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let licenses: Vec<(&'static str, &'static str), LICENSES> = CRATES
        .lines()
        .filter_map(|line| line.split_once(": "))
        .collect();
    let part = |i: usize| {
        let (name, body) = PARTS[i];
        entry(m, name, body, keys::credit(i))
    };
    page(
        m,
        "Credits",
        VStack::new((
            part(0),
            part(1),
            part(2),
            part(3),
            super::line(
                "Rust crates",
                &font::BOLD,
                m.secondary,
                theme::TEXT_SECONDARY,
            )
            .flex_infinite_width(HorizontalAlignment::Leading)
            .padding(Edges::Leading, INSET)
            .padding(Edges::Vertical, 6),
            ForEach::<LICENSES>::new_vertical(&INDICES[..licenses.len()], move |&i| {
                let (license, crates) = licenses[i];
                entry(m, license, crates, keys::credit(PARTS.len() + i))
            })
            .keyed(|&i| keys::credit(PARTS.len() + i)),
        ))
        .with_spacing(0),
    )
}

/// An entry of the credits: `name`, and below it `body`'s lines, which
/// wrap. It takes focus so the wheel passes through it.
fn entry(
    m: &'static Metrics,
    name: &'static str,
    body: &'static str,
    key: FocusKey,
) -> impl View<Rgb565, State> + use<> {
    Button::new(
        |_: &mut State| {},
        move |button: ButtonState| Lazy::new((name, body, button.is_focused(), m), entry_look),
    )
    .focus_key(key)
}

/// What an entry of the credits draws.
///
/// Built from its text each time it is drawn ([`Lazy`]): kept in the
/// render trees, every entry's would outweigh the rest of the screen.
fn entry_look(
    &(name, body, focused, m): &(&'static str, &'static str, bool, &'static Metrics),
) -> impl View<Rgb565, ()> + use<> {
    let face = if focused { &font::BOLD } else { &font::REGULAR };
    VStack::new((
        Text::new(name, face)
            .with_font_size(m.body)
            .foreground_color(theme::TEXT),
        Text::new(body, &font::REGULAR)
            .with_font_size(m.small)
            .foreground_color(theme::TEXT_SECONDARY),
    ))
    .with_alignment(HorizontalAlignment::Leading)
    .with_spacing(2)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .hint_background_color(if focused {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    })
    .padding(Edges::Horizontal, INSET - 4)
    .padding(Edges::Vertical, 6)
    .background(
        Alignment::Center,
        focused.then(|| {
            ZStack::new((
                RoundedRectangle::new(RADIUS).foreground_color(theme::FOCUS),
                RoundedRectangle::new(RADIUS)
                    .stroked(2)
                    .foreground_color(theme::ACCENT),
            ))
        }),
    )
    .padding(Edges::Horizontal, 4)
    .padding(Edges::Vertical, 1)
    .overlay(
        Alignment::Bottom,
        (!focused).then(|| {
            Rectangle
                .foreground_color(theme::LINE)
                .frame()
                .with_height(1)
                .padding(Edges::Leading, INSET)
        }),
    )
}

/// `bytes` in kilobytes, or in megabytes to a tenth from a megabyte up.
fn size(bytes: u32) -> String<10> {
    const KB: u32 = 1024;
    const MB: u32 = 1024 * KB;
    let mut text = String::new();
    _ = if bytes < MB {
        core::fmt::write(&mut text, format_args!("{} KB", bytes.div_ceil(KB)))
    } else {
        let tenths = (u64::from(bytes) * 10).div_ceil(u64::from(MB));
        core::fmt::write(
            &mut text,
            format_args!("{}.{} MB", tenths / 10, tenths % 10),
        )
    };
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_in_kilobytes_then_megabytes() {
        assert_eq!(size(0), "0 KB");
        assert_eq!(size(31_744), "31 KB");
        assert_eq!(size(307_200), "300 KB");
        assert_eq!(size(1_048_576), "1.0 MB");
        assert_eq!(size(1_572_864), "1.5 MB");
    }

    #[test]
    fn every_license_has_room() {
        let lines = CRATES.lines().count();
        assert!(lines <= LICENSES, "{lines} licenses");
        assert!(CRATES.lines().all(|line| line.split_once(": ").is_some()));
    }
}
