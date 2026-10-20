//! What the keyboard brings to the screen: its settings, a field that
//! takes a number, the character picker, and the glances that show a
//! setting a key changed.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::match_view;
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::add_peer::field_look;
use super::conversation::header;
use super::setting::{End, row};
use super::{label, line};
use crate::board::{Board, Metrics};
use crate::keyboard::{Field, PICKER};
use crate::model::{BRIGHTNESS_LEVELS, Glance, KeyboardSettings, State};
use crate::nav::{PowerText, keys};
use crate::{font, icon, theme};

const ROW: u32 = 36;
/// The label above a field, and the field's inset.
const LABEL: u32 = 24;
const INSET: u32 = 8;
const fn power_width(m: &Metrics) -> u32 {
    m.width - 2 * INSET - 24
}

/// The picker: its inset from the screen's edges, and its grid's inset in
/// it.
const PICKER_INSET: u32 = 6;
const GRID_INSET: u32 = 12;

/// A cell of the picker: a character at body size, with room around it.
const fn cell(m: &Metrics) -> u32 {
    2 * m.body + 1
}

/// How many cells a row of the picker holds.
#[must_use]
pub const fn picker_columns(m: &Metrics) -> usize {
    ((m.width - 2 * PICKER_INSET - 2 * GRID_INSET) / cell(m)) as usize
}
/// The most rows the picker takes. Its grid is built for no more, so the
/// render tree stays small enough for the stack; every board's row holds
/// at least half the characters.
const PICKER_ROWS: usize = 2;
const _: () = {
    let boards = [&Board::PAGER, &Board::TDECK];
    let mut i = 0;
    while i < boards.len() {
        assert!(PICKER.len().div_ceil(picker_columns(&boards[i].metrics)) <= PICKER_ROWS);
        i += 1;
    }
};
/// Where the picker lies over a conversation: under its header.
const HEADER: u32 = 34;

/// A glance's height, and its top on the screen: a little below the
/// middle.
const GLANCE_HEIGHT: u32 = 56;
const fn glance_top(m: &Metrics) -> u32 {
    (m.height - GLANCE_HEIGHT) / 2 + 8
}

/// The keyboard's settings.
pub fn settings(
    m: &'static Metrics,
    settings: &KeyboardSettings,
) -> impl View<Rgb565, State> + use<> {
    VStack::new((
        header(m, "Keyboard", None, None),
        row(
            m,
            "Capitalize sentences",
            keys::CAPITALIZE,
            State::toggle_capitalize,
            End::Switch(settings.capitalize),
            false,
            ROW,
        ),
        row(
            m,
            "Period on double space",
            keys::PERIOD,
            State::toggle_period,
            End::Switch(settings.period),
            false,
            ROW,
        ),
        row(
            m,
            "Keyboard light",
            keys::KEYBOARD_LIGHT,
            State::toggle_keyboard_light,
            End::Switch(settings.light),
            false,
            ROW,
        ),
    ))
    .with_spacing(0)
    .flex_infinite_height(VerticalAlignment::Top)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(back)
}

/// The radio's transmit power, typed in dBm. Enter sets it.
pub fn transmit_power(m: &'static Metrics, text: &PowerText) -> impl View<Rgb565, State> + use<> {
    VStack::new((
        header(m, "Radio", None, None),
        label::<16>(
            "Transmit power",
            &font::BOLD,
            m.small,
            theme::TEXT_SECONDARY,
        )
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(LABEL),
        TextField::new(text, &font::REGULAR, State::power_text_mut)
            .with_font_size(m.body)
            .on_submit(State::submit_transmit_power)
            .on_active(State::field_active)
            .with_label(|status, area| field_look(status, area, power_width(m)))
            .focus_key(keys::POWER_FIELD)
            .overlay(
                Alignment::Trailing,
                line("dBm", &font::MEDIUM, m.secondary, theme::TEXT_TERTIARY)
                    .padding(Edges::Trailing, 12),
            )
            .padding(Edges::Horizontal, INSET),
    ))
    .with_spacing(0)
    .flex_infinite_height(VerticalAlignment::Top)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(back)
}

fn back(key: Key, s: &mut State) -> KeyResponse {
    match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    }
}

/// The character picker, with the character at `at` focused. Over a
/// conversation it lies under the header, so the composer below stays in
/// view; over any other field, at the bottom of the screen.
pub fn picker(state: &State, at: u8) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let over_conversation = state.keyboard.field() == Some(Field::Prose);
    Lazy::new((at, m), grid)
        .padding(Edges::Horizontal, PICKER_INSET)
        .padding(Edges::Top, m.strip + HEADER + 4)
        .flex_infinite_height(if over_conversation {
            VerticalAlignment::Top
        } else {
            VerticalAlignment::Bottom
        })
        .padding(Edges::Bottom, PICKER_INSET)
}

/// The picker's grid, built from its data each time it is drawn
/// ([`Lazy`]): a cell for every character is more than the screen keeps.
fn grid(&(at, m): &(u8, &'static Metrics)) -> impl View<Rgb565, ()> + use<> {
    static ALL: [u8; PICKER.len()] = {
        let mut all = [0; PICKER.len()];
        let mut i = 0;
        while i < all.len() {
            all[i] = i as u8;
            i += 1;
        }
        all
    };
    let size = cell(m);
    let cell = move |&i: &u8| {
        let mut glyph: String<4> = String::new();
        _ = glyph.push(PICKER[usize::from(i)]);
        Text::new(glyph, &font::REGULAR)
            .with_font_size(m.body)
            .with_line_limit(1)
            .foreground_color(theme::TEXT)
            .frame_sized(size - 2, size - 2)
            .background(
                Alignment::Center,
                (i == at).then(|| {
                    ZStack::new((
                        RoundedRectangle::new(8).foreground_color(theme::FOCUS),
                        RoundedRectangle::new(8)
                            .stroked(2)
                            .foreground_color(theme::ACCENT),
                    ))
                }),
            )
            .padding(Edges::All, 1)
    };
    static ROWS: [usize; PICKER_ROWS] = [0, 1];
    let columns = picker_columns(m).max(1);
    let rows = ALL.len().div_ceil(columns).min(PICKER_ROWS);
    ForEach::<PICKER_ROWS>::new_vertical(&ROWS[..rows], move |&row| {
        let start = row * columns;
        let end = (start + columns).min(ALL.len());
        ForEach::<{ PICKER.len() }>::new_horizontal(&ALL[start..end], cell)
    })
    .with_alignment(HorizontalAlignment::Leading)
    .padding(Edges::Horizontal, GRID_INSET)
    .padding(Edges::Vertical, 4)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .background(Alignment::Center, card(12, theme::MENU, theme::MENU_LINE))
}

/// A setting a key changed, shown briefly with no words.
pub fn glance(m: &'static Metrics, glance: Glance) -> impl View<Rgb565, State> + use<> {
    match_view!(glance, {
        Glance::Brightness { level, .. } => HStack::new((
            Image::new(&icon::SUN)
                .as_template()
                .foreground_color(theme::TEXT),
            level_bar(level),
        ))
        .with_spacing(14)
        .padding(Edges::Horizontal, 18)
        .frame()
        .with_height(GLANCE_HEIGHT)
        .background(Alignment::Center, card(14, theme::GLANCE, theme::GLANCE_LINE)),
        Glance::KeyboardLight { on, .. } => Image::new(if on {
            &icon::KEYBOARD_LIT
        } else {
            &icon::KEYBOARD_UNLIT
        })
        .as_template()
        .foreground_color(theme::TEXT)
        .frame_sized(96, GLANCE_HEIGHT)
        .background(Alignment::Center, card(14, theme::GLANCE, theme::GLANCE_LINE)),
    })
    .padding(Edges::Top, glance_top(m))
    .flex_infinite_width(HorizontalAlignment::Center)
}

/// The brightness's steps, lit up to `level`.
fn level_bar(level: u8) -> impl View<Rgb565, State> + use<> {
    let step = move |i: u8| {
        RoundedRectangle::new(3)
            .foreground_color(if i < level {
                theme::TEXT
            } else {
                theme::LEVEL_OFF
            })
            .frame_sized(14, 12)
    };
    const _: () = assert!(BRIGHTNESS_LEVELS == 10);
    HStack::new((
        step(0),
        step(1),
        step(2),
        step(3),
        step(4),
        step(5),
        step(6),
        step(7),
        step(8),
        step(9),
    ))
    .with_spacing(4)
}

/// A card's face, with its shadow.
fn card<C>(radius: u16, fill: Rgb565, edge: Rgb565) -> impl View<Rgb565, C> + use<C> {
    ZStack::new((
        RoundedRectangle::new(radius)
            .foreground_color(Rgb565::new(0, 0, 0))
            .offset(1, 3),
        RoundedRectangle::new(radius).foreground_color(fill),
        RoundedRectangle::new(radius)
            .stroked(1)
            .foreground_color(edge),
    ))
}
