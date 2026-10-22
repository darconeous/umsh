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

use super::conversation::header;
use super::enter_address::field_look;
use super::setting::{End, row};
use super::{label, line};
use crate::board::{Board, Metrics};
use crate::keyboard::Field;
use crate::model::{BRIGHTNESS_LEVELS, Glance, KeyboardSettings, State};
use crate::nav::{PowerText, keys};
use crate::picker::{COLUMNS, FILTER, ROWS, Shown, TABS, Tab};
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

/// The row of tabs, or of the name typed, above the cells.
const fn tabs_height(m: &Metrics) -> u32 {
    cell(m) * 5 / 8
}

/// Between the tabs and the cells.
const TABS_GAP: u32 = 4;

/// The picker's height: its tabs, two rows, and a quarter of the next, cut
/// by its edge to show there is more.
const fn picker_height(m: &Metrics) -> u32 {
    4 + tabs_height(m) + TABS_GAP + 2 * cell(m) + cell(m) / 4
}

/// The width the picker's tabs and cells have.
const fn grid_width(m: &Metrics) -> u32 {
    m.width - 2 * PICKER_INSET - 2 * GRID_INSET
}

/// How many cells a row of the picker holds.
#[must_use]
pub const fn picker_columns(m: &Metrics) -> usize {
    (grid_width(m) / cell(m)) as usize
}
const _: () = {
    let boards = [&Board::PAGER, &Board::TDECK];
    let mut i = 0;
    while i < boards.len() {
        assert!(picker_columns(&boards[i].metrics) <= COLUMNS);
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

/// The character picker. Over a conversation it lies under the header,
/// so the composer below stays in view; over any other field, at the
/// bottom of the screen.
pub fn picker(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let reacting = state
        .picker
        .as_ref()
        .is_some_and(|p| p.reacting().is_some());
    let over_conversation = reacting || state.keyboard.field() == Some(Field::Prose);
    let look = PickerLook {
        shown: state
            .picker
            .as_ref()
            .map(|p| p.shown(state.recents.picks(), state.picker_columns()))
            .unwrap_or_default(),
        m,
    };
    Lazy::new(look, picker_card)
        .padding(Edges::Horizontal, PICKER_INSET)
        .padding(Edges::Top, m.strip + HEADER + 4)
        .flex_infinite_height(if over_conversation {
            VerticalAlignment::Top
        } else {
            VerticalAlignment::Bottom
        })
        .padding(Edges::Bottom, PICKER_INSET)
}

/// What the picker is drawn from.
#[derive(Clone, Debug)]
struct PickerLook {
    shown: Shown,
    m: &'static Metrics,
}

/// The picker, built from its data each time it is drawn ([`Lazy`]): its
/// cells are more than the screen keeps.
fn picker_card(look: &PickerLook) -> impl View<Rgb565, ()> + use<> {
    let m = look.m;
    let head = match_view!(look.shown.filter.is_empty(), {
        true => tabs(m, look.shown.tabs, look.shown.tab),
        false => filter(m, &look.shown.filter),
    });
    VStack::new((
        head.frame().with_height(tabs_height(m)),
        grid(m, &look.shown).clipped(),
    ))
    .with_spacing(TABS_GAP)
    .with_alignment(HorizontalAlignment::Leading)
    .padding(Edges::Horizontal, GRID_INSET)
    .padding(Edges::Top, 4)
    .frame()
    .with_width(m.width - 2 * PICKER_INSET)
    .with_height(picker_height(m))
    .with_alignment(Alignment::TopLeading)
    .background(Alignment::Center, card(12, theme::MENU, theme::MENU_LINE))
}

/// The tabs, with `current`'s underlined.
fn tabs(
    m: &'static Metrics,
    tabs: &'static [Tab],
    current: Option<Tab>,
) -> impl View<Rgb565, ()> + use<> {
    let width = grid_width(m) / tabs.len().max(1) as u32;
    ForEach::<{ TABS.len() }>::new_horizontal(tabs, move |&tab| {
        let face = (tab != Tab::Recent).then(|| {
            Text::new(tab.face(), &font::BOLD)
                .with_font_size(m.small)
                .with_line_limit(1)
                .foreground_color(theme::TEXT_SECONDARY)
        });
        let clock = (tab == Tab::Recent).then(|| {
            Image::new(&icon::CLOCK)
                .as_template()
                .foreground_color(theme::TEXT_SECONDARY)
        });
        ZStack::new((face, clock))
            .frame_sized(width, tabs_height(m))
            .overlay(
                Alignment::Bottom,
                (Some(tab) == current).then(|| {
                    RoundedRectangle::new(1)
                        .foreground_color(theme::ACCENT)
                        .frame_sized(width * 2 / 3, 2)
                }),
            )
    })
}

/// The name typed, in place of the tabs.
fn filter(m: &'static Metrics, filter: &str) -> impl View<Rgb565, ()> + use<> {
    let filter: String<FILTER> = String::try_from(filter).unwrap_or_default();
    HStack::new((
        Image::new(&icon::SEARCH)
            .as_template()
            .foreground_color(theme::TEXT_SECONDARY),
        line(filter, &font::REGULAR, m.body, theme::TEXT),
        Rectangle
            .foreground_color(theme::ACCENT)
            .frame_sized(2, m.body),
    ))
    .with_spacing(4)
    .flex_infinite_width(HorizontalAlignment::Leading)
}

/// The rows in view, the focused pick ringed.
fn grid(m: &'static Metrics, shown: &Shown) -> impl View<Rgb565, ()> + use<> {
    static ROWS_SHOWN: [usize; ROWS] = [0, 1, 2];
    static CELLS: [usize; COLUMNS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let rows = shown.rows.clone();
    let focus = shown.focus;
    let size = cell(m);
    ForEach::<ROWS>::new_vertical(&ROWS_SHOWN[..rows.len()], move |&r| {
        let picks = rows[r].clone();
        ForEach::<COLUMNS>::new_horizontal(&CELLS[..picks.len()], move |&i| {
            let focused = focus == Some((r, i));
            Text::new(picks[i].text(), &font::REGULAR)
                .with_font_size(m.body)
                .with_line_limit(1)
                .foreground_color(theme::TEXT)
                .frame_sized(size - 2, size - 2)
                .background(
                    Alignment::Center,
                    focused.then(|| RoundedRectangle::new(8).foreground_color(theme::FOCUS)),
                )
                // The ring over the pick, which an emoji may reach.
                .overlay(
                    Alignment::Center,
                    focused.then(|| {
                        RoundedRectangle::new(8)
                            .stroked(2)
                            .foreground_color(theme::ACCENT)
                    }),
                )
                .padding(Edges::All, 1)
        })
    })
    .with_alignment(HorizontalAlignment::Leading)
    .flex_infinite_width(HorizontalAlignment::Leading)
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
