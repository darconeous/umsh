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
use super::setting::{End, readout, row};
use super::{label, line};
use crate::board::{Board, Metrics};
use crate::keyboard::Field;
use crate::model::{Glance, KeyboardFirmware, KeyboardSettings, LEVELS, State};
use crate::nav::{PowerText, keys};
use crate::picker::{COLUMNS, FILTER, Geometry, Pick, ROWS, Shown, Spot, TABS, Tab};
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
/// Above the tabs, in the picker.
const CARD_TOP: u32 = 4;

/// A row of the picker: a character at body size with room around it, or,
/// on a touchscreen, room for a finger.
const fn cell(m: &Metrics) -> u32 {
    let room = 2 * m.body + 1;
    match m.touch_target {
        Some(finger) if finger * 3 / 4 > room => finger * 3 / 4,
        _ => room,
    }
}

/// The row of tabs, or of the name typed, above the cells.
const fn tabs_height(m: &Metrics) -> u32 {
    (2 * m.body + 1) * 5 / 8
}

/// Between the tabs and the cells.
const TABS_GAP: u32 = 4;

/// Where the picker lies over a conversation: under its header, and over
/// all but the composer's band, one line tall, below.
const HEADER: u32 = 34;
const fn composer(m: &Metrics) -> u32 {
    m.body + 14
}

/// The picker's height: from under a conversation's header to the
/// composer, the last row cut by its edge to show there is more.
const fn picker_height(m: &Metrics) -> u32 {
    m.height - (m.strip + HEADER + 4) - composer(m) - 4
}

/// The height of the rows in view.
const fn rows_height(m: &Metrics) -> u32 {
    picker_height(m) - CARD_TOP - tabs_height(m) - TABS_GAP
}

/// The width the picker's tabs and cells have.
const fn grid_width(m: &Metrics) -> u32 {
    m.width - 2 * PICKER_INSET - 2 * GRID_INSET
}

/// How the picker's grid is laid out on a board.
#[must_use]
pub const fn picker_geometry(m: &Metrics) -> Geometry {
    Geometry {
        columns: (grid_width(m) / cell(m)) as u16,
        row: cell(m) as u16,
        height: rows_height(m) as u16,
    }
}

/// A cell's width: a row's width shared evenly.
const fn cell_width(m: &Metrics) -> u32 {
    grid_width(m) / picker_geometry(m).columns as u32
}

const _: () = {
    let boards = [&Board::PAGER, &Board::TDECK];
    let mut i = 0;
    while i < boards.len() {
        let m = &boards[i].metrics;
        assert!(picker_geometry(m).columns as usize <= COLUMNS);
        // Scrolled, a row more: one cut at the top, and one at the bottom.
        assert!((rows_height(m).div_ceil(cell(m)) as usize) < ROWS);
        i += 1;
    }
};

/// Where the picker's card starts down the screen: over a conversation,
/// under its header, so the composer below stays in view; over any other
/// field, at the bottom of the screen.
const fn card_top(m: &Metrics, over_conversation: bool) -> u32 {
    if over_conversation {
        m.strip + HEADER + 4
    } else {
        m.height - PICKER_INSET - picker_height(m)
    }
}

/// Whether the picker lies over a conversation.
fn over_conversation(state: &State) -> bool {
    let reacting = state
        .picker
        .as_ref()
        .is_some_and(|p| p.reacting().is_some());
    reacting || state.keyboard.field() == Some(Field::Prose)
}

/// What is at `x`, `y` on the screen, as the open picker sees it. The
/// tabs reach from the picker's top to the rows, and the cells at either
/// end out to its sides, so a finger near them still finds them.
#[must_use]
pub fn picker_spot(state: &State, x: i32, y: i32) -> Spot {
    let m = state.metrics();
    let Some(picker) = state.picker.as_ref() else {
        return Spot::Outside;
    };
    let top = card_top(m, over_conversation(state)) as i32;
    let left = PICKER_INSET as i32;
    if x < left || x >= (m.width - PICKER_INSET) as i32 {
        return Spot::Outside;
    }
    if y < top || y >= top + picker_height(m) as i32 {
        return Spot::Outside;
    }
    let across = (x - left - GRID_INSET as i32).clamp(0, grid_width(m) as i32 - 1) as u32;
    let rows_top = top + (CARD_TOP + tabs_height(m) + TABS_GAP) as i32;
    if y >= rows_top {
        let column = (across / cell_width(m)) as u16;
        return Spot::Grid {
            column: column.min(picker_geometry(m).columns - 1),
            y: (y - rows_top) as u16,
        };
    }
    if !picker.filter().is_empty() {
        return Spot::Card;
    }
    let tabs = picker.tabs(state.recents.picks()).len().max(1) as u32;
    let width = grid_width(m) / tabs;
    Spot::Tab((across / width).min(tabs - 1) as u8)
}

/// A glance's height, and its top on the screen: a little below the
/// middle.
const GLANCE_HEIGHT: u32 = 56;
const fn glance_top(m: &Metrics) -> u32 {
    (m.height - GLANCE_HEIGHT) / 2 + 8
}

/// The keyboard's settings, and its firmware where its controller has
/// said.
pub fn settings(
    m: &'static Metrics,
    settings: &KeyboardSettings,
    firmware: Option<KeyboardFirmware>,
) -> impl View<Rgb565, State> + use<> {
    let firmware = firmware.map(|firmware| {
        let mut text = String::<16>::new();
        _ = match firmware {
            KeyboardFirmware::Stock => core::fmt::write(&mut text, format_args!("Stock")),
            KeyboardFirmware::Umsh { major, minor } => {
                core::fmt::write(&mut text, format_args!("UMSH {major}.{minor}"))
            }
        };
        text
    });
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
        firmware.map(|firmware| readout(m, "Firmware", &firmware, ROW)),
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

/// The character picker, over a conversation or another field.
pub fn picker(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let look = PickerLook {
        shown: state
            .picker
            .as_ref()
            .map(|p| p.shown(state.recents.picks(), picker_geometry(m)))
            .unwrap_or_default(),
        m,
    };
    Lazy::new(look, picker_card)
        .padding(Edges::Horizontal, PICKER_INSET)
        .padding(Edges::Top, card_top(m, over_conversation(state)))
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
    let shown = &look.shown;
    let head = match_view!(shown.filter.is_empty(), {
        true => tabs(m, shown.tabs, shown.tab, shown.on_tabs),
        false => filter(m, &shown.filter, shown.name),
    });
    let nothing = !shown.filter.is_empty() && shown.rows.is_empty();
    VStack::new((
        head.frame()
            .with_height(tabs_height(m))
            // The rule under the tabs, which the current tab's mark sits on.
            .background(
                Alignment::Bottom,
                Rectangle
                    .foreground_color(theme::MENU_LINE)
                    .frame_sized(grid_width(m), 1),
            ),
        grid(m, shown)
            .overlay(
                Alignment::Center,
                nothing.then(|| line("No matches", &font::REGULAR, m.small, theme::TEXT_TERTIARY)),
            )
            .clipped(),
    ))
    .with_spacing(TABS_GAP)
    .with_alignment(HorizontalAlignment::Leading)
    .padding(Edges::Horizontal, GRID_INSET)
    .padding(Edges::Top, CARD_TOP)
    .frame()
    .with_width(m.width - 2 * PICKER_INSET)
    .with_height(picker_height(m))
    .with_alignment(Alignment::TopLeading)
    .background(Alignment::Center, card(12, theme::MENU, theme::MENU_LINE))
}

/// The tabs, `current`'s marked: ringed while focus is on it, and
/// otherwise underlined.
fn tabs(
    m: &'static Metrics,
    tabs: &'static [Tab],
    current: Option<Tab>,
    on_tabs: bool,
) -> impl View<Rgb565, ()> + use<> {
    let width = grid_width(m) / tabs.len().max(1) as u32;
    let height = tabs_height(m);
    ForEach::<{ TABS.len() }>::new_horizontal(tabs, move |&tab| {
        let this = Some(tab) == current;
        let color = if this {
            theme::TEXT
        } else {
            theme::TEXT_SECONDARY
        };
        let face = (tab != Tab::Recent).then(|| {
            Text::new(tab.face(), &font::BOLD)
                .with_font_size(m.small)
                .with_line_limit(1)
                .foreground_color(color)
        });
        let clock = (tab == Tab::Recent).then(|| {
            Image::new(&icon::CLOCK)
                .as_template()
                .foreground_color(color)
        });
        let focused = this && on_tabs;
        ZStack::new((face, clock))
            .frame_sized(width, height)
            .background(
                Alignment::Center,
                focused.then(|| {
                    ZStack::new((
                        RoundedRectangle::new(6).foreground_color(theme::FOCUS),
                        RoundedRectangle::new(6)
                            .stroked(2)
                            .foreground_color(theme::ACCENT),
                    ))
                    .frame_sized(width - 2, height - 2)
                }),
            )
            .overlay(
                Alignment::Bottom,
                (this && !on_tabs).then(|| {
                    RoundedRectangle::new(1)
                        .foreground_color(theme::ACCENT)
                        .frame_sized(width * 2 / 3, 2)
                }),
            )
    })
}

/// The name typed, in place of the tabs, and the focused pick's name.
fn filter(m: &'static Metrics, filter: &str, name: &str) -> impl View<Rgb565, ()> + use<> {
    let filter: String<FILTER> = String::try_from(filter).unwrap_or_default();
    // A character's name is kept in lowercase.
    let mut title = String::<48>::new();
    let mut chars = umsh_grapheme::cut(name, 44).chars();
    for c in chars.next().into_iter().flat_map(char::to_uppercase) {
        _ = title.push(c);
    }
    _ = title.push_str(chars.as_str());
    HStack::new((
        Image::new(&icon::SEARCH)
            .as_template()
            .foreground_color(theme::TEXT_SECONDARY),
        line(filter, &font::REGULAR, m.body, theme::TEXT),
        Rectangle
            .foreground_color(theme::ACCENT)
            .frame_sized(2, m.body),
        line(title, &font::REGULAR, m.small, theme::TEXT_TERTIARY)
            .flex_infinite_width(HorizontalAlignment::Trailing),
    ))
    .with_spacing(4)
    .flex_infinite_width(HorizontalAlignment::Leading)
}

/// The rows in view, the first cut `offset` pixels by the top. Each row
/// is built only while it is drawn ([`Lazy`]), so no more than one row's
/// cells are ever on the stack.
fn grid(m: &'static Metrics, shown: &Shown) -> impl View<Rgb565, ()> + use<> {
    static ROWS_SHOWN: [usize; ROWS] = [0, 1, 2, 3, 4];
    let rows = shown.rows.clone();
    let focus = shown.focus;
    ForEach::<ROWS>::new_vertical(&ROWS_SHOWN[..rows.len()], move |&r| {
        let look = RowLook {
            picks: rows[r].clone(),
            focus: focus.and_then(|(row, cell)| (row == r).then_some(cell)),
            m,
        };
        Lazy::new(look, picker_row)
    })
    .with_alignment(HorizontalAlignment::Leading)
    .offset(0, -i32::from(shown.offset))
    .frame()
    .with_width(grid_width(m))
    .with_height(rows_height(m))
    .with_alignment(Alignment::Top)
}

/// What a row of the picker is drawn from: its picks, and the focused
/// one's cell.
#[derive(Clone, Debug)]
struct RowLook {
    picks: heapless::Vec<Pick, COLUMNS>,
    focus: Option<usize>,
    m: &'static Metrics,
}

/// A row of the picker, the focused pick ringed.
fn picker_row(look: &RowLook) -> impl View<Rgb565, ()> + use<> {
    static CELLS: [usize; COLUMNS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let m = look.m;
    let picks = look.picks.clone();
    let focus = look.focus;
    let (width, height) = (cell_width(m), cell(m));
    ForEach::<COLUMNS>::new_horizontal(&CELLS[..picks.len()], move |&i| {
        let focused = focus == Some(i);
        Text::new(picks[i].text(), &font::REGULAR)
            .with_font_size(m.body)
            .with_line_limit(1)
            .foreground_color(theme::TEXT)
            .frame_sized(width - 2, height - 2)
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
    const _: () = assert!(LEVELS == 10);
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
