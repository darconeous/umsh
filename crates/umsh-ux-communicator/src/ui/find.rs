//! Find: letters typed on the Chats list filter it, at once. Chats that
//! match come first, then peers, saved or heard nearby, each name lit where
//! it matches. Enter opens the top result, which is tinted while the field
//! has focus; turning moves into the results once the edit ends. Backspace
//! on an empty field ends the edit, and again closes Find; where the board
//! has touch, an arrow before the field closes it too.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::font::PrerenderedFont;
use buoyant::render::AreaColors;
use buoyant::view::TextArea;
use buoyant::view::prelude::*;
use buoyant::view::text_field::TextFieldStatus;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::label;
use crate::board::Metrics;
use crate::model::{Found, FoundKind, MAX_FOUND, State, word_match};
use crate::nav::{FindText, keys};
use crate::{font, icon, theme};

/// The field, a pill inset from the list's edges.
const FIELD_INSET: u32 = 6;
const FIELD: u32 = 28;
const RADIUS: u16 = 14;
const CARET: u32 = 3;
/// A group's label, and a result under it.
const GROUP: u32 = 20;
const ROW: u32 = 34;
const AVATAR: u32 = 28;
/// From the list's leading edge to the name.
const TEXT_X: u32 = 45;

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; MAX_FOUND] = {
    let mut a = [0; MAX_FOUND];
    let mut i = 0;
    while i < MAX_FOUND {
        a[i] = i;
        i += 1;
    }
    a
};

pub fn view(state: &State, text: &FindText) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let (found, count) = state.found();
    let query: String<24> = String::try_from(text.text().trim()).unwrap_or_default();
    // Enter's target while the field has focus: tinted, with no focus bar.
    let tint = state.screen().focus().current() == Some(keys::FIND_FIELD);
    let items = found.len();
    let back = super::conversation::back(m, State::end_find);
    // The field starts after the way out, where touch has one.
    let leading = if back.is_some() {
        super::conversation::ARROW_GAP
    } else {
        FIELD_INSET
    };
    VStack::new((
        HStack::new((
            back,
            TextField::new(text, &font::REGULAR, State::find_text_mut)
                .with_font_size(m.body)
                .with_max_lines(1)
                .with_caret_width(CARET)
                .on_submit(State::open_top_found)
                .on_active(State::field_active)
                .with_label(move |status, area| field_look(m, status, area, count))
                .focus_key(keys::FIND_FIELD)
                .padding(Edges::Leading, leading)
                .padding(Edges::Trailing, FIELD_INSET)
                .padding(Edges::Vertical, 3),
        )),
        super::list(
            ForEach::<MAX_FOUND>::new_vertical(&INDICES[..items], move |&i| {
                let group = match (
                    found[i].kind.clone(),
                    i.checked_sub(1).map(|p| &found[p].kind),
                ) {
                    (FoundKind::Chat(_), None) => Some("Conversations"),
                    (FoundKind::Chat(_), Some(_)) => None,
                    (_, None | Some(FoundKind::Chat(_))) => Some("Peers"),
                    _ => None,
                };
                result(m, i, &found[i], &query, group, tint && i == 0)
            })
            .keyed(|&i| keys::found(i)),
        ),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.end_find();
            KeyResponse::Handled
        }
        Key::LeftArrow => {
            s.focus_rail();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// The pill: a magnifier, what is typed, and how many it finds.
fn field_look(
    m: &'static Metrics,
    status: TextFieldStatus,
    area: TextArea<'static, String<24>, PrerenderedFont>,
    count: usize,
) -> impl View<Rgb565, State> + use<> {
    let (fill, ring, stroke) = if status.is_active() {
        (theme::ACTIVE_FIELD, theme::ACCENT, 2)
    } else if status.is_focused() {
        (theme::FIELD, theme::ACCENT, 1)
    } else {
        (theme::FIELD, theme::MENU_LINE, 1)
    };
    let mut found: String<12> = String::new();
    _ = core::fmt::write(&mut found, format_args!("{count} found"));
    HStack::new((
        Image::new(&icon::SEARCH)
            .as_template()
            .foreground_color(theme::TEXT_SECONDARY),
        area.colors(AreaColors {
            caret: Some(theme::ACCENT),
            scroll_bar: None,
        })
        .foreground_color(theme::TEXT)
        .flex_infinite_width(HorizontalAlignment::Leading),
        label::<12>(&found, &font::MEDIUM, m.small, theme::TEXT_TERTIARY).fixed_size(true, false),
    ))
    .with_spacing(6)
    .hint_background_color(fill)
    .padding(Edges::Leading, 6)
    .padding(Edges::Trailing, 12)
    .frame()
    .with_height(FIELD)
    .background(
        Alignment::Center,
        ZStack::new((
            RoundedRectangle::new(RADIUS).foreground_color(fill),
            RoundedRectangle::new(RADIUS)
                .stroked(stroke)
                .foreground_color(ring),
        )),
    )
}

/// A result, under its group's label when it is the group's first.
fn result(
    m: &'static Metrics,
    index: usize,
    found: &Found,
    query: &str,
    group: Option<&'static str>,
    tint: bool,
) -> impl View<Rgb565, State> + use<> {
    let found = found.clone();
    // The name around where the query matches it.
    let at = word_match(&found.name, query).unwrap_or(0);
    let end = (at + query.len()).min(found.name.len());
    let (before, rest) = found.name.split_at(at);
    let (matched, after) = rest.split_at(end - at);
    let (before, matched, after): (String<32>, String<32>, String<32>) = (
        String::try_from(before).unwrap_or_default(),
        String::try_from(matched).unwrap_or_default(),
        String::try_from(after).unwrap_or_default(),
    );
    VStack::new((
        group.map(|group| {
            super::line(group, &font::BOLD, m.small, theme::TEXT_SECONDARY)
                .padding(Edges::Leading, 10)
                .flex_infinite_width(HorizontalAlignment::Leading)
                .frame()
                .with_height(GROUP)
        }),
        Button::new(
            move |s: &mut State| s.open_found(index),
            move |button: ButtonState| {
                let focused = button.is_focused();
                let fill = if focused || tint {
                    theme::FOCUS
                } else {
                    theme::BACKGROUND
                };
                HStack::new((
                    label::<32>(&before, &font::SEMIBOLD, m.body, theme::TEXT),
                    label::<32>(&matched, &font::EXTRABOLD, m.body, theme::ACCENT),
                    label::<32>(&after, &font::SEMIBOLD, m.body, theme::TEXT),
                    (!found.distance.is_empty()).then(|| {
                        label::<12>(
                            &found.distance,
                            &font::REGULAR,
                            m.secondary,
                            theme::TEXT_TERTIARY,
                        )
                        .padding(Edges::Leading, 10)
                    }),
                    Spacer::default(),
                    label::<6>(&found.age, &font::SEMIBOLD, m.small, theme::TEXT_TERTIARY),
                ))
                .with_spacing(0)
                .hint_background_color(fill)
                .padding(Edges::Leading, TEXT_X)
                .padding(Edges::Trailing, 10)
                .frame()
                .with_height(ROW)
                .overlay(
                    Alignment::Leading,
                    super::avatar::view(&found.avatar, AVATAR)
                        .frame()
                        .with_width(TEXT_X),
                )
                .background(
                    Alignment::Center,
                    (focused || tint).then(|| Rectangle.foreground_color(theme::FOCUS)),
                )
                .overlay(
                    Alignment::Leading,
                    focused.then(|| {
                        Rectangle
                            .foreground_color(theme::ACCENT)
                            .frame_sized(4, ROW)
                    }),
                )
                .frame()
                .with_width(m.beside_rail())
            },
        ),
    ))
    .with_spacing(0)
    .with_alignment(HorizontalAlignment::Leading)
}
