//! A channel an invitation offers, before it is joined. Nothing is joined
//! or sent until Join channel. Name is what the channel is called here;
//! pressing it edits it. Backspace goes back.

use crate::typeface::Typeface;
use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, FocusKey};
use buoyant::render::AreaColors;
use buoyant::view::prelude::*;
use buoyant::view::text_field::TextFieldStatus;
use buoyant::view::{EditBuffer, TextArea};
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::label;
use super::member::detail_head;
use crate::board::Metrics;
use crate::model::{Invite, State};
use crate::nav::{JoinName, keys};
use crate::{font, icon, theme};

const WARNING: u32 = 28;
const ROW: u32 = 36;
const INSET: u32 = 12;
const RADIUS: u16 = 8;
const CARET: u32 = 3;

pub fn view(
    m: &'static Metrics,
    invite: &Invite,
    name: &JoinName,
) -> impl View<Rgb565, State> + use<> {
    let (kind, warning) = if invite.access.is_open() {
        ("Public channel", "Anyone who knows the name can read it.")
    } else {
        (
            "Private channel",
            "Anyone with this invite can read and post.",
        )
    };
    VStack::new((
        header(m, "Join channel", None, None),
        detail_head(m, &invite.avatar(), invite.title().as_ref(), kind, false),
        HStack::new((
            Image::new(&icon::WARNING)
                .as_template()
                .foreground_color(theme::AMBER),
            label::<48>(warning, &font::MEDIUM, m.secondary, theme::AMBER),
        ))
        .with_spacing(6)
        .padding(Edges::Leading, 9)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(WARNING),
        name_row(m, name),
        join_button(m),
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

/// What the channel is to be called here, edited in place.
fn name_row(m: &'static Metrics, name: &JoinName) -> impl View<Rgb565, State> + use<> {
    edited_name(
        m,
        "Name",
        name,
        State::join_name_mut,
        State::field_active,
        keys::JOIN_NAME,
    )
}

/// A row named `label` whose value, a name, is edited where it stands:
/// `edit` reaches the text, and `active` hears the edit begin and end.
/// Enter ends it.
pub(super) fn edited_name<const N: usize>(
    m: &'static Metrics,
    label: &'static str,
    name: &EditBuffer<String<N>>,
    edit: fn(&mut State) -> Option<&mut EditBuffer<String<N>>>,
    active: fn(&mut State, bool),
    key: FocusKey,
) -> impl View<Rgb565, State> + use<N> {
    let shown: String<N> = String::try_from(name.text()).unwrap_or_default();
    TextField::new(name, &font::REGULAR, edit)
        .with_font_size(m.secondary)
        .with_max_lines(1)
        .with_caret_width(CARET)
        // Enter ends the edit.
        .on_submit(|_: &mut State| {})
        .on_active(active)
        .with_label(move |status, area| name_look(m, label, status, area, &shown))
        .focus_key(key)
}

fn name_look<const N: usize>(
    m: &'static Metrics,
    name: &'static str,
    status: TextFieldStatus,
    area: TextArea<'static, String<N>, Typeface>,
    shown: &str,
) -> impl View<Rgb565, State> + use<N> {
    let editing = status.is_active();
    let focused = status.is_focused() || editing;
    let face = if focused { &font::BOLD } else { &font::REGULAR };
    let fill = if focused {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    };
    // Set at the end, as a value is, and edited where it stands: the area
    // is as wide as the text and its caret, up to the room the row leaves.
    let room = m.width - 8 - (INSET - 4) - 10 - 2 * 8 - super::advance(name, face, m.body);
    let wide = super::advance(shown, &font::REGULAR, m.secondary) + CARET;
    HStack::new((
        label::<16>(name, face, m.body, theme::TEXT),
        Spacer::default(),
        editing.then(|| {
            area.colors(AreaColors {
                caret: Some(theme::ACCENT),
                scroll_bar: None,
            })
            .foreground_color(theme::TEXT)
            .frame()
            .with_width(wide.min(room))
        }),
        (!editing).then(|| label::<32>(shown, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY)),
    ))
    .with_spacing(8)
    .hint_background_color(fill)
    .padding(Edges::Leading, INSET - 4)
    .padding(Edges::Trailing, 10)
    .frame()
    .with_height(ROW - 2)
    .background(Alignment::Center, ring(focused))
    .padding(Edges::Horizontal, 4)
    .padding(Edges::Vertical, 1)
}

/// Joins, and opens the channel.
fn join_button(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    Button::new(State::join, |button: ButtonState| {
        let focused = button.is_focused();
        label::<16>("Join channel", &font::BOLD, m.body, theme::ACCENT)
            .hint_background_color(if focused {
                theme::FOCUS
            } else {
                theme::BACKGROUND
            })
            .flex_infinite_width(HorizontalAlignment::Center)
            .frame()
            .with_height(ROW - 2)
            .background(Alignment::Center, ring(focused))
            .padding(Edges::Horizontal, 4)
            .padding(Edges::Vertical, 1)
    })
    .focus_key(keys::JOIN_CHANNEL)
}

/// The focused look of a row.
fn ring(focused: bool) -> Option<impl View<Rgb565, State> + use<>> {
    focused.then(|| {
        ZStack::new((
            RoundedRectangle::new(RADIUS).foreground_color(theme::FOCUS),
            RoundedRectangle::new(RADIUS)
                .stroked(2)
                .foreground_color(theme::ACCENT),
        ))
    })
}
