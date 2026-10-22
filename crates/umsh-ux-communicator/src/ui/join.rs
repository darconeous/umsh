//! A channel an invitation offers, before it is joined. Nothing is joined
//! or sent until Join channel. Name is what the channel is called here;
//! pressing it edits it. Backspace goes back.

use crate::typeface::Typeface;
use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::render::AreaColors;
use buoyant::view::TextArea;
use buoyant::view::prelude::*;
use buoyant::view::text_field::TextFieldStatus;
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
        detail_head(m, &invite.avatar(), &invite.name, kind, false),
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
    let shown: String<32> = String::try_from(name.text()).unwrap_or_default();
    TextField::new(name, &font::REGULAR, State::join_name_mut)
        .with_font_size(m.secondary)
        .with_max_lines(1)
        // Enter ends the edit.
        .on_submit(|_: &mut State| {})
        .on_active(State::field_active)
        .with_label(move |status, area| name_look(m, status, area, &shown))
        .focus_key(keys::JOIN_NAME)
}

fn name_look(
    m: &'static Metrics,
    status: TextFieldStatus,
    area: TextArea<'static, String<32>, Typeface>,
    shown: &str,
) -> impl View<Rgb565, State> + use<> {
    let editing = status.is_active();
    let focused = status.is_focused() || editing;
    let face = if focused { &font::BOLD } else { &font::REGULAR };
    let fill = if focused {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    };
    HStack::new((
        label::<8>("Name", face, m.body, theme::TEXT),
        // Edited where it stands; otherwise set at the end, as a value is.
        editing.then(|| {
            area.colors(AreaColors {
                caret: Some(theme::ACCENT),
                scroll_bar: None,
            })
            .foreground_color(theme::TEXT)
        }),
        (!editing).then(|| {
            HStack::new((
                Spacer::default(),
                label::<32>(shown, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY),
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY),
            ))
            .with_spacing(8)
        }),
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
