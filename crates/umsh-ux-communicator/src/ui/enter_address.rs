//! Enter an address: one field takes a 44-character address or a
//! `umsh:n:` invitation. The address wraps at a fixed column so its groups line up;
//! the avatar appears from the first characters, and Message unlocks when
//! the address is whole. Backspace goes back.

use crate::typeface::Typeface;
use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::render::AreaColors;
use buoyant::view::prelude::*;
use buoyant::view::text_field::TextFieldStatus;
use buoyant::view::{EditText, TextArea};
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::label;
use super::member::{End, action};
use crate::board::Metrics;
use crate::model::{PeerEntry, State};
use crate::nav::{PeerText, keys};
use crate::{font, theme};

/// The label above the field, and the field's place.
const LABEL: u32 = 24;
const INSET: u32 = 8;
const RADIUS: u16 = 12;
/// How many characters a line of the field holds: half an address.
const COLUMN: u32 = 22;
/// A character's width in the field's monospaced face, at body size.
const ADVANCE: u32 = 10;
const CARET: u32 = 3;
/// The line under the field, its avatar, and the gap above it.
const ENTRY: u32 = 44;
const AVATAR: u32 = 34;
const ROW: u32 = 36;

pub fn view(state: &State, text: &PeerText) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let entry = state.peer_entry();
    let complete = matches!(entry, PeerEntry::Complete { .. });
    VStack::new((
        header(m, "Enter an address", None, None),
        label::<24>(
            "Address or invitation",
            &font::BOLD,
            m.small,
            theme::TEXT_SECONDARY,
        )
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(LABEL),
        field(m, text),
        entry_line(m, &entry),
        complete.then(|| {
            action(
                m,
                "Message",
                keys::MESSAGE_PEER,
                State::message_entry,
                End::Chevron,
            )
        }),
        (!complete).then(|| {
            label::<8>("Message", &font::REGULAR, m.body, theme::TEXT_TERTIARY)
                .padding(Edges::Leading, 12)
                .flex_infinite_width(HorizontalAlignment::Leading)
                .frame()
                .with_height(ROW)
        }),
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

fn field(m: &'static Metrics, text: &PeerText) -> impl View<Rgb565, State> + use<> {
    TextField::new(text, &font::MONO, State::peer_text_mut)
        .with_font_size(m.body)
        .with_max_lines(3)
        .with_caret_width(CARET)
        // Enter messages the peer once the address is whole.
        .on_submit(State::message_entry)
        // Half an address to a line, so its groups line up.
        .on_active(State::field_active)
        .with_label(|status, area| field_look(status, area, COLUMN * ADVANCE + CARET))
        .focus_key(keys::PEER_FIELD)
        .padding(Edges::Horizontal, INSET)
}

/// A field typed in monospace, its text `width` wide at most.
pub(super) fn field_look<B: EditText>(
    status: TextFieldStatus,
    area: TextArea<'static, B, Typeface>,
    width: u32,
) -> impl View<Rgb565, State> + use<B> {
    let (fill, ring, stroke) = if status.is_active() {
        (theme::ACTIVE_FIELD, theme::ACCENT, 2)
    } else if status.is_focused() {
        (theme::FIELD, theme::ACCENT, 1)
    } else {
        (theme::FIELD, theme::MENU_LINE, 1)
    };
    area.colors(AreaColors {
        caret: Some(theme::ACCENT),
        scroll_bar: None,
    })
    .foreground_color(theme::TEXT)
    .hint_background_color(fill)
    .frame()
    .with_width(width)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .padding(Edges::Horizontal, 12)
    .padding(Edges::Vertical, 5)
    .background(
        Alignment::Center,
        RoundedRectangle::new(RADIUS).foreground_color(fill),
    )
    // The ring over the text, which an emoji may reach.
    .overlay(
        Alignment::Center,
        RoundedRectangle::new(RADIUS)
            .stroked(stroke)
            .foreground_color(ring),
    )
}

/// Who the address belongs to as far as it goes, and what it still lacks.
fn entry_line(m: &'static Metrics, entry: &PeerEntry) -> impl View<Rgb565, State> + use<> {
    let (avatar, hint, note): (_, &str, Option<String<24>>) = match entry {
        PeerEntry::Empty => (None, "", None),
        PeerEntry::Invalid => (
            None,
            "",
            Some(String::try_from("Not an address").unwrap_or_default()),
        ),
        PeerEntry::Partial {
            avatar,
            hint,
            missing,
        } => {
            let mut note: String<24> = String::new();
            let unit = if *missing == 1 {
                "character"
            } else {
                "characters"
            };
            _ = core::fmt::write(&mut note, format_args!("{missing} more {unit}"));
            (avatar.clone(), hint.as_str(), Some(note))
        }
        PeerEntry::Complete { avatar, hint, .. } => (Some(avatar.clone()), hint.as_str(), None),
    };
    HStack::new((
        avatar.map(|avatar| super::avatar::view(&avatar, AVATAR)),
        VStack::new((
            (!hint.is_empty()).then(|| label::<8>(hint, &font::MONO_BOLD, m.body, theme::TEXT)),
            note.map(|note| label::<24>(&note, &font::SEMIBOLD, m.small, theme::AMBER)),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading),
    ))
    .with_spacing(10)
    .padding(Edges::Leading, 11)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .frame()
    .with_height(ENTRY)
}
