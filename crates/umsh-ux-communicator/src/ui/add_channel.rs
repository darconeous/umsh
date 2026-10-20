//! Add channel: one field takes a channel's name or a `umsh:ck:`
//! invitation, and the line under it says which as it is typed. Join
//! unlocks once it names a channel. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::add_peer::field_look;
use super::conversation::header;
use super::label;
use super::member::{End, action};
use crate::board::Metrics;
use crate::model::{ChannelEntry, State};
use crate::nav::{ChannelText, keys};
use crate::{font, theme};

/// The label above the field, and the field's place.
const LABEL: u32 = 24;
const INSET: u32 = 8;
/// The field's text: the screen less the field's inset and padding.
const fn text_width(m: &Metrics) -> u32 {
    m.width - 2 * INSET - 24
}
const CARET: u32 = 3;
/// The line under the field, and the row under that.
const NOTE: u32 = 30;
const ROW: u32 = 36;

pub fn view(state: &State, text: &ChannelText) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let entry = state.channel_entry();
    let joinable = matches!(entry, ChannelEntry::Named | ChannelEntry::Private);
    VStack::new((
        header(m, "Add channel", None, None),
        label::<32>(
            "Channel name or invitation",
            &font::BOLD,
            m.small,
            theme::TEXT_SECONDARY,
        )
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(LABEL),
        TextField::new(text, &font::MONO, State::channel_text_mut)
            .with_font_size(m.body)
            .with_max_lines(3)
            .with_caret_width(CARET)
            // Enter joins once the text names a channel.
            .on_submit(State::add_channel)
            .on_active(State::field_active)
            .with_label(|status, area| field_look(status, area, text_width(m)))
            .focus_key(keys::CHANNEL_FIELD)
            .padding(Edges::Horizontal, INSET),
        note(m, entry),
        joinable.then(|| {
            action(
                m,
                "Join",
                keys::JOIN_ENTRY,
                State::add_channel,
                End::Nothing,
            )
        }),
        (!joinable).then(|| {
            label::<8>("Join", &font::REGULAR, m.body, theme::TEXT_TERTIARY)
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

/// What the text names, and what it still lacks.
fn note(m: &'static Metrics, entry: ChannelEntry) -> impl View<Rgb565, State> + use<> {
    let mut text: String<40> = String::new();
    let color = match entry {
        ChannelEntry::Empty => theme::TEXT_SECONDARY,
        ChannelEntry::Invalid => {
            _ = text.push_str("Not a channel");
            theme::AMBER
        }
        ChannelEntry::Named => {
            _ = text.push_str("Named channel");
            theme::TEXT_SECONDARY
        }
        ChannelEntry::Partial { missing } => {
            let unit = if missing == 1 {
                "character"
            } else {
                "characters"
            };
            _ = core::fmt::write(
                &mut text,
                format_args!("Private channel \u{B7} {missing} {unit} short"),
            );
            theme::AMBER
        }
        ChannelEntry::Private => {
            _ = text.push_str("Private channel");
            theme::TEXT_SECONDARY
        }
    };
    label::<40>(&text, &font::SEMIBOLD, m.small, color)
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(NOTE)
}
