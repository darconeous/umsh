//! The rail: Chats, Peers, and Device, beside the top-level lists.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::image::ImageRaw;
use embedded_graphics::pixelcolor::{Gray4, Rgb565};

use super::label;
use crate::board::Metrics;
use crate::model::{Section, State};
use crate::nav::keys;
use crate::{font, icon, theme};

pub fn view(
    m: &'static Metrics,
    active: Section,
    unread_chats: usize,
) -> impl View<Rgb565, State> + use<> {
    VStack::new((
        item(
            m,
            Section::Chats,
            "Chats",
            &icon::CHATS,
            active,
            unread_chats,
        ),
        item(m, Section::Peers, "Peers", &icon::PEERS, active, 0),
        item(m, Section::Device, "Device", &icon::DEVICE, active, 0),
    ))
    .with_spacing(0)
    .with_alignment(HorizontalAlignment::Leading)
    .bound_focus(BoundaryBehavior::Stop)
    // The arrow toward the list enters the section, as a press does. With
    // nowhere further back to go, Backspace locks a board that has no lock
    // button.
    .on_key(|key, s: &mut State| match key {
        Key::Backspace if !s.board.controls.lock_button => {
            s.lock();
            KeyResponse::Handled
        }
        Key::RightArrow => match s.focus().current().and_then(keys::section) {
            Some(section) => {
                s.enter_section(section);
                KeyResponse::Handled
            }
            None => KeyResponse::Ignored,
        },
        _ => KeyResponse::Ignored,
    })
    .frame()
    .with_width(m.rail)
    .with_height(m.below_strip())
    .with_alignment(Alignment::Leading)
    .overlay(
        Alignment::Trailing,
        Rectangle
            .foreground_color(theme::LINE)
            .frame()
            .with_width(1),
    )
    .background_color(theme::CHROME, Rectangle)
}

/// One section's item. Pressing it enters the section's list.
fn item(
    m: &'static Metrics,
    section: Section,
    name: &'static str,
    glyph: &'static ImageRaw<'static, Gray4>,
    shown: Section,
    badge: usize,
) -> impl View<Rgb565, State> + use<> {
    Button::new(
        move |s: &mut State| s.enter_section(section),
        move |button: ButtonState| {
            item_look(m, name, glyph, section == shown, button.is_focused(), badge)
        },
    )
    .focus_key(keys::rail(section))
}

fn item_look(
    m: &'static Metrics,
    name: &str,
    glyph: &'static ImageRaw<'static, Gray4>,
    active: bool,
    focused: bool,
    badge: usize,
) -> impl View<Rgb565, State> + use<> {
    let color = if active {
        theme::ACCENT
    } else {
        theme::TEXT_TERTIARY
    };
    let face = if active { &font::BOLD } else { &font::MEDIUM };
    let cell = m.below_strip() / 3;
    VStack::new((
        Image::new(glyph)
            .as_template()
            .foreground_color(color)
            .overlay(
                Alignment::TopTrailing,
                (badge > 0)
                    .then(|| badge_view(m, badge))
                    .map(|b| b.offset(7, -5)),
            ),
        label::<8>(name, face, m.small, color),
    ))
    .with_spacing(2)
    .frame()
    .with_width(m.rail - 9)
    .with_height(cell - 8)
    // Focused, the item is boxed in place of its bar.
    .background(
        Alignment::Center,
        focused.then(|| {
            ZStack::new((
                RoundedRectangle::new(7).foreground_color(theme::FOCUS),
                RoundedRectangle::new(7)
                    .stroked(2)
                    .foreground_color(theme::ACCENT),
            ))
        }),
    )
    .frame()
    .with_width(m.rail - 1)
    .with_height(cell)
    .overlay(
        Alignment::Leading,
        (active && !focused).then(|| {
            RoundedRectangle::new(2)
                .foreground_color(theme::ACCENT)
                .frame_sized(4, cell - 20)
        }),
    )
}

/// The count of chats with unread messages, on the Chats glyph.
fn badge_view(m: &'static Metrics, count: usize) -> impl View<Rgb565, State> + use<> {
    let mut digits: heapless::String<4> = heapless::String::new();
    let _ = core::fmt::write(&mut digits, format_args!("{count}"));
    ZStack::new((
        Circle.foreground_color(theme::RED).frame_sized(19, 19),
        Text::new(digits, &font::BOLD)
            .with_font_size(m.small)
            .foreground_color(Rgb565::new(31, 63, 31))
            .hint_background_color(theme::RED),
    ))
}
