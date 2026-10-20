//! The member who sent a channel message, or the unsaved peer of a direct
//! chat. A channel message carries only a hint of its sender, so until their
//! identity is known the screen offers to ask the channel for it; once it is,
//! it offers to message them and to save them as a peer. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::details::row;
use super::label;
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{Member, State};
use crate::nav::keys;
use crate::{font, icon, theme};

/// The head's height, and its avatar's size and place.
const HEAD: u32 = 62;
/// The address line under the head.
const ADDRESS: u32 = 22;
const AVATAR: u32 = 44;
const AVATAR_X: u32 = 10;
const ROW: u32 = 36;
const INSET: u32 = 12;

/// What an action row shows at its end.
#[derive(Clone, Copy)]
pub(super) enum End {
    Nothing,
    /// It goes to another screen.
    Chevron,
    Value(&'static str),
}

/// `member`, heard in the channel named `channel`, or the peer of a direct
/// chat when there is none. `requested` says their identity has been asked
/// for.
pub fn view(
    m: &'static Metrics,
    member: &Member,
    requested: bool,
    channel: Option<&str>,
) -> impl View<Rgb565, State> + use<> {
    let known = member.address.is_some();
    VStack::new((
        header(
            m,
            if channel.is_some() { "Member" } else { "Peer" },
            None,
            None,
        ),
        head(m, member, channel),
        (!known).then(|| {
            action(
                m,
                "Request identity",
                keys::REQUEST_IDENTITY,
                State::request_identity,
                if requested {
                    End::Value("Requested")
                } else {
                    End::Nothing
                },
            )
        }),
        known.then(|| {
            action(
                m,
                "Message",
                keys::MESSAGE_MEMBER,
                State::message_member,
                End::Chevron,
            )
        }),
        (known && !member.saved).then(|| {
            action(
                m,
                "Save peer",
                keys::SAVE_PEER,
                State::save_member,
                End::Nothing,
            )
        }),
        // Once known, the address under the head shows the hint.
        (!known).then(|| row(m, "Hint", &member.hint, false)),
        (!known).then(|| row(m, "Address", "Not yet known", true)),
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

/// Their avatar and name, where and when they were last heard, and their
/// address once it is known.
fn head(
    m: &'static Metrics,
    member: &Member,
    channel: Option<&str>,
) -> impl View<Rgb565, State> + use<> {
    let mut heard: String<48> = String::new();
    _ = match (channel, member.heard.is_empty()) {
        (Some(channel), _) => core::fmt::write(
            &mut heard,
            format_args!("Heard in {channel} \u{B7} {}", member.heard),
        ),
        (None, false) => core::fmt::write(&mut heard, format_args!("Heard {} ago", member.heard)),
        (None, true) => Ok(()),
    };
    VStack::new((
        detail_head(m, &member.sender.avatar, &member.sender.name, &heard, false),
        member.address.as_ref().map(|address| {
            super::address(
                address,
                &font::REGULAR,
                m.small,
                theme::TEXT_SECONDARY,
                m.width - 2 * AVATAR_X,
                ADDRESS,
            )
            .padding(Edges::Leading, AVATAR_X)
        }),
    ))
    .with_spacing(0)
}

/// The head of a screen about one peer or channel: its avatar, its name, and
/// a line about it.
pub(super) fn detail_head(
    m: &'static Metrics,
    avatar: &AvatarStyle,
    name: &str,
    about: &str,
    back: bool,
) -> impl View<Rgb565, State> + use<> {
    let back = back
        .then(|| super::conversation::back(m, |s| _ = s.back()))
        .flatten();
    let leading = if back.is_some() { 0 } else { AVATAR_X };
    HStack::new((
        back,
        super::avatar::view(avatar, AVATAR),
        VStack::new((
            label::<32>(name, &font::BOLD, m.body, theme::TEXT),
            label::<48>(about, &font::MEDIUM, m.small, theme::TEXT_TERTIARY),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading),
    ))
    .with_spacing(10)
    .padding(Edges::Leading, leading)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .frame()
    .with_height(HEAD)
}

/// A row that does something when pressed.
pub(super) fn action(
    m: &'static Metrics,
    text: &'static str,
    key: buoyant::focus::FocusKey,
    act: fn(&mut State),
    end: End,
) -> impl View<Rgb565, State> + use<> {
    Button::new(act, move |button: ButtonState| {
        let focused = button.is_focused();
        let face = if focused { &font::BOLD } else { &font::REGULAR };
        HStack::new((
            label::<24>(text, face, m.body, theme::TEXT),
            Spacer::default(),
            match end {
                End::Value(value) => Some(label::<16>(
                    value,
                    &font::REGULAR,
                    m.secondary,
                    theme::TEXT_SECONDARY,
                )),
                End::Nothing | End::Chevron => None,
            },
            matches!(end, End::Chevron).then(|| {
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY)
            }),
        ))
        .with_spacing(8)
        .hint_background_color(if focused {
            theme::FOCUS
        } else {
            theme::BACKGROUND
        })
        .padding(Edges::Leading, INSET - 4)
        .padding(Edges::Trailing, 10)
        .frame()
        .with_height(ROW - 2)
        .background(
            Alignment::Center,
            focused.then(|| {
                ZStack::new((
                    RoundedRectangle::new(8).foreground_color(theme::FOCUS),
                    RoundedRectangle::new(8)
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
    })
    .focus_key(key)
}
