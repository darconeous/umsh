//! A saved peer's Share contact: the chats their contact can be sent to, in
//! list order. Pressing one sends it there and opens it; Backspace goes
//! back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::header;
use super::label;
use super::peers::{AVATAR, ROW, TEXT_X, focused_row};
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{ChatId, ChatKind, MAX_CHATS, State};
use crate::nav::keys;
use crate::{font, theme};

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; MAX_CHATS] = {
    let mut a = [0; MAX_CHATS];
    let mut i = 0;
    while i < MAX_CHATS {
        a[i] = i;
        i += 1;
    }
    a
};

/// What a chat's row shows.
#[derive(Clone)]
struct Chat {
    id: ChatId,
    avatar: AvatarStyle,
    name: String<32>,
    about: &'static str,
}

/// How far the line naming whom is sent sits in from the left.
const INSET: u32 = 12;

pub fn view(state: &State, name: &str) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let rows: Vec<Chat, MAX_CHATS> = state
        .chats
        .iter()
        .map(|c| Chat {
            id: c.id,
            avatar: c.avatar.clone(),
            name: c.name.clone(),
            about: match c.kind {
                ChatKind::Channel { .. } => "Channel",
                ChatKind::Peer { .. } => "Direct chat",
            },
        })
        .collect();
    let ids: Vec<ChatId, MAX_CHATS> = rows.iter().map(|c| c.id).collect();
    let count = rows.len();
    let mut whom: String<48> = String::new();
    _ = whom.push_str("Send ");
    for c in name.chars() {
        if whom.push(c).is_err() {
            break;
        }
    }
    _ = whom.push_str(" to");
    VStack::new((
        header(m, "Share contact", None, None),
        label::<48>(&whom, &font::MEDIUM, m.small, theme::TEXT_TERTIARY)
            .padding(Edges::Leading, INSET)
            .padding(Edges::Vertical, 4)
            .flex_infinite_width(HorizontalAlignment::Leading),
        super::list(
            ForEach::<MAX_CHATS>::new_vertical(&INDICES[..count], move |&i| row(m, &rows[i]))
                .keyed(move |&i| keys::chat(ids[i])),
        ),
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

fn row(m: &'static Metrics, chat: &Chat) -> impl View<Rgb565, State> + use<> {
    let chat = chat.clone();
    let id = chat.id;
    Button::new(
        move |s: &mut State| s.send_contact(id),
        move |button: ButtonState| {
            focused_row(
                HStack::new((
                    label::<32>(&chat.name, &font::SEMIBOLD, m.body, theme::TEXT),
                    Spacer::default(),
                    super::line(
                        chat.about,
                        &font::REGULAR,
                        m.secondary,
                        theme::TEXT_TERTIARY,
                    ),
                ))
                .with_spacing(8)
                .padding(Edges::Leading, TEXT_X)
                .padding(Edges::Trailing, 10)
                .frame()
                .with_height(ROW)
                .overlay(
                    Alignment::Leading,
                    super::avatar::view(&chat.avatar, AVATAR)
                        .frame()
                        .with_width(TEXT_X),
                ),
                button.is_focused(),
                m.width,
            )
        },
    )
}
