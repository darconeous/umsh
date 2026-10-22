//! Device › Channels: Add channel, then the joined channels in list order.
//! Pressing one shows it; Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::Vec;

use super::conversation::header;
use super::peers::{AVATAR, ROW, TEXT_X, add_row, focused_row};
use crate::avatar::{AvatarStyle, Title};
use crate::board::Metrics;
use crate::model::{ChannelAccess, ChatId, ChatKind, MAX_CHATS, State};
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

/// What a channel's row shows.
#[derive(Clone)]
struct Channel {
    id: ChatId,
    avatar: AvatarStyle,
    title: Title,
    about: &'static str,
}

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let rows: Vec<Channel, MAX_CHATS> = state
        .chats
        .iter()
        .filter_map(|c| match c.kind {
            ChatKind::Channel { access } => Some(Channel {
                id: c.id,
                avatar: c.avatar.clone(),
                title: c.title(),
                about: match access {
                    ChannelAccess::Private => "Private",
                    ChannelAccess::Named => "Named",
                    ChannelAccess::Clear => "Not encrypted",
                },
            }),
            ChatKind::Peer { .. } => None,
        })
        .collect();
    let ids: Vec<ChatId, MAX_CHATS> = rows.iter().map(|c| c.id).collect();
    let count = rows.len();
    VStack::new((
        header(m, "Channels", None, None),
        super::list(
            VStack::new((
                add_row(
                    m,
                    "Add channel",
                    State::open_add_channel,
                    keys::ADD_CHANNEL,
                    m.width,
                ),
                ForEach::<MAX_CHATS>::new_vertical(&INDICES[..count], move |&i| row(m, &rows[i]))
                    .keyed(move |&i| keys::chat(ids[i])),
            ))
            .with_spacing(0),
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

fn row(m: &'static Metrics, channel: &Channel) -> impl View<Rgb565, State> + use<> {
    let channel = channel.clone();
    let id = channel.id;
    Button::new(
        move |s: &mut State| s.open_channel(id),
        move |button: ButtonState| {
            focused_row(
                HStack::new((
                    super::line(channel.title.clone(), &font::SEMIBOLD, m.body, theme::TEXT),
                    Spacer::default(),
                    super::line(
                        channel.about,
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
                    super::avatar::view(&channel.avatar, AVATAR)
                        .frame()
                        .with_width(TEXT_X),
                ),
                button.is_focused(),
                m.width,
            )
        },
    )
}
