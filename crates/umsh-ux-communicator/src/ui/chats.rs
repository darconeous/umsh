//! The Chats list: two lines per chat, newest first. The last row is
//! clipped by the screen edge when the list goes on.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::Lazy;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::line;
use super::setting::{card, choice};
use crate::avatar::{AvatarStyle, Title};
use crate::board::Metrics;
use crate::model::{Age, ChatSummary, Chats, MAX_CHATS, State, age};
use crate::nav::{ChatMenu, keys};
use crate::text::DraftText;
use crate::{font, icon, theme};

const ROW: u32 = 44;
/// The lines' heights: a line of each one's type, which together fill a row.
const NAME_LINE: u32 = 24;
const PREVIEW_LINE: u32 = ROW - NAME_LINE;
const AVATAR: u32 = 34;
/// From the list's leading edge to the text.
const TEXT_X: u32 = 51;
/// A chat's menu, and Delete's confirmation.
const MENU_WIDTH: u32 = 220;

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

/// The list, with each chat's age counted to `now`, and over it `menu`:
/// a chat's menu or Delete's confirmation. Backspace moves to the rail, Enter opens the
/// focused chat, as a press does, and a letter starts Find with it.
pub fn view(
    m: &'static Metrics,
    chats: &Chats,
    now: Option<u32>,
    menu: Option<ChatMenu>,
) -> impl View<Rgb565, State> + use<> {
    let rows = chats.clone();
    let ids: Vec<u32, MAX_CHATS> = chats.iter().map(|c| c.id).collect();
    let count = rows.len();
    // The chat a menu is open for stays lit behind it.
    let held = menu.map(ChatMenu::chat);
    super::list(
        ForEach::<MAX_CHATS>::new_vertical(&INDICES[..count], move |&i| {
            let chat = &rows[i];
            row(m, chat, age(chat.last_activity, now), held == Some(chat.id))
        })
        .keyed(move |&i| keys::chat(ids[i])),
    )
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        // Back, or the arrow toward the rail.
        Key::Backspace | Key::LeftArrow => {
            s.focus_rail();
            KeyResponse::Handled
        }
        Key::Enter => match s.focus().current().and_then(keys::chat_of) {
            Some(chat) => {
                s.open_chat(chat);
                KeyResponse::Handled
            }
            None => KeyResponse::Ignored,
        },
        // Find's field, focused as it opens, takes the key.
        Key::Character(c) if !c.is_whitespace() => {
            s.start_find();
            KeyResponse::Redirect
        }
        _ => KeyResponse::Ignored,
    })
    .popover(menu.as_ref(), move |menu| over(m, *menu))
    // A tap outside closes it, as Backspace does.
    .on_blur(|s: &mut State| {
        s.close_chat_menu();
        Dismissal::Dismiss
    })
}

/// A chat's menu, or Delete's confirmation, Cancel focused. Backspace
/// closes either.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
fn over(m: &'static Metrics, menu: ChatMenu) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| String::try_from(text).unwrap_or_default();
    let (first, second) = match menu {
        ChatMenu::Open(_) => (
            Some(choice(
                m,
                text("Show peer"),
                keys::CHAT_SHOW_PEER,
                State::show_chat_peer,
                theme::TEXT,
                None,
            )),
            choice(
                m,
                text("Delete"),
                keys::CHAT_DELETE,
                State::ask_delete_chat,
                theme::RED,
                None,
            ),
        ),
        ChatMenu::ConfirmDelete(_) => (
            Some(choice(
                m,
                text("Delete chat"),
                keys::DELETE_CONFIRM,
                State::delete_chat,
                theme::RED,
                None,
            )),
            choice(
                m,
                text("Cancel"),
                keys::DELETE_CANCEL,
                State::close_chat_menu,
                theme::TEXT,
                None,
            ),
        ),
    };
    card(
        m,
        VStack::new((first, second)).with_spacing(0),
        MENU_WIDTH,
        match menu {
            ChatMenu::Open(_) => HorizontalAlignment::Trailing,
            ChatMenu::ConfirmDelete(_) => HorizontalAlignment::Center,
        },
        State::close_chat_menu,
    )
}

fn row(
    m: &'static Metrics,
    chat: &ChatSummary,
    age: Age,
    held: bool,
) -> impl View<Rgb565, State> + use<> {
    let id = chat.id;
    let look = Row {
        avatar: chat.avatar.clone(),
        title: chat.title(),
        preview: chat.preview.clone(),
        draft: (!chat.draft.is_empty()).then(|| chat.draft.storage().clone()),
        age,
        unread: chat.unread,
        muted: chat.muted,
        focused: false,
        m,
    };
    Button::new(
        move |s: &mut State| s.open_chat(id),
        move |button: ButtonState| {
            let mut look = look.clone();
            look.focused = held || button.is_focused();
            Lazy::new(look, row_look)
        },
    )
}

/// What a chat's row draws.
#[derive(Clone)]
struct Row {
    avatar: AvatarStyle,
    title: Title,
    preview: String<64>,
    draft: Option<DraftText>,
    age: Age,
    unread: bool,
    muted: bool,
    focused: bool,
    m: &'static Metrics,
}

/// A chat's row: its avatar, then its name over its last message.
///
/// Built from its data each time it is drawn ([`Lazy`]): kept in the
/// render trees, every row's would outweigh the rest of the screen.
fn row_look(row: &Row) -> impl View<Rgb565, ()> + use<> {
    let background = if row.focused {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    };
    // Each line has a fixed height and the avatar is an overlay, so no
    // stack nests in another: every size a stack probes a line with is the
    // same, and its text is measured once. A chat with nothing in it has
    // its name alone, in the middle.
    let previewed = !row.preview.is_empty() || row.draft.is_some();
    VStack::new((
        name_line(row).frame().with_height(NAME_LINE),
        previewed.then(|| preview_line(row).frame().with_height(PREVIEW_LINE)),
    ))
    .with_spacing(0)
    .with_alignment(HorizontalAlignment::Leading)
    .padding(Edges::Leading, TEXT_X)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .frame()
    .with_height(ROW)
    // Inside the background, so its edges blend into the row's color.
    .overlay(
        Alignment::Leading,
        super::avatar::view(&row.avatar, AVATAR)
            .frame()
            .with_width(TEXT_X),
    )
    // Only the focused row is filled: the others show the screen's
    // background, and painting it again is most of what a frame would
    // cost on the device.
    .hint_background_color(background)
    .background(
        Alignment::Center,
        row.focused
            .then(|| Rectangle.foreground_color(theme::FOCUS)),
    )
    .overlay(
        Alignment::Leading,
        row.focused.then(|| {
            Rectangle
                .foreground_color(theme::ACCENT)
                .frame_sized(4, ROW)
        }),
    )
    .overlay(
        Alignment::BottomTrailing,
        (!row.focused).then(|| {
            Rectangle
                .foreground_color(theme::LINE)
                .frame_sized(row.m.beside_rail() - TEXT_X, 1)
        }),
    )
}

/// The chat's name, then its age at the trailing edge.
fn name_line(row: &Row) -> impl View<Rgb565, ()> + use<> {
    let age_color = if row.unread {
        theme::ACCENT
    } else {
        theme::TEXT_TERTIARY
    };
    let name_face = if row.unread {
        &font::BOLD
    } else {
        &font::SEMIBOLD
    };
    let name_color = if row.title.as_ref() == "EMERGENCY" {
        theme::RED
    } else {
        theme::TEXT
    };
    HStack::new((
        line(row.title.clone(), name_face, row.m.body, name_color),
        Spacer::default(),
        row.muted.then(|| {
            Image::new(&icon::BELL_SLASH)
                .as_template()
                .foreground_color(theme::TEXT_TERTIARY)
        }),
        line(row.age.clone(), &font::SEMIBOLD, row.m.small, age_color).fixed_size(true, false),
    ))
    .with_spacing(4)
    .padding(Edges::Trailing, 10)
}

/// The last message, or the draft, with the unread dot at the trailing edge.
fn preview_line(row: &Row) -> impl View<Rgb565, ()> + use<> {
    let color = if row.unread {
        theme::TEXT_SECONDARY
    } else {
        theme::TEXT_TERTIARY
    };
    HStack::new((
        row.draft.is_some().then(|| {
            line("Draft", &font::BOLD, row.m.secondary, theme::AMBER).fixed_size(true, false)
        }),
        row.draft
            .clone()
            .map(|draft| line(draft, &font::REGULAR, row.m.secondary, color)),
        row.draft
            .is_none()
            .then(|| line(row.preview.clone(), &font::REGULAR, row.m.secondary, color)),
        Spacer::default(),
        row.unread
            .then(|| Circle.foreground_color(theme::ACCENT).frame_sized(10, 10)),
    ))
    .with_spacing(6)
    .padding(Edges::Trailing, 9)
}
