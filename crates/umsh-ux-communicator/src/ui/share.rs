//! Share: a code for this node or a joined channel, with what it shares
//! beside it. Turning moves Shows between them; Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use buoyant::view::scroll_view::{ScrollBarVisibility, ScrollDirection};
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::label;
use crate::board::Metrics;
use crate::model::{ChannelAccess, ChatKind, MAX_CHATS, Shareable, State};
use crate::nav::keys;
use crate::qr::{Owned, QrImage};
use crate::{font, icon, theme};

/// The room the code takes: the screen's height where Shows fits beside
/// it, and otherwise what the name and its lines leave. The quiet zone is
/// in modules.
const fn room(m: &Metrics) -> u32 {
    if shows_beside(m) {
        tall(m)
    } else {
        m.width - INSET - GAP - TRAILING - NARROW_COLUMN
    }
}
const fn tall(m: &Metrics) -> u32 {
    m.below_strip() - header(m) - 8
}
/// The header, with the way back, on a board with touch: the keys' Back
/// is no sign of one on screen.
const fn header(m: &Metrics) -> u32 {
    if m.back.is_some() { m.header } else { 0 }
}
const QUIET: u32 = 2;
const INSET: u32 = 8;
const GAP: u32 = 12;
const TRAILING: u32 = 4;
/// The least Shows takes beside the code; where it has less, it goes under
/// the code, and the column beside the code is this wide.
const SHOWS_BESIDE: u32 = 200;
const NARROW_COLUMN: u32 = 156;
/// The name, each line under it, and Shows.
const NAME: u32 = 40;
const LINE: u32 = 20;
const ROW: u32 = 36;
const RADIUS: u16 = 8;
/// Whether Shows fits beside the code at the screen's full height.
const fn shows_beside(m: &Metrics) -> bool {
    m.width - INSET - tall(m) - GAP - TRAILING >= SHOWS_BESIDE
}
/// The column beside the code.
const fn column(m: &Metrics) -> u32 {
    m.width - INSET - room(m) - GAP - TRAILING
}
/// Shows' width: the column beside the code, or the screen under it.
const fn shows_width(m: &Metrics) -> u32 {
    if shows_beside(m) {
        column(m)
    } else {
        m.width - INSET - TRAILING
    }
}
/// How many things there are to show: this node and every chat.
const SHAREABLES: usize = MAX_CHATS + 1;

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; SHAREABLES] = {
    let mut a = [0; SHAREABLES];
    let mut i = 0;
    while i < SHAREABLES {
        a[i] = i;
        i += 1;
    }
    a
};

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let shown = state.shared();
    let items = state.shareables();
    let last = items.len().saturating_sub(1);
    let mut name: String<32> = String::new();
    let mut lines: Vec<String<24>, 2> = Vec::new();
    match shown {
        Shareable::Identity => {
            _ = name.push_str(&state.status.device_name);
            let address = state.node.address();
            let (first, second) = address.split_at(address.len().min(22));
            _ = lines.push(String::try_from(first).unwrap_or_default());
            _ = lines.push(String::try_from(second).unwrap_or_default());
        }
        Shareable::Channel(chat) => {
            if let Some(chat) = state.chat(chat) {
                _ = name.push_str(&chat.name);
                let about = match chat.kind {
                    ChatKind::Channel {
                        access: ChannelAccess::Private,
                    } => "Private channel",
                    ChatKind::Channel {
                        access: ChannelAccess::Clear,
                    } => "Not encrypted",
                    _ => "Named channel",
                };
                _ = lines.push(String::try_from(about).unwrap_or_default());
            }
        }
    }
    // What Shows reads at each place it turns to.
    let values: Vec<String<32>, SHAREABLES> = items
        .iter()
        .map(|item| match item {
            Shareable::Identity => String::try_from("Identity").unwrap_or_default(),
            Shareable::Channel(chat) => state
                .chat(*chat)
                .map(|c| c.name.clone())
                .unwrap_or_default(),
        })
        .collect();
    let code = state
        .node
        .share_uri(shown)
        .and_then(|uri| QrImage::encode(&uri, room(m), QUIET));
    let mono = matches!(shown, Shareable::Identity);
    // Turned in place: each place is a row as wide as Shows, and the row
    // focused scrolls into view.
    let width = shows_width(m);
    let turned = ScrollView::new(
        ForEach::<SHAREABLES>::new_horizontal(&INDICES[..items.len()], move |&i| {
            shows(m, width, i > 0, i < last, values[i].clone())
        })
        .keyed(move |&i| keys::share(items[i])),
    )
    .with_direction(ScrollDirection::Horizontal)
    .with_bar_visibility(ScrollBarVisibility::Never)
    .frame()
    .with_width(width)
    .with_height(ROW)
    .padding(Edges::Top, 8);
    let (beside, under) = if shows_beside(m) {
        (Some(turned), None)
    } else {
        (None, Some(turned))
    };
    VStack::new((
        m.back
            .is_some()
            .then(|| super::conversation::header(m, "Share", None, None)),
        VStack::new((
            HStack::new((
                card(m, code),
                VStack::new((
                    label::<32>(&name, &font::BOLD, m.body, theme::TEXT)
                        .frame()
                        .with_height(NAME),
                    lines.first().map(|line| about(m, line, mono)),
                    lines.get(1).map(|line| about(m, line, mono)),
                    beside,
                ))
                .with_spacing(0)
                .with_alignment(HorizontalAlignment::Leading)
                .flex_infinite_width(HorizontalAlignment::Leading),
            ))
            .with_spacing(GAP)
            .with_alignment(VerticalAlignment::Top),
            under,
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading)
        .padding(Edges::Leading, INSET)
        .padding(Edges::Trailing, TRAILING),
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

/// A line under the name: the address, set in monospace so its two halves
/// line up, or what kind of channel it is.
fn about(m: &'static Metrics, line: &str, mono: bool) -> impl View<Rgb565, State> + use<> {
    label::<24>(
        line,
        if mono { &font::MONO } else { &font::REGULAR },
        m.small,
        theme::TEXT_SECONDARY,
    )
    .frame()
    .with_height(LINE)
}

/// The code on its light card, centered in the room it has.
/// The room is the same whatever the code's size, so what is beside it stays
/// put as Shows turns.
fn card(m: &'static Metrics, code: Option<QrImage>) -> impl View<Rgb565, State> + use<> {
    code.map(|code| {
        let quiet = QUIET * code.scale();
        Image::new(Owned(code))
            .padding(Edges::All, quiet)
            .background(
                Alignment::Center,
                RoundedRectangle::new(4).foreground_color(Rgb565::new(31, 63, 31)),
            )
    })
    .frame()
    .with_width(room(m))
    .with_height(if shows_beside(m) {
        m.below_strip()
    } else {
        room(m)
    })
}

/// Shows at one of the places it turns to, with arrows toward the places
/// on either side.
fn shows(
    m: &'static Metrics,
    width: u32,
    before: bool,
    after: bool,
    value: String<32>,
) -> impl View<Rgb565, State> + use<> {
    Button::new(
        |_: &mut State| {},
        move |button: ButtonState| {
            let focused = button.is_focused();
            let arrow = |icon, on: bool| {
                Image::new(icon).as_template().foreground_color(if on {
                    theme::ACCENT
                } else {
                    theme::FOCUS
                })
            };
            HStack::new((
                label::<8>("Shows", &font::BOLD, m.body, theme::TEXT),
                Spacer::default(),
                arrow(&icon::BACK, before),
                label::<32>(&value, &font::BOLD, m.secondary, theme::TEXT),
                arrow(&icon::CHEVRON, after),
            ))
            .with_spacing(6)
            .hint_background_color(theme::FOCUS)
            .padding(Edges::Leading, 10)
            .padding(Edges::Trailing, 6)
            .frame()
            .with_height(ROW - 2)
            .background(
                Alignment::Center,
                focused.then(|| {
                    ZStack::new((
                        RoundedRectangle::new(RADIUS).foreground_color(theme::FOCUS),
                        RoundedRectangle::new(RADIUS)
                            .stroked(2)
                            .foreground_color(theme::ACCENT),
                    ))
                }),
            )
            .padding(Edges::Leading, 4)
            .frame()
            .with_width(width)
        },
    )
}
