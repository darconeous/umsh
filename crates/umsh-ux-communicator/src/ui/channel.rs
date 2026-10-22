//! A joined channel: what it is, then one focusable list of its actions
//! and settings that the wheel scrolls through. Its name is edited in
//! place; Leave is last and asks to confirm. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::join::edited_name;
use super::member::detail_head;
use super::setting::{End, card, choice, row};
use crate::board::Metrics;
use crate::model::{ChannelAccess, ChatKind, ChatSummary, State};
use crate::nav::{JoinName, keys};
use crate::theme;

const ROW: u32 = 36;
/// The confirmation's width.
const CONFIRM_WIDTH: u32 = 300;

/// What kind of channel one with `access` is.
pub(super) const fn kind(access: ChannelAccess) -> &'static str {
    match access {
        ChannelAccess::Private => "Private channel",
        ChannelAccess::Named => "Public channel",
        ChannelAccess::Clear => "Not encrypted",
    }
}

pub fn view(
    m: &'static Metrics,
    summary: &ChatSummary,
    name: &JoinName,
    confirm: bool,
) -> impl View<Rgb565, State> + use<> {
    let about = match summary.kind {
        ChatKind::Channel { access } => kind(access),
        ChatKind::Peer { .. } => "",
    };
    let called = summary.name.clone();
    super::list(
        VStack::new((
            // Beside its badge, by what the badge leaves out.
            detail_head(m, &summary.avatar, summary.title().as_ref(), about, true),
            row(
                m,
                "Message",
                keys::CHANNEL_MESSAGE,
                State::message_channel,
                End::Chevron,
                false,
                ROW,
            ),
            row(
                m,
                "View QR code",
                keys::CHANNEL_CODE,
                State::open_channel_code,
                End::Chevron,
                false,
                ROW,
            ),
            edited_name(
                m,
                name,
                State::channel_name_mut,
                State::channel_name_active,
                keys::CHANNEL_NAME,
            ),
            row(
                m,
                "Notifications",
                keys::CHANNEL_NOTIFICATIONS,
                State::toggle_channel_notifications,
                End::Switch(!summary.muted),
                false,
                ROW,
            ),
            row(
                m,
                "Leave",
                keys::CHANNEL_LEAVE,
                State::ask_leave,
                End::Nothing,
                true,
                ROW,
            ),
        ))
        .with_spacing(0),
    )
    .with_scroll_step(ROW)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
    .popover(confirm.then_some(called).as_ref(), move |name| {
        confirmation(m, name)
    })
    // A tap outside is Cancel.
    .on_blur(|s: &mut State| {
        s.cancel_leave();
        Dismissal::Dismiss
    })
}

/// Leave, confirmed, or Cancel, which is focused.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
fn confirmation(m: &'static Metrics, name: &String<32>) -> impl View<Rgb565, State> + use<> {
    let mut leave: String<48> = String::new();
    _ = core::fmt::write(&mut leave, format_args!("Leave {name}"));
    card(
        m,
        VStack::new((
            choice(
                m,
                leave,
                keys::LEAVE_CONFIRM,
                State::leave_channel,
                theme::RED,
                None,
            ),
            choice(
                m,
                String::try_from("Cancel").unwrap_or_default(),
                keys::LEAVE_CANCEL,
                State::cancel_leave,
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        CONFIRM_WIDTH,
        HorizontalAlignment::Center,
        State::cancel_leave,
    )
}
