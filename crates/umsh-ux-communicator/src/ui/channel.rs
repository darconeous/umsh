//! A joined channel: what it is, then one focusable list of its actions
//! and settings that the wheel scrolls through. Its name is edited in
//! place; Leave is last and asks to confirm. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use super::join::edited_name;
use super::member::detail_head;
use super::setting::{End, Removal, ask_card, row};
use crate::board::Metrics;
use crate::model::{ChannelAccess, ChatKind, ChatSummary, State};
use crate::nav::{Ask, JoinName, keys};

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
    test_messages: Option<bool>,
    messages: usize,
    confirm: Option<Ask>,
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
                "Name",
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
            test_messages.map(|on| {
                row(
                    m,
                    "Test Messages",
                    keys::CHANNEL_TEST_MESSAGES,
                    State::toggle_test_messages,
                    End::Switch(on),
                    false,
                    ROW,
                )
            }),
            (messages > 0).then(|| {
                row(
                    m,
                    "Clear messages",
                    keys::CLEAR_MESSAGES,
                    State::ask_clear_messages,
                    End::Nothing,
                    true,
                    ROW,
                )
            }),
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
    .popover(confirm.as_ref(), move |&asked| {
        ask_card(m, asked, Some(LEAVE), &called, messages, CONFIRM_WIDTH)
    })
    // A tap outside is Cancel.
    .on_blur(|s: &mut State| {
        s.cancel_ask();
        Dismissal::Dismiss
    })
}

/// Leaving, as its confirmation offers it.
const LEAVE: Removal = Removal {
    label: "Leave",
    confirm: keys::LEAVE_CONFIRM,
    cancel: keys::LEAVE_CANCEL,
    act: State::leave_channel,
};
