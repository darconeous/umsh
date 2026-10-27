//! A saved peer: who they are, their whole address, then one focusable list
//! of actions and readouts that the wheel scrolls through. Their alias is
//! edited in place; Forget is last and asks to confirm. Backspace goes
//! back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::join::edited_name;
use super::member::detail_head;
use super::setting::{End, card, choice, readout, row};
use crate::board::Metrics;
use crate::model::{PeerDetail, PeerSummary, State, hops_text};
use crate::nav::{JoinName, keys};
use crate::{font, theme};

const ROW: u32 = 34;
const ADDRESS: u32 = 22;
/// The address's inset from the screen's edges.
const INSET: u32 = 10;
/// The confirmation's width.
const CONFIRM_WIDTH: u32 = 300;

pub fn view(
    m: &'static Metrics,
    summary: &PeerSummary,
    detail: &PeerDetail,
    alias: &JoinName,
    confirm: bool,
    requested: bool,
) -> impl View<Rgb565, State> + use<> {
    // What the peer calls itself, when an alias here hides it.
    let advertised = detail
        .advertised
        .as_deref()
        .filter(|own| detail.alias.as_deref().is_some_and(|alias| alias != *own));
    let mut about: String<48> = String::new();
    _ = about.push_str("Saved peer");
    if let Some(hops) = summary.hops {
        _ = about.push_str(" \u{B7} ");
        _ = about.push_str(&hops_text(hops));
    }
    let name = summary.name.clone();
    super::list(
        VStack::new((
            detail_head(m, &summary.avatar, &summary.name, &about, true),
            super::address(
                &detail.address,
                &font::REGULAR,
                m.small,
                theme::TEXT_SECONDARY,
                m.width - 2 * INSET,
                ADDRESS,
            )
            .padding(Edges::Leading, INSET),
            row(
                m,
                "Message",
                keys::PEER_MESSAGE,
                State::message_peer,
                End::Chevron,
                false,
                ROW,
            ),
            row(
                m,
                "Share contact",
                keys::PEER_SHARE,
                State::share_contact,
                End::Chevron,
                false,
                ROW,
            ),
            VStack::new((
                edited_name(
                    m,
                    "Alias",
                    alias,
                    State::peer_alias_mut,
                    State::peer_alias_active,
                    keys::PEER_ALIAS,
                ),
                advertised.map(|own| readout(m, "Advertised name", own, ROW)),
            ))
            .with_spacing(0),
            VStack::new((
                row(
                    m,
                    "Route",
                    keys::PEER_ROUTE,
                    State::open_route,
                    End::value_chevron(detail.route.as_deref().unwrap_or_default()),
                    false,
                    ROW,
                ),
                readout(m, "Last heard", &detail.heard, ROW),
            ))
            .with_spacing(0),
            row(
                m,
                "Forward secrecy",
                keys::PEER_SECRECY,
                State::toggle_forward_secrecy,
                End::Switch(detail.forward_secrecy),
                false,
                ROW,
            ),
            row(
                m,
                "Ping",
                keys::PEER_PING,
                State::open_ping,
                End::Chevron,
                false,
                ROW,
            ),
            row(
                m,
                "Refresh identity",
                keys::PEER_IDENTITY,
                State::request_peer_identity,
                if requested {
                    End::value("Requested")
                } else {
                    End::Nothing
                },
                false,
                ROW,
            ),
            row(
                m,
                "Forget",
                keys::PEER_FORGET,
                State::ask_forget,
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
    .popover(confirm.then_some(name).as_ref(), move |name| {
        confirmation(m, name)
    })
    // A tap outside is Cancel.
    .on_blur(|s: &mut State| {
        s.cancel_forget();
        Dismissal::Dismiss
    })
}

/// Forget, confirmed, or Cancel, which is focused.
// Kept out of line, as `setting::row` is and for the same back-end failure,
// here on `State::forget_peer`'s address once `root_view` took the setup
// screens.
#[inline(never)]
fn confirmation(m: &'static Metrics, name: &String<32>) -> impl View<Rgb565, State> + use<> {
    let mut forget: String<48> = String::new();
    _ = core::fmt::write(&mut forget, format_args!("Forget {name}"));
    card(
        m,
        VStack::new((
            choice(
                m,
                forget,
                keys::FORGET_CONFIRM,
                State::forget_peer,
                theme::RED,
                None,
            ),
            choice(
                m,
                String::try_from("Cancel").unwrap_or_default(),
                keys::FORGET_CANCEL,
                State::cancel_forget,
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        CONFIRM_WIDTH,
        HorizontalAlignment::Center,
        State::cancel_forget,
    )
}
