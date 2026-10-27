//! The route the next message to a saved peer takes: this device, the
//! repeaters it names, and the peer, then when a send on it was last
//! acknowledged and Reset route. With none learned, Ping, which is how one
//! is. The wheel stops on each repeater, which a press opens or asks who it
//! is; Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::titled;
use super::path::{self, Hop};
use super::setting::{End, readout, row};
use crate::model::{Leg, MAX_PATH, PeerId, PeerRoute, PeerSummary, RouteKind, State, route_text};
use crate::nav::keys;
use crate::theme;

const ROW: u32 = 34;

/// The route to the saved peer `id`, `peer`, as the node holds it.
pub fn view(state: &State, id: PeerId, peer: &PeerSummary) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let route = state.node.peer_route(id);
    let route = route.as_ref();
    let identifying = state.identifying();
    let phase = state.spinner_phase();
    let kind = route.map(|r| r.kind);
    let held = kind.is_some_and(|kind| kind != RouteKind::Unknown);
    let mut hops: Vec<Hop, { MAX_PATH + 2 }> = Vec::new();
    let (repeaters, unnamed) = match route {
        Some(route) if held => (route.repeaters.as_slice(), route.unnamed),
        _ => (&[][..], 0),
    };
    match (route, kind) {
        (Some(route), Some(RouteKind::Direct)) => {
            _ = hops.push(
                route
                    .signal
                    .map_or(Hop::Plain, |s| Hop::Read(Leg::Heard(s))),
            );
        }
        (Some(route), Some(RouteKind::Source)) => {
            for _ in 0..=route.repeaters.len() {
                _ = hops.push(Hop::Plain);
            }
        }
        (Some(route), Some(RouteKind::Flood)) if route.unnamed > 0 => {
            _ = hops.push(Hop::Dashed);
            _ = hops.push(Hop::Dashed);
        }
        (Some(_), Some(RouteKind::Flood)) => _ = hops.push(Hop::Plain),
        _ => _ = hops.push(Hop::Dashed),
    }
    let confirmed = route.and_then(|r| r.confirmed.clone()).filter(|_| held);
    VStack::new((
        titled(m, "Route", theme::TEXT, None, &about(route)),
        super::list(
            VStack::new((
                path::view(
                    m,
                    (&peer.avatar, peer.name.as_str()),
                    repeaters,
                    unnamed,
                    &hops,
                    &identifying,
                    phase,
                    !held,
                ),
                confirmed.map(|confirmed| readout(m, "Confirmed", &confirmed, ROW)),
                held.then(|| {
                    row(
                        m,
                        "Reset route",
                        keys::ROUTE_RESET,
                        State::reset_route,
                        End::Nothing,
                        true,
                        ROW,
                    )
                }),
                (kind == Some(RouteKind::Unknown)).then(|| {
                    row(
                        m,
                        "Ping",
                        keys::ROUTE_PING,
                        State::open_ping,
                        End::Chevron,
                        false,
                        ROW,
                    )
                }),
            ))
            .with_spacing(0),
        )
        .with_scroll_step(ROW)
        .with_self_focus(true)
        .focus_key(keys::READING),
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

/// What the header says of the route: how far it goes, how, or that none
/// is held.
fn about(route: Option<&PeerRoute>) -> String<24> {
    route.map(route_text).unwrap_or_default()
}
