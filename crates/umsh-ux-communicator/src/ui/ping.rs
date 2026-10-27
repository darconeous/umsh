//! Pings to a saved peer: how the latest went, Ping again once it has, the
//! path its answer took, and the pings before it. Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::titled;
use super::details::{INSET, spinner};
use super::path::{self, Hop};
use super::setting::{End, row};
use super::{label, line};
use crate::board::Metrics;
use crate::model::{Leg, MAX_PATH, PeerId, PeerSummary, PingView, State, age, hops_text};
use crate::nav::{MAX_EARLIER, PingSummary, keys};
use crate::{font, icon, theme};

const ROW: u32 = 34;
/// The line saying how the latest ping went.
const HERO: u32 = 44;
/// The disc behind its mark.
const MARK: u32 = 22;
/// The caption over the earlier pings.
const CAPTION: u32 = 30;

static EARLIER: [usize; MAX_EARLIER] = {
    let mut a = [0; MAX_EARLIER];
    let mut i = 0;
    while i < MAX_EARLIER {
        a[i] = i;
        i += 1;
    }
    a
};

/// Pings to the saved peer `id`, `peer`: the latest as the node says it
/// went, and the `earlier` ones.
pub fn view(
    state: &State,
    id: PeerId,
    peer: &PeerSummary,
    earlier: &[PingSummary],
) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let latest = state.node.ping_view(id);
    let latest = latest.as_ref();
    let elapsed = state.ping_elapsed();
    let identifying = state.identifying();
    let phase = state.spinner_phase();
    let reply = match latest {
        Some(PingView::Reply(reply)) => Some(reply),
        _ => None,
    };
    let settled = matches!(latest, Some(PingView::Reply(_) | PingView::NoReply));
    let mut hops: Vec<Hop, { MAX_PATH + 2 }> = Vec::new();
    match reply {
        Some(reply) => {
            for i in 0..=reply.repeaters.len() {
                _ = hops.push(match reply.legs.get(i) {
                    Some(Leg::Unknown) | None => Hop::Plain,
                    Some(&leg) => Hop::Read(leg),
                });
            }
            _ = hops.push(Hop::Dashed);
        }
        None => _ = hops.push(Hop::Dashed),
    }
    // Each with how long ago it settled, in seconds.
    let earlier: Vec<(PingSummary, u64), MAX_EARLIER> = earlier
        .iter()
        .map(|&ping| (ping, state.since(ping.at) / 1000))
        .collect();
    VStack::new((
        titled(m, "Ping", theme::TEXT, None, peer.name.as_str()),
        super::list(
            VStack::new((
                hero(m, latest, elapsed, phase),
                settled.then(|| {
                    row(
                        m,
                        "Ping again",
                        keys::PING_AGAIN,
                        State::ping_again,
                        End::Nothing,
                        false,
                        ROW,
                    )
                }),
                path::view(
                    m,
                    (&peer.avatar, peer.name.as_str()),
                    reply.map_or(&[][..], |r| r.repeaters.as_slice()),
                    reply.map_or(0, |r| r.unnamed),
                    &hops,
                    &identifying,
                    phase,
                    reply.is_none(),
                ),
                (!earlier.is_empty()).then(|| {
                    label::<16>("Earlier", &font::BOLD, m.small, theme::TEXT_SECONDARY)
                        .padding(Edges::Leading, INSET)
                        .flex_infinite_width(HorizontalAlignment::Leading)
                        .frame()
                        .with_height(CAPTION)
                        .with_alignment(Alignment::BottomLeading)
                }),
                ForEach::<MAX_EARLIER>::new_vertical(&EARLIER[..earlier.len()], move |&i| {
                    let (ping, ago) = earlier[i];
                    earlier_row(m, ping, ago)
                })
                .with_spacing(0),
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

/// How the latest ping went: the time counting up beside a spinner while
/// it waits, the round trip and how far the answer came, or that none did.
fn hero(
    m: &'static Metrics,
    latest: Option<&PingView>,
    elapsed: Option<u64>,
    phase: u8,
) -> impl View<Rgb565, State> + use<> {
    let (big, color, hops) = match latest {
        Some(PingView::Reply(reply)) => (
            seconds(u64::from(reply.round_trip_ms).div_ceil(100)),
            theme::TEXT,
            reply.hops.map(hops_text),
        ),
        Some(PingView::NoReply) => (
            String::try_from("No reply").unwrap_or_default(),
            theme::AMBER,
            None,
        ),
        Some(PingView::Waiting) | None => (
            seconds(elapsed.unwrap_or_default() / 100),
            theme::TEXT_SECONDARY,
            None,
        ),
    };
    let disc = |fill: Rgb565| Circle.foreground_color(fill).frame_sized(MARK, MARK);
    HStack::new((
        matches!(latest, Some(PingView::Waiting) | None).then(|| spinner(phase)),
        matches!(latest, Some(PingView::Reply(_))).then(|| {
            disc(theme::GREEN).overlay(
                Alignment::Center,
                Image::new(&icon::CHECK)
                    .as_template()
                    .foreground_color(theme::BACKGROUND),
            )
        }),
        matches!(latest, Some(PingView::NoReply)).then(|| {
            Image::new(&icon::WARNING)
                .as_template()
                .foreground_color(theme::AMBER)
        }),
        line(big, &font::BOLD, m.title, color),
        Spacer::default(),
        hops.map(|hops| line(hops, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY)),
    ))
    .with_spacing(10)
    .with_alignment(VerticalAlignment::Center)
    .padding(Edges::Leading, INSET)
    .padding(Edges::Trailing, 14)
    .frame()
    .with_height(HERO)
}

/// A ping before the latest: its round trip and how far its answer came,
/// or that none did, and how long ago it settled.
fn earlier_row(
    m: &'static Metrics,
    ping: PingSummary,
    ago: u64,
) -> impl View<Rgb565, State> + use<> {
    let mut what: String<24> = String::new();
    let color = match ping.round_trip_ms {
        Some(ms) => {
            _ = what.push_str(&seconds(u64::from(ms).div_ceil(100)));
            if let Some(hops) = ping.hops {
                _ = what.push_str(" \u{B7} ");
                _ = what.push_str(&hops_text(hops));
            }
            theme::TEXT
        }
        None => {
            _ = what.push_str("No reply");
            theme::AMBER
        }
    };
    let ago = age(Some(0), Some(u32::try_from(ago).unwrap_or(u32::MAX)));
    HStack::new((
        line(what, &font::REGULAR, m.body, color),
        Spacer::default(),
        line(ago, &font::REGULAR, m.secondary, theme::TEXT_TERTIARY),
    ))
    .with_spacing(8)
    .padding(Edges::Leading, INSET)
    .padding(Edges::Trailing, 14)
    .frame()
    .with_height(ROW)
    .overlay(
        Alignment::Bottom,
        Rectangle
            .foreground_color(theme::LINE)
            .frame()
            .with_height(1)
            .padding(Edges::Leading, INSET),
    )
}

/// `tenths` of a second, such as `1.4 s`.
fn seconds(tenths: u64) -> String<12> {
    let mut text = String::new();
    _ = core::fmt::write(&mut text, format_args!("{}.{} s", tenths / 10, tenths % 10));
    text
}
