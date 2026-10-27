//! A path between this device and a saved peer, as the Route and Ping
//! screens list it: this device first, then each repeater, a row the wheel
//! stops on, then the peer, with a rail joining them. Between two rows,
//! how that hop was heard, when that is known.

use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::details::{AVATAR, INSET, NAME_X, repeater_look};
use super::line;
use super::peers::bars;
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{Leg, MAX_PATH, Repeater, Signal, State};
use crate::nav::keys;
use crate::{font, icon, theme};

/// A node's row: an action row with its margins.
const NODE: u32 = 36;
/// A hop between two rows: with a reading, without one, and one nobody
/// traced.
const READING: u32 = 22;
const PLAIN: u32 = 8;
const DASHED: u32 = 16;
/// The rail, down the middle of the avatars.
const RAIL: u32 = 2;
const RAIL_X: u32 = INSET + AVATAR / 2 - RAIL / 2;
/// The dashes of a hop nobody traced.
const DASH: u32 = 3;
/// The hollow dots in the place of repeaters nobody named.
const DOT: u32 = 6;

static INDICES: [usize; MAX_PATH] = {
    let mut a = [0; MAX_PATH];
    let mut i = 0;
    while i < MAX_PATH {
        a[i] = i;
        i += 1;
    }
    a
};

/// One hop between two rows of a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hop {
    /// Nothing is said of it.
    Plain,
    /// Nobody traced it.
    Dashed,
    /// How it was heard.
    Read(Leg),
}

/// The path from this device to the peer `peer`, an avatar and a name:
/// through `repeaters`, the nearest first, then `unnamed` more nobody
/// named. `hops` are the hops between the rows, in the same order. The
/// repeaters `identifying` were asked who they are, and spin at `phase`.
/// A `dim` path is one not known yet.
#[allow(clippy::too_many_arguments)]
pub(super) fn view(
    m: &'static Metrics,
    peer: (&AvatarStyle, &str),
    repeaters: &[Repeater],
    unnamed: u8,
    hops: &[Hop],
    identifying: &[[u8; 2]],
    phase: u8,
    dim: bool,
) -> impl View<Rgb565, State> + use<> {
    let hop = |i: usize| hops.get(i).copied().unwrap_or(Hop::Dashed);
    let first = hop(0);
    let stops: Vec<(Repeater, bool, Hop), MAX_PATH> = repeaters
        .iter()
        .enumerate()
        .map(|(i, repeater)| {
            (
                repeater.clone(),
                identifying.contains(&repeater.hint),
                hop(i + 1),
            )
        })
        .collect();
    let past = hop(repeaters.len() + 1);
    let avatar = peer.0.clone();
    let mut name: String<32> = String::new();
    _ = name.push_str(umsh_grapheme::cut(peer.1, 32));
    VStack::new((
        you(m),
        hop_row(m, first),
        ForEach::<MAX_PATH>::new_vertical(&INDICES[..stops.len()], move |&i| {
            let (repeater, waiting, after) = stops[i].clone();
            stop(m, i, repeater, waiting, phase, after)
        })
        .keyed(|&i| keys::path(i))
        .with_spacing(0),
        (unnamed > 0).then(|| VStack::new((nobody(m, unnamed), hop_row(m, past))).with_spacing(0)),
        end(m, avatar, name, dim),
    ))
    .with_spacing(0)
}

/// This device, where the path starts.
fn you(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    node_row(
        Image::new(&icon::HANDHELD_26)
            .as_template()
            .foreground_color(theme::TEXT_SECONDARY),
        line("You", &font::REGULAR, m.body, theme::TEXT_SECONDARY),
        false,
        true,
    )
}

/// The peer, where the path ends.
fn end(
    m: &'static Metrics,
    avatar: AvatarStyle,
    name: String<32>,
    dim: bool,
) -> impl View<Rgb565, State> + use<> {
    let color = if dim {
        theme::TEXT_TERTIARY
    } else {
        theme::TEXT
    };
    node_row(
        super::avatar::view(&avatar, AVATAR),
        line(name, &font::REGULAR, m.body, color),
        true,
        false,
    )
}

/// Repeaters nobody named, `count` of them, in one row.
fn nobody(m: &'static Metrics, count: u8) -> impl View<Rgb565, State> + use<> {
    let mut text: String<16> = String::new();
    _ = core::fmt::write(&mut text, format_args!("{count} unnamed"));
    let dot = || {
        Circle
            .stroked(1)
            .foreground_color(theme::TEXT_TERTIARY)
            .frame_sized(DOT, DOT)
    };
    node_row(
        VStack::new((dot(), dot(), dot())).with_spacing(2),
        line(text, &font::REGULAR, m.body, theme::TEXT_TERTIARY),
        false,
        false,
    )
}

/// A row for a node no press goes to: `mark` on the rail, `text` after it,
/// and the rail on toward the rows `above` and `below`.
fn node_row<C, M: View<Rgb565, C>, T: View<Rgb565, C>>(
    mark: M,
    text: T,
    above: bool,
    below: bool,
) -> impl View<Rgb565, C> + use<C, M, T> {
    text.padding(Edges::Leading, NAME_X)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(NODE)
        .overlay(
            Alignment::Leading,
            mark.frame()
                .with_width(AVATAR)
                .padding(Edges::Leading, INSET),
        )
        .background(Alignment::Leading, rail(NODE, above, below))
}

/// A repeater on the path, the `index`th: a press opens the node it most
/// plausibly is, or asks who it is when none is known. The hop `after` it
/// comes with it.
fn stop(
    m: &'static Metrics,
    index: usize,
    repeater: Repeater,
    waiting: bool,
    phase: u8,
    after: Hop,
) -> impl View<Rgb565, State> + use<> {
    Button::new(
        move |s: &mut State| s.open_repeater(index),
        move |button: ButtonState| {
            Lazy::new(
                (
                    repeater.clone(),
                    button.is_focused(),
                    waiting,
                    phase,
                    m,
                    after,
                ),
                stop_look,
            )
        },
    )
}

/// A repeater's row, as the details screen draws it, on the rail, and the
/// hop after it. Built each time it is drawn, as that row is.
fn stop_look(
    (repeater, focused, waiting, phase, m, after): &(
        Repeater,
        bool,
        bool,
        u8,
        &'static Metrics,
        Hop,
    ),
) -> impl View<Rgb565, ()> + use<> {
    VStack::new((
        repeater_look(&(repeater.clone(), *focused, *waiting, *phase, *m))
            .background(Alignment::Leading, rail(NODE, true, true)),
        hop_row(m, *after),
    ))
    .with_spacing(0)
}

/// The rail through a row `height` tall: from its top when it joins a row
/// `above`, to its bottom when it joins one `below`.
fn rail<C>(height: u32, above: bool, below: bool) -> impl View<Rgb565, C> + use<C> {
    let half = |on: bool| {
        Rectangle
            .foreground_color(if on { theme::RAIL } else { theme::BACKGROUND })
            .frame_sized(RAIL, height / 2)
    };
    VStack::new((half(above), half(below)))
        .with_spacing(0)
        .padding(Edges::Leading, RAIL_X)
}

/// One hop between two rows.
fn hop_row<C>(m: &'static Metrics, hop: Hop) -> impl View<Rgb565, C> + use<C> {
    let height = match hop {
        Hop::Plain => PLAIN,
        Hop::Dashed => DASHED,
        Hop::Read(_) => READING,
    };
    let dashed = hop == Hop::Dashed;
    let dash = || {
        Rectangle
            .foreground_color(theme::RAIL)
            .frame_sized(RAIL, DASH)
    };
    let rail = VStack::new((
        (!dashed).then(|| {
            Rectangle
                .foreground_color(theme::RAIL)
                .frame_sized(RAIL, height)
        }),
        // Dashes with gaps their own length between them.
        dashed.then(|| VStack::new((dash(), dash(), dash())).with_spacing(DASH)),
    ))
    .with_spacing(0)
    .padding(Edges::Leading, RAIL_X)
    .frame()
    .with_height(height);
    let reading = match hop {
        Hop::Read(leg) => Some(reading(m, leg)),
        Hop::Plain | Hop::Dashed => None,
    };
    reading
        .padding(Edges::Leading, NAME_X)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(height)
        .overlay(Alignment::Leading, rail)
}

/// How a hop was heard: bars and the reading, or that a bridge carried it.
fn reading<C>(m: &'static Metrics, leg: Leg) -> impl View<Rgb565, C> + use<C> {
    let (lit, text) = match leg {
        Leg::Heard(signal) => (Some(lit(signal)), signal_text(signal)),
        Leg::Bridge => (None, String::try_from("Bridge").unwrap_or_default()),
        Leg::Unknown => (None, String::new()),
    };
    HStack::new((
        lit.map(|lit| bars(lit, bar_color(lit))),
        line(text, &font::REGULAR, m.small, theme::TEXT_TERTIARY),
    ))
    .with_spacing(6)
    .with_alignment(VerticalAlignment::Center)
}

/// Of four bars, how strongly a hop was heard, by its signal-to-noise
/// ratio.
fn lit(signal: Signal) -> u8 {
    match signal.snr {
        50.. => 4,
        0.. => 3,
        -50.. => 2,
        _ => 1,
    }
}

/// Green for a hop heard well, amber, then red as it fades.
fn bar_color(lit: u8) -> Rgb565 {
    match lit {
        3.. => theme::GREEN,
        2 => theme::AMBER,
        _ => theme::RED,
    }
}

/// A reading, such as `−97 dBm · SNR 6.5 dB`, with true minuses.
pub(super) fn signal_text(signal: Signal) -> String<32> {
    let minus = |negative: bool| if negative { "\u{2212}" } else { "" };
    let snr = signal.snr.unsigned_abs();
    let mut text = String::new();
    _ = core::fmt::write(
        &mut text,
        format_args!(
            "{}{} dBm \u{B7} SNR {}{}.{} dB",
            minus(signal.rssi < 0),
            signal.rssi.unsigned_abs(),
            minus(signal.snr < 0),
            snr / 10,
            snr % 10,
        ),
    );
    text
}
