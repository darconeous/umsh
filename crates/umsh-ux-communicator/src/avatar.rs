//! Avatars: the colors, lettering, and outline that identify a peer or a
//! channel at a glance.
//!
//! These follow the iOS app's `AvatarStyle`, `ChannelAvatar`, and
//! `PeerAvatarShape`, which are canonical. An avatar that differed between
//! the phone and the device would read as a different node.

use embedded_graphics::image::ImageRaw;
use embedded_graphics::pixelcolor::{Gray4, Rgb565, Rgb888};
use heapless::String;

include!(concat!(env!("OUT_DIR"), "/shapes.rs"));

/// The outline of a peer's avatar, which says what kind of node it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerShape {
    /// A node that chats.
    Circle,
    /// A repeater or bridge.
    Triangle,
    /// Anything else.
    Hexagon,
}

/// The outline an avatar is drawn in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outline {
    Peer(PeerShape),
    /// A channel's rounded square.
    Channel,
}

impl Outline {
    /// The mask for this outline at `size` pixels, or `None` when that size
    /// was not rasterized.
    #[must_use]
    pub fn mask(self, size: u32) -> Option<&'static ImageRaw<'static, Gray4>> {
        Some(match (self, size) {
            (Self::Peer(PeerShape::Circle), 26) => &CIRCLE_26,
            (Self::Peer(PeerShape::Circle), 28) => &CIRCLE_28,
            (Self::Peer(PeerShape::Circle), 30) => &CIRCLE_30,
            (Self::Peer(PeerShape::Circle), 34) => &CIRCLE_34,
            (Self::Peer(PeerShape::Circle), 44) => &CIRCLE_44,
            (Self::Peer(PeerShape::Triangle), 26) => &TRIANGLE_26,
            (Self::Peer(PeerShape::Triangle), 28) => &TRIANGLE_28,
            (Self::Peer(PeerShape::Triangle), 30) => &TRIANGLE_30,
            (Self::Peer(PeerShape::Triangle), 34) => &TRIANGLE_34,
            (Self::Peer(PeerShape::Triangle), 44) => &TRIANGLE_44,
            (Self::Peer(PeerShape::Hexagon), 26) => &HEXAGON_26,
            (Self::Peer(PeerShape::Hexagon), 28) => &HEXAGON_28,
            (Self::Peer(PeerShape::Hexagon), 30) => &HEXAGON_30,
            (Self::Peer(PeerShape::Hexagon), 34) => &HEXAGON_34,
            (Self::Peer(PeerShape::Hexagon), 44) => &HEXAGON_44,
            (Self::Channel, 26) => &SQUARE_26,
            (Self::Channel, 28) => &SQUARE_28,
            (Self::Channel, 30) => &SQUARE_30,
            (Self::Channel, 34) => &SQUARE_34,
            (Self::Channel, 44) => &SQUARE_44,
            _ => return None,
        })
    }
}

/// Everything an avatar is drawn from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvatarStyle {
    pub outline: Outline,
    pub fill: Rgb565,
    pub text: Rgb565,
    /// One or two lines of lettering, stacked.
    pub lines: [Lettering; 2],
}

/// A line of an avatar's lettering: up to two grapheme clusters, such as two
/// letters, or a letter and an emoji.
pub type Lettering = String<32>;

/// A channel the two standard names are recognized by, which keep fixed
/// colors instead of derived ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinChannel {
    Public,
    Emergency,
}

impl AvatarStyle {
    /// A peer's avatar: the hint's three leading octets as the fill, and
    /// whichever of black or white has the greater APCA contrast against it.
    /// `hint_text` is the hint as presented, such as `kBkQ` or `H1x*`.
    #[must_use]
    pub fn peer(hint: [u8; 3], hint_text: &str, shape: PeerShape) -> Self {
        let rgb = [hint[0], hint[1], hint[2]];
        Self {
            outline: Outline::Peer(shape),
            fill: rgb565(rgb),
            text: if prefers_white_text(rgb) {
                WHITE
            } else {
                BLACK
            },
            lines: two_lines(hint_text),
        }
    }

    /// A channel's badge: initials from its name, fill from its key's tint.
    /// An initial is the first grapheme cluster of a word, so a channel
    /// named "🔥 Crew" is lettered 🔥C, as on iOS.
    #[must_use]
    pub fn channel(builtin: Option<BuiltinChannel>, title: &str, tint: [u8; 3]) -> Self {
        let initials: heapless::Vec<&str, 4> = title
            .split(|c: char| c.is_whitespace() || c == '-' || c == '_')
            .filter_map(umsh_grapheme::first_cluster)
            .take(4)
            .collect();
        let (fill, text) = match builtin {
            Some(BuiltinChannel::Public) => (rgb565([0x0A, 0x84, 0xFF]), WHITE),
            Some(BuiltinChannel::Emergency) => (rgb565([0xFF, 0x45, 0x3A]), WHITE),
            None => derived_channel_fill(tint),
        };
        // Up to two initials share a line; more go two over two.
        let first_line = if initials.len() > 2 {
            2
        } else {
            initials.len()
        };
        let mut lines = [String::new(), String::new()];
        for (i, initial) in initials.iter().enumerate() {
            push_uppercase(&mut lines[usize::from(i >= first_line)], initial);
        }
        Self {
            outline: Outline::Channel,
            fill,
            text,
            lines,
        }
    }
}

const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const BLACK: Rgb565 = Rgb565::new(0, 0, 0);

fn rgb565(rgb: [u8; 3]) -> Rgb565 {
    Rgb888::new(rgb[0], rgb[1], rgb[2]).into()
}

/// The first two clusters, then the next two.
fn two_lines(s: &str) -> [Lettering; 2] {
    let mut lines = [String::new(), String::new()];
    for (i, cluster) in umsh_grapheme::clusters(s).take(4).enumerate() {
        let _ = lines[i / 2].push_str(cluster);
    }
    lines
}

/// Appends `cluster` uppercased, whole or not at all.
fn push_uppercase(line: &mut Lettering, cluster: &str) {
    let mut upper = Lettering::new();
    for c in cluster.chars().flat_map(char::to_uppercase) {
        if upper.push(c).is_err() {
            return;
        }
    }
    let _ = line.push_str(&upper);
}

/// Whether white text has the greater APCA lightness contrast (SAPC 0.0.98G)
/// against `rgb` than black text does.
fn prefers_white_text(rgb: [u8; 3]) -> bool {
    fn screen_luminance(rgb: [f32; 3]) -> f32 {
        let y = 0.212_672_9 * libm::powf(rgb[0], 2.4)
            + 0.715_152_2 * libm::powf(rgb[1], 2.4)
            + 0.072_175 * libm::powf(rgb[2], 2.4);
        // Soft clamp near black, where the display's flare dominates.
        if y < 0.022 {
            y + libm::powf(0.022 - y, 1.414)
        } else {
            y
        }
    }
    let background = screen_luminance(rgb.map(|v| f32::from(v) / 255.0));
    let white = screen_luminance([1.0; 3]);
    let black = screen_luminance([0.0; 3]);
    let white_contrast = (libm::powf(white, 0.62) - libm::powf(background, 0.65)).max(0.0);
    let black_contrast = (libm::powf(background, 0.56) - libm::powf(black, 0.57)).max(0.0);
    white_contrast > black_contrast
}

/// The key-derived color moved out of the middle of the brightness range,
/// keeping its hue: dark colors go darker under white text, light ones
/// lighter under black.
fn derived_channel_fill(tint: [u8; 3]) -> (Rgb565, Rgb565) {
    let [r, g, b] = tint.map(|v| f32::from(v) / 255.0);
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;
    let hue = if delta == 0.0 {
        0.0
    } else if max == r {
        let sector = (g - b) / delta;
        (if sector < 0.0 { sector + 6.0 } else { sector }) / 6.0
    } else if max == g {
        ((b - r) / delta + 2.0) / 6.0
    } else {
        ((r - g) / delta + 4.0) / 6.0
    };
    let saturation = if max == 0.0 { 0.0 } else { delta / max };
    let goes_dark = max < 0.62;
    let saturation = if goes_dark {
        saturation.min(0.85)
    } else {
        saturation.min(0.45)
    };
    let value = if goes_dark { 0.42 } else { 0.90 };
    (
        rgb565(hsv_to_rgb(hue, saturation, value)),
        if goes_dark { WHITE } else { BLACK },
    )
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> [u8; 3] {
    let sector = h * 6.0;
    let i = libm::floorf(sector);
    let f = sector - i;
    let p = v * (1.0 - s);
    let q = v * (1.0 - s * f);
    let t = v * (1.0 - s * (1.0 - f));
    let (r, g, b) = match i as i32 % 6 {
        0 => (v, t, p),
        1 => (q, v, p),
        2 => (p, v, t),
        3 => (p, q, v),
        4 => (t, p, v),
        _ => (v, p, q),
    };
    [r, g, b].map(|c| libm::roundf(c * 255.0) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lettering(title: &str) -> [Lettering; 2] {
        AvatarStyle::channel(None, title, [0, 0, 0]).lines
    }

    #[test]
    fn channel_initials_are_whole_clusters() {
        assert_eq!(lettering("🔥 Crew"), ["🔥C", ""]);
        assert_eq!(lettering("hike-club"), ["HC", ""]);
        assert_eq!(lettering("one two 👍🏽 four five"), ["OT", "👍🏽F"]);
        assert_eq!(lettering("🇫🇷"), ["🇫🇷", ""]);
    }
}
