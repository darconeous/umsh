//! An avatar drawn from its [`AvatarStyle`]: the tinted outline with the
//! lettering centered over it.

use crate::typeface::Typeface;
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

use crate::avatar::{AvatarStyle, Lettering, Outline, PeerShape};
use crate::font;

/// `style` at `size` pixels across.
///
/// Built from the style each time it is drawn ([`Lazy`]): kept in the
/// render trees, every avatar's lettering would be held there again as
/// text.
pub fn view<C>(style: &AvatarStyle, size: u32) -> impl View<Rgb565, C> + use<C> {
    Lazy::new((style.clone(), size), look)
}

fn look((style, size): &(AvatarStyle, u32)) -> impl View<Rgb565, ()> + use<> {
    let size = *size;
    // A peer's hint is set in the monospaced face, two over two. A
    // triangle's lettering is smaller and its lines closer, as on iOS, and
    // centered on the triangle's incenter, a third of its height above its
    // base: the triangle stands 1.16 times the avatar's size, its rounded
    // apex above the frame, so that is 0.113 of the size below the middle.
    let triangle = matches!(style.outline, Outline::Peer(PeerShape::Triangle));
    let lines = style.lines();
    let (face, text_size, below) = match style.outline {
        Outline::Peer(PeerShape::Triangle) => {
            (&font::MONO_BOLD, size * 27 / 80, (size * 17 + 75) / 150)
        }
        Outline::Peer(_) => (&font::MONO_BOLD, size * 3 / 8, 0),
        Outline::Channel
            if lines[1].is_empty() && umsh_grapheme::clusters(lines[0]).count() == 1 =>
        {
            (&font::BOLD, size * 3 / 4, 0)
        }
        Outline::Channel => (&font::BOLD, size * 2 / 5, 0),
    };
    let shown = face.face(text_size);
    let pitch = if triangle {
        i32::from(shown.size) * 15 / 16
    } else {
        i32::from(shown.ascent) - i32::from(shown.descent) + i32::from(shown.line_gap)
    };
    let two = !lines[1].is_empty();
    // Capitals are centered by dropping them below the middle of their
    // line; an emoji is drawn centered on its line already.
    let drop = if !two && face.shows_emoji(text_size, lines[0]) {
        0
    } else {
        cap_drop(face, text_size)
    };
    let line = |s: &str, offset: i32| {
        Text::new(Lettering::try_from(s).unwrap_or_default(), face)
            .with_font_size(text_size)
            .foreground_color(style.text)
            .offset(0, offset)
    };
    ZStack::new((
        style
            .outline
            .mask(size)
            .map(|mask| Image::new(mask).as_template().foreground_color(style.fill)),
        ZStack::new((
            line(lines[0], if two { -(pitch / 2) } else { 0 }),
            two.then(|| line(lines[1], pitch - pitch / 2)),
        ))
        .offset(0, below as i32 + drop)
        .hint_background_color(style.fill),
    ))
    .frame()
    .with_height(size)
    .with_width(size)
}

/// How far lettering in `face` at `size` drops to center its capitals on
/// its line. A line holds the face's tallest ascent above the baseline, and
/// its descent and the gap to the next line below it, so capitals centered
/// as a line is sit high by half of what is under them less what is over.
fn cap_drop(face: &Typeface, size: u32) -> i32 {
    let face = face.face(size);
    let over = face.glyph('H').map_or(0, |cap| i32::from(cap.top));
    let under = -i32::from(face.descent) + i32::from(face.line_gap);
    (under - over + 1) / 2
}
