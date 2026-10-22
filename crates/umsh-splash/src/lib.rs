//! The boot splash of a device with a color panel: the UMSH logo in its
//! orange, with the firmware version under it in anti-aliased type, on
//! black.
//!
//! It is drawn before the identity, the journals, or the radio are up, and
//! must come up whatever else does, so it is kept small and plain: the
//! logo is finished bytes (see `assets/README.md`), the type is a face the
//! interface already keeps in flash, each coverage level is one entry of a
//! sixteen-color palette over black, and nothing here allocates or blends.
//! Buoyant supplies only the face's table types; none of its layout or
//! rendering runs here.
//!
//! A board picks the [`Splash`] made for its panel and renders it into
//! the panel's full-color frame, in the face its interface sets body text
//! in.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use buoyant::font::prerendered::{Face, GlyphEntry};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;

/// The logo's orange, International Orange `#FA5000` (`docs/logo`).
pub const ORANGE: [u8; 3] = [0xFA, 0x50, 0x00];
const WHITE: [u8; 3] = [0xFF, 0xFF, 0xFF];

/// Shown in place of an empty version string.
const UNKNOWN_VERSION: &str = "unknown";
/// Clearance between the version and the panel's sides.
const MARGIN: u32 = 6;
/// The most lines the version wraps onto; the last is cut with an ellipsis.
const MAX_LINES: usize = 3;
const ELLIPSIS: &str = "...";

/// A panel's splash: the logo sized for it.
pub struct Splash {
    pub logo: Logo,
}

impl Splash {
    /// The T-LoRa Pager's 480×222 panel.
    pub const TFT_480X222: Self = Self {
        logo: Logo(include_bytes!("../assets/umsh-432x101.rle")),
    };
    /// The T-Deck's 320×240 panel.
    pub const TFT_320X240: Self = Self {
        logo: Logo(include_bytes!("../assets/umsh-288x67.rle")),
    };

    /// Draws the whole frame: black, the logo centered, and `version` in
    /// `face` centered under it. Errors are the panel's and are dropped.
    pub fn render<D: DrawTarget<Color = Rgb565>>(
        &self,
        target: &mut D,
        face: &Face,
        version: &str,
    ) {
        let _ = target.clear(Rgb565::BLACK);
        let size = target.bounding_box().size;
        let version = if version.is_empty() {
            UNKNOWN_VERSION
        } else {
            version
        };
        let face = Type(face);
        let lines = Lines::wrap(face, version, size.width.saturating_sub(2 * MARGIN));
        let logo = self.logo.size();
        let pitch = face.line_height();
        let gap = pitch / 2;
        let text_height = lines.count() as u32 * pitch;
        let top = size.height.saturating_sub(logo.height + gap + text_height) / 2;
        self.logo.draw(
            target,
            Point::new(size.width.saturating_sub(logo.width) as i32 / 2, top as i32),
        );
        for (index, line) in lines.iter().enumerate() {
            let x = size.width.saturating_sub(line.width(face)) / 2;
            let y = top + logo.height + gap + index as u32 * pitch;
            line.draw(target, face, &WHITES, Point::new(x as i32, y as i32));
        }
    }
}

/// The palettes: the logo's, and the version's.
const ORANGES: [Rgb565; 16] = shades(ORANGE);
const WHITES: [Rgb565; 16] = shades(WHITE);

/// Sixteen shades of `color` over black, one per coverage level.
const fn shades(color: [u8; 3]) -> [Rgb565; 16] {
    let mut palette = [Rgb565::BLACK; 16];
    let mut level = 0;
    while level < 16 {
        palette[level as usize] = Rgb565::new(
            scale(color[0], level) >> 3,
            scale(color[1], level) >> 2,
            scale(color[2], level) >> 3,
        );
        level += 1;
    }
    palette
}

/// `channel` at `level` of 15.
const fn scale(channel: u8, level: u16) -> u8 {
    (channel as u16 * level / 15) as u8
}

// ─── Logo ────────────────────────────────────────────────────────────────────

/// A run-length coded image of coverage levels: a four-byte size, then
/// tokens of one level and one run.
pub struct Logo(&'static [u8]);

impl Logo {
    const HEADER: usize = 4;

    pub fn size(&self) -> Size {
        let dimension = |at: usize| u32::from(u16::from_be_bytes([self.0[at], self.0[at + 1]]));
        Size::new(dimension(0), dimension(2))
    }

    /// The levels, row by row. A damaged stream ends early, and the frame
    /// is left as it was past that point.
    fn levels(&self) -> Levels<'_> {
        Levels {
            data: &self.0[Self::HEADER..],
            level: 0,
            left: 0,
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D, top_left: Point) {
        let area = Rectangle::new(top_left, self.size());
        let _ = target.fill_contiguous(
            &area,
            self.levels().map(|level| ORANGES[usize::from(level)]),
        );
    }
}

/// A token is a level in its high nibble and a run of 1 to 15 in its low
/// nibble; a low nibble of 0 means the run is 16 more than the next byte.
struct Levels<'a> {
    data: &'a [u8],
    level: u8,
    left: u16,
}

impl Iterator for Levels<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.left == 0 {
            let (&token, rest) = self.data.split_first()?;
            self.data = rest;
            self.level = token >> 4;
            self.left = match token & 0x0F {
                0 => {
                    let (&more, rest) = self.data.split_first()?;
                    self.data = rest;
                    16 + u16::from(more)
                }
                run => u16::from(run),
            };
        }
        self.left -= 1;
        Some(self.level)
    }
}

// ─── Type ────────────────────────────────────────────────────────────────────

/// A rasterized face, read directly: its tables are plain data in flash,
/// so drawing from them needs nothing set up first.
#[derive(Clone, Copy)]
struct Type<'a>(&'a Face);

impl Type<'_> {
    /// The distance between the tops of consecutive lines.
    fn line_height(self) -> u32 {
        let face = self.0;
        (i32::from(face.ascent) - i32::from(face.descent) + i32::from(face.line_gap)).max(1) as u32
    }

    /// The glyph for `c`, or the face's fallback. A face without a fallback
    /// skips what it lacks.
    fn glyph(self, c: char) -> Option<GlyphEntry> {
        self.0.glyph(c).copied()
    }

    fn advance(self, c: char) -> u32 {
        self.glyph(c).map_or(0, |glyph| u32::from(glyph.advance))
    }

    /// How wide `text` is set, in pixels.
    fn width(self, text: &str) -> u32 {
        text.chars().map(|c| self.advance(c)).sum()
    }

    /// The longest prefix of `text` that sets within `width`, as a byte
    /// length.
    fn prefix(self, text: &str, width: u32) -> usize {
        let mut used = 0;
        for (at, c) in text.char_indices() {
            used += self.advance(c);
            if used > width {
                return at;
            }
        }
        text.len()
    }

    /// The coverage level of pixel `index`, counted across the whole face.
    fn level(self, index: usize) -> u8 {
        let byte = self.0.coverage.get(index / 2).copied().unwrap_or(0);
        if index.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0F
        }
    }

    /// Draws `text` with its line box's top-left corner at `origin`,
    /// returning where the next character would go.
    fn draw<D: DrawTarget<Color = Rgb565>>(
        self,
        target: &mut D,
        palette: &[Rgb565; 16],
        origin: Point,
        text: &str,
    ) -> Point {
        let mut pen = origin;
        for c in text.chars() {
            let Some(glyph) = self.glyph(c) else {
                continue;
            };
            let (width, height) = (usize::from(glyph.width), usize::from(glyph.height));
            let start = glyph.start as usize;
            let corner = pen + Point::new(i32::from(glyph.left), i32::from(glyph.top));
            let pixels = (0..width * height)
                .map(|index| (index, self.level(start + index)))
                .filter(|&(_, level)| level != 0)
                .map(|(index, level)| {
                    let (x, y) = ((index % width) as i32, (index / width) as i32);
                    Pixel(corner + Point::new(x, y), palette[usize::from(level)])
                });
            let _ = target.draw_iter(pixels);
            pen.x += i32::from(glyph.advance);
        }
        pen
    }
}

// ─── Wrapping ────────────────────────────────────────────────────────────────

/// One line of the version: a slice of it, cut short or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Line<'a> {
    text: &'a str,
    truncated: bool,
}

impl Line<'_> {
    fn width(&self, font: Type<'_>) -> u32 {
        font.width(self.text)
            + if self.truncated {
                font.width(ELLIPSIS)
            } else {
                0
            }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(
        &self,
        target: &mut D,
        font: Type<'_>,
        palette: &[Rgb565; 16],
        origin: Point,
    ) {
        let pen = font.draw(target, palette, origin, self.text);
        if self.truncated {
            font.draw(target, palette, pen, ELLIPSIS);
        }
    }
}

/// The version across at most [`MAX_LINES`] lines. Hyphens stay on the
/// line they end, so the lines read back as the whole identifier; a last
/// line that still does not fit is cut and ends in an ellipsis.
#[derive(Debug, Default)]
struct Lines<'a> {
    lines: [Option<Line<'a>>; MAX_LINES],
}

impl<'a> Lines<'a> {
    fn wrap(font: Type<'_>, text: &'a str, width: u32) -> Self {
        let mut lines = Self::default();
        let mut rest = text;
        for (index, slot) in lines.lines.iter_mut().enumerate() {
            let whole = font.prefix(rest, width);
            if whole == rest.len() {
                *slot = Some(Line {
                    text: rest,
                    truncated: false,
                });
                break;
            }
            if index == MAX_LINES - 1 {
                let end = font.prefix(rest, width.saturating_sub(font.width(ELLIPSIS)));
                *slot = Some(Line {
                    text: &rest[..end],
                    truncated: true,
                });
                break;
            }
            let mut end = whole;
            if let Some(hyphen) = rest[..whole].rfind('-') {
                end = hyphen + 1;
            }
            if end == 0 {
                // Narrower than one glyph: one character a line, rather
                // than nothing at all.
                end = rest.chars().next().map_or(0, char::len_utf8);
            }
            if end == 0 {
                break;
            }
            *slot = Some(Line {
                text: &rest[..end],
                truncated: false,
            });
            rest = &rest[end..];
        }
        lines
    }

    fn iter(&self) -> impl Iterator<Item = &Line<'a>> {
        self.lines.iter().flatten()
    }

    fn count(&self) -> usize {
        self.iter().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPLASHES: [&Splash; 2] = [&Splash::TFT_480X222, &Splash::TFT_320X240];

    /// The communicator's Medium at `size`, as the firmware passes it.
    fn medium(size: u32) -> Type<'static> {
        Type(umsh_ux_communicator::font::MEDIUM.face(size))
    }

    #[test]
    fn every_logo_decodes_to_exactly_its_size() {
        for splash in SPLASHES {
            let size = splash.logo.size();
            let levels: Vec<u8> = splash.logo.levels().collect();
            assert_eq!(levels.len(), (size.width * size.height) as usize);
            assert!(levels.iter().all(|&level| level < 16));
            assert_eq!(*levels.iter().max().unwrap(), 15, "the logo has solid ink");
        }
        assert_eq!(Splash::TFT_480X222.logo.size(), Size::new(432, 101));
        assert_eq!(Splash::TFT_320X240.logo.size(), Size::new(288, 67));
    }

    #[test]
    fn the_shared_faces_are_the_sizes_the_splash_sets() {
        assert_eq!(medium(20).0.size, 20);
        assert_eq!(medium(16).0.size, 16);
        assert!(medium(20).line_height() > medium(16).line_height());
    }

    #[test]
    fn characters_beyond_ascii_draw_from_the_face_or_its_fallback() {
        let face = medium(16);
        assert_eq!(face.glyph('é').map(|glyph| glyph.character), Some('é'));
        // Not in the face: its replacement glyph stands in, with width.
        assert!(face.advance('\u{4E00}') > 0);
        assert!(face.width("fw-é") > face.width("fw-"));
    }

    #[test]
    fn a_version_that_fits_is_one_line() {
        let font = medium(20);
        let lines = Lines::wrap(font, "fw-2026.10.19-44-ga945d5290", 480 - 2 * MARGIN);
        assert_eq!(lines.count(), 1);
        assert_eq!(lines.lines[0].unwrap().text, "fw-2026.10.19-44-ga945d5290");
    }

    #[test]
    fn lines_break_after_hyphens_and_join_back_into_the_version() {
        let font = medium(16);
        let version = "fw-2026.10.19-44-ga945d5290-dirty";
        // The whole string sets within a T-Deck's width; a narrower one
        // has to break.
        assert_eq!(Lines::wrap(font, version, 320 - 2 * MARGIN).count(), 1);
        let width = 200;
        let lines = Lines::wrap(font, version, width);
        assert_eq!(lines.count(), 2);
        let first = lines.lines[0].unwrap();
        assert!(first.text.ends_with('-'), "{first:?}");
        assert!(lines.iter().all(|line| !line.truncated));
        assert!(lines.iter().all(|line| line.width(font) <= width));
        let joined: String = lines.iter().map(|line| line.text).collect();
        assert_eq!(joined, version);
    }

    #[test]
    fn the_third_line_is_cut_with_an_ellipsis() {
        let font = medium(16);
        let version = "0123456789-abcdefghij-0123456789-abcdefghij-0123456789-abcdefghij";
        let width = 120;
        let lines = Lines::wrap(font, version, width);
        assert_eq!(lines.count(), 3);
        let last = lines.lines[2].unwrap();
        assert!(last.truncated);
        for line in lines.iter() {
            assert!(line.width(font) <= width, "{line:?}");
        }
        let kept: String = lines.iter().map(|line| line.text).collect();
        assert!(version.starts_with(&kept));
    }

    #[test]
    fn a_width_narrower_than_a_glyph_still_makes_progress() {
        let lines = Lines::wrap(medium(16), "abc", 1);
        assert_eq!(lines.count(), 3);
        assert_eq!(lines.lines[0].unwrap().text, "a");
    }

    #[test]
    fn the_palettes_run_from_black_to_the_color() {
        assert_eq!(ORANGES[0], Rgb565::BLACK);
        assert_eq!(ORANGES[15], Rgb565::new(0xFA >> 3, 0x50 >> 2, 0));
        assert_eq!(WHITES[15], Rgb565::WHITE);
        for level in 1..16 {
            assert!(WHITES[level].r() >= WHITES[level - 1].r());
        }
    }
}
