//! A typeface: text from M PLUS, and emoji from Twemoji beside it.
//!
//! Text is laid out a grapheme cluster at a time. A cluster that is one
//! character the face has is drawn from the face; any other is looked up
//! in the emoji set (`umsh-emoji`), at the size that suits the text, and
//! drawn as what it finds: the emoji's glyph, its parts side by side, a
//! flag's region code on a badge, or the placeholder. Clusters that are
//! not emoji at all are drawn from the face, a character at a time.
//!
//! Glyphs are inflated through the [`EmojiCache`] the device installs;
//! without one, every emoji is the placeholder.

use core::ops::Deref;
use core::sync::atomic::{AtomicPtr, Ordering};

use buoyant::font::prerendered::{Face, PrerenderedAttributes};
use buoyant::font::{Font, FontMetrics, FontRender, PrerenderedFont, VMetrics};
use buoyant::primitives::geometry::Rectangle;
use buoyant::primitives::{Interpolate, Pixel, Point, Size};
use buoyant::render_target::Surface;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::pixelcolor::raw::RawU16;
use umsh_emoji::{Id, Shown, Store};

use crate::theme;

include!(concat!(env!("OUT_DIR"), "/placeholder.rs"));

/// Emoji kept inflated: enough for a screen of them.
pub const EMOJI_SLOTS: usize = 48;

/// The glyph cache the interface draws emoji through.
pub type EmojiCache = umsh_emoji::Cache<EMOJI_SLOTS>;

/// The installed cache, taken out while it is drawn from: the pointer is
/// its lock, and lives here rather than in the cache, which may be kept
/// where atomics do not work.
static CACHE: AtomicPtr<EmojiCache> = AtomicPtr::new(core::ptr::null_mut());

/// Draws emoji through `cache` from now on. A device makes it once, where
/// it has room: it is about 45 KB.
pub fn install(cache: &'static mut EmojiCache) {
    CACHE.store(cache, Ordering::Release);
}

/// Runs `f` with the cache, unless there is none or it is in use.
fn with_cache<R>(f: impl FnOnce(&mut EmojiCache) -> R) -> Option<R> {
    let ptr = CACHE.swap(core::ptr::null_mut(), Ordering::Acquire);
    // SAFETY: the pointer came from a `&'static mut EmojiCache`, and was
    // taken out of `CACHE`, so nothing else holds it until it is put back.
    let cache = unsafe { ptr.as_mut() }?;
    let out = f(cache);
    CACHE.store(ptr, Ordering::Release);
    Some(out)
}

/// The fill behind a flag's region code.
const BADGE: Rgb565 = theme::PLACEHOLDER;

/// A typeface at one weight: text, with emoji where the text has none.
#[derive(Debug, PartialEq, Eq)]
pub struct Typeface {
    text: PrerenderedFont,
}

impl Typeface {
    #[must_use]
    pub const fn new(text: PrerenderedFont) -> Self {
        Self { text }
    }
}

impl Deref for Typeface {
    type Target = PrerenderedFont;

    fn deref(&self) -> &PrerenderedFont {
        &self.text
    }
}

/// What a cluster is drawn as in `face`: `None` for the face's own text.
fn emoji(face: &Face, cluster: &str) -> Option<Shown> {
    let mut chars = cluster.chars();
    if let (Some(c), None) = (chars.next(), chars.next())
        && (c.is_ascii() || face.glyph(c).is_some_and(|g| g.character == c))
    {
        return None;
    }
    match umsh_emoji::shown(cluster) {
        Shown::Text => None,
        shown => Some(shown),
    }
}

/// Where emoji go beside text in a face.
struct Cell {
    store: &'static Store,
    /// The top of a glyph, below the top of the line.
    top: i32,
    /// From one emoji to the next.
    advance: u32,
}

impl Cell {
    fn of(face: &Face) -> Self {
        let store = Store::beside_text(u32::from(face.size));
        let size = i32::from(store.size);
        // Centered on the capitals, as the letters beside it are.
        let middle = face
            .glyph('H')
            .filter(|g| g.character == 'H')
            .map_or(i32::from(face.ascent) * 3 / 5, |cap| {
                i32::from(cap.top) + i32::from(cap.height) / 2
            });
        Self {
            store,
            top: middle - size / 2,
            advance: u32::from(store.size) + (u32::from(store.size) / 10).max(1),
        }
    }

    /// The face a flag's region code is set in, from `font`.
    fn badge_face(&self, font: &PrerenderedFont) -> &'static Face {
        font.face(u32::from(self.store.size) * 11 / 20)
    }

    /// A badge's width and height, holding `code` set in `face`.
    fn badge(&self, face: &Face, code: &str) -> (u32, u32) {
        let text: u32 = code
            .chars()
            .map(|c| face.glyph(c).map_or(0, |g| u32::from(g.advance)))
            .sum();
        let height = u32::from(self.store.size) * 4 / 5;
        (text + height / 2, height)
    }

    fn width(&self, font: &PrerenderedFont, shown: Shown) -> u32 {
        match shown {
            Shown::Glyph(_) | Shown::Placeholder => self.advance,
            Shown::Parts(_, count) => self.advance * u32::from(count),
            Shown::Flag(region) => {
                let (width, _) = self.badge(self.badge_face(font), region.as_str());
                width + self.advance - u32::from(self.store.size)
            }
            Shown::Text | Shown::Nothing => 0,
        }
    }
}

impl Font for Typeface {
    type Attributes = PrerenderedAttributes;

    fn metrics(&self, attributes: &Self::Attributes) -> impl FontMetrics {
        Metrics {
            font: &self.text,
            face: self.text.face(attributes.size),
        }
    }
}

struct Metrics<'a> {
    font: &'a PrerenderedFont,
    face: &'static Face,
}

impl FontMetrics for Metrics<'_> {
    fn rendered_size(&self, character: char) -> Option<Rectangle> {
        self.face.rendered_size(character)
    }

    fn vertical_metrics(&self) -> VMetrics {
        self.face.vertical_metrics()
    }

    fn advance(&self, character: char) -> u32 {
        self.face.advance(character)
    }

    fn cluster_advance(&self, cluster: &str) -> u32 {
        match emoji(self.face, cluster) {
            None => cluster.chars().map(|c| self.face.advance(c)).sum(),
            Some(shown) => Cell::of(self.face).width(self.font, shown),
        }
    }

    fn cluster_rendered_size(&self, cluster: &str) -> Option<Rectangle> {
        match emoji(self.face, cluster) {
            None => {
                let mut x = 0;
                let mut bounds: Option<Rectangle> = None;
                for c in cluster.chars() {
                    if let Some(mut glyph) = self.face.rendered_size(c) {
                        glyph.origin.x += x;
                        bounds = Some(bounds.map_or(glyph, |b| b.union(&glyph)));
                    }
                    x += self.face.advance(c) as i32;
                }
                bounds
            }
            Some(Shown::Nothing | Shown::Text) => None,
            Some(shown) => {
                let cell = Cell::of(self.face);
                let size = u32::from(cell.store.size);
                let width = cell.width(self.font, shown) - (cell.advance - size);
                Some(Rectangle::new(
                    Point::new(0, cell.top),
                    Size::new(width, size),
                ))
            }
        }
    }
}

impl FontRender<Rgb565> for Typeface {
    fn draw(
        &self,
        character: char,
        offset: Point,
        color: Rgb565,
        background_color: Option<Rgb565>,
        attributes: &Self::Attributes,
        surface: &mut impl Surface<Color = Rgb565>,
    ) {
        self.text.draw(
            character,
            offset,
            color,
            background_color,
            attributes,
            surface,
        );
    }

    fn draw_cluster(
        &self,
        cluster: &str,
        offset: Point,
        color: Rgb565,
        background_color: Option<Rgb565>,
        attributes: &Self::Attributes,
        surface: &mut impl Surface<Color = Rgb565>,
    ) {
        let face = self.text.face(attributes.size);
        let Some(shown) = emoji(face, cluster) else {
            self.text.draw_cluster(
                cluster,
                offset,
                color,
                background_color,
                attributes,
                surface,
            );
            return;
        };
        let cell = Cell::of(face);
        let at = offset + Point::new(0, cell.top);
        match shown {
            Shown::Glyph(id) => glyph(cell.store, id, at, background_color, surface),
            Shown::Parts(ids, count) => {
                for (i, &id) in ids[..usize::from(count)].iter().enumerate() {
                    let x = (cell.advance * i as u32) as i32;
                    glyph(
                        cell.store,
                        id,
                        at + Point::new(x, 0),
                        background_color,
                        surface,
                    );
                }
            }
            Shown::Flag(region) => {
                self.badge(&cell, region.as_str(), at, surface);
            }
            Shown::Placeholder => placeholder(cell.store, at, background_color, surface),
            Shown::Text | Shown::Nothing => {}
        }
    }
}

impl Typeface {
    /// A flag's region code on a rounded badge, centered in the cell.
    fn badge(
        &self,
        cell: &Cell,
        code: &str,
        at: Point,
        surface: &mut impl Surface<Color = Rgb565>,
    ) {
        let face = cell.badge_face(&self.text);
        let (width, height) = cell.badge(face, code);
        let top = at.y + (i32::from(cell.store.size) - height as i32) / 2;
        let radius = (height / 4) as i32;
        let (w, h) = (width as i32, height as i32);
        let inside = move |x: i32, y: i32| {
            let cx = x.clamp(radius, w - 1 - radius);
            let cy = y.clamp(radius, h - 1 - radius);
            (x - cx).pow(2) + (y - cy).pow(2) <= radius * radius
        };
        surface.draw_iter((0..h).flat_map(move |y| {
            (0..w).filter(move |&x| inside(x, y)).map(move |x| Pixel {
                point: Point::new(at.x + x, top + y),
                color: BADGE,
            })
        }));
        let attributes = PrerenderedAttributes {
            size: u32::from(face.size),
        };
        let line = i32::from(face.ascent) - i32::from(face.descent);
        let mut x = at.x + (height / 4) as i32;
        let y = top + (h - line) / 2;
        for c in code.chars() {
            self.text.draw(
                c,
                Point::new(x, y),
                theme::TEXT,
                Some(BADGE),
                &attributes,
                surface,
            );
            x += face.glyph(c).map_or(0, |g| i32::from(g.advance));
        }
    }
}

/// An RGB565 color and its alpha, as it is drawn: blended into the
/// background where there is one, and where there is not, drawn whole at
/// half coverage or more, as text is.
fn blend(rgb565: u16, alpha: u8, background: Option<Rgb565>) -> Option<Rgb565> {
    let color = Rgb565::from(RawU16::new(rgb565));
    match (alpha, background) {
        (0, _) => None,
        (255, _) => Some(color),
        (alpha, Some(background)) => Some(Rgb565::interpolate(background, color, alpha)),
        (alpha, None) => (alpha >= 128).then_some(color),
    }
}

/// Emoji `id` of `store`, its top left at `at`.
fn glyph(
    store: &Store,
    id: Id,
    at: Point,
    background: Option<Rgb565>,
    surface: &mut impl Surface<Color = Rgb565>,
) {
    let drawn = with_cache(|cache| {
        cache.glyph(store, id).map(|glyph| {
            // Each palette entry blended once, rather than once a pixel.
            let mut colors = [None; 32];
            for (color, (rgb565, alpha)) in colors.iter_mut().zip(glyph.palette()) {
                *color = blend(rgb565, alpha, background);
            }
            let size = usize::from(glyph.size);
            surface.draw_iter(
                glyph
                    .indices()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &index)| {
                        colors
                            .get(usize::from(index))
                            .copied()
                            .flatten()
                            .map(|color| Pixel {
                                point: at + Point::new((i % size) as i32, (i / size) as i32),
                                color,
                            })
                    }),
            );
        })
    })
    .flatten()
    .is_some();
    if !drawn {
        placeholder(store, at, background, surface);
    }
}

/// The placeholder at `store`'s size, its top left at `at`.
fn placeholder(
    store: &Store,
    at: Point,
    background: Option<Rgb565>,
    surface: &mut impl Surface<Color = Rgb565>,
) {
    let Some((size, pixels)) = PLACEHOLDERS
        .iter()
        .min_by_key(|(size, _)| size.abs_diff(store.size))
    else {
        return;
    };
    let size = usize::from(*size);
    surface.draw_iter(
        pixels
            .iter()
            .enumerate()
            .filter_map(|(i, &(rgb565, alpha))| {
                blend(rgb565, alpha, background).map(|color| Pixel {
                    point: at + Point::new((i % size) as i32, (i / size) as i32),
                    color,
                })
            }),
    );
}
