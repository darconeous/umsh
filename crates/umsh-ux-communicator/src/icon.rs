//! Interface icons, rasterized at build time from the mockup's glyphs and
//! drawn as templates in the foreground color.

use embedded_graphics::image::ImageRaw;
use embedded_graphics::pixelcolor::Gray4;

include!(concat!(env!("OUT_DIR"), "/icons.rs"));

/// The columns an icon's mask actually inks, for packing icons by what
/// shows rather than by their square masks. Each icon's is
/// `ink::NAME`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ink {
    /// Blank columns before the first inked one.
    pub left: u32,
    pub width: u32,
}
