//! Interface icons, rasterized at build time from the mockup's glyphs and
//! drawn as templates in the foreground color.

use embedded_graphics::image::ImageRaw;
use embedded_graphics::pixelcolor::Gray4;

include!(concat!(env!("OUT_DIR"), "/icons.rs"));
