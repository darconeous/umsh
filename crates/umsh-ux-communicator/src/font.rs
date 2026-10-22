//! The bundled typefaces: M PLUS 1 for text and M PLUS Code Latin for
//! addresses, each at the weights and pixel sizes the screens use.
//!
//! A view names the size it wants with `with_font_size`; the nearest
//! rasterized size is drawn.

use buoyant::font::PrerenderedFont;
use buoyant::font::prerendered::{Face, GlyphEntry};

use crate::typeface::Typeface;

include!(concat!(env!("OUT_DIR"), "/fonts.rs"));
