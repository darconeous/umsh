//! Emoji for UMSH communicators: Twemoji art, pre-rendered and compressed.
//!
//! The emoji drawn are those in `manifest.txt`; drawing another is a line
//! there. Each is rendered at build time at every size in [`STORES`], and a
//! glyph is identified by its place in the manifest, the same at every
//! size.
//!
//! To draw a grapheme cluster, [`shown`] says what it is drawn as: an emoji's
//! glyph, the glyphs of its parts, a flag's region code, the placeholder,
//! or text. A [`Cache`] inflates glyphs and keeps the ones last drawn.
//!
//! For a picker, [`GROUPS`] lists the glyphs by CLDR group, [`sequence`]
//! gives what to send for one, and [`matching`] finds them by name.
//!
//! The art is Twemoji (<https://github.com/jdecked/twemoji>), licensed
//! under CC BY 4.0, rasterized, color-reduced, and compressed here.

#![no_std]

mod cache;
mod inflate;
mod lookup;
mod names;
mod store;

pub use cache::Cache;
pub use lookup::{MAX_PARTS, PLACEHOLDER, Region, Shown, find, shown};
pub use names::{Group, Match, matching, name, sequence, words};
use store::Blocks;
pub use store::{BLOCK, Glyph, Id, Store};

include!(concat!(env!("OUT_DIR"), "/emoji.rs"));
