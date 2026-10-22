//! The compressed glyphs, and a glyph once inflated.
//!
//! Every size of a glyph shares one palette. The palettes are kept apart
//! from the pixels, which are kept a store a size, each pixel an index
//! into its glyph's palette. Both are compressed in blocks of [`BLOCK`]
//! glyphs in manifest order, each block a codec byte and then a stream.
//!
//! Inflated, a block of palettes is one record a glyph: the palette's
//! length, then each color as RGB565 (big endian) and an alpha. A block of
//! pixels is each glyph's indices, a row at a time, one glyph after
//! another.

/// A glyph, the same in every store: its place in the manifest.
pub type Id = u16;

/// Glyphs to a block.
pub const BLOCK: usize = 16;

/// A block compressed with raw DEFLATE.
const CODEC_DEFLATE: u8 = 1;

/// Compressed blocks, one after another.
#[derive(Debug)]
pub(crate) struct Blocks {
    /// Where each block starts in `data`, and then where the last ends.
    pub(crate) starts: &'static [u32],
    pub(crate) data: &'static [u8],
}

impl Blocks {
    /// Inflates block `index` into `out`, returning the part filled.
    pub(crate) fn inflate<'o>(
        &self,
        index: usize,
        out: &'o mut [u8],
        tables: &mut crate::inflate::Tables,
    ) -> Option<&'o [u8]> {
        let start = *self.starts.get(index)? as usize;
        let end = *self.starts.get(index + 1)? as usize;
        let (&codec, stream) = self.data.get(start..end)?.split_first()?;
        if codec != CODEC_DEFLATE {
            return None;
        }
        let len = crate::inflate::inflate(stream, out, tables)?;
        Some(&out[..len])
    }
}

/// The glyphs' pixels at one size.
#[derive(Debug)]
pub struct Store {
    /// Each glyph's width and height, in pixels.
    pub size: u16,
    pub(crate) indices: Blocks,
}

impl Store {
    /// The store whose glyphs are nearest `size` pixels, preferring the
    /// smaller on a tie.
    #[must_use]
    pub fn nearest(size: u32) -> &'static Self {
        let mut best = crate::STORES[0];
        for store in crate::STORES {
            if u32::from(store.size).abs_diff(size) < u32::from(best.size).abs_diff(size) {
                best = store;
            }
        }
        best
    }

    /// The store for emoji set beside text `text_size` pixels to the em:
    /// about a fifth larger, as emoji fill their cell where letters do not.
    #[must_use]
    pub fn beside_text(text_size: u32) -> &'static Self {
        Self::nearest(text_size * 6 / 5)
    }

    /// Pixels in a glyph.
    pub(crate) fn pixels(&self) -> usize {
        usize::from(self.size) * usize::from(self.size)
    }
}

/// The length of the palette record that starts with `first`.
pub(crate) fn palette_len(first: u8) -> usize {
    1 + 3 * usize::from(first)
}

/// Palette record `n` of an inflated block of palettes.
pub(crate) fn palette_record(block: &[u8], n: usize) -> Option<&[u8]> {
    let mut at = 0;
    for _ in 0..n {
        at += palette_len(*block.get(at)?);
    }
    block.get(at..at + palette_len(*block.get(at)?))
}

/// One inflated glyph.
#[derive(Clone, Copy, Debug)]
pub struct Glyph<'a> {
    /// Its width and height, in pixels.
    pub size: u16,
    palette: &'a [u8],
    indices: &'a [u8],
}

impl<'a> Glyph<'a> {
    pub(crate) fn new(size: u16, palette: &'a [u8], indices: &'a [u8]) -> Self {
        Self {
            size,
            palette,
            indices,
        }
    }

    /// The palette: each color as RGB565, and its alpha.
    pub fn palette(&self) -> impl Iterator<Item = (u16, u8)> + 'a {
        self.palette
            .get(1..)
            .unwrap_or_default()
            .chunks_exact(3)
            .map(|c| (u16::from_be_bytes([c[0], c[1]]), c[2]))
    }

    /// Each pixel's palette index, a row at a time.
    #[must_use]
    pub fn indices(&self) -> &'a [u8] {
        self.indices
    }
}
