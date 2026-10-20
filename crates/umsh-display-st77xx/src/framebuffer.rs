//! The frame in RAM, and what the panel last showed of it.

use embedded_graphics::{
    pixelcolor::{BinaryColor, Rgb565, raw::RawU16},
    prelude::*,
};

pub const STRIPE_ROWS: usize = 4;

/// RGB565, big-endian: the panel's own pixel format, so a stripe is sent
/// as it is stored.
pub struct Framebuffer {
    bytes: &'static mut [u8],
    width: usize,
    height: usize,
}
impl Framebuffer {
    /// A `width` by `height` frame in `bytes`, which holds exactly that.
    pub fn new(bytes: &'static mut [u8], width: usize, height: usize) -> Self {
        assert!(bytes.len() == width * height * 2);
        bytes.fill(0);
        Self {
            bytes,
            width,
            height,
        }
    }
    pub fn width(&self) -> usize {
        self.width
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn invert(&mut self) {
        for byte in self.bytes.iter_mut() {
            *byte = !*byte;
        }
    }
    fn stripe_range(&self, y: usize) -> core::ops::Range<usize> {
        assert!(y < self.height);
        let row = self.width * 2;
        y * row..(y + STRIPE_ROWS).min(self.height) * row
    }
    /// Copies the stripe from row `y` into `out`, returning its length.
    pub fn stripe(&self, y: usize, out: &mut [u8]) -> usize {
        let range = self.stripe_range(y);
        let len = range.len();
        out[..len].copy_from_slice(&self.bytes[range]);
        len
    }
    /// The same frame drawn in black and white, for screens that have
    /// only two colors: on is white.
    pub fn binary(&mut self) -> Binary<'_> {
        Binary(self)
    }
    fn put(&mut self, x: i32, y: i32, color: Rgb565) {
        if x < 0 || y < 0 || x as usize >= self.width || y as usize >= self.height {
            return;
        }
        let i = (y as usize * self.width + x as usize) * 2;
        self.bytes[i..i + 2].copy_from_slice(&RawU16::from(color).into_inner().to_be_bytes());
    }
}
impl OriginDimensions for Framebuffer {
    fn size(&self) -> Size {
        Size::new(self.width as u32, self.height as u32)
    }
}
impl DrawTarget for Framebuffer {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<T: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: T,
    ) -> Result<(), Self::Error> {
        for Pixel(Point { x, y }, c) in pixels {
            self.put(x, y, c);
        }
        Ok(())
    }
    fn fill_solid(
        &mut self,
        area: &embedded_graphics::primitives::Rectangle,
        color: Rgb565,
    ) -> Result<(), Self::Error> {
        let area = area.intersection(&self.bounding_box());
        let Some(bottom_right) = area.bottom_right() else {
            return Ok(());
        };
        let pixel = RawU16::from(color).into_inner().to_be_bytes();
        for y in area.top_left.y..=bottom_right.y {
            let row = y as usize * self.width * 2;
            let start = row + area.top_left.x as usize * 2;
            let end = row + (bottom_right.x as usize + 1) * 2;
            fill_pixels(&mut self.bytes[start..end], pixel);
        }
        Ok(())
    }
    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        fill_pixels(
            &mut self.bytes[..],
            RawU16::from(color).into_inner().to_be_bytes(),
        );
        Ok(())
    }
}

/// Fills `bytes`, which starts on a pixel, with `pixel`. Solid fills are
/// most of what a frame draws, and the frame is in external RAM: the bulk
/// goes as aligned 32-bit stores, two pixels each, rather than one byte or
/// one pixel at a time.
pub(crate) fn fill_pixels(bytes: &mut [u8], pixel: [u8; 2]) {
    // Safety: any bit pattern is a valid u32.
    let (head, words, tail) = unsafe { bytes.align_to_mut::<u32>() };
    for (i, byte) in head.iter_mut().enumerate() {
        *byte = pixel[i % 2];
    }
    // The words start partway into a pixel when the head is odd.
    let phase = head.len() % 2;
    let word = u32::from_ne_bytes([
        pixel[phase],
        pixel[1 - phase],
        pixel[phase],
        pixel[1 - phase],
    ]);
    words.fill(word);
    for (i, byte) in tail.iter_mut().enumerate() {
        *byte = pixel[(phase + i) % 2];
    }
}

/// What the panel last showed, as one hash per stripe. Rendering clears
/// and redraws the whole working frame, so write-time dirty flags would
/// mark every stripe; comparing against what was sent finds the ones that
/// changed. A hash does that without a second frame to compare against.
/// `N` is the frame's stripes, [`PanelSpec::stripes`](crate::PanelSpec::stripes).
pub struct SentStripes<const N: usize>([Option<u64>; N]);

impl<const N: usize> SentStripes<N> {
    /// Nothing is known to be on the panel: every stripe goes out.
    pub const fn new() -> Self {
        Self([None; N])
    }
    /// After a failed transfer, which may have written part of a stripe.
    pub fn forget(&mut self) {
        self.0 = [None; N];
    }
    /// The hash of `pixels` for stripe `index`, or `None` when the panel
    /// already shows them.
    pub fn changed(&self, index: usize, pixels: &[u8]) -> Option<u64> {
        let hash = stripe_hash(pixels);
        (self.0[index] != Some(hash)).then_some(hash)
    }
    /// Stripe `index` reached the panel.
    pub fn sent(&mut self, index: usize, hash: u64) {
        self.0[index] = Some(hash);
    }
}

impl<const N: usize> Default for SentStripes<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Two independent 32-bit lanes over 32-bit words, together 64 bits wide
/// so that a changed stripe hashing the same is not a practical concern.
/// The ESP32-S3 core has no 64-bit multiply; 32-bit lanes keep this to a
/// couple of milliseconds a frame.
fn stripe_hash(pixels: &[u8]) -> u64 {
    // FNV-1a, and a rotate-xor-multiply with the golden-ratio constant.
    let (mut a, mut b) = (0x811c_9dc5_u32, 0x9e37_79b9_u32);
    for word in pixels.chunks_exact(4) {
        let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        a = (a ^ word).wrapping_mul(0x0100_0193);
        b = (b.rotate_left(5) ^ word).wrapping_mul(0x9e37_79b1);
    }
    // Rows are an even number of pixels, so a stripe is whole words.
    debug_assert!(pixels.len().is_multiple_of(4));
    u64::from(a) << 32 | u64::from(b)
}

/// A [`Framebuffer`] drawn in [`BinaryColor`].
pub struct Binary<'a>(&'a mut Framebuffer);

fn rgb(color: BinaryColor) -> Rgb565 {
    if color.is_on() {
        Rgb565::WHITE
    } else {
        Rgb565::BLACK
    }
}

impl OriginDimensions for Binary<'_> {
    fn size(&self) -> Size {
        self.0.size()
    }
}
impl DrawTarget for Binary<'_> {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;
    fn draw_iter<T: IntoIterator<Item = Pixel<BinaryColor>>>(
        &mut self,
        pixels: T,
    ) -> Result<(), Self::Error> {
        for Pixel(Point { x, y }, c) in pixels {
            self.0.put(x, y, rgb(c));
        }
        Ok(())
    }
    fn clear(&mut self, color: BinaryColor) -> Result<(), Self::Error> {
        self.0.clear(rgb(color))
    }
}
