//! A QR code drawn as an image the view holds itself, so a code made while
//! the interface runs needs no place of its own to live.

use core::ops::Deref;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};

/// The largest code made: version 9, 53 modules a side, which holds a
/// node's link with its signed contact.
const MAX_VERSION: Version = Version::new(9);
const MAX_SIDE: usize = 53;
const BYTES: usize = (MAX_SIDE * MAX_SIDE).div_ceil(8);

/// A code's modules, each drawn `scale` pixels square, dark on light. The
/// quiet zone around them is not part of the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrImage {
    side: u8,
    scale: u8,
    /// Row by row, one bit a module, set where it is dark.
    modules: [u8; BYTES],
}

impl QrImage {
    /// Encodes `text` at the largest scale that fits `room` pixels square
    /// with a quiet zone of `quiet` modules each side. `None` when it does
    /// not fit a version 9 code.
    #[must_use]
    pub fn encode(text: &str, room: u32, quiet: u32) -> Option<Self> {
        let mut out = [0u8; MAX_VERSION.buffer_len()];
        let mut temp = [0u8; MAX_VERSION.buffer_len()];
        let code = QrCode::encode_text(
            text,
            &mut temp,
            &mut out,
            QrCodeEcc::Low,
            Version::MIN,
            MAX_VERSION,
            None,
            true,
        )
        .ok()?;
        let side = code.size();
        let mut modules = [0u8; BYTES];
        for y in 0..side {
            for x in 0..side {
                if code.get_module(x, y) {
                    let i = (y * side + x) as usize;
                    modules[i / 8] |= 0x80 >> (i % 8);
                }
            }
        }
        let scale = room / (side as u32 + 2 * quiet);
        Some(Self {
            side: side as u8,
            scale: u8::try_from(scale.max(1)).unwrap_or(u8::MAX),
            modules,
        })
    }

    /// The pixels a module takes each way.
    #[must_use]
    pub fn scale(&self) -> u32 {
        u32::from(self.scale)
    }

    fn dark(&self, x: usize, y: usize) -> bool {
        let i = y * usize::from(self.side) + x;
        self.modules[i / 8] & (0x80 >> (i % 8)) != 0
    }
}

impl OriginDimensions for QrImage {
    fn size(&self) -> Size {
        let side = u32::from(self.side) * self.scale();
        Size::new(side, side)
    }
}

impl ImageDrawable for QrImage {
    type Color = Rgb565;

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        target.fill_solid(&Rectangle::new(Point::zero(), self.size()), Rgb565::WHITE)?;
        let scale = self.scale();
        let side = usize::from(self.side);
        for y in 0..side {
            // Each run of dark modules in a row as one rectangle.
            let mut x = 0;
            while x < side {
                if !self.dark(x, y) {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < side && self.dark(x, y) {
                    x += 1;
                }
                let origin = Point::new((start as u32 * scale) as i32, (y as u32 * scale) as i32);
                let size = Size::new((x - start) as u32 * scale, scale);
                target.fill_solid(&Rectangle::new(origin, size), Rgb565::BLACK)?;
            }
        }
        Ok(())
    }

    fn draw_sub_image<D: DrawTarget<Color = Rgb565>>(
        &self,
        target: &mut D,
        area: &Rectangle,
    ) -> Result<(), D::Error> {
        self.draw(
            &mut target
                .translated(-area.top_left)
                .clipped(&Rectangle::new(area.top_left, area.size)),
        )
    }
}

/// An image a view holds by value: the view points at it through this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owned<T>(pub T);

impl<T> Deref for Owned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}
