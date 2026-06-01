//! SH1106 128×64 OLED driver for the Wio Tracker L1 (I²C, async).
//!
//! The sh1106 crate (v0.5.0) depends on embedded-hal 0.2, which is
//! incompatible with embassy's embedded-hal 1.0 I²C. This thin inline
//! driver avoids that mismatch and is simpler than the T-Echo's e-paper
//! driver: no busy pin, no ~2 s full-refresh flash, no RED-RAM tracking,
//! no panel-rotation transform.
//!
//! I²C address: 0x3D (per Meshtastic and MeshCore variant files).
//! TWIM0 pins: SDA=P0.06, SCL=P0.05.
//!
//! Frame buffer layout (SH1106 native page-major order):
//!   `buf[page * 128 + col]` bit `(row % 8)` = pixel at column `col`,
//!   row `page * 8 + (row % 8)`.
//!   Bit 0 = topmost pixel of page (lowest y), bit 7 = bottom.
//!   1 = pixel on (white / lit), 0 = pixel off (black).

use embassy_nrf::twim::Twim;
use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Point, Size};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::Pixel;

pub const WIDTH:    usize = 128;
pub const HEIGHT:   usize = 64;
const PAGES:        usize = HEIGHT / 8;
pub const BUF_SIZE: usize = WIDTH * PAGES;  // 1024 bytes

const OLED_ADDR: u8 = 0x3D;

// ─── Low-level I²C driver ─────────────────────────────────────────────────

pub struct Sh1106<'d>(Twim<'d>);

impl<'d> Sh1106<'d> {
    pub fn new(i2c: Twim<'d>) -> Self {
        Self(i2c)
    }

    /// Send a run of command bytes in a single I²C transaction.
    ///
    /// Stack-copies the payload so nRF EasyDMA reads from SRAM.
    /// Maximum 17 command bytes per call (covers all SH1106 sequences
    /// we need; split into two calls if a sequence is longer).
    async fn cmds(&mut self, bytes: &[u8]) {
        let mut buf = [0u8; 18];  // 1 control + ≤17 command bytes
        buf[0] = 0x00;            // control byte: command stream
        let n = bytes.len().min(buf.len() - 1);
        buf[1..=n].copy_from_slice(&bytes[..n]);
        let _ = self.0.write(OLED_ADDR, &buf[..=n]).await;
    }

    pub async fn init(&mut self) {
        self.cmds(&[
            0xAE,        // display off
            0xA8, 0x3F,  // multiplex ratio = 64
            0xD3, 0x00,  // display offset = 0
            0x40,        // display start line = 0
            0xA1,        // segment remap: col 127 → SEG0
            0xC8,        // COM scan: remapped (top-to-bottom)
            0xDA, 0x12,  // COM pins: alternative, no LR remap (128×64)
            0x81, 0x7F,  // contrast = 127
            0xA4,        // display from GDDRAM
            0xA6,        // normal (non-inverted)
            0xD5, 0x80,  // clock: div=1, fosc=8
        ]).await;
        self.cmds(&[
            0x8D, 0x14,  // charge pump: enable
            0xAF,        // display on
        ]).await;
    }

    /// Push a full 1024-byte frame buffer to the panel.
    ///
    /// SH1106 requires page-by-page writes. Column start is 0x02 because
    /// the SH1106's internal GDDRAM has 132 columns but the visible panel
    /// starts at column 2.
    pub async fn flush(&mut self, fb: &Sh1106Fb) {
        for page in 0..PAGES {
            self.cmds(&[
                0xB0 | page as u8,  // set page address (0xB0..0xB7)
                0x02,               // low column = 2 (SH1106 internal offset)
                0x10,               // high column = 0
            ]).await;

            // Prepend control byte 0x40 (data stream) on the stack so
            // we can hand a single contiguous slice to write().
            let mut data = [0u8; 1 + WIDTH];
            data[0] = 0x40;
            data[1..].copy_from_slice(&fb.0[page * WIDTH..(page + 1) * WIDTH]);
            let _ = self.0.write(OLED_ADDR, &data).await;
        }
    }
}

// ─── Frame buffer (embedded-graphics DrawTarget) ──────────────────────────

/// 128×64 monochrome frame buffer for the SH1106.
pub struct Sh1106Fb(pub [u8; BUF_SIZE]);

impl Sh1106Fb {
    pub const fn new() -> Self {
        Self([0u8; BUF_SIZE])
    }

    pub fn clear(&mut self) {
        self.0.fill(0);
    }
}

impl DrawTarget for Sh1106Fb {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<BinaryColor>>,
    {
        for Pixel(Point { x, y }, color) in pixels {
            if (0..WIDTH as i32).contains(&x) && (0..HEIGHT as i32).contains(&y) {
                let page = y as usize / 8;
                let col  = x as usize;
                let bit  = y as usize % 8;
                let byte = &mut self.0[page * WIDTH + col];
                if color.is_on() {
                    *byte |= 1 << bit;
                } else {
                    *byte &= !(1 << bit);
                }
            }
        }
        Ok(())
    }
}

impl OriginDimensions for Sh1106Fb {
    fn size(&self) -> Size { Size::new(WIDTH as u32, HEIGHT as u32) }
}
