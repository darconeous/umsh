//! SH1106 128×64 monochrome OLED, async, over `embedded-hal-async` I²C.
//!
//! The `sh1106` crate (v0.5.0) depends on embedded-hal 0.2, which is
//! incompatible with the embedded-hal 1.0 I²C both cargo workspaces run
//! on. This driver avoids that mismatch and carries only what UMSH
//! needs: init, contrast, panel on/off, and a full-frame flush.
//!
//! The panel's I²C address is **not** fixed across boards. The Wio
//! Tracker L1 populates 0x3D; the T-Beam Supreme ships both 0x3C and
//! 0x3D populations, where 0x3C may instead be a QMC6310N magnetometer.
//! So the address is a constructor parameter and [`probe`] resolves it
//! at runtime rather than any board hard-coding one.
//!
//! Frame buffer layout (SH1106 native page-major order):
//!   `buf[page * 128 + col]` bit `(row % 8)` = pixel at column `col`,
//!   row `page * 8 + (row % 8)`.
//!   Bit 0 = topmost pixel of page (lowest y), bit 7 = bottom.
//!   1 = pixel on (white / lit), 0 = pixel off (black).
//!
//! The nRF boards' `umsh-bsp-wio-tracker-l1::display` predates this
//! crate and still carries its own copy over `embassy_nrf::twim`. The
//! two are intended to converge on this one once that board's next
//! hardware pass makes a change there safe.

#![no_std]

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Point, Size};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::Pixel;
use embedded_hal_async::i2c::I2c;

#[cfg(test)]
mod tests;

pub const WIDTH: usize = 128;
pub const HEIGHT: usize = 64;
const PAGES: usize = HEIGHT / 8;
pub const BUF_SIZE: usize = WIDTH * PAGES; // 1024 bytes

/// The two addresses an SH1106 is strapped to on the boards UMSH
/// supports, in the order [`probe`] tries them.
pub const ADDR_CANDIDATES: [u8; 2] = [0x3D, 0x3C];

/// Panel contrast for an actively used display.
pub const CONTRAST_NORMAL: u8 = 0x7F;
/// Panel contrast for the dim warning that precedes lapsing. Far darker
/// than [`CONTRAST_NORMAL`] while still legible in the dark, so the
/// warning is unmistakable and the user still has a screen to answer it
/// on before the panel goes dark.
pub const CONTRAST_DIM: u8 = 0x07;

/// Where between [`CONTRAST_DIM`] and [`CONTRAST_NORMAL`] to sit, given a
/// permille of the way from the first to the second.
///
/// This is the mapping the display-attention policy's
/// `brightness_permille` needs, and the reason it deals in permille of the
/// gap rather than in absolute brightness: full brightness on this
/// controller is 0x7F where an SSD1306's is 0x5F, so a policy that named
/// a contrast would be naming the wrong one on half the class.
pub const fn contrast_for(permille: u16) -> u8 {
    let span = (CONTRAST_NORMAL - CONTRAST_DIM) as u32;
    let permille = if permille > 1_000 { 1_000 } else { permille };
    CONTRAST_DIM + (span * permille as u32 / 1_000) as u8
}

/// Control byte introducing a command stream.
const CTRL_CMD: u8 = 0x00;
/// Control byte introducing a data stream.
const CTRL_DATA: u8 = 0x40;

/// Longest command run any sequence below sends in one transaction.
const MAX_CMDS: usize = 17;

// ─── Address discovery ────────────────────────────────────────────────────

/// Find the panel's I²C address, trying 0x3D before 0x3C.
///
/// The order is not arbitrary. On a T-Beam Supreme carrying a QMC6310N
/// magnetometer, the magnetometer occupies 0x3C and the panel moves to
/// 0x3D — so an ACK at 0x3C proves nothing on its own, while an ACK at
/// 0x3D is unambiguous on every population UMSH supports. Trying 0x3D
/// first therefore resolves the overlap without needing a magnetometer
/// driver to disambiguate.
///
/// Probes with a one-byte read: a zero-length write is not reliably
/// translated into a bare address frame across HAL implementations.
pub async fn probe<I: I2c>(i2c: &mut I) -> Option<u8> {
    for addr in ADDR_CANDIDATES {
        let mut scratch = [0u8; 1];
        if i2c.read(addr, &mut scratch).await.is_ok() {
            return Some(addr);
        }
    }
    None
}

// ─── Low-level I²C driver ─────────────────────────────────────────────────

/// An SH1106 panel at a known address.
pub struct Sh1106<I> {
    i2c: I,
    addr: u8,
}

impl<I: I2c> Sh1106<I> {
    /// Bind the panel at `addr` — normally the value [`probe`] returned.
    pub fn new(i2c: I, addr: u8) -> Self {
        Self { i2c, addr }
    }

    /// The address this panel was bound to.
    pub fn address(&self) -> u8 {
        self.addr
    }

    /// Release the bus back to the caller.
    pub fn release(self) -> I {
        self.i2c
    }

    /// Send a run of command bytes in a single I²C transaction.
    ///
    /// The payload is copied into a stack buffer so the control byte and
    /// the commands reach the wire as one contiguous slice; nRF EasyDMA
    /// additionally requires the source to live in SRAM. Runs longer
    /// than [`MAX_CMDS`] are truncated — split the sequence instead.
    async fn cmds(&mut self, bytes: &[u8]) -> Result<(), I::Error> {
        let mut buf = [0u8; 1 + MAX_CMDS];
        buf[0] = CTRL_CMD;
        let n = bytes.len().min(MAX_CMDS);
        buf[1..=n].copy_from_slice(&bytes[..n]);
        self.i2c.write(self.addr, &buf[..=n]).await
    }

    pub async fn init(&mut self) -> Result<(), I::Error> {
        self.cmds(&[
            0xAE, // display off
            0xA8,
            0x3F, // multiplex ratio = 64
            0xD3,
            0x00, // display offset = 0
            0x40, // display start line = 0
            0xA1, // segment remap: col 127 → SEG0
            0xC8, // COM scan: remapped (top-to-bottom)
            0xDA,
            0x12, // COM pins: alternative, no LR remap (128×64)
            0x81,
            CONTRAST_NORMAL, // contrast
            0xA4,            // display from GDDRAM
            0xA6,            // normal (non-inverted)
            0xD5,
            0x80, // clock: div=1, fosc=8
        ])
        .await?;
        self.cmds(&[
            0x8D, 0x14, // charge pump: enable
            0xAF, // display on
        ])
        .await
    }

    /// Set panel contrast. Used by the display-attention policy to dim
    /// the panel as a warning before it lapses dark.
    pub async fn set_contrast(&mut self, contrast: u8) -> Result<(), I::Error> {
        self.cmds(&[0x81, contrast]).await
    }

    /// Turn the panel on or off without discarding GDDRAM, so a later
    /// `set_display_on(true)` restores the same frame instantly.
    pub async fn set_display_on(&mut self, on: bool) -> Result<(), I::Error> {
        self.cmds(&[if on { 0xAF } else { 0xAE }]).await
    }

    /// Push a full frame buffer to the panel.
    ///
    /// SH1106 requires page-by-page writes. Column start is 0x02 because
    /// the SH1106's internal GDDRAM has 132 columns but the visible panel
    /// starts at column 2.
    pub async fn flush(&mut self, fb: &Sh1106Fb) -> Result<(), I::Error> {
        for page in 0..PAGES {
            self.cmds(&[
                0xB0 | page as u8, // set page address (0xB0..0xB7)
                0x02,              // low column = 2 (SH1106 internal offset)
                0x10,              // high column = 0
            ])
            .await?;

            let mut data = [0u8; 1 + WIDTH];
            data[0] = CTRL_DATA;
            data[1..].copy_from_slice(&fb.0[page * WIDTH..(page + 1) * WIDTH]);
            self.i2c.write(self.addr, &data).await?;
        }
        Ok(())
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

impl Default for Sh1106Fb {
    fn default() -> Self {
        Self::new()
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
                let col = x as usize;
                let bit = y as usize % 8;
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
    fn size(&self) -> Size {
        Size::new(WIDTH as u32, HEIGHT as u32)
    }
}
