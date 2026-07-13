//! Low-level SSD1681 / GDEH0154D67 e-paper driver for the T-Echo.
//!
//! Init sequence matches GxEPD2_154_D67 byte-for-byte. Three things that
//! cost us a session to discover and are worth carrying as a warning:
//!
//! 1. Cmd `0x01` third byte must be `0x00` (GD=0). Setting GD=1 mirrors
//!    the panel scan.
//! 2. Cmd `0x11` (data entry mode) must be `0x03` (X+, Y+). Mode `0x01`
//!    walks the Y address counter the wrong way off the first row, and
//!    most of the frame ends up in unmapped RAM.
//! 3. NO pre-RAM load cycle. Activating with `0x22 [0xB1]` before the
//!    first RAM write ends in "disable clock", which silently kills any
//!    subsequent `0x24` data. The only activation is the post-RAM
//!    `0x22 [0xF7]` full refresh.
//!
//! The panel is mounted 90° CCW from the chip's natural scan order on the
//! T-Echo. [`EpdFb`] (the `DrawTarget` impl) applies the GxEPD2 rotation-3
//! transform so callers can think in normal screen coordinates.

use embassy_nrf::gpio::{Input, Output};
use embassy_nrf::spim::Spim;
use embassy_time::{Duration, Timer};
use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Point, Size};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::Pixel;

pub const WIDTH: usize = 200;
pub const HEIGHT: usize = 200;
pub const BYTES_PER_ROW: usize = WIDTH / 8;
pub const BUF_SIZE: usize = BYTES_PER_ROW * HEIGHT;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Hardware-reset, software-reset, and load all SSD1681 control registers.
/// After this returns the panel is ready to accept RAM writes via [`render`].
pub async fn init(
    spi: &mut Spim<'_>,
    cs: &mut Output<'_>,
    dc: &mut Output<'_>,
    rst: &mut Output<'_>,
    busy: &mut Input<'_>,
) {
    Timer::after(Duration::from_millis(10)).await;
    rst.set_low();
    Timer::after(Duration::from_millis(10)).await;
    rst.set_high();
    wait_idle(busy).await;

    cmd(spi, cs, dc, 0x12, &[]).await; // SW reset
    wait_idle(busy).await;

    cmd(spi, cs, dc, 0x01, &[0xC7, 0x00, 0x00]).await; // driver output: MUX=199
    cmd(spi, cs, dc, 0x3C, &[0x05]).await; // border = VSS
    cmd(spi, cs, dc, 0x18, &[0x80]).await; // built-in temp sensor
    cmd(spi, cs, dc, 0x11, &[0x03]).await; // data entry: X+, Y+
    cmd(spi, cs, dc, 0x44, &[0x00, 0x18]).await; // X window 0..24
    cmd(spi, cs, dc, 0x45, &[0x00, 0x00, 0xC7, 0x00]).await; // Y window 0..199
}

/// Write `pixels` into both B/W RAM and RED RAM, trigger a full refresh, and
/// wait for the panel to complete (~2 s; the panel visibly flashes during).
///
/// RED RAM is cleared with the same buffer because prior firmware (e.g.
/// Meshtastic) may have left content in it that would otherwise combine
/// with our B/W frame.
pub async fn render(
    spi: &mut Spim<'_>,
    cs: &mut Output<'_>,
    dc: &mut Output<'_>,
    busy: &mut Input<'_>,
    pixels: &[u8],
) {
    cmd(spi, cs, dc, 0x4E, &[0x00]).await;
    cmd(spi, cs, dc, 0x4F, &[0x00, 0x00]).await;
    write_ram(spi, cs, dc, 0x24, pixels).await;
    cmd(spi, cs, dc, 0x4E, &[0x00]).await;
    cmd(spi, cs, dc, 0x4F, &[0x00, 0x00]).await;
    write_ram(spi, cs, dc, 0x26, pixels).await;
    cmd(spi, cs, dc, 0x22, &[0xF7]).await;
    cmd(spi, cs, dc, 0x20, &[]).await;
    wait_idle(busy).await;
}

/// Deep Sleep Mode 1: lowest power, RAM retained, hardware reset required
/// to wake. Use this once the final frame is on the glass and you don't
/// expect to update again for a while.
#[allow(dead_code)] // kept for low-power flows we'll add later
pub async fn sleep(spi: &mut Spim<'_>, cs: &mut Output<'_>, dc: &mut Output<'_>) {
    cmd(spi, cs, dc, 0x10, &[0x01]).await;
}

// ─── Frame buffer (embedded-graphics DrawTarget) ─────────────────────────────

/// `embedded-graphics::DrawTarget` over a packed-MSB B/W frame buffer.
///
/// Layout: bit 7 of byte 0 is pixel (0,0). 1 = white paper, 0 = black ink.
/// `BinaryColor::On` is treated as ink (clears the bit), matching the
/// convention used by `epd-waveshare` and friends.
///
/// Applies a 90° CCW rotation on every pixel write (GxEPD2 rotation-3) so
/// callers can use natural screen coordinates with the T-Echo's panel
/// mounting.
pub struct EpdFb<'a>(pub &'a mut [u8]);

impl DrawTarget for EpdFb<'_> {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), core::convert::Infallible>
    where
        I: IntoIterator<Item = Pixel<BinaryColor>>,
    {
        for Pixel(Point { x, y }, color) in pixels {
            if (0..WIDTH as i32).contains(&x) && (0..HEIGHT as i32).contains(&y) {
                // chip_x = logical_y,  chip_y = (HEIGHT-1) - logical_x
                let cx = y as usize;
                let cy = HEIGHT - 1 - x as usize;
                let idx = cy * BYTES_PER_ROW + cx / 8;
                let bit = 7 - (cx % 8);
                if color.is_on() {
                    self.0[idx] &= !(1 << bit);
                } else {
                    self.0[idx] |= 1 << bit;
                }
            }
        }
        Ok(())
    }
}

impl OriginDimensions for EpdFb<'_> {
    fn size(&self) -> Size {
        Size::new(WIDTH as u32, HEIGHT as u32)
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Wait, suspended via GPIOTE, until BUSY goes low (panel idle).
async fn wait_idle(busy: &mut Input<'_>) {
    busy.wait_for_low().await;
}

/// Send one SSD1681 command byte plus optional small data payload.
///
/// All buffers are copied to the stack first — nRF52840 EasyDMA can only
/// read SRAM, and `&[...]` literals in release builds may live in flash
/// (`.rodata`), which would silently produce garbage on the bus.
async fn cmd(
    spi: &mut Spim<'_>,
    cs: &mut Output<'_>,
    dc: &mut Output<'_>,
    command: u8,
    data: &[u8],
) {
    let cmd_buf = [command];
    let mut data_buf = [0u8; 8];
    let n = data.len().min(data_buf.len());
    data_buf[..n].copy_from_slice(&data[..n]);

    cs.set_low();
    dc.set_low();
    let _ = spi.write(&cmd_buf).await;
    if n > 0 {
        dc.set_high();
        let _ = spi.write(&data_buf[..n]).await;
    }
    cs.set_high();
}

/// Write a large pixel payload to the addressed RAM (`cmd_byte` = 0x24 for
/// B/W, 0x26 for RED). Single DMA burst — SPIM2's TXD MAXCNT comfortably
/// covers 5000 bytes despite the misleading 8-bit-only rumor for SPIM0/1.
async fn write_ram(
    spi: &mut Spim<'_>,
    cs: &mut Output<'_>,
    dc: &mut Output<'_>,
    cmd_byte: u8,
    pixels: &[u8],
) {
    let cmd_buf = [cmd_byte];
    cs.set_low();
    dc.set_low();
    let _ = spi.write(&cmd_buf).await;
    dc.set_high();
    let _ = spi.write(pixels).await;
    cs.set_high();
}
