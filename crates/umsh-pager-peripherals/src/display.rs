//! ST7796 controller, 480×222 landscape window. Transport handles bus sharing.
use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
use embedded_hal::digital::OutputPin;
use embedded_hal_async::{delay::DelayNs, spi::SpiDevice};

pub const WIDTH: usize = 480;
pub const HEIGHT: usize = 222;
pub const FRAME_BYTES: usize = WIDTH * HEIGHT / 8;
pub const STRIPE_ROWS: usize = 4;
pub const STRIPE_BYTES: usize = WIDTH * STRIPE_ROWS * 2;

pub struct Framebuffer {
    bytes: &'static mut [u8; FRAME_BYTES],
}
impl Framebuffer {
    pub fn new(bytes: &'static mut [u8; FRAME_BYTES]) -> Self {
        bytes.fill(0);
        Self { bytes }
    }
    /// Compare against the last successfully transferred pixels. Rendering
    /// clears and redraws the working frame, so write-time dirty flags alone
    /// would incorrectly mark the whole screen dirty.
    pub fn stripe_matches(&self, y: usize, other: &Self) -> bool {
        assert!(y < HEIGHT);
        let start = y * WIDTH / 8;
        let end = (y + STRIPE_ROWS).min(HEIGHT) * WIDTH / 8;
        self.bytes[start..end] == other.bytes[start..end]
    }
    pub fn copy_stripe_from(&mut self, y: usize, source: &Self) {
        assert!(y < HEIGHT);
        let start = y * WIDTH / 8;
        let end = (y + STRIPE_ROWS).min(HEIGHT) * WIDTH / 8;
        self.bytes[start..end].copy_from_slice(&source.bytes[start..end]);
    }
    pub fn stripe(&self, y: usize, out: &mut [u8; STRIPE_BYTES]) -> usize {
        let rows = STRIPE_ROWS.min(HEIGHT.saturating_sub(y));
        for i in 0..rows * WIDTH {
            let pixel = y * WIDTH + i;
            let color = if self.bytes[pixel / 8] & (0x80 >> (pixel % 8)) != 0 {
                0xff
            } else {
                0
            };
            out[2 * i] = color;
            out[2 * i + 1] = color;
        }
        rows * WIDTH * 2
    }
}
impl OriginDimensions for Framebuffer {
    fn size(&self) -> Size {
        Size::new(WIDTH as u32, HEIGHT as u32)
    }
}
impl DrawTarget for Framebuffer {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;
    fn draw_iter<T: IntoIterator<Item = Pixel<BinaryColor>>>(
        &mut self,
        pixels: T,
    ) -> Result<(), Self::Error> {
        for Pixel(Point { x, y }, c) in pixels {
            if x < 0 || y < 0 || x >= WIDTH as i32 || y >= HEIGHT as i32 {
                continue;
            }
            let i = y as usize * WIDTH + x as usize;
            let mask = 0x80 >> (i % 8);
            if c.is_on() {
                self.bytes[i / 8] |= mask;
            } else {
                self.bytes[i / 8] &= !mask;
            }
        }
        Ok(())
    }
    fn clear(&mut self, color: BinaryColor) -> Result<(), Self::Error> {
        self.bytes.fill(if color.is_on() { 0xff } else { 0 });
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error<S, P> {
    Spi(S),
    Pin(P),
}
pub struct St7796<S, P> {
    spi: S,
    dc: P,
}
impl<S: SpiDevice<u8>, P: OutputPin> St7796<S, P> {
    pub fn new(spi: S, dc: P) -> Self {
        Self { spi, dc }
    }
    pub async fn command(
        &mut self,
        command: u8,
        data: &[u8],
    ) -> Result<(), Error<S::Error, P::Error>> {
        self.dc.set_low().map_err(Error::Pin)?;
        self.spi.write(&[command]).await.map_err(Error::Spi)?;
        self.dc.set_high().map_err(Error::Pin)?;
        if !data.is_empty() {
            self.spi.write(data).await.map_err(Error::Spi)?;
        }
        Ok(())
    }
    pub async fn init(
        &mut self,
        delay: &mut impl DelayNs,
    ) -> Result<(), Error<S::Error, P::Error>> {
        self.command(0x01, &[]).await?;
        delay.delay_ms(150).await;
        self.command(0x11, &[]).await?;
        delay.delay_ms(120).await;
        // Board-specific ST7796 settings from LilyGo's panel initialization.
        for (cmd, data) in [
            (0xf0, &[0xc3][..]),
            (0xf0, &[0x96]),
            (0x36, &[0xe8]),
            (0x3a, &[0x55]),
            (0xb4, &[1]),
            (0xb6, &[0x80, 2, 0x3b]),
            (0xe8, &[0x40, 0x8a, 0, 0, 0x29, 0x19, 0xa5, 0x33]),
            (0xc1, &[6]),
            (0xc2, &[0xa7]),
            (0xc5, &[0x18]),
            (
                0xe0,
                &[
                    0xf0, 9, 0x0b, 6, 4, 0x15, 0x2f, 0x54, 0x42, 0x3c, 0x17, 0x14, 0x18, 0x1b,
                ],
            ),
            (
                0xe1,
                &[
                    0xe0, 9, 0x0b, 6, 4, 3, 0x2b, 0x43, 0x42, 0x3b, 0x16, 0x14, 0x17, 0x1b,
                ],
            ),
            (0xf0, &[0x3c]),
            (0xf0, &[0x69]),
            (0x21, &[]),
        ] {
            self.command(cmd, data).await?;
        }
        self.command(0x28, &[]).await
    }
    pub async fn on(&mut self, on: bool) -> Result<(), Error<S::Error, P::Error>> {
        self.command(if on { 0x29 } else { 0x28 }, &[]).await
    }
    pub async fn stripe(
        &mut self,
        y: usize,
        pixels: &[u8],
    ) -> Result<(), Error<S::Error, P::Error>> {
        assert!(y < HEIGHT && pixels.len() <= STRIPE_BYTES && pixels.len() % (WIDTH * 2) == 0);
        let rows = pixels.len() / (WIDTH * 2);
        assert!(rows != 0 && y + rows <= HEIGHT);
        // Landscape rotation maps the portrait column offset to the Y address.
        let start = (49 + y) as u16;
        let end = start + rows as u16 - 1;
        self.command(0x2a, &[0, 0, 1, 0xdf]).await?;
        self.command(
            0x2b,
            &[(start >> 8) as u8, start as u8, (end >> 8) as u8, end as u8],
        )
        .await?;
        self.command(0x2c, pixels).await
    }
}
