//! ST7789 and ST7796 color panels over SPI, async, with the frame drawn in
//! RAM and sent a stripe at a time.
//!
//! The two controllers share their command set; a board's panel differs
//! only in its size, where its window sits in the controller's memory,
//! and the settings it is brought up with. Those make up a
//! [`PanelSpec`], and one driver serves every panel. The transport
//! handles bus sharing: a stripe is one SPI transaction, so a radio on
//! the same bus waits at most one stripe.
#![no_std]

mod framebuffer;
mod panel;

pub use framebuffer::{Binary, Framebuffer, STRIPE_ROWS, SentStripes};
pub use panel::{PanelSpec, ST7789_TDECK, ST7796_PAGER};

use embedded_hal::digital::OutputPin;
use embedded_hal_async::{delay::DelayNs, spi::SpiDevice};

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum Error<S, P> {
    Spi(S),
    Pin(P),
}

pub struct St77xx<S, P> {
    spi: S,
    dc: P,
    spec: &'static PanelSpec,
}

impl<S: SpiDevice<u8>, P: OutputPin> St77xx<S, P> {
    pub fn new(spi: S, dc: P, spec: &'static PanelSpec) -> Self {
        Self { spi, dc, spec }
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
    /// Brings the panel up from any state, leaving it awake with its
    /// display off.
    pub async fn init(
        &mut self,
        delay: &mut impl DelayNs,
    ) -> Result<(), Error<S::Error, P::Error>> {
        self.command(0x01, &[]).await?;
        // ST7796S §9.2.2, ST7789V §9.1.2: reset while asleep requires
        // 120 ms before SLPOUT. Use that interval on both cold and warm
        // boots; prior mode is unknown.
        delay.delay_ms(120).await;
        self.command(0x11, &[]).await?;
        // ST7796S §9.2.13: new commands may follow SLPOUT after 5 ms. The
        // separate 120 ms restriction applies to SLPIN, which this driver
        // never sends.
        delay.delay_ms(5).await;
        for &(cmd, data) in self.spec.init {
            self.command(cmd, data).await?;
        }
        self.command(0x28, &[]).await
    }
    pub async fn on(&mut self, on: bool) -> Result<(), Error<S::Error, P::Error>> {
        self.command(if on { 0x29 } else { 0x28 }, &[]).await
    }
    /// Sleep in, for a panel that keeps its supply while the board is off.
    /// Only [`init`](Self::init) brings it back.
    pub async fn sleep(&mut self) -> Result<(), Error<S::Error, P::Error>> {
        self.command(0x10, &[]).await
    }
    /// Writes whole rows from row `y`. With `continues`, the rows follow
    /// straight on from the last ones written, and only the pixels go out;
    /// otherwise the window is set first, from `y` to the bottom of the
    /// screen, so that later rows can follow on the same way.
    pub async fn stripe(
        &mut self,
        y: usize,
        pixels: &[u8],
        continues: bool,
    ) -> Result<(), Error<S::Error, P::Error>> {
        let spec = self.spec;
        let (width, height) = (spec.width as usize, spec.height as usize);
        assert!(
            y < height
                && pixels.len() <= spec.stripe_bytes()
                && pixels.len().is_multiple_of(width * 2)
        );
        let rows = pixels.len() / (width * 2);
        assert!(rows != 0 && y + rows <= height);
        if continues {
            // Write Memory Continue: on from where the last write stopped.
            return self.command(0x3c, pixels).await;
        }
        let window = |start: u16, end: u16| {
            let [s0, s1] = start.to_be_bytes();
            let [e0, e1] = end.to_be_bytes();
            [s0, s1, e0, e1]
        };
        let column = spec.column_offset;
        self.command(0x2a, &window(column, column + spec.width - 1))
            .await?;
        let row = spec.row_offset;
        self.command(0x2b, &window(row + y as u16, row + spec.height - 1))
            .await?;
        self.command(0x2c, pixels).await
    }
}
