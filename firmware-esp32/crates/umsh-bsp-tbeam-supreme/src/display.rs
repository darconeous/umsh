//! SH1106 OLED on the sensor I²C bus (SDA=GPIO17, SCL=GPIO18).
//!
//! The driver itself lives in `umsh-display-sh1106`, shared with the
//! root workspace; this module pins it to this board's bus and wraps it
//! in the surface the shared ESP32 tracker sources drive a panel
//! through (the ssd1306 crate's shape on the Heltec boards): a buffered
//! [`DrawTarget`] with `init` / `flush` / `set_brightness` /
//! `set_display_on`. Board facts:
//!
//! - The address is a **population variable**, not a constant: 0x3C
//!   normally, 0x3D when a QMC6310N magnetometer occupies 0x3C
//!   (hardware doc §2.4). [`probe`] resolves it — 0x3D first, so a
//!   magnetometer ACK cannot be mistaken for the panel.
//! - There is no reset GPIO. The panel's reset is its ALDO1 rail; after
//!   a rail cycle, re-init is the whole recovery path (§9.1).
//! - The bus must not be probed before [`crate::power::bring_up`] has
//!   the sensor rails on (§8.1) — an unpowered panel looks exactly like
//!   an absent one.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::Pixel;
use esp_hal::Async;
use esp_hal::i2c::master::I2c;
use umsh_display_sh1106::{Sh1106, Sh1106Fb};

pub use umsh_display_sh1106::probe;

type Bus = I2c<'static, Async>;
type BusError = esp_hal::i2c::master::Error;

/// Panel brightness, in the two levels the display-attention policy
/// uses. Mirrors the ssd1306 crate's type so the shared display task
/// drives both panels through one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Brightness(u8);

impl Brightness {
    pub const NORMAL: Self = Self(umsh_display_sh1106::CONTRAST_NORMAL);
    pub const DIM: Self = Self(umsh_display_sh1106::CONTRAST_DIM);
}

/// The panel plus its frame buffer, presenting the buffered-graphics
/// surface the shared tracker sources expect: draw into it, `flush` to
/// push the frame.
///
/// The bus is owned whole: the OLED is the only in-scope device on it.
/// When the BME280 or magnetometer land, the `Bus` alias becomes a
/// shared-bus device handle and nothing else changes.
pub struct Display {
    panel: Sh1106<Bus>,
    fb: Sh1106Fb,
}

/// Bind the panel at a probed address — the value [`probe`] returned.
pub fn new_display(i2c: Bus, addr: u8) -> Display {
    Display {
        panel: Sh1106::new(i2c, addr),
        fb: Sh1106Fb::new(),
    }
}

impl Display {
    pub async fn init(&mut self) -> Result<(), BusError> {
        self.panel.init().await
    }

    /// Push the buffered frame to the panel.
    pub async fn flush(&mut self) -> Result<(), BusError> {
        self.panel.flush(&self.fb).await
    }

    pub async fn set_brightness(&mut self, brightness: Brightness) -> Result<(), BusError> {
        self.panel.set_contrast(brightness.0).await
    }

    /// Panel on/off without discarding GDDRAM, so switching back on
    /// restores the same frame instantly.
    pub async fn set_display_on(&mut self, on: bool) -> Result<(), BusError> {
        self.panel.set_display_on(on).await
    }
}

impl DrawTarget for Display {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<BinaryColor>>,
    {
        self.fb.draw_iter(pixels)
    }
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        self.fb.size()
    }
}
