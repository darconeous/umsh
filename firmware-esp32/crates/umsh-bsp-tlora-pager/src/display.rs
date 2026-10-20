//! ST7796 and AW9364 backlight. The SPI handle releases the bus per stripe.
use crate::SpiHandle;
use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
use esp_hal::gpio::Output;
use esp_hal::gpio::{Level, OutputConfig};
use esp_hal::peripherals::{GPIO42, GPIO46};
use umsh_bsp_esp32::aw9364::Aw9364;
use umsh_bsp_esp32::panel::Panel;
use umsh_display_st77xx::{Framebuffer, PanelSpec, ST7796_PAGER};
pub const PANEL: &PanelSpec = &ST7796_PAGER;
pub const FRAME_BYTES: usize = PANEL.frame_bytes();
pub const STRIPE_BYTES: usize = PANEL.stripe_bytes();
const STRIPES: usize = PANEL.stripes();
pub type Error = umsh_bsp_esp32::panel::Error<
    embassy_embedded_hal::shared_bus::SpiDeviceError<
        esp_hal::spi::Error,
        core::convert::Infallible,
    >,
>;
pub use umsh_bsp_esp32::aw9364::{Brightness, brightness_from_permille};
/// Light the board before panel, heap, or async timer initialization.
/// Ownership passes to the display without toggling either output.
pub struct BootBacklights {
    display: Aw9364,
    keyboard: Output<'static>,
}
impl BootBacklights {
    pub fn new(display: GPIO42<'static>, keyboard: GPIO46<'static>) -> Self {
        let keyboard = Output::new(keyboard, Level::High, OutputConfig::default());
        let display = Aw9364::boot(Output::new(display, Level::Low, OutputConfig::default()));
        Self { display, keyboard }
    }
}
pub struct Display {
    panel: Panel<SpiHandle, STRIPES>,
    keyboard_light: Output<'static>,
    /// Whether the keyboard lights with the panel.
    keyboard_lit: bool,
}
impl Display {
    pub fn invert(&mut self) {
        self.panel.frame().invert();
    }
    /// The working frame in full color. Drawing on the display itself is
    /// black and white.
    pub fn color(&mut self) -> &mut Framebuffer {
        self.panel.frame()
    }
    pub fn new(
        spi: SpiHandle,
        dc: Output<'static>,
        lights: BootBacklights,
        fb: &'static mut [u8; FRAME_BYTES],
        stripe: &'static mut [u8; STRIPE_BYTES],
    ) -> Self {
        Self {
            panel: Panel::new(spi, dc, PANEL, lights.display, fb, stripe),
            keyboard_light: lights.keyboard,
            keyboard_lit: true,
        }
    }
    pub async fn init(&mut self) -> Result<(), Error> {
        self.panel.init().await
    }
    pub async fn flush(&mut self) -> Result<(), Error> {
        self.panel.flush().await
    }
    pub async fn set_brightness(&mut self, brightness: Brightness) -> Result<(), Error> {
        self.panel.set_brightness(brightness).await;
        Ok(())
    }
    pub async fn set_display_on(&mut self, on: bool) -> Result<(), Error> {
        if !on {
            self.keyboard_light.set_low();
        }
        self.panel.set_on(on).await?;
        if on && self.keyboard_lit {
            self.keyboard_light.set_high();
        }
        Ok(())
    }
    /// Dark for good: the board is turning off.
    pub async fn sleep(&mut self) -> Result<(), Error> {
        self.set_display_on(false).await?;
        self.panel.sleep().await
    }
    /// Whether the keyboard lights while the panel is on.
    pub fn set_keyboard_light(&mut self, lit: bool) {
        self.keyboard_lit = lit;
        if self.panel.is_on() {
            self.keyboard_light.set_level(Level::from(lit));
        }
    }
}
impl OriginDimensions for Display {
    fn size(&self) -> Size {
        self.panel.frame_ref().size()
    }
}
impl DrawTarget for Display {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;
    fn draw_iter<I: IntoIterator<Item = Pixel<BinaryColor>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.panel.frame().binary().draw_iter(pixels)
    }
    fn clear(&mut self, color: BinaryColor) -> Result<(), Self::Error> {
        self.panel.frame().binary().clear(color)
    }
}
