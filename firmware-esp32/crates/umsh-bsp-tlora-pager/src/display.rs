//! ST7796 and AW9364 backlight. The SPI handle releases the bus per stripe.
use crate::SpiHandle;
use embassy_time::{Delay, Timer};
use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
use esp_hal::gpio::Output;
use umsh_pager_peripherals::display::{
    FRAME_BYTES, Framebuffer, HEIGHT, STRIPE_BYTES, STRIPE_ROWS, St7796,
};
pub type Error = umsh_pager_peripherals::display::Error<
    embassy_embedded_hal::shared_bus::SpiDeviceError<
        esp_hal::spi::Error,
        core::convert::Infallible,
    >,
    core::convert::Infallible,
>;
#[derive(Clone, Copy)]
pub struct Brightness(u8);
impl Brightness {
    pub const NORMAL: Self = Self(8);
}
pub const fn brightness_from_permille(p: u16) -> Brightness {
    Brightness(1 + ((if p > 1000 { 1000 } else { p }) * 7 / 1000) as u8)
}
pub struct Display {
    panel: St7796<SpiHandle, Output<'static>>,
    fb: Framebuffer,
    sent: Framebuffer,
    sent_valid: bool,
    stripe: &'static mut [u8; STRIPE_BYTES],
    backlight: Output<'static>,
    keyboard_light: Output<'static>,
    brightness: u8,
    physical_brightness: u8,
    on: bool,
}
impl Display {
    pub fn new(
        spi: SpiHandle,
        dc: Output<'static>,
        backlight: Output<'static>,
        keyboard_light: Output<'static>,
        fb: &'static mut [u8; FRAME_BYTES],
        sent: &'static mut [u8; FRAME_BYTES],
        stripe: &'static mut [u8; STRIPE_BYTES],
    ) -> Self {
        Self {
            panel: St7796::new(spi, dc),
            fb: Framebuffer::new(fb),
            sent: Framebuffer::new(sent),
            sent_valid: false,
            stripe,
            backlight,
            keyboard_light,
            brightness: 8,
            physical_brightness: 0,
            on: false,
        }
    }
    pub async fn init(&mut self) -> Result<(), Error> {
        self.sent_valid = false;
        self.panel.init(&mut Delay).await
    }
    pub async fn flush(&mut self) -> Result<(), Error> {
        for y in (0..HEIGHT).step_by(STRIPE_ROWS) {
            if self.sent_valid && self.fb.stripe_matches(y, &self.sent) {
                continue;
            }
            let len = self.fb.stripe(y, self.stripe);
            if let Err(error) = self.panel.stripe(y, &self.stripe[..len]).await {
                // A failed transfer may have written part of the stripe. Even
                // a later frame matching old history must repair those pixels.
                self.sent_valid = false;
                return Err(error);
            }
            self.sent.copy_stripe_from(y, &self.fb);
            embassy_futures::yield_now().await;
        }
        self.sent_valid = true;
        Ok(())
    }
    async fn backlight(&mut self, value: u8) {
        if value == self.physical_brightness {
            return;
        }
        // AW9364 starts at step 16, subsequent falling/rising pulses decrement
        // modulo 16. Hold low to reset before enabling. No PWM on this pin.
        if value == 0 {
            self.backlight.set_low();
            Timer::after_millis(3).await;
        } else {
            if self.physical_brightness == 0 {
                self.backlight.set_high();
                Timer::after_micros(100).await;
                self.physical_brightness = 16;
            }
            let pulses = (16 + self.physical_brightness - value) % 16;
            let delay = esp_hal::delay::Delay::new();
            for _ in 0..pulses {
                // A preemption must not stretch the low pulse into a reset.
                // Mask interrupts for only this 1 us pulse, not the pulse train.
                critical_section::with(|_| {
                    self.backlight.set_low();
                    delay.delay_micros(1);
                    self.backlight.set_high();
                });
                delay.delay_micros(1);
            }
        }
        self.physical_brightness = value;
    }
    pub async fn set_brightness(&mut self, brightness: Brightness) -> Result<(), Error> {
        self.brightness = brightness.0;
        if self.on {
            self.backlight(self.brightness).await;
        }
        Ok(())
    }
    pub async fn set_display_on(&mut self, on: bool) -> Result<(), Error> {
        if !on {
            self.backlight(0).await;
            self.keyboard_light.set_low();
        }
        self.panel.on(on).await?;
        self.on = on;
        if on {
            self.backlight(self.brightness).await;
            self.keyboard_light.set_high();
        }
        Ok(())
    }
}
impl OriginDimensions for Display {
    fn size(&self) -> Size {
        self.fb.size()
    }
}
impl DrawTarget for Display {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;
    fn draw_iter<I: IntoIterator<Item = Pixel<BinaryColor>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.fb.draw_iter(pixels)
    }
    fn clear(&mut self, color: BinaryColor) -> Result<(), Self::Error> {
        self.fb.clear(color)
    }
}
