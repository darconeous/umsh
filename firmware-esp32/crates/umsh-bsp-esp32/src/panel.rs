//! A color panel on an ST77xx controller with an AW9364 backlight, as the
//! keyboard boards carry: the frame drawn in RAM, sent a stripe at a time
//! where it changed, and the backlight following the panel on and off.

use crate::aw9364::{Aw9364, Brightness};
use embassy_time::Delay;
use embedded_hal_async::spi::SpiDevice;
use esp_hal::gpio::Output;
use umsh_display_st77xx::{Framebuffer, PanelSpec, STRIPE_ROWS, SentStripes, St77xx};

pub type Error<S> = umsh_display_st77xx::Error<S, core::convert::Infallible>;

/// `N` is the panel's stripes, [`PanelSpec::stripes`].
pub struct Panel<S, const N: usize> {
    panel: St77xx<S, Output<'static>>,
    fb: Framebuffer,
    sent: SentStripes<N>,
    stripe: &'static mut [u8],
    backlight: Aw9364,
    brightness: u8,
    on: bool,
}

impl<S: SpiDevice<u8>, const N: usize> Panel<S, N> {
    /// `frame` holds a whole frame and `stripe` the most one stripe can be.
    pub fn new(
        spi: S,
        dc: Output<'static>,
        spec: &'static PanelSpec,
        backlight: Aw9364,
        frame: &'static mut [u8],
        stripe: &'static mut [u8],
    ) -> Self {
        assert!(spec.stripes() == N && stripe.len() == spec.stripe_bytes());
        Self {
            panel: St77xx::new(spi, dc, spec),
            fb: Framebuffer::new(frame, spec.width.into(), spec.height.into()),
            sent: SentStripes::new(),
            stripe,
            backlight,
            brightness: Brightness::NORMAL.step(),
            on: false,
        }
    }
    pub fn frame(&mut self) -> &mut Framebuffer {
        &mut self.fb
    }
    pub fn frame_ref(&self) -> &Framebuffer {
        &self.fb
    }
    pub fn is_on(&self) -> bool {
        self.on
    }
    pub async fn init(&mut self) -> Result<(), Error<S::Error>> {
        self.sent.forget();
        self.backlight.set(self.brightness).await;
        self.panel.init(&mut Delay).await
    }
    pub async fn flush(&mut self) -> Result<(), Error<S::Error>> {
        // Where the panel's write pointer is, after a stripe just sent: a
        // changed stripe there follows on without setting a window.
        let mut next_row = None;
        for (index, y) in (0..self.fb.height()).step_by(STRIPE_ROWS).enumerate() {
            let len = self.fb.stripe(y, self.stripe);
            let Some(hash) = self.sent.changed(index, &self.stripe[..len]) else {
                continue;
            };
            let continues = next_row == Some(y);
            if let Err(error) = self.panel.stripe(y, &self.stripe[..len], continues).await {
                // A failed transfer may have written part of the stripe. Even
                // a later frame matching old history must repair those pixels.
                self.sent.forget();
                return Err(error);
            }
            self.sent.sent(index, hash);
            next_row = Some(y + STRIPE_ROWS);
            embassy_futures::yield_now().await;
        }
        Ok(())
    }
    pub async fn set_brightness(&mut self, brightness: Brightness) {
        self.brightness = brightness.step();
        if self.on {
            self.backlight.set(self.brightness).await;
        }
    }
    /// Asleep, once off, until [`init`](Self::init).
    pub async fn sleep(&mut self) -> Result<(), Error<S::Error>> {
        self.panel.sleep().await
    }
    /// The panel and its backlight on or off together, the backlight dark
    /// whenever the panel is.
    pub async fn set_on(&mut self, on: bool) -> Result<(), Error<S::Error>> {
        if !on {
            self.backlight.set(0).await;
        }
        self.panel.on(on).await?;
        self.on = on;
        if on {
            self.backlight.set(self.brightness).await;
        }
        Ok(())
    }
}
