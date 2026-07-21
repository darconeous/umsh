//! SSD1306 OLED bring-up (128×64, I²C on SDA=GPIO17 / SCL=GPIO18,
//! reset on GPIO21, address 0x3C, powered from `Vext`).
//!
//! The controller is only usable after the full power-up sequence from
//! hardware doc §5.3: `Vext` up (see [`crate::vext::Vext`]) → reset
//! pulse → controller init. Because the panel supply is `Vext`, every
//! `Vext` power cycle invalidates the controller state — callers must
//! repeat [`reset`] plus the driver's `init()` after re-enabling the
//! rail, not just resume drawing (§5.4).
//!
//! UI code draws through `embedded-graphics` on the buffered-graphics
//! mode of the `ssd1306` driver; there is no board-specific display
//! abstraction on top.

use embassy_time::Timer;
use esp_hal::Async;
use esp_hal::gpio::Output;
use esp_hal::i2c::master::I2c;
use ssd1306::mode::BufferedGraphicsModeAsync;
use ssd1306::prelude::*;
use ssd1306::{I2CDisplayInterface, Ssd1306Async};

// The trait carrying `Display::init()`; re-exported so firmware doesn't
// need its own ssd1306 dependency just to call it.
pub use ssd1306::mode::DisplayConfigAsync;

/// The concrete driver type for this board's OLED.
pub type Display = Ssd1306Async<
    I2CInterface<I2c<'static, Async>>,
    DisplaySize128x64,
    BufferedGraphicsModeAsync<DisplaySize128x64>,
>;

/// Wrap an already-configured I²C bus (400 kHz, SDA=17, SCL=18) in the
/// SSD1306 driver at the board's fixed address, in buffered-graphics
/// mode. The controller is NOT initialized yet: run [`reset`] and then
/// `Display::init()` with `Vext` up.
pub fn new_display(i2c: I2c<'static, Async>) -> Display {
    Ssd1306Async::new(
        I2CDisplayInterface::new(i2c),
        DisplaySize128x64,
        DisplayRotation::Rotate0,
    )
    .into_buffered_graphics_mode()
}

/// Hardware-reset pulse on GPIO21 (hardware doc §5.3 steps 3–5).
/// `Vext` must already be enabled and settled; follow with the driver's
/// `init()`.
pub async fn reset(reset: &mut Output<'static>) {
    reset.set_low();
    Timer::after_millis(10).await;
    reset.set_high();
    Timer::after_millis(20).await;
}
