//! SSD1306 OLED bring-up (128×64, I²C on SDA=GPIO4 / SCL=GPIO15,
//! reset on GPIO16, address 0x3C, powered from `Vext`).
//!
//! The controller is only usable after the full power-up sequence from
//! hardware doc §5.3: `Vext` up (see [`crate::vext::Vext`]) → reset
//! pulse → controller init. Because the panel supply is `Vext`, every
//! `Vext` power cycle invalidates the controller state — callers must
//! repeat [`reset`] plus the driver's `init()` after re-enabling the
//! rail, not just resume drawing.
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
// need its own ssd1306 dependency just to call it. `Brightness` rides
// along for the same reason — the display-attention policy dims the
// panel before switching it off.
pub use ssd1306::mode::DisplayConfigAsync;
pub use ssd1306::prelude::Brightness;

/// The two ends of the ramp, as raw contrast. The ssd1306 crate keeps
/// these behind preset constants, so they are restated here to be
/// interpolated between.
///
/// The dim end is the bottom of the register, well below the crate's own
/// `Brightness::DIM` (0x2F). This panel needs it: measured against the
/// hardware, an SSD1306 at the 0x07 the SH1106 boards dim to is still
/// bright enough that the warning does not read as one. Contrast 0 is not
/// off — the panel stays faintly legible, which is the whole point of the
/// dim state. `CONTRAST_NORMAL` is the crate's `Brightness::NORMAL`, so
/// the lit end is exactly where it has always been.
const CONTRAST_DIM: u8 = 0x00;
const CONTRAST_NORMAL: u8 = 0x5F;
/// Precharge period, the controller's other brightness lever and the only
/// one left once contrast is on the floor. The crate's own `DIMMEST`
/// preset pairs the short period with contrast 0, so the bottom of this
/// ramp does too; every step above it keeps the period the lit presets
/// use, which leaves contrast the only thing moving across the fade.
const PRECHARGE_DIM: u8 = 0x1;
const PRECHARGE_NORMAL: u8 = 0x2;

/// A point on the way from the dim floor to full brightness, given a
/// permille of the gap — what the display-attention policy's
/// `brightness_permille` hands back while the panel is falling into its
/// dim state. Present under this name on every board in the ESP32
/// workspace, so the shared display task never learns which panel it has.
///
/// The presets are a five-step ladder, which is too coarse to read as a
/// fade; `Brightness::custom` reaches the controller's whole 8-bit
/// contrast range.
pub const fn brightness_from_permille(permille: u16) -> Brightness {
    let span = (CONTRAST_NORMAL - CONTRAST_DIM) as u32;
    let permille = if permille > 1_000 { 1_000 } else { permille };
    let precharge = if permille == 0 {
        PRECHARGE_DIM
    } else {
        PRECHARGE_NORMAL
    };
    Brightness::custom(
        precharge,
        CONTRAST_DIM + (span * permille as u32 / 1_000) as u8,
    )
}

/// The concrete driver type for this board's OLED.
pub type Display = Ssd1306Async<
    I2CInterface<I2c<'static, Async>>,
    DisplaySize128x64,
    BufferedGraphicsModeAsync<DisplaySize128x64>,
>;

/// Wrap an already-configured I²C bus (400 kHz, SDA=4, SCL=15) in the
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

/// Hardware-reset pulse on GPIO16 (hardware doc §5.3 steps 2–5).
/// `Vext` must already be enabled and settled; follow with the driver's
/// `init()`.
pub async fn reset(reset: &mut Output<'static>) {
    reset.set_low();
    Timer::after_millis(10).await;
    reset.set_high();
    Timer::after_millis(20).await;
}
