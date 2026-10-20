//! AW9364 LED driver, dimmed by counting pulses on its `EN` pin: the
//! panel backlight on the T-LoRa Pager and the T-Deck. There is no PWM;
//! under the datasheet every low shorter than 500 µs is a dimming step,
//! and a low longer than 2.5 ms shuts the driver down.

use embassy_time::Timer;
use esp_hal::gpio::Output;

/// A backlight step, 1 (dimmest) through 16 (full).
#[derive(Clone, Copy)]
pub struct Brightness(u8);
impl Brightness {
    pub const NORMAL: Self = Self(8);
    pub const ALERT: Self = Self(16);
    /// Steps for levels 1 through 10; level 5 is [`Self::NORMAL`].
    const LEVELS: [u8; 10] = [1, 2, 4, 6, 8, 10, 12, 13, 14, 16];
    /// The brightness at `level`, from 1 to 10.
    pub const fn level(level: u8) -> Self {
        let index = match level {
            0 => 0,
            1..=10 => level - 1,
            _ => 9,
        };
        Self(Self::LEVELS[index as usize])
    }
    /// This brightness dimmed to `p` permille of itself, never dark.
    pub const fn dimmed(self, p: u16) -> Self {
        let p = if p > 1000 { 1000 } else { p };
        Self(1 + ((self.0 - 1) as u16 * p / 1000) as u8)
    }
    pub const fn step(self) -> u8 {
        self.0
    }
}
pub const fn brightness_from_permille(p: u16) -> Brightness {
    Brightness(1 + ((if p > 1000 { 1000 } else { p }) * 7 / 1000) as u8)
}

pub struct Aw9364 {
    en: Output<'static>,
    /// The step the driver is at; 0 is shut down.
    step: u8,
}
impl Aw9364 {
    /// Lights the driver at full from whatever state a warm reset left it
    /// in, before async timers run.
    pub fn boot(mut en: Output<'static>) -> Self {
        en.set_low();
        // Shut down even after a warm reset. Async timers are not running
        // yet; this is the only early-boot settling delay.
        esp_hal::delay::Delay::new().delay_millis(3);
        en.set_high();
        Self { en, step: 16 }
    }
    /// Goes to `step`, 0 (off) through 16.
    pub async fn set(&mut self, step: u8) {
        if step == self.step {
            return;
        }
        // The driver starts at step 16, and each further falling/rising
        // pulse steps down one, modulo 16. Hold low to shut down.
        if step == 0 {
            self.en.set_low();
            Timer::after_millis(3).await;
        } else {
            if self.step == 0 {
                self.en.set_high();
                Timer::after_micros(100).await;
                self.step = 16;
            }
            let pulses = (16 + self.step - step) % 16;
            let delay = esp_hal::delay::Delay::new();
            for _ in 0..pulses {
                // A preemption must not stretch the low pulse into a shutdown.
                // Mask interrupts for only this 1 µs pulse, not the train.
                critical_section::with(|_| {
                    self.en.set_low();
                    delay.delay_micros(1);
                    self.en.set_high();
                });
                delay.delay_micros(1);
            }
        }
        self.step = step;
    }
}
