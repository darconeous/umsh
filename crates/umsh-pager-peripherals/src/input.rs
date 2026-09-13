//! Quadrature policy and TCA8418 key events. Quadrature `transition` is
//! called from the GPIO interrupt handler on BOTH edges of BOTH inputs.
use embedded_hal_async::i2c::I2c;

/// Full-step decoder: a detent is a complete cycle back to both inputs high.
/// Partial reversals cancel; a two-bit jump invalidates the current cycle.
pub struct Quadrature {
    previous: u8,
    quarters: i8,
    synchronized: bool,
}
impl Quadrature {
    pub const fn new(ab: u8) -> Self {
        Self {
            previous: ab & 3,
            quarters: 0,
            synchronized: ab & 3 == 3,
        }
    }
    #[inline(always)]
    pub fn transition(&mut self, ab: u8) -> i8 {
        let ab = ab & 3;
        let old = self.previous;
        self.previous = ab;
        if old ^ ab == 3 {
            self.quarters = 0;
            self.synchronized = false;
        } else if self.synchronized {
            self.quarters += match (old, ab) {
                (3, 1) | (1, 0) | (0, 2) | (2, 3) => 1,
                (3, 2) | (2, 0) | (0, 1) | (1, 3) => -1,
                _ => 0,
            };
        }
        if ab != 3 {
            return 0;
        }
        let step = if self.synchronized {
            match self.quarters {
                4 => 1,
                -4 => -1,
                _ => 0,
            }
        } else {
            0
        };
        self.quarters = 0;
        self.synchronized = true;
        step
    }
}

/// Stable-level debounce for the push button, distinct from quadrature.
pub struct Debounce {
    stable: bool,
    observed: bool,
    since: u64,
}
impl Debounce {
    pub const fn new(pressed: bool) -> Self {
        Self {
            stable: pressed,
            observed: pressed,
            since: 0,
        }
    }
    pub fn sample(&mut self, pressed: bool, now_ms: u64) -> Option<bool> {
        if pressed != self.observed {
            self.observed = pressed;
            self.since = now_ms;
        }
        if self.observed != self.stable && now_ms.saturating_sub(self.since) >= 15 {
            self.stable = self.observed;
            Some(self.stable)
        } else {
            None
        }
    }
}

pub const KEYBOARD_ADDRESS: u8 = 0x34;
/// Backspace is row 2, column 9; TCA8418 FIFO key numbers start at one.
pub const BACKSPACE_EVENT: u8 = 30;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    BackPress,
    BackRelease,
    Other,
    Overflow,
}

pub struct Keyboard<I> {
    i2c: I,
    back_down: bool,
}
impl<I: I2c> Keyboard<I> {
    pub fn new(i2c: I) -> Self {
        Self {
            i2c,
            back_down: false,
        }
    }
    pub async fn init(&mut self) -> Result<(), I::Error> {
        // No auto-increment required: every register is addressed explicitly.
        self.i2c.write(KEYBOARD_ADDRESS, &[0x01, 0]).await?;
        for (reg, value) in [
            (0x1d, 0x0f),
            (0x1e, 0xff),
            (0x1f, 3),
            (0x29, 0),
            (0x2a, 0),
            (0x2b, 0),
            (0x2c, 0),
            (0x2d, 0),
            (0x2e, 0),
        ] {
            self.i2c.write(KEYBOARD_ADDRESS, &[reg, value]).await?;
        }
        self.flush().await?;
        // Key event and FIFO overflow interrupts; discard new entries on overflow.
        self.i2c.write(KEYBOARD_ADDRESS, &[0x01, 0x09]).await
    }
    pub async fn flush(&mut self) -> Result<(), I::Error> {
        // FIFO is ten entries deep. Bound recovery even if keys keep arriving.
        for _ in 0..10 {
            let _ = crate::read(&mut self.i2c, KEYBOARD_ADDRESS, 4).await?;
        }
        self.back_down = false;
        self.i2c.write(KEYBOARD_ADDRESS, &[2, 0x1f]).await
    }
    pub async fn next(&mut self) -> Result<Option<KeyEvent>, I::Error> {
        let status = crate::read(&mut self.i2c, KEYBOARD_ADDRESS, 2).await?;
        if status & 8 != 0 {
            self.flush().await?;
            return Ok(Some(KeyEvent::Overflow));
        }
        let event = crate::read(&mut self.i2c, KEYBOARD_ADDRESS, 4).await?;
        if event == 0 {
            self.i2c.write(KEYBOARD_ADDRESS, &[2, 1]).await?;
            // Check after acknowledging, so an arrival racing the clear isn't lost.
            if crate::read(&mut self.i2c, KEYBOARD_ADDRESS, 3).await? & 0x0f != 0 {
                return Ok(Some(KeyEvent::Other));
            }
            return Ok(None);
        }
        Ok(Some(self.decode(event)))
    }
    pub fn decode(&mut self, event: u8) -> KeyEvent {
        if event & 0x7f != BACKSPACE_EVENT {
            return KeyEvent::Other;
        }
        let pressed = event & 0x80 != 0;
        if pressed == self.back_down {
            return KeyEvent::Other;
        }
        self.back_down = pressed;
        if pressed {
            KeyEvent::BackPress
        } else {
            KeyEvent::BackRelease
        }
    }
}
