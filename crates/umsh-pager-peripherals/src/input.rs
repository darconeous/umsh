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

pub const KEYBOARD_ADDRESS: u8 = 0x34;
/// Backspace is row 2, column 9; TCA8418 FIFO key numbers start at one.
pub const BACKSPACE_EVENT: u8 = 30;

/// Matrix positions, row times ten plus column, of the keys that do not
/// type a letter.
const ENTER: u8 = 19;
const SYM: u8 = 20;
const CAP: u8 = 28;
const BACKSPACE: u8 = BACKSPACE_EVENT - 1;
const SPACE: u8 = 30;

/// What the first three rows type, and with Alt (the orange key, Sym on
/// the matrix). Zero is a key that types nothing on that layer. The fourth
/// row is the space bar alone.
const LETTERS: [&[u8; 10]; 3] = [b"qwertyuiop", b"asdfghjkl\0", b"\0zxcvbnm\0\0"];
const SYMBOLS: [&[u8; 10]; 3] = [b"1234567890", b"*/+-=:'\"@\0", b"\0_$;?!,.\0\0"];

/// What the key that types `letter` types under Alt, if it has a second
/// legend.
#[must_use]
pub fn alt_legend(letter: char) -> Option<char> {
    let letter = u8::try_from(letter.to_ascii_lowercase()).ok()?;
    LETTERS.iter().zip(SYMBOLS).find_map(|(letters, symbols)| {
        let column = letters.iter().position(|&l| l == letter && l != 0)?;
        (symbols[column] != 0).then(|| char::from(symbols[column]))
    })
}

/// The keyboard's modifier keys: Shift is CAP, and Alt the orange key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modifier {
    Shift,
    Alt,
}

/// What happened on the keyboard. Keys are reported as they are, not as
/// what they type: what the modifiers make of them is for the interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    BackPress,
    BackRelease,
    Enter,
    /// A key that types `plain`, and `alt` under Alt, went down.
    Key {
        plain: char,
        alt: Option<char>,
    },
    Space,
    /// A modifier went down, or up.
    Modifier {
        modifier: Modifier,
        down: bool,
    },
    /// A key other than a modifier or Backspace went up.
    Release,
    Other,
    Overflow,
}

pub struct Keyboard<I> {
    i2c: I,
    down: u64,
}
impl<I: I2c> Keyboard<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c, down: 0 }
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
        self.down = 0;
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
        let key = event & 0x7f;
        // The Pager configures a 4 x 10 matrix. Other FIFO codes are not keys.
        if !(1..=40).contains(&key) {
            return KeyEvent::Other;
        }
        let pressed = event & 0x80 != 0;
        let mask = 1u64 << key;
        if pressed == (self.down & mask != 0) {
            return KeyEvent::Other;
        }
        if pressed {
            self.down |= mask;
        } else {
            self.down &= !mask;
        }
        let position = key - 1;
        let modifier = match position {
            SYM => Some(Modifier::Alt),
            CAP => Some(Modifier::Shift),
            _ => None,
        };
        if let Some(modifier) = modifier {
            return KeyEvent::Modifier {
                modifier,
                down: pressed,
            };
        }
        if !pressed {
            return if key == BACKSPACE_EVENT {
                KeyEvent::BackRelease
            } else {
                KeyEvent::Release
            };
        }
        match position {
            BACKSPACE => return KeyEvent::BackPress,
            ENTER => return KeyEvent::Enter,
            SPACE => return KeyEvent::Space,
            _ => {}
        }
        let (row, column) = (usize::from(position / 10), usize::from(position % 10));
        let Some(letters) = LETTERS.get(row) else {
            return KeyEvent::Other;
        };
        match (letters[column], SYMBOLS[row][column]) {
            (0, _) => KeyEvent::Other,
            (plain, alt) => KeyEvent::Key {
                plain: char::from(plain),
                alt: (alt != 0).then(|| char::from(alt)),
            },
        }
    }
}
