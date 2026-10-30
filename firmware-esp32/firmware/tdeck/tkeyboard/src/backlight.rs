//! The key light as the stock firmware runs it: a duty the host sets, and
//! a second duty that Alt+B uses when the host's is 0, so Alt+B can always
//! turn the light on.
//!
//! Unlike stock, the light is kept dark through a sleep and for
//! [`RESTORE_MS`] after it, so a host waking the keyboard can set the
//! light first. The light fades to each new duty, along a [`Fade`].

/// The duty at power-on: off.
const BOOT_DUTY: u8 = 0;
/// Alt+B's duty until a host sets another.
const ALT_B_DEFAULT: u8 = 127;
/// Alt+B duties at or below this are refused, so it never turns the light
/// "on" too dimly to see.
const ALT_B_FLOOR: u8 = 30;
/// How long after waking the light stays dark unless the host sets it.
pub const RESTORE_MS: u64 = 100;
/// How long every fade takes, however far it goes.
pub const FADE_MS: u64 = 250;

/// Why the light is kept dark whatever its duty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    None,
    Asleep,
    /// Awake for less than [`RESTORE_MS`].
    Waking,
}

#[derive(Clone, Debug)]
pub struct Backlight {
    /// The host's duty.
    duty: u8,
    /// Alt+B's duty, used when `duty` is 0.
    alt_b: u8,
    lit: bool,
    /// The duty the light is at, held or not.
    output: u8,
    hold: Hold,
}

impl Default for Backlight {
    fn default() -> Self {
        Self::new()
    }
}

impl Backlight {
    pub const fn new() -> Self {
        Self {
            duty: BOOT_DUTY,
            alt_b: ALT_B_DEFAULT,
            lit: false,
            output: BOOT_DUTY,
            hold: Hold::None,
        }
    }

    pub fn set(&mut self, duty: u8) {
        self.duty = duty;
        self.output = duty;
        self.lit = duty > 0;
        self.hold = Hold::None;
    }

    pub fn set_alt_b(&mut self, duty: u8) {
        if duty > ALT_B_FLOOR {
            self.alt_b = duty;
        }
    }

    /// Alt+B.
    pub fn toggle(&mut self) {
        self.lit = !self.lit;
        self.output = match (self.lit, self.duty) {
            (false, _) => 0,
            (true, 0) => self.alt_b,
            (true, duty) => duty,
        };
        self.hold = Hold::None;
    }

    /// The keyboard is going to sleep: the light goes dark until
    /// [`restore`](Self::restore) or a new duty.
    pub fn sleep(&mut self) {
        self.hold = Hold::Asleep;
    }

    /// The keyboard woke from sleep.
    pub fn woke(&mut self) {
        if self.hold == Hold::Asleep {
            self.hold = Hold::Waking;
        }
    }

    /// [`RESTORE_MS`] after waking: the light comes back as it was, unless
    /// it has been set since, or the keyboard has gone back to sleep.
    pub fn restore(&mut self) {
        if self.hold == Hold::Waking {
            self.hold = Hold::None;
        }
    }

    /// Whether the light is on, as Alt+B and the host last left it.
    pub fn is_lit(&self) -> bool {
        self.lit
    }

    /// The duty to drive, 0 (off) to 255 (fully on).
    pub fn output(&self) -> u8 {
        match self.hold {
            Hold::None => self.output,
            Hold::Asleep | Hold::Waking => 0,
        }
    }
}

/// A change of duty spread over [`FADE_MS`]. It moves evenly in the duty's
/// square root, roughly perceived brightness, so a fade does not rush
/// through the dim end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fade {
    from: u8,
    to: u8,
    start_ms: u64,
}

impl Fade {
    /// A fade from `from` to `to`, starting at `start_ms`.
    pub const fn new(from: u8, to: u8, start_ms: u64) -> Self {
        Self { from, to, start_ms }
    }

    /// The duty at `at_ms`.
    pub fn level(&self, at_ms: u64) -> u8 {
        let elapsed = at_ms.saturating_sub(self.start_ms);
        if elapsed >= FADE_MS {
            return self.to;
        }
        let [from, to] = [self.from, self.to].map(|duty| i64::from(root(duty)));
        let at = (from + (to - from) * elapsed as i64 / FADE_MS as i64) as u32;
        // Squared back, rounded: the error in a root is under one part in
        // 256 of a duty step, so `from` and `to` come back exactly.
        ((at * at + (1 << 15)) >> 16) as u8
    }

    /// Whether the fade has arrived by `at_ms`.
    pub fn done(&self, at_ms: u64) -> bool {
        at_ms.saturating_sub(self.start_ms) >= FADE_MS
    }
}

/// A duty's square root, in 1/256ths: `floor(sqrt(duty) * 256)`.
fn root(duty: u8) -> u32 {
    let square = u32::from(duty) << 16;
    let mut root = 0;
    // From the highest bit a root of a 24-bit square can have.
    let mut bit = 1 << 11;
    while bit > 0 {
        let tried = root | bit;
        if tried * tried <= square {
            root = tried;
        }
        bit >>= 1;
    }
    root
}
