//! The key light as the stock firmware runs it: a duty the host sets, and
//! a second duty that Alt+B uses when the host's is 0, so Alt+B can always
//! turn the light on.

/// The duty at power-on: off.
const BOOT_DUTY: u8 = 0;
/// Alt+B's duty until a host sets another.
const ALT_B_DEFAULT: u8 = 127;
/// Alt+B duties at or below this are refused, so it never turns the light
/// "on" too dimly to see.
const ALT_B_FLOOR: u8 = 30;

#[derive(Clone, Debug)]
pub struct Backlight {
    /// The host's duty.
    duty: u8,
    /// Alt+B's duty, used when `duty` is 0.
    alt_b: u8,
    lit: bool,
    /// The duty the light is at.
    output: u8,
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
        }
    }

    pub fn set(&mut self, duty: u8) {
        self.duty = duty;
        self.output = duty;
        self.lit = duty > 0;
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
    }

    /// Whether the light is on, as Alt+B and the host last left it.
    pub fn is_lit(&self) -> bool {
        self.lit
    }

    /// The duty to drive, 0 (off) to 255 (fully on).
    pub fn output(&self) -> u8 {
        self.output
    }
}
