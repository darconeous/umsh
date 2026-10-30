//! Everything the keyboard does, behind three inputs (a debounced scan, a
//! host write, a host read) and one output (the key light's duty).

use crate::backlight::Backlight;
use crate::keymap;
use crate::legacy::{self, LegacyEncoder};
use crate::matrix::{COLS, Snapshot};
use crate::protocol::{self, Command};

/// The longest reply a read can return.
pub const MAX_REPLY: usize = protocol::IDENTIFY_LEN;
const _: () = assert!(MAX_REPLY >= COLS);

/// What a plain read returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The last key pressed, as one byte.
    Key,
    /// The matrix, one byte per column.
    Raw,
}

/// What the host wants of the keyboard's I²C target after a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Power {
    /// Keep answering.
    Awake,
    /// Stop answering until the bus is next used.
    Sleep,
}

pub struct Controller {
    mode: Mode,
    keys: Snapshot,
    legacy: LegacyEncoder,
    backlight: Backlight,
    /// A reply a command asked for, which the next read returns in place
    /// of the mode's.
    latched: Option<[u8; protocol::IDENTIFY_LEN]>,
}

impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}

impl Controller {
    pub const fn new() -> Self {
        Self {
            mode: Mode::Key,
            keys: Snapshot::EMPTY,
            legacy: LegacyEncoder::new(),
            backlight: Backlight::new(),
            latched: None,
        }
    }

    /// Takes a debounced state of the matrix, scanned `at_ms` milliseconds
    /// after any fixed point, such as boot.
    pub fn on_scan(&mut self, now: Snapshot, at_ms: u64) {
        let before = core::mem::replace(&mut self.keys, now);
        if before != now {
            self.route(&before, &now, at_ms);
        }
    }

    /// Where key changes go. Today that is always the host-facing
    /// encoding; this is the one place to send them elsewhere instead.
    fn route(&mut self, before: &Snapshot, now: &Snapshot, at_ms: u64) {
        if self.legacy.on_scan(before, now, at_ms) {
            self.backlight.toggle();
        }
    }

    /// Takes one write from the host, and says whether the host is done
    /// with the keyboard until it next uses the bus.
    pub fn on_write(&mut self, bytes: &[u8]) -> Power {
        let mut power = Power::Awake;
        for command in protocol::commands(bytes) {
            match command {
                Command::Backlight(duty) => self.backlight.set(duty),
                Command::AltBBacklight(duty) => self.backlight.set_alt_b(duty),
                Command::ModeRaw => self.mode = Mode::Raw,
                Command::ModeKey => self.mode = Mode::Key,
                Command::Sleep => power = Power::Sleep,
                Command::Identify => self.latched = Some(protocol::identify_reply()),
            }
        }
        power
    }

    /// Writes what a host read returns into `reply` and gives its length.
    pub fn on_read(&mut self, reply: &mut [u8; MAX_REPLY]) -> usize {
        if let Some(latched) = self.latched.take() {
            reply[..latched.len()].copy_from_slice(&latched);
            return latched.len();
        }
        match self.mode {
            // A stock host reads the character alone. The rest are 0 for
            // fields to come.
            Mode::Key => {
                let (byte, repeat) = self.legacy.take();
                reply.fill(0);
                reply[0] = byte;
                reply[1] = self.status();
                if repeat && byte != 0 {
                    reply[1] |= legacy::STATUS_REPEAT;
                }
                MAX_REPLY
            }
            Mode::Raw => {
                reply[..COLS].copy_from_slice(&self.keys.0);
                COLS
            }
        }
    }

    /// Key mode's second byte, without the repeat bit: the latch, the
    /// light, and the modifiers held now.
    fn status(&self) -> u8 {
        let mut status = self.legacy.latch().code();
        for (on, bit) in [
            (self.backlight.is_lit(), legacy::STATUS_BACKLIGHT),
            (
                self.keys.is_down(keymap::LEFT_SHIFT),
                legacy::STATUS_LEFT_SHIFT,
            ),
            (
                self.keys.is_down(keymap::RIGHT_SHIFT),
                legacy::STATUS_RIGHT_SHIFT,
            ),
            (self.keys.is_down(keymap::ALT), legacy::STATUS_ALT),
        ] {
            if on {
                status |= bit;
            }
        }
        status
    }

    /// The key light's duty, 0 (off) to 255 (fully on).
    pub fn backlight(&self) -> u8 {
        self.backlight.output()
    }
}
