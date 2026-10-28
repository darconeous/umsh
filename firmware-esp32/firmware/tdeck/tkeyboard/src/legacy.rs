//! The stock firmware's key mode: finished bytes, one held at a time.
//!
//! Every quirk is kept, because existing hosts decode them: Shift
//! subtracts 32 from whatever the key would send (so Shift on a symbol
//! gives a control code, and Shift+Space gives 0), a key with a legend on
//! one layer only sends 0 on the other, and Alt+B clears a byte the host
//! has not read yet.

use crate::keymap;
use crate::matrix::{Key, Snapshot};

#[derive(Clone, Debug, Default)]
pub struct LegacyEncoder {
    pending: Option<u8>,
}

impl LegacyEncoder {
    pub const fn new() -> Self {
        Self { pending: None }
    }

    /// Encodes the change from `before` to `now`. Returns whether Alt+B was
    /// pressed, which toggles the key light.
    pub fn on_scan(&mut self, before: &Snapshot, now: &Snapshot) -> bool {
        let pressed = now.pressed_since(before);
        let held = |key| now.is_down(key);
        for key in Key::all().filter(|&key| pressed.is_down(key)) {
            let (base, symbol) = (keymap::base(key), keymap::symbol(key));
            if base == 0 && symbol == 0 {
                continue;
            }
            let mut byte = if held(keymap::SYM) { symbol } else { base };
            if held(keymap::LEFT_SHIFT) || held(keymap::RIGHT_SHIFT) {
                byte = byte.wrapping_sub(32);
            }
            self.pending = Some(byte);
        }
        if pressed.is_down(keymap::ENTER) {
            self.pending = Some(0x0d);
        }
        if pressed.is_down(keymap::BACKSPACE) {
            self.pending = Some(0x08);
        }
        let toggle = held(keymap::ALT) && pressed.is_down(keymap::B);
        if toggle {
            self.pending = None;
        }
        if held(keymap::ALT) && pressed.is_down(keymap::C) {
            self.pending = Some(0x0c);
        }
        toggle
    }

    /// The byte a key-mode read returns, which it consumes.
    pub fn take(&mut self) -> u8 {
        self.pending.take().unwrap_or(0)
    }
}
