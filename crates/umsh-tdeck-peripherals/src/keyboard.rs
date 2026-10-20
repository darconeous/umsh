//! The keyboard's ESP32-C3 at [`ADDRESS`], in its stock key mode (§8.4):
//! a one-byte read gives the last key pressed, or 0. There are no
//! releases, no modifiers, and no repeat.

/// The C3's I²C target address.
pub const ADDRESS: u8 = 0x55;

/// What one key-mode byte means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Character(char),
    Space,
    Enter,
    Backspace,
    /// Alt+C, the only Alt chord the C3 reports.
    AltC,
}

/// The key behind `byte`, if it is one. Shift subtracts 32 from whatever
/// the key would have sent, so Shift on a symbol gives a control code;
/// those are taken back to the symbol, except where the code is one the
/// C3 sends for a key of its own.
#[must_use]
pub fn key(byte: u8) -> Option<Key> {
    Some(match byte {
        0x08 => Key::Backspace,
        0x0c => Key::AltC,
        0x0d => Key::Enter,
        b' ' => Key::Space,
        0x21..=0x7e => Key::Character(char::from(byte)),
        // Shift held on a symbol: `$` comes as 0x04, `1` as 0x11.
        0x01..=0x1f => Key::Character(char::from(byte + 32)),
        _ => return None,
    })
}

/// Sets the key backlight's duty, 0 (off) to 255, on C3 firmware from
/// 2024-12-25; earlier firmware ignores it.
#[must_use]
pub const fn backlight(duty: u8) -> [u8; 2] {
    [0x01, duty]
}
