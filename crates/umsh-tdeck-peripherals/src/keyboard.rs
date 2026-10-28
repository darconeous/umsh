//! The keyboard's ESP32-C3 at [`ADDRESS`], in its stock key mode (§8.4):
//! a one-byte read gives the last key pressed, or 0. There are no
//! releases, no modifiers, and no repeat.
//!
//! UMSH's own C3 firmware answers [`IDENTIFY`] as well, and may sleep. Its
//! protocol is `docs/tdeck-keyboard-firmware.md`; the constants here are
//! copies of those in its `protocol.rs`.

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

/// Asks UMSH's C3 firmware to identify itself in the next read, of
/// [`IDENTIFY_LEN`] bytes. Stock firmware ignores it, and that read's first
/// byte is then an ordinary key-mode byte.
pub const IDENTIFY: [u8; 1] = [0xa0];
pub const IDENTIFY_LEN: usize = 7;
const IDENTIFY_MAGIC: [u8; 2] = [0xa5, 0x5a];
const CAP_SLEEP: u16 = 1 << 0;

/// Sends the keyboard to sleep until the bus is next used. It must be a
/// write of its own, and only to a keyboard whose [`Identity`] sleeps.
pub const SLEEP: [u8; 1] = [0x50];

/// What UMSH's C3 firmware says of itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub major: u8,
    pub minor: u8,
    pub capabilities: u16,
}

impl Identity {
    /// Whether [`SLEEP`] is understood.
    pub const fn sleeps(&self) -> bool {
        self.capabilities & CAP_SLEEP != 0
    }
}

/// The identity in a read after [`IDENTIFY`], or `None` from stock
/// firmware, whose first byte is then the key it was holding: no key-mode
/// byte is ever 0xA5.
#[must_use]
pub fn identity(reply: &[u8; IDENTIFY_LEN]) -> Option<Identity> {
    if reply[..2] != IDENTIFY_MAGIC || pec(reply) != 0 {
        return None;
    }
    Some(Identity {
        major: reply[2],
        minor: reply[3],
        capabilities: u16::from_be_bytes([reply[4], reply[5]]),
    })
}

/// CRC-8 with the SMBus polynomial; over a reply and its own PEC, 0.
fn pec(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |crc, &byte| {
        (0..8).fold(crc ^ byte, |crc, _| {
            if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            }
        })
    })
}
