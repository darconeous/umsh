//! The keys' legends and the modifier positions, as the stock firmware
//! has them. A legend of 0 is no legend.

use crate::matrix::{COLS, Key, ROWS};

pub const SYM: Key = Key::new(0, 2);
pub const ALT: Key = Key::new(0, 4);
pub const SPACE: Key = Key::new(0, 5);
pub const MIC: Key = Key::new(0, 6);
pub const LEFT_SHIFT: Key = Key::new(1, 6);
pub const RIGHT_SHIFT: Key = Key::new(2, 3);
pub const ENTER: Key = Key::new(3, 3);
pub const BACKSPACE: Key = Key::new(4, 3);
/// Alt+B toggles the key light.
pub const B: Key = Key::new(3, 4);
/// Alt+C sends 0x0C.
pub const C: Key = Key::new(2, 5);
/// The speaker key. Shift+`$` sends 0x04.
pub const DOLLAR: Key = Key::new(4, 4);

/// Sym, Alt, and the Shifts, which send nothing alone.
pub fn is_modifier(key: Key) -> bool {
    [SYM, ALT, LEFT_SHIFT, RIGHT_SHIFT].contains(&key)
}

/// The base layer, by column and then row.
pub const BASE: [[u8; ROWS]; COLS] = [
    [b'q', b'w', 0, b'a', 0, b' ', 0],
    [b'e', b's', b'd', b'p', b'x', b'z', 0],
    [b'r', b'g', b't', 0, b'v', b'c', b'f'],
    [b'u', b'h', b'y', 0, b'b', b'n', b'j'],
    [b'o', b'l', b'i', 0, b'$', b'm', b'k'],
];

/// The Sym layer, by column and then row.
pub const SYMBOL: [[u8; ROWS]; COLS] = [
    [b'#', b'1', 0, b'*', 0, 0, b'0'],
    [b'2', b'4', b'5', b'@', b'8', b'7', 0],
    [b'3', b'/', b'(', 0, b'?', b'9', b'6'],
    [b'_', b':', b')', 0, b'!', b',', b';'],
    [b'+', b'"', b'-', 0, 0, b'.', b'\''],
];

pub const fn base(key: Key) -> u8 {
    BASE[key.col as usize][key.row as usize]
}

pub const fn symbol(key: Key) -> u8 {
    SYMBOL[key.col as usize][key.row as usize]
}
