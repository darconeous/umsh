//! The 5 × 7 key matrix: positions, whole-matrix states, and debouncing.

/// Matrix columns, driven low one at a time to scan.
pub const COLS: usize = 5;
/// Matrix rows, read for each column.
pub const ROWS: usize = 7;

/// One position in the matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub col: u8,
    pub row: u8,
}

impl Key {
    pub const fn new(col: u8, row: u8) -> Self {
        Self { col, row }
    }

    /// Every position, rows outer and columns inner: the order the stock
    /// firmware encodes presses in, so the last of several wins.
    pub fn all() -> impl Iterator<Item = Key> {
        (0..ROWS as u8).flat_map(|row| (0..COLS as u8).map(move |col| Key::new(col, row)))
    }
}

/// Which keys are down: one byte per column, bit *r* set while row *r* is
/// pressed. This is the stock raw-mode report, byte for byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot(pub [u8; COLS]);

impl Snapshot {
    pub const EMPTY: Snapshot = Snapshot([0; COLS]);

    pub const fn is_down(&self, key: Key) -> bool {
        self.0[key.col as usize] & (1 << key.row) != 0
    }

    pub fn set(&mut self, key: Key, down: bool) {
        let bit = 1 << key.row;
        let col = &mut self.0[key.col as usize];
        if down {
            *col |= bit;
        } else {
            *col &= !bit;
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::EMPTY
    }

    /// The keys down here and not in `before`.
    pub fn pressed_since(&self, before: &Snapshot) -> Snapshot {
        Snapshot(core::array::from_fn(|c| self.0[c] & !before.0[c]))
    }
}

impl FromIterator<Key> for Snapshot {
    fn from_iter<I: IntoIterator<Item = Key>>(keys: I) -> Self {
        let mut snapshot = Snapshot::EMPTY;
        for key in keys {
            snapshot.set(key, true);
        }
        snapshot
    }
}

/// Turns raw scans into a debounced state: a key changes once two
/// consecutive scans agree on its new level, so at one scan every few
/// milliseconds a bounce shorter than the scan period never shows.
#[derive(Clone, Debug, Default)]
pub struct Debouncer {
    stable: Snapshot,
    last: Snapshot,
}

impl Debouncer {
    pub const fn new() -> Self {
        Self {
            stable: Snapshot::EMPTY,
            last: Snapshot::EMPTY,
        }
    }

    /// Takes one raw scan and returns the debounced state after it.
    pub fn update(&mut self, raw: Snapshot) -> Snapshot {
        for c in 0..COLS {
            let agreed = !(raw.0[c] ^ self.last.0[c]);
            self.stable.0[c] = (self.stable.0[c] & !agreed) | (raw.0[c] & agreed);
        }
        self.last = raw;
        self.stable
    }

    /// Whether nothing is down and nothing is settling: scanning can stop
    /// until a key is pressed again.
    pub fn is_idle(&self) -> bool {
        self.stable.is_empty() && self.last.is_empty()
    }
}
