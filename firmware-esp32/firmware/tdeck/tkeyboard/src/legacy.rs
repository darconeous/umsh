//! Key mode: characters queued for the host, and the modifier state the
//! status byte reports.
//!
//! Stock firmware's bytes are kept where a host can use them: the legends,
//! Enter `0D`, Backspace `08`, Alt+C `0C`, and Shift+`$` `04` (the speaker
//! key, a natural mute). Shift otherwise changes letters only, and Sym on a
//! key with no Sym legend sends the base one. Sym and Shift never combine:
//! the one pressed last decides.
//!
//! Sym and Shift latch as well, one state at a time ([`Latch`]): one press
//! applies to the next key, a second within [`DOUBLE_TAP_MS`] locks it on,
//! and the press after that, or a late second, lets it go. Pressing the
//! other modifier replaces the state with its own.

use crate::keymap;
use crate::matrix::{Key, Snapshot};

/// The longest gap between a modifier's presses that locks it.
pub const DOUBLE_TAP_MS: u64 = 500;
/// Characters held for the host. One typed into a full queue is dropped.
pub const QUEUE_LEN: usize = 16;

/// Status bits 0–2.
pub const STATUS_LATCH: u8 = 0b111;
pub const STATUS_BACKLIGHT: u8 = 1 << 3;
pub const STATUS_LEFT_SHIFT: u8 = 1 << 4;
pub const STATUS_RIGHT_SHIFT: u8 = 1 << 5;
pub const STATUS_ALT: u8 = 1 << 6;
/// The character beside it is a key's auto-repeat. Never set yet.
pub const STATUS_REPEAT: u8 = 1 << 7;

/// The latching modifier state, apart from what is held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Latch {
    #[default]
    None,
    /// Shift for the next key, since the press at this time.
    ShiftNext(u64),
    /// Sym for the next key, since the press at this time.
    SymNext(u64),
    CapsLock,
    SymLock,
}

impl Latch {
    /// The status byte's bits 0–2. 3 is reserved for Alt next, 6 and 7
    /// for later.
    pub const fn code(self) -> u8 {
        match self {
            Latch::None => 0,
            Latch::ShiftNext(_) => 1,
            Latch::SymNext(_) => 2,
            Latch::CapsLock => 4,
            Latch::SymLock => 5,
        }
    }

    fn press(&mut self, modifier: Modifier, at_ms: u64) {
        let quick = |since: u64| at_ms.saturating_sub(since) <= DOUBLE_TAP_MS;
        *self = match (*self, modifier) {
            (Latch::ShiftNext(since), Modifier::Shift) if quick(since) => Latch::CapsLock,
            (Latch::SymNext(since), Modifier::Sym) if quick(since) => Latch::SymLock,
            (Latch::ShiftNext(_) | Latch::CapsLock, Modifier::Shift)
            | (Latch::SymNext(_) | Latch::SymLock, Modifier::Sym) => Latch::None,
            (_, Modifier::Shift) => Latch::ShiftNext(at_ms),
            (_, Modifier::Sym) => Latch::SymNext(at_ms),
        };
    }

    fn layer(self) -> Layer {
        match self {
            Latch::None => Layer::Base,
            Latch::ShiftNext(_) => Layer::Shift,
            Latch::SymNext(_) | Latch::SymLock => Layer::Sym,
            Latch::CapsLock => Layer::Caps,
        }
    }

    fn use_up(&mut self) {
        if let Latch::ShiftNext(_) | Latch::SymNext(_) = self {
            *self = Latch::None;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Modifier {
    Shift,
    Sym,
}

/// How a key is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layer {
    Base,
    Shift,
    /// Shift, for letters alone.
    Caps,
    Sym,
}

/// What `key` sends on `layer`, or 0 for nothing.
fn encode(key: Key, layer: Layer) -> u8 {
    let (base, symbol) = (keymap::base(key), keymap::symbol(key));
    match layer {
        Layer::Sym if symbol != 0 => symbol,
        Layer::Shift if key == keymap::DOLLAR => 0x04,
        Layer::Shift | Layer::Caps => base.to_ascii_uppercase(),
        Layer::Base | Layer::Sym => base,
    }
}

/// A queued character.
#[derive(Clone, Copy, Debug, Default)]
struct Typed {
    byte: u8,
    /// For [`STATUS_REPEAT`], once keys repeat.
    repeat: bool,
}

#[derive(Clone, Debug, Default)]
pub struct LegacyEncoder {
    queue: [Typed; QUEUE_LEN],
    head: usize,
    len: usize,
    latch: Latch,
    /// Of Sym and Shift, the one pressed last.
    last: Option<Modifier>,
}

impl LegacyEncoder {
    pub const fn new() -> Self {
        Self {
            queue: [Typed {
                byte: 0,
                repeat: false,
            }; QUEUE_LEN],
            head: 0,
            len: 0,
            latch: Latch::None,
            last: None,
        }
    }

    /// Encodes the change from `before` to `now`, scanned at `at_ms`.
    /// Returns whether Alt+B was pressed, which toggles the key light.
    pub fn on_scan(&mut self, before: &Snapshot, now: &Snapshot, at_ms: u64) -> bool {
        let pressed = now.pressed_since(before);
        let held = |key| now.is_down(key);
        let shift_held = held(keymap::LEFT_SHIFT) || held(keymap::RIGHT_SHIFT);
        if pressed.is_down(keymap::SYM) {
            self.press(Modifier::Sym, at_ms);
        }
        if pressed.is_down(keymap::LEFT_SHIFT) || pressed.is_down(keymap::RIGHT_SHIFT) {
            self.press(Modifier::Shift, at_ms);
        }
        let layer = match (held(keymap::SYM), shift_held) {
            (false, false) => self.latch.layer(),
            (true, false) => Layer::Sym,
            (false, true) => Layer::Shift,
            (true, true) if self.last == Some(Modifier::Sym) => Layer::Sym,
            (true, true) => Layer::Shift,
        };
        let alt = held(keymap::ALT);
        let toggle = alt && pressed.is_down(keymap::B);
        let mut typed = false;
        for key in Key::all().filter(|&key| pressed.is_down(key)) {
            if keymap::is_modifier(key) {
                continue;
            }
            typed = true;
            if !(alt && (key == keymap::B || key == keymap::C)) {
                self.push(encode(key, layer));
            }
        }
        if pressed.is_down(keymap::ENTER) {
            self.push(0x0d);
        }
        if pressed.is_down(keymap::BACKSPACE) {
            self.push(0x08);
        }
        if alt && pressed.is_down(keymap::C) {
            self.push(0x0c);
        }
        if typed {
            self.latch.use_up();
        }
        toggle
    }

    fn press(&mut self, modifier: Modifier, at_ms: u64) {
        self.latch.press(modifier, at_ms);
        self.last = Some(modifier);
    }

    fn push(&mut self, byte: u8) {
        if byte != 0 && self.len < QUEUE_LEN {
            self.queue[(self.head + self.len) % QUEUE_LEN] = Typed {
                byte,
                repeat: false,
            };
            self.len += 1;
        }
    }

    /// The oldest character, which a key-mode read takes, or 0 for none,
    /// with whether it is a repeat.
    pub fn take(&mut self) -> (u8, bool) {
        if self.len == 0 {
            return (0, false);
        }
        let typed = self.queue[self.head];
        self.head = (self.head + 1) % QUEUE_LEN;
        self.len -= 1;
        (typed.byte, typed.repeat)
    }

    pub fn latch(&self) -> Latch {
        self.latch
    }
}
