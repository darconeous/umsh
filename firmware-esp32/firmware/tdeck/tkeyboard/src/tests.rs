//! [`Controller`] held against the stock firmware, exhaustively where the
//! space allows. Where key mode means to differ from it (Sym and Shift
//! latching, Shift on letters and `$` only, the queue, the status byte),
//! the tests say so.

use std::vec::Vec;

use crate::Controller;
use crate::backlight::{FADE_MS, Fade};
use crate::controller::{MAX_REPLY, Power};
use crate::matrix::{COLS, Debouncer, Key, ROWS, Snapshot};
use crate::protocol::{self, Command};
use crate::{keymap, legacy};

/// LilyGO's `Keyboard_ESP32C3.ino` (2025-06-12), transliterated as
/// literally as Rust allows: the same arrays, the same order, the same
/// `int` and `char` arithmetic. `scan` stands in for `readMatrix()` plus
/// the rest of `loop()`.
struct Stock {
    keys: [[bool; ROWS]; COLS],
    last_value: [[bool; ROWS]; COLS],
    changed_value: [[bool; ROWS]; COLS],
    raw_mode: bool,
    bl_state: bool,
    comdata_flag: bool,
    comdata: i8,
    kb_brightness_duty: u8,
    kb_brightness_setting_duty: u8,
    /// The last `ledcWrite`.
    ledc: u8,
}

impl Stock {
    fn new() -> Self {
        Self {
            keys: Default::default(),
            last_value: Default::default(),
            changed_value: Default::default(),
            raw_mode: false,
            bl_state: false,
            comdata_flag: false,
            comdata: 0,
            kb_brightness_duty: 0,
            kb_brightness_setting_duty: 127,
            ledc: 0,
        }
    }

    fn key_pressed(&self, col: usize, row: usize) -> bool {
        self.changed_value[col][row] && self.keys[col][row]
    }

    fn key_active(&self, col: usize, row: usize) -> bool {
        self.keys[col][row]
    }

    fn is_printable_key(col: usize, row: usize) -> bool {
        keymap::SYMBOL[col][row] != 0 || keymap::BASE[col][row] != 0
    }

    fn read_matrix(&mut self, matrix: &Snapshot) {
        for col in 0..COLS {
            for row in 0..ROWS {
                let button_pressed = matrix.is_down(Key::new(col as u8, row as u8));
                self.keys[col][row] = button_pressed;
                self.changed_value[col][row] = self.last_value[col][row] != button_pressed;
                self.last_value[col][row] = button_pressed;
            }
        }
    }

    fn print_matrix(&mut self) {
        for row in 0..ROWS {
            for col in 0..COLS {
                if self.key_pressed(col, row) && Self::is_printable_key(col, row) {
                    let mut to_print = if self.key_active(0, 2) {
                        keymap::SYMBOL[col][row] as i8
                    } else {
                        keymap::BASE[col][row] as i8
                    };
                    if self.key_active(1, 6) || self.key_active(2, 3) {
                        to_print = (to_print as i32 - 32) as i8;
                    }
                    self.comdata = to_print;
                    self.comdata_flag = true;
                }
            }
        }
    }

    fn scan(&mut self, matrix: &Snapshot) {
        self.read_matrix(matrix);
        self.print_matrix();
        if self.key_pressed(3, 3) {
            self.comdata = 0x0d;
            self.comdata_flag = true;
        }
        if self.key_pressed(4, 3) {
            self.comdata = 0x08;
            self.comdata_flag = true;
        }
        if self.key_active(0, 4) && self.key_pressed(3, 4) {
            if self.bl_state {
                self.bl_state = false;
                self.ledc = 0;
            } else {
                self.bl_state = true;
                if self.kb_brightness_duty == 0 {
                    self.ledc = self.kb_brightness_setting_duty;
                } else {
                    self.ledc = self.kb_brightness_duty;
                }
            }
            self.comdata_flag = false;
        }
        if self.key_active(0, 4) && self.key_pressed(2, 5) {
            self.comdata = 0x0c;
            self.comdata_flag = true;
        }
    }

    fn on_receive(&mut self, write: &[u8]) {
        let mut wire = write.iter();
        // `Wire.read()`: -1 once the write is used up.
        let mut read = || wire.next().map_or(-1, |&b| b as i32);
        loop {
            let cmd = read();
            if cmd < 0 {
                break;
            }
            match cmd {
                0x01 | 0x02 => {
                    if cmd == 0x01 {
                        let duty = read();
                        if duty >= 0 {
                            self.kb_brightness_duty = duty as u8;
                            self.ledc = duty as u8;
                            if duty > 0 {
                                self.bl_state = true;
                            } else if duty == 0 {
                                self.bl_state = false;
                            }
                        }
                    }
                    // `case 0x01` has no `break`.
                    let duty = read();
                    if duty > 30 {
                        self.kb_brightness_setting_duty = duty as u8;
                    }
                }
                0x03 => self.raw_mode = true,
                0x04 => self.raw_mode = false,
                _ => {}
            }
        }
    }

    fn on_request(&mut self) -> Vec<u8> {
        if self.raw_mode {
            (0..COLS)
                .map(|col| {
                    (0..ROWS).fold(0, |val, row| val | (self.last_value[col][row] as u8) << row)
                })
                .collect()
        } else if self.comdata_flag {
            self.comdata_flag = false;
            vec![self.comdata as u8]
        } else {
            vec![0]
        }
    }
}

/// The stock model and ours, fed the same things. A read compares what
/// stock firmware returns, which in key mode is the character alone.
struct Pair {
    stock: Stock,
    ours: Controller,
    /// Milliseconds, a scan period apart.
    ms: u64,
}

impl Pair {
    fn new() -> Self {
        Self {
            stock: Stock::new(),
            ours: Controller::new(),
            ms: 0,
        }
    }

    fn scan(&mut self, keys: &[Key]) {
        let snapshot: Snapshot = keys.iter().copied().collect();
        self.stock.scan(&snapshot);
        self.ms += 5;
        self.ours.on_scan(snapshot, self.ms);
        self.check_backlight();
    }

    fn write(&mut self, bytes: &[u8]) {
        self.stock.on_receive(bytes);
        // Sleep stops the target answering, which no state here shows.
        let _power = self.ours.on_write(bytes);
        self.check_backlight();
    }

    fn read(&mut self) -> Vec<u8> {
        let stock = self.stock.on_request();
        let mut reply = [0; MAX_REPLY];
        let len = self.ours.on_read(&mut reply);
        assert!(len >= stock.len());
        assert_eq!(stock, &reply[..stock.len()]);
        stock
    }

    /// A key-mode read on each, uncompared: stock's byte and ours.
    fn read_key(&mut self) -> (u8, u8) {
        let mut reply = [0; MAX_REPLY];
        self.ours.on_read(&mut reply);
        (self.stock.on_request()[0], reply[0])
    }

    fn check_backlight(&self) {
        assert_eq!(self.stock.ledc, self.ours.backlight());
    }
}

const MODIFIERS: [Key; 4] = [
    keymap::SYM,
    keymap::ALT,
    keymap::LEFT_SHIFT,
    keymap::RIGHT_SHIFT,
];

/// Every combination of the four modifiers.
fn modifier_sets() -> impl Iterator<Item = Vec<Key>> {
    (0..1 << MODIFIERS.len()).map(|mask| {
        MODIFIERS
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, &key)| key)
            .collect()
    })
}

fn with(keys: &[Key], more: &[Key]) -> Vec<Key> {
    keys.iter().chain(more).copied().collect()
}

/// Every key but the modifiers.
fn typed_keys() -> impl Iterator<Item = Key> {
    Key::all().filter(|&key| !keymap::is_modifier(key))
}

/// What `key` sends with `mods` held, pressed in that order, or `None`.
fn expected(mods: &[Key], key: Key) -> Option<u8> {
    let alt = mods.contains(&keymap::ALT);
    if keymap::is_modifier(key) || alt && key == keymap::B {
        return None;
    }
    if alt && key == keymap::C {
        return Some(0x0c);
    }
    if key == keymap::ENTER {
        return Some(0x0d);
    }
    if key == keymap::BACKSPACE {
        return Some(0x08);
    }
    let (base, symbol) = (keymap::base(key), keymap::symbol(key));
    // Of Sym and Shift, the one pressed last.
    let byte = match mods.iter().rev().find(|&&m| m != keymap::ALT) {
        Some(&m) if m == keymap::SYM && symbol != 0 => symbol,
        Some(&m) if m == keymap::SYM => base,
        Some(_) if key == keymap::DOLLAR => 0x04,
        Some(_) => base.to_ascii_uppercase(),
        None => base,
    };
    (byte != 0).then_some(byte)
}

/// Where stock firmware sends something else for `key` under `mods`: Sym
/// with Shift, Shift on anything but a letter or `$`, and Sym on a key
/// with no Sym legend.
fn differs_from_stock(mods: &[Key], key: Key) -> bool {
    let alt = mods.contains(&keymap::ALT);
    if keymap::is_modifier(key)
        || [keymap::ENTER, keymap::BACKSPACE].contains(&key)
        || alt && [keymap::B, keymap::C].contains(&key)
    {
        return false;
    }
    let sym = mods.contains(&keymap::SYM);
    let shift = mods.contains(&keymap::LEFT_SHIFT) || mods.contains(&keymap::RIGHT_SHIFT);
    let (base, symbol) = (keymap::base(key), keymap::symbol(key));
    sym && shift
        || shift && !base.is_ascii_lowercase() && key != keymap::DOLLAR
        || sym && symbol == 0
}

#[test]
fn every_key_under_every_modifier_set() {
    let mut sent = Vec::new();
    for mods in modifier_sets() {
        for key in Key::all() {
            let want = expected(&mods, key).unwrap_or(0);
            // Modifiers one at a time, then the key.
            let mut pair = Pair::new();
            for n in 1..=mods.len() {
                pair.scan(&mods[..n]);
            }
            pair.scan(&with(&mods, &[key]));
            let (stock, ours) = pair.read_key();
            assert_eq!(ours, want, "{mods:?} {key:?}");
            if !differs_from_stock(&mods, key) {
                assert_eq!(stock, ours, "{mods:?} {key:?}");
            }
            sent.push(ours);
            assert_eq!(pair.read_key().1, 0);
            pair.scan(&[]);
            pair.read();
            // Everything in one scan.
            let mut pair = Pair::new();
            pair.scan(&with(&mods, &[key]));
            let (stock, ours) = pair.read_key();
            assert_eq!(ours, want, "{mods:?} {key:?}");
            if !differs_from_stock(&mods, key) {
                assert_eq!(stock, ours, "{mods:?} {key:?}");
            }
        }
    }
    // What makes the identify probe safe on a stock keyboard.
    assert!(sent.iter().all(|&b| b <= 0x7a));
    assert!(!sent.contains(&protocol::IDENTIFY_MAGIC[0]));
}

/// Every character waiting in `keyboard`, oldest first.
fn drain(keyboard: &mut Controller) -> Vec<u8> {
    let mut reply = [0; MAX_REPLY];
    core::iter::from_fn(|| {
        keyboard.on_read(&mut reply);
        (reply[0] != 0).then_some(reply[0])
    })
    .collect()
}

#[test]
fn every_two_keys_under_every_modifier_set() {
    for mods in modifier_sets() {
        for first in typed_keys() {
            for second in typed_keys().filter(|&key| key != first) {
                let bytes = |keys: &[Key]| -> Vec<u8> {
                    keys.iter().filter_map(|&k| expected(&mods, k)).collect()
                };
                // In one scan: in scan order, with Enter, Backspace, and
                // Alt+C after the rest, as stock firmware has them.
                let mut keyboard = Controller::new();
                keyboard.on_scan(mods.iter().copied().collect(), 0);
                keyboard.on_scan(with(&mods, &[first, second]).into_iter().collect(), 10);
                let late = |&k: &Key| {
                    k == keymap::ENTER
                        || k == keymap::BACKSPACE
                        || mods.contains(&keymap::ALT) && k == keymap::C
                };
                let (mut early, mut after): (Vec<Key>, Vec<Key>) = Key::all()
                    .filter(|k| [first, second].contains(k))
                    .partition(|k| !late(k));
                after.sort_by_key(|&k| {
                    [keymap::ENTER, keymap::BACKSPACE, keymap::C]
                        .iter()
                        .position(|&l| l == k)
                });
                early.extend(after);
                assert_eq!(drain(&mut keyboard), bytes(&early));
                // One after the other, unread in between: both wait.
                let mut keyboard = Controller::new();
                keyboard.on_scan(mods.iter().copied().collect(), 0);
                keyboard.on_scan(with(&mods, &[first]).into_iter().collect(), 10);
                keyboard.on_scan(with(&mods, &[first, second]).into_iter().collect(), 20);
                assert_eq!(drain(&mut keyboard), bytes(&[first, second]));
            }
        }
    }
}

#[test]
fn the_queue_holds_what_the_host_has_not_read() {
    let mut keyboard = Controller::new();
    let keys: Vec<Key> = typed_keys()
        .filter(|&key| keymap::base(key).is_ascii_lowercase())
        .collect();
    for (n, &key) in keys.iter().enumerate() {
        keyboard.on_scan([key].into_iter().collect(), 100 * n as u64);
        keyboard.on_scan(Snapshot::EMPTY, 100 * n as u64 + 50);
    }
    // A full queue drops what comes after.
    let want: Vec<u8> = keys[..legacy::QUEUE_LEN]
        .iter()
        .map(|&key| keymap::base(key))
        .collect();
    assert_eq!(drain(&mut keyboard), want);
}

#[test]
fn raw_mode_reports_the_matrix() {
    for mods in modifier_sets() {
        for key in Key::all() {
            let mut pair = Pair::new();
            pair.write(&[protocol::CMD_MODE_RAW]);
            pair.scan(&with(&mods, &[key]));
            pair.read();
            // The character still waits for key mode.
            pair.write(&[protocol::CMD_MODE_KEY]);
            assert_eq!(pair.read_key().1, expected(&mods, key).unwrap_or(0));
        }
    }
}

/// Someone typing on a [`Controller`], a tap at a time.
struct Typist {
    keyboard: Controller,
    ms: u64,
}

impl Typist {
    /// Taps are this far apart unless a test waits.
    const BRISK_MS: u64 = 150;

    fn new() -> Self {
        Self {
            keyboard: Controller::new(),
            ms: 0,
        }
    }

    /// Lets `ms` pass before the next tap.
    fn wait(&mut self, ms: u64) {
        self.ms += ms - Self::BRISK_MS;
    }

    /// Presses `keys` together, holds them through `held`, releases
    /// everything, and reads the character.
    fn tap_holding(&mut self, held: &[Key], keys: &[Key]) -> u8 {
        self.ms += Self::BRISK_MS;
        self.keyboard
            .on_scan(held.iter().copied().collect(), self.ms - 50);
        self.keyboard
            .on_scan(with(held, keys).into_iter().collect(), self.ms);
        self.keyboard.on_scan(Snapshot::EMPTY, self.ms + 50);
        self.read()[0]
    }

    fn tap(&mut self, keys: &[Key]) -> u8 {
        self.tap_holding(&[], keys)
    }

    fn read(&mut self) -> [u8; MAX_REPLY] {
        let mut reply = [0; MAX_REPLY];
        self.keyboard.on_read(&mut reply);
        reply
    }

    /// The latch the status byte reports.
    fn latch(&mut self) -> u8 {
        self.read()[1] & legacy::STATUS_LATCH
    }
}

const Q: Key = Key::new(0, 0);
const SPACE: Key = keymap::SPACE;

#[test]
fn one_tap_applies_to_the_next_key_only() {
    for modifier in [keymap::SYM, keymap::LEFT_SHIFT, keymap::RIGHT_SHIFT] {
        for key in typed_keys() {
            let mut typist = Typist::new();
            typist.tap(&[modifier]);
            assert_eq!(typist.tap(&[key]), expected(&[modifier], key).unwrap_or(0));
            assert_eq!(typist.tap(&[key]), expected(&[], key).unwrap_or(0));
        }
    }
}

#[test]
fn the_other_modifier_replaces_a_latch() {
    let mut typist = Typist::new();
    typist.tap(&[keymap::SYM]);
    typist.tap(&[keymap::LEFT_SHIFT]);
    assert_eq!(typist.tap(&[Q]), b'Q');
    typist.tap(&[keymap::LEFT_SHIFT]);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.tap(&[Q]), b'#');
    // Out of Caps Lock, for one symbol.
    typist.tap(&[keymap::RIGHT_SHIFT]);
    typist.tap(&[keymap::RIGHT_SHIFT]);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.tap(&[Q]), b'#');
    assert_eq!(typist.tap(&[Q]), b'q');
}

#[test]
fn two_quick_taps_lock_until_the_next_tap() {
    let mut typist = Typist::new();
    typist.tap(&[keymap::LEFT_SHIFT]);
    typist.tap(&[keymap::RIGHT_SHIFT]);
    for _ in 0..3 {
        assert_eq!(typist.tap(&[Q]), b'Q');
    }
    // Caps Lock is for letters.
    assert_eq!(typist.tap(&[keymap::DOLLAR]), b'$');
    assert_eq!(typist.tap(&[keymap::ENTER]), 0x0d);
    assert_eq!(typist.tap(&[Q]), b'Q');
    typist.tap(&[keymap::LEFT_SHIFT]);
    assert_eq!(typist.tap(&[Q]), b'q');

    typist.tap(&[keymap::SYM]);
    typist.tap(&[keymap::SYM]);
    for _ in 0..3 {
        assert_eq!(typist.tap(&[Q]), b'#');
    }
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.tap(&[Q]), b'q');
}

#[test]
fn three_quick_taps_cancel() {
    for modifier in [keymap::SYM, keymap::LEFT_SHIFT] {
        let mut typist = Typist::new();
        for _ in 0..3 {
            typist.tap(&[modifier]);
        }
        assert_eq!(typist.tap(&[Q]), b'q');
    }
}

#[test]
fn a_tap_after_a_pause_cancels() {
    let mut typist = Typist::new();
    typist.tap(&[keymap::LEFT_SHIFT]);
    typist.wait(legacy::DOUBLE_TAP_MS + 1);
    typist.tap(&[keymap::RIGHT_SHIFT]);
    assert_eq!(typist.tap(&[Q]), b'q');
    // At the limit, it still locks.
    let mut typist = Typist::new();
    typist.tap(&[keymap::SYM]);
    typist.wait(legacy::DOUBLE_TAP_MS);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.tap(&[Q]), b'#');
    assert_eq!(typist.tap(&[Q]), b'#');
}

#[test]
fn a_held_modifier_applies_to_every_key_until_released() {
    let held: [&[Key]; 5] = [
        &[keymap::SYM],
        &[keymap::LEFT_SHIFT],
        &[keymap::RIGHT_SHIFT],
        &[keymap::SYM, keymap::LEFT_SHIFT],
        &[keymap::RIGHT_SHIFT, keymap::SYM],
    ];
    for mods in held {
        let mut keyboard = Controller::new();
        for n in 1..=mods.len() {
            keyboard.on_scan(mods[..n].iter().copied().collect(), 10 * n as u64);
        }
        for (n, key) in typed_keys().enumerate() {
            let ms = 100 + 100 * n as u64;
            keyboard.on_scan(with(mods, &[key]).into_iter().collect(), ms);
            keyboard.on_scan(mods.iter().copied().collect(), ms + 50);
            let mut reply = [0; MAX_REPLY];
            keyboard.on_read(&mut reply);
            assert_eq!(
                reply[0],
                expected(mods, key).unwrap_or(0),
                "{mods:?} {key:?}"
            );
        }
        // Released, it is gone.
        let mut typist = Typist {
            keyboard,
            ms: 10_000,
        };
        assert_eq!(typist.tap(&[Q]), b'q');
    }
}

#[test]
fn a_hold_then_a_quick_tap_does_not_lock() {
    let mut typist = Typist::new();
    assert_eq!(typist.tap_holding(&[keymap::LEFT_SHIFT], &[Q]), b'Q');
    typist.tap(&[keymap::LEFT_SHIFT]);
    assert_eq!(typist.tap(&[Q]), b'Q');
    assert_eq!(typist.tap(&[Q]), b'q');
}

#[test]
fn enter_uses_one_tap_up_but_not_a_lock() {
    let mut typist = Typist::new();
    typist.tap(&[keymap::LEFT_SHIFT]);
    assert_eq!(typist.tap(&[keymap::ENTER]), 0x0d);
    assert_eq!(typist.tap(&[Q]), b'q');
    typist.tap(&[keymap::SYM]);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.tap(&[keymap::ENTER]), 0x0d);
    assert_eq!(typist.tap(&[Q]), b'#');
}

#[test]
fn shift_changes_letters_and_the_speaker_key_alone() {
    let mut typist = Typist::new();
    assert_eq!(typist.tap_holding(&[keymap::LEFT_SHIFT], &[SPACE]), b' ');
    assert_eq!(
        typist.tap_holding(&[keymap::LEFT_SHIFT], &[keymap::DOLLAR]),
        0x04
    );
    assert_eq!(
        typist.tap_holding(&[keymap::RIGHT_SHIFT], &[keymap::MIC]),
        0
    );
    // Sym on a key with no Sym legend sends the base one.
    assert_eq!(typist.tap_holding(&[keymap::SYM], &[SPACE]), b' ');
    assert_eq!(typist.tap_holding(&[keymap::SYM], &[keymap::DOLLAR]), b'$');
    assert_eq!(typist.tap_holding(&[keymap::SYM], &[keymap::MIC]), b'0');
}

#[test]
fn the_status_byte_reports_the_latch() {
    let mut typist = Typist::new();
    assert_eq!(typist.latch(), 0);
    typist.tap(&[keymap::LEFT_SHIFT]);
    assert_eq!(typist.latch(), 1);
    typist.tap(&[keymap::LEFT_SHIFT]);
    assert_eq!(typist.latch(), 4);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.latch(), 2);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.latch(), 5);
    typist.tap(&[keymap::SYM]);
    assert_eq!(typist.latch(), 0);
    // A character's own read already shows the latch it used up.
    typist.tap(&[keymap::SYM]);
    typist.ms += Typist::BRISK_MS;
    typist
        .keyboard
        .on_scan([Q].into_iter().collect(), typist.ms);
    let reply = typist.read();
    assert_eq!((reply[0], reply[1] & legacy::STATUS_LATCH), (b'#', 0));
}

#[test]
fn the_status_byte_reports_held_keys_and_the_light() {
    let mut keyboard = Controller::new();
    let status = |keyboard: &mut Controller| {
        let mut reply = [0xff; MAX_REPLY];
        keyboard.on_read(&mut reply);
        // Nothing past the status byte yet, and no repeat beside nothing.
        assert!(reply[2..].iter().all(|&b| b == 0));
        assert_eq!(reply[1] & legacy::STATUS_REPEAT, 0);
        reply[1] & !legacy::STATUS_LATCH
    };
    assert_eq!(status(&mut keyboard), 0);
    for (key, bit) in [
        (keymap::LEFT_SHIFT, legacy::STATUS_LEFT_SHIFT),
        (keymap::RIGHT_SHIFT, legacy::STATUS_RIGHT_SHIFT),
        (keymap::ALT, legacy::STATUS_ALT),
    ] {
        keyboard.on_scan([key].into_iter().collect(), 0);
        assert_eq!(status(&mut keyboard), bit);
        keyboard.on_scan(Snapshot::EMPTY, 0);
        assert_eq!(status(&mut keyboard), 0);
    }
    keyboard.on_scan([keymap::ALT].into_iter().collect(), 0);
    keyboard.on_scan([keymap::ALT, keymap::B].into_iter().collect(), 0);
    keyboard.on_scan(Snapshot::EMPTY, 0);
    assert_eq!(status(&mut keyboard), legacy::STATUS_BACKLIGHT);
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0]);
    assert_eq!(status(&mut keyboard), 0);
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x80]);
    assert_eq!(status(&mut keyboard), legacy::STATUS_BACKLIGHT);
}

/// After a write, the light and the next read agree, and so does what
/// Alt+B then does twice.
fn check_write(bytes: &[u8]) {
    let mut pair = Pair::new();
    // A key waiting, which the write must not disturb.
    pair.scan(&[Key::new(0, 0)]);
    pair.scan(&[]);
    pair.write(bytes);
    if protocol::commands(bytes).any(|c| c == Command::Identify) {
        // The one deliberate difference: stock returns the key here.
        let mut reply = [0; MAX_REPLY];
        let len = pair.ours.on_read(&mut reply);
        assert_eq!(&reply[..len], &protocol::identify_reply());
    }
    pair.read();
    for _ in 0..2 {
        pair.scan(&[keymap::ALT]);
        pair.scan(&[keymap::ALT, keymap::B]);
        pair.scan(&[]);
        pair.read();
    }
}

#[test]
fn every_one_and_two_byte_write() {
    for a in 0..=u8::MAX {
        check_write(&[a]);
        for b in 0..=u8::MAX {
            check_write(&[a, b]);
        }
    }
}

#[test]
fn every_three_byte_light_write() {
    for a in [protocol::CMD_BACKLIGHT, protocol::CMD_ALT_B_BACKLIGHT] {
        for b in 0..=u8::MAX {
            for c in 0..=u8::MAX {
                check_write(&[a, b, c]);
            }
        }
    }
}

#[test]
fn identify_is_latched_for_one_read() {
    let mut keyboard = Controller::new();
    keyboard.on_scan([Key::new(0, 0)].into_iter().collect(), 0);
    assert_eq!(keyboard.on_write(&[protocol::CMD_IDENTIFY]), Power::Awake);
    let mut reply = [0; MAX_REPLY];
    let len = keyboard.on_read(&mut reply);
    assert_eq!(&reply[..2], &protocol::IDENTIFY_MAGIC);
    assert_eq!(reply[2], protocol::PROTOCOL_MAJOR);
    let capabilities = u16::from_be_bytes([reply[4], reply[5]]);
    assert_ne!(capabilities & protocol::CAP_SLEEP, 0);
    assert_ne!(capabilities & protocol::CAP_STATUS, 0);
    // A CRC over the data and its own value leaves nothing.
    assert_eq!(protocol::pec(&reply[..len]), 0);
    // The key pressed before the probe is still there.
    keyboard.on_read(&mut reply);
    assert_eq!(reply[0], b'q');
}

#[test]
fn sleep_keeps_the_keyboard_as_it_was() {
    let mut keyboard = Controller::new();
    assert_eq!(
        keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x80]),
        Power::Awake
    );
    assert_eq!(keyboard.on_write(&[protocol::CMD_SLEEP]), Power::Sleep);
    // A key pressed while asleep is there when the host comes back.
    keyboard.on_scan([Key::new(0, 0)].into_iter().collect(), 0);
    keyboard.on_wake();
    let mut reply = [0; MAX_REPLY];
    keyboard.on_read(&mut reply);
    assert_eq!(reply[0], b'q');
    // The light counts as on, though it is dark until it is restored.
    assert_ne!(reply[1] & legacy::STATUS_BACKLIGHT, 0);
    assert_eq!(keyboard.backlight(), 0);
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0x80);
}

#[test]
fn the_light_stays_dark_through_a_sleep_until_restored() {
    let mut keyboard = Controller::new();
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x80]);
    let _ = keyboard.on_write(&[protocol::CMD_SLEEP]);
    assert_eq!(keyboard.backlight(), 0);
    // Not before a wake.
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0);
    keyboard.on_wake();
    assert_eq!(keyboard.backlight(), 0);
    // Back to sleep before the restore: it waits for the next wake.
    let _ = keyboard.on_write(&[protocol::CMD_SLEEP]);
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0);
    keyboard.on_wake();
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0x80);
    // A restore with no sleep before it changes nothing.
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x40]);
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0x40);
}

#[test]
fn a_light_set_on_waking_wins_over_the_restore() {
    let mut keyboard = Controller::new();
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x80]);
    let _ = keyboard.on_write(&[protocol::CMD_SLEEP]);
    keyboard.on_wake();
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x20]);
    assert_eq!(keyboard.backlight(), 0x20);
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0x20);
    // Turned off on waking, it stays off.
    let _ = keyboard.on_write(&[protocol::CMD_SLEEP]);
    keyboard.on_wake();
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0]);
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0);
}

#[test]
fn alt_b_duty_on_waking_does_not_set_the_light() {
    let mut keyboard = Controller::new();
    let _ = keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0x80]);
    let _ = keyboard.on_write(&[protocol::CMD_SLEEP]);
    keyboard.on_wake();
    let _ = keyboard.on_write(&[protocol::CMD_ALT_B_BACKLIGHT, 0x60]);
    assert_eq!(keyboard.backlight(), 0);
    keyboard.restore_light();
    assert_eq!(keyboard.backlight(), 0x80);
}

#[test]
fn a_fade_starts_and_ends_exactly_where_it_says() {
    for from in 0..=u8::MAX {
        for to in 0..=u8::MAX {
            let fade = Fade::new(from, to, 1000);
            assert_eq!(fade.level(1000), from, "{from} to {to}");
            assert!(!fade.done(1000 + FADE_MS - 1));
            assert_eq!(fade.level(1000 + FADE_MS), to, "{from} to {to}");
            assert!(fade.done(1000 + FADE_MS));
        }
    }
}

#[test]
fn a_fade_moves_one_way_and_slowly_at_the_dim_end() {
    for (from, to) in [(0, u8::MAX), (u8::MAX, 0), (20, 200), (127, 30)] {
        let fade = Fade::new(from, to, 0);
        let levels: Vec<u8> = (0..=FADE_MS).map(|at| fade.level(at)).collect();
        let one_way = levels.windows(2).all(|pair| {
            if from < to {
                pair[0] <= pair[1]
            } else {
                pair[0] >= pair[1]
            }
        });
        assert!(one_way, "{from} to {to}: {levels:?}");
    }
    // Halfway up from dark is a quarter of the duty.
    assert_eq!(Fade::new(0, u8::MAX, 0).level(FADE_MS / 2), 64);
}

#[test]
fn sleep_after_a_light_duty_is_the_alt_b_duty() {
    // As on stock firmware, `01 d` takes the byte after it for Alt+B, so
    // sleep goes in a write of its own.
    let mut keyboard = Controller::new();
    assert_eq!(
        keyboard.on_write(&[protocol::CMD_BACKLIGHT, 0, protocol::CMD_SLEEP]),
        Power::Awake
    );
}

#[test]
fn pec_is_crc8_smbus() {
    // The CRC-8/SMBUS check value.
    assert_eq!(protocol::pec(b"123456789"), 0xf4);
}

#[test]
fn backlight_write_falls_through_to_alt_b() {
    let parsed: Vec<_> = protocol::commands(&[0x01, 0x00, 0x50, 0x04]).collect();
    assert_eq!(
        parsed,
        [
            Command::Backlight(0x00),
            Command::AltBBacklight(0x50),
            Command::ModeKey,
        ]
    );
}

#[test]
fn debouncer_needs_two_agreeing_scans() {
    let q: Snapshot = [Key::new(0, 0)].into_iter().collect();
    let mut debouncer = Debouncer::new();
    // A one-scan glitch never shows.
    assert_eq!(debouncer.update(q), Snapshot::EMPTY);
    assert_eq!(debouncer.update(Snapshot::EMPTY), Snapshot::EMPTY);
    assert!(debouncer.is_idle());
    // A press does, on its second scan, and so does the release.
    debouncer.update(q);
    assert_eq!(debouncer.update(q), q);
    assert_eq!(debouncer.update(Snapshot::EMPTY), q);
    assert!(!debouncer.is_idle());
    assert_eq!(debouncer.update(Snapshot::EMPTY), Snapshot::EMPTY);
    assert!(debouncer.is_idle());
}
