//! [`Controller`] held against the stock firmware, exhaustively where the
//! space allows.

use std::vec::Vec;

use crate::Controller;
use crate::controller::{MAX_REPLY, Power};
use crate::keymap;
use crate::matrix::{COLS, Debouncer, Key, ROWS, Snapshot};
use crate::protocol::{self, Command};

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

/// The stock model and ours, fed the same things.
struct Pair {
    stock: Stock,
    ours: Controller,
}

impl Pair {
    fn new() -> Self {
        Self {
            stock: Stock::new(),
            ours: Controller::new(),
        }
    }

    fn scan(&mut self, keys: &[Key]) {
        let snapshot: Snapshot = keys.iter().copied().collect();
        self.stock.scan(&snapshot);
        self.ours.on_scan(snapshot);
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
        assert_eq!(stock, &reply[..len]);
        stock
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

#[test]
fn every_key_under_every_modifier_set() {
    let mut sent = Vec::new();
    for mods in modifier_sets() {
        for key in Key::all() {
            // Modifiers first, then the key.
            let mut pair = Pair::new();
            pair.scan(&mods);
            pair.read();
            pair.scan(&with(&mods, &[key]));
            sent.extend(pair.read());
            pair.scan(&mods);
            pair.read();
            pair.scan(&[]);
            pair.read();
            // Everything in one scan.
            let mut pair = Pair::new();
            pair.scan(&with(&mods, &[key]));
            sent.extend(pair.read());
            pair.read();
        }
    }
    // What makes the identify probe safe on a stock keyboard.
    assert!(sent.iter().all(|&b| b <= 0x7a || b == 0xe0));
    assert!(!sent.contains(&protocol::IDENTIFY_MAGIC[0]));
}

#[test]
fn every_two_keys_under_every_modifier_set() {
    for mods in modifier_sets() {
        for first in Key::all() {
            for second in Key::all() {
                // In one scan: the later in scan order wins.
                let mut pair = Pair::new();
                pair.scan(&with(&mods, &[first, second]));
                pair.read();
                // One after the other, unread in between: the second
                // replaces the first, or Alt+B clears it.
                let mut pair = Pair::new();
                pair.scan(&with(&mods, &[first]));
                pair.scan(&with(&mods, &[first, second]));
                pair.read();
                pair.scan(&[]);
                pair.read();
            }
        }
    }
}

#[test]
fn raw_mode_reports_the_matrix() {
    for mods in modifier_sets() {
        for key in Key::all() {
            let mut pair = Pair::new();
            pair.write(&[protocol::CMD_MODE_RAW]);
            pair.scan(&with(&mods, &[key]));
            pair.read();
            // The key byte is still encoded and waits for key mode.
            pair.write(&[protocol::CMD_MODE_KEY]);
            pair.read();
        }
    }
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
    keyboard.on_scan([Key::new(0, 0)].into_iter().collect());
    assert_eq!(keyboard.on_write(&[protocol::CMD_IDENTIFY]), Power::Awake);
    let mut reply = [0; MAX_REPLY];
    let len = keyboard.on_read(&mut reply);
    assert_eq!(&reply[..2], &protocol::IDENTIFY_MAGIC);
    assert_eq!(reply[2], protocol::PROTOCOL_MAJOR);
    let capabilities = u16::from_be_bytes([reply[4], reply[5]]);
    assert_ne!(capabilities & protocol::CAP_SLEEP, 0);
    // A CRC over the data and its own value leaves nothing.
    assert_eq!(protocol::pec(&reply[..len]), 0);
    // The key pressed before the probe is still there.
    assert_eq!(keyboard.on_read(&mut reply), 1);
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
    assert_eq!(keyboard.backlight(), 0x80);
    // A key pressed while asleep is there when the host comes back.
    keyboard.on_scan([Key::new(0, 0)].into_iter().collect());
    let mut reply = [0; MAX_REPLY];
    assert_eq!(keyboard.on_read(&mut reply), 1);
    assert_eq!(reply[0], b'q');
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
