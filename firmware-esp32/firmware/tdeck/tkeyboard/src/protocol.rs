//! The I²C protocol: what a host's write means, and the identify reply.
//! The full description is `docs/tdeck-keyboard-firmware.md`.

/// The keyboard's I²C target address.
pub const ADDRESS: u8 = 0x55;

/// `01 d`: set the key light's duty.
pub const CMD_BACKLIGHT: u8 = 0x01;
/// `02 d`: set Alt+B's duty.
pub const CMD_ALT_B_BACKLIGHT: u8 = 0x02;
/// Reads return the matrix, one byte per column.
pub const CMD_MODE_RAW: u8 = 0x03;
/// Reads return the next character typed (the power-on mode).
pub const CMD_MODE_KEY: u8 = 0x04;
/// Low-power mode: the keyboard stops answering until the bus is next
/// used, and sleeps whenever it has nothing to do. Keys pressed meanwhile
/// are still taken. Send only after identify reports [`CAP_SLEEP`].
pub const CMD_SLEEP: u8 = 0x50;
/// The next read returns [`identify_reply`]. Stock firmware ignores it.
pub const CMD_IDENTIFY: u8 = 0xa0;

/// The identify reply's first two bytes. No key-mode byte is ever 0xA5,
/// so a host that reads anything else from a stock keyboard has a key.
pub const IDENTIFY_MAGIC: [u8; 2] = [0xa5, 0x5a];
pub const PROTOCOL_MAJOR: u8 = 1;
pub const PROTOCOL_MINOR: u8 = 2;
/// [`CMD_SLEEP`] is understood.
pub const CAP_SLEEP: u16 = 1 << 0;
/// A key-mode read's second byte is the status byte.
pub const CAP_STATUS: u16 = 1 << 1;
/// Capabilities beyond the stock protocol and identify.
pub const CAPABILITIES: u16 = CAP_SLEEP | CAP_STATUS;
pub const IDENTIFY_LEN: usize = 7;

/// What one write asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Backlight(u8),
    AltBBacklight(u8),
    ModeRaw,
    ModeKey,
    Sleep,
    Identify,
}

/// The commands in one write, parsed the way the stock firmware parses
/// them: every byte is a command except an operand, an unknown byte is
/// skipped, a missing operand is no command, and `01`'s handler falls
/// through into `02`'s, so the byte after `01 d` (if any) is Alt+B's duty.
pub fn commands(write: &[u8]) -> Commands<'_> {
    Commands {
        bytes: write.iter(),
        fall_through: false,
    }
}

pub struct Commands<'a> {
    bytes: core::slice::Iter<'a, u8>,
    /// The last command was `01`, whose operand-taking tail is `02`'s.
    fall_through: bool,
}

impl Iterator for Commands<'_> {
    type Item = Command;

    fn next(&mut self) -> Option<Command> {
        if core::mem::take(&mut self.fall_through) {
            return self.bytes.next().map(|&d| Command::AltBBacklight(d));
        }
        loop {
            let command = match *self.bytes.next()? {
                CMD_BACKLIGHT => {
                    let duty = *self.bytes.next()?;
                    self.fall_through = true;
                    Command::Backlight(duty)
                }
                CMD_ALT_B_BACKLIGHT => Command::AltBBacklight(*self.bytes.next()?),
                CMD_MODE_RAW => Command::ModeRaw,
                CMD_MODE_KEY => Command::ModeKey,
                CMD_SLEEP => Command::Sleep,
                CMD_IDENTIFY => Command::Identify,
                _ => continue,
            };
            return Some(command);
        }
    }
}

/// `A5 5A <major> <minor> <capabilities, big-endian> <PEC>`.
pub fn identify_reply() -> [u8; IDENTIFY_LEN] {
    let [caps_hi, caps_lo] = CAPABILITIES.to_be_bytes();
    let mut reply = [
        IDENTIFY_MAGIC[0],
        IDENTIFY_MAGIC[1],
        PROTOCOL_MAJOR,
        PROTOCOL_MINOR,
        caps_hi,
        caps_lo,
        0,
    ];
    reply[IDENTIFY_LEN - 1] = pec(&reply[..IDENTIFY_LEN - 1]);
    reply
}

/// CRC-8 with the SMBus PEC polynomial (x⁸ + x² + x + 1, initial 0), over
/// a reply's bytes alone.
pub fn pec(bytes: &[u8]) -> u8 {
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
