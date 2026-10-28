//! Which receiver is on the UART, from its answer to a version query.
//!
//! Send [`QUERIES`], then feed every byte that comes back to an
//! [`Identifier`]. Each receiver answers only its own query and passes the
//! other over as noise:
//!
//! * **u-blox** answers UBX-MON-VER with a binary frame whose extension
//!   strings name the module, as `MOD=MIA-M10Q`.
//! * **CASIC** firmware, which the L76K runs, answers `$PCAS06,0` with a
//!   `$GPTXT` line carrying `SW=` and its firmware version. The L76K is the
//!   only CASIC receiver on UMSH's boards, so that answer is taken as one;
//!   Meshtastic identifies it the same way.

/// UBX-MON-VER, polled (an empty payload), then `$PCAS06,0`.
pub const QUERIES: [&[u8]; 2] = [
    &[0xB5, 0x62, 0x0A, 0x04, 0x00, 0x00, 0x0E, 0x34],
    b"$PCAS06,0*1B\r\n",
];

/// The longest name a receiver is given.
pub const NAME_MAX: usize = 24;

/// A receiver's name, as a page shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name {
    bytes: [u8; NAME_MAX],
    len: u8,
}

impl Name {
    fn new(parts: &[&[u8]]) -> Self {
        let mut name = Self {
            bytes: [0; NAME_MAX],
            len: 0,
        };
        for &byte in parts.iter().flat_map(|part| part.iter()) {
            if usize::from(name.len) == NAME_MAX {
                break;
            }
            name.bytes[usize::from(name.len)] = byte;
            name.len += 1;
        }
        name
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only printable ASCII is ever copied in.
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

/// MON-VER's fixed fields: the software version, then the hardware's.
const VERSIONS_LEN: usize = 30 + 10;
/// Each extension string's field, NUL-padded.
const EXTENSION_LEN: usize = 30;
/// The longest MON-VER taken: a dozen extensions.
const MON_VER_MAX: usize = VERSIONS_LEN + 12 * EXTENSION_LEN;
const MODULE_TAG: &[u8] = b"MOD=";

/// Where a UBX frame being read has got to.
#[derive(Clone, Copy)]
enum Ubx {
    /// Not in a frame; `true` once the first sync byte is seen.
    Idle(bool),
    /// The class, the ID, and the payload length, `at` bytes in.
    Header { at: u8, header: [u8; 4] },
    /// The payload, `at` of `len` bytes read.
    Payload { at: u16, len: u16 },
    /// The checksum's first byte, then its second.
    Checksum(Option<u8>),
}

/// Reads a receiver's answers to [`QUERIES`] out of whatever else it
/// sends.
pub struct Identifier {
    ubx: Ubx,
    /// The Fletcher sums over the frame being read.
    sums: (u8, u8),
    /// The frame is a MON-VER, so its payload is looked through.
    mon_ver: bool,
    /// The extension being read, then the module it names, if it names
    /// one.
    extension: [u8; EXTENSION_LEN],
    module: Option<Name>,
    line: [u8; crate::nmea::MAX_SENTENCE],
    line_len: usize,
    in_line: bool,
}

impl Default for Identifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Identifier {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ubx: Ubx::Idle(false),
            sums: (0, 0),
            mon_ver: false,
            extension: [0; EXTENSION_LEN],
            module: None,
            line: [0; crate::nmea::MAX_SENTENCE],
            line_len: 0,
            in_line: false,
        }
    }

    /// The receiver, once `byte` completes an answer that names it.
    pub fn push(&mut self, byte: u8) -> Option<Name> {
        self.push_ubx(byte).or_else(|| self.push_line(byte))
    }

    fn sum(&mut self, byte: u8) {
        self.sums.0 = self.sums.0.wrapping_add(byte);
        self.sums.1 = self.sums.1.wrapping_add(self.sums.0);
    }

    fn push_ubx(&mut self, byte: u8) -> Option<Name> {
        self.ubx = match self.ubx {
            Ubx::Idle(false) => Ubx::Idle(byte == 0xB5),
            Ubx::Idle(true) if byte == 0x62 => {
                self.sums = (0, 0);
                Ubx::Header {
                    at: 0,
                    header: [0; 4],
                }
            }
            Ubx::Idle(true) => Ubx::Idle(byte == 0xB5),
            Ubx::Header { at, mut header } => {
                self.sum(byte);
                header[usize::from(at)] = byte;
                if at < 3 {
                    Ubx::Header { at: at + 1, header }
                } else {
                    let len = u16::from_le_bytes([header[2], header[3]]);
                    self.mon_ver = header[..2] == [0x0A, 0x04]
                        && usize::from(len) >= VERSIONS_LEN
                        && usize::from(len) <= MON_VER_MAX;
                    self.module = None;
                    if len == 0 {
                        Ubx::Checksum(None)
                    } else {
                        Ubx::Payload { at: 0, len }
                    }
                }
            }
            Ubx::Payload { at, len } => {
                self.sum(byte);
                if self.mon_ver {
                    self.look_through(usize::from(at), byte);
                }
                if at + 1 < len {
                    Ubx::Payload { at: at + 1, len }
                } else {
                    Ubx::Checksum(None)
                }
            }
            Ubx::Checksum(None) => Ubx::Checksum(Some(byte)),
            Ubx::Checksum(Some(first)) => {
                self.ubx = Ubx::Idle(false);
                let named = self.mon_ver && (first, byte) == self.sums;
                self.mon_ver = false;
                return named.then(|| match self.module.take() {
                    Some(module) => module,
                    None => Name::new(&[b"u-blox"]),
                });
            }
        };
        None
    }

    /// Keeps the extension that names the module.
    fn look_through(&mut self, at: usize, byte: u8) {
        let Some(at) = at.checked_sub(VERSIONS_LEN) else {
            return;
        };
        let offset = at % EXTENSION_LEN;
        self.extension[offset] = byte;
        if offset + 1 < EXTENSION_LEN {
            return;
        }
        let text = self.extension.split(|&b| b == 0).next().unwrap_or(&[]);
        if let Some(module) = text.strip_prefix(MODULE_TAG)
            && !module.is_empty()
            && module.iter().all(u8::is_ascii_graphic)
        {
            self.module = Some(Name::new(&[b"u-blox ", module]));
        }
    }

    fn push_line(&mut self, byte: u8) -> Option<Name> {
        match byte {
            b'$' => {
                self.in_line = true;
                self.line_len = 0;
            }
            b'\r' | b'\n' if self.in_line => {
                self.in_line = false;
                return casic_answer(&self.line[..self.line_len]).then(|| Name::new(&[b"L76K"]));
            }
            _ if self.in_line => {
                if self.line_len == self.line.len() {
                    self.in_line = false;
                } else {
                    self.line[self.line_len] = byte;
                    self.line_len += 1;
                }
            }
            _ => {}
        }
        None
    }
}

/// Whether `line`, everything after its `$`, is a checksummed `TXT`
/// sentence whose text gives a firmware version, as CASIC's answer to
/// `$PCAS06,0` does: `GPTXT,01,01,02,SW=...*hh`.
fn casic_answer(line: &[u8]) -> bool {
    let Some(star) = line.iter().rposition(|&b| b == b'*') else {
        return false;
    };
    let (body, given) = (&line[..star], &line[star + 1..]);
    let sum = body.iter().fold(0, |sum, &b| sum ^ b);
    let hex = |b: u8| char::from(b).to_digit(16);
    let matches = match given {
        [high, low] => hex(*high)
            .zip(hex(*low))
            .is_some_and(|(high, low)| (high << 4 | low) == u32::from(sum)),
        _ => false,
    };
    if !matches || body.len() < 6 || &body[2..6] != b"TXT," {
        return false;
    }
    body.split(|&b| b == b',')
        .nth(4)
        .is_some_and(|text| text.starts_with(b"SW="))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(bytes: &[u8]) -> Option<Name> {
        let mut identifier = Identifier::new();
        bytes.iter().find_map(|&byte| identifier.push(byte))
    }

    /// A MON-VER answer with `extensions`, checksummed.
    fn mon_ver(extensions: &[&str]) -> std::vec::Vec<u8> {
        let mut payload = std::vec![0u8; VERSIONS_LEN];
        payload[..8].copy_from_slice(b"ROM SPG ");
        for extension in extensions {
            let mut field = [0u8; EXTENSION_LEN];
            field[..extension.len()].copy_from_slice(extension.as_bytes());
            payload.extend_from_slice(&field);
        }
        let len = (payload.len() as u16).to_le_bytes();
        let mut frame = std::vec![0xB5, 0x62, 0x0A, 0x04, len[0], len[1]];
        frame.extend_from_slice(&payload);
        let (mut a, mut b) = (0u8, 0u8);
        for &byte in &frame[2..] {
            a = a.wrapping_add(byte);
            b = b.wrapping_add(a);
        }
        frame.extend_from_slice(&[a, b]);
        frame
    }

    #[test]
    fn a_u_blox_names_its_module() {
        let frame = mon_ver(&["FWVER=SPG 5.10", "PROTVER=34.10", "MOD=MIA-M10Q"]);
        let mut stream = b"$GNGGA,,,,,,0,00,99.99,,,,,,*56\r\n".to_vec();
        stream.extend_from_slice(&frame);
        assert_eq!(feed(&stream).unwrap().as_str(), "u-blox MIA-M10Q");
    }

    #[test]
    fn a_u_blox_that_names_no_module_is_still_a_u_blox() {
        let frame = mon_ver(&["FWVER=SPG 5.10"]);
        assert_eq!(feed(&frame).unwrap().as_str(), "u-blox");
    }

    #[test]
    fn a_damaged_frame_names_nothing() {
        let mut frame = mon_ver(&["MOD=MIA-M10Q"]);
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert_eq!(feed(&frame), None);
    }

    #[test]
    fn an_answer_from_casic_firmware_is_the_l76k() {
        let line = b"$GPRMC,,V,,,,,,,,,,N*53\r\n$GPTXT,01,01,02,SW=URANUS5,V5.3.0.0*1D\r\n";
        assert_eq!(feed(line).unwrap().as_str(), "L76K");
    }

    #[test]
    fn other_text_and_bad_checksums_name_nothing() {
        assert_eq!(feed(b"$GPTXT,01,01,01,ANTENNA OK*35\r\n"), None);
        assert_eq!(feed(b"$GPTXT,01,01,02,SW=URANUS5,V5.3.0.0*1E\r\n"), None);
    }

    #[test]
    fn the_l76k_query_is_checksummed() {
        let line = &QUERIES[1][1..QUERIES[1].len() - 2];
        let star = line.iter().position(|&b| b == b'*').unwrap();
        let sum = line[..star].iter().fold(0, |sum, &b| sum ^ b);
        assert_eq!(&line[star + 1..], std::format!("{sum:02X}").as_bytes());
    }
}
