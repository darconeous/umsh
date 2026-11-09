//! The u-blox UBX frames UMSH sends and the few it reads.
//!
//! Receivers are otherwise read as NMEA and never configured. These exist
//! for boards whose receiver may be a u-blox: its own UART is the only way
//! to lower the draw of one with no enable or standby line, and it can be
//! asked for the time rather than waited on.

use crate::DateTime;

/// UBX-RXM-PMREQ: enter backup with no time limit, waking on activity at
/// the receiver's UART RX.
///
/// The receiver's RTC and backup RAM keep running, so the time it reports
/// on waking is still the time, and the fix that follows is a hot start.
/// The long form the M10 requires (version 0); `flags` sets `backup` and
/// `force`, and `wakeupSources` sets `uartrx`.
///
/// A receiver that does not speak UBX skips it as noise: an L76K's
/// binary protocol has another sync pair, and NMEA starts at `$`.
pub const BACKUP: [u8; 24] = with_checksum([
    0xB5, 0x62, // sync
    0x02, 0x41, // RXM-PMREQ
    0x10, 0x00, // payload length, little-endian
    0x00, // version
    0x00, 0x00, 0x00, // reserved
    0x00, 0x00, 0x00, 0x00, // duration: none
    0x06, 0x00, 0x00, 0x00, // flags: backup, force
    0x08, 0x00, 0x00, 0x00, // wakeupSources: uartrx
    0x00, 0x00, // checksum
]);

/// What wakes a receiver parked by [`BACKUP`]: any edge at its RX does,
/// and the byte that carries it is lost.
pub const WAKE: u8 = 0xFF;

/// UBX-NAV-TIMEUTC, polled: the message with an empty payload. A u-blox
/// answers with its latest navigation epoch's UTC time and says whether
/// it vouches for it; anything else skips it, as with [`BACKUP`].
pub const POLL_TIME_UTC: [u8; 8] = with_checksum([
    0xB5, 0x62, // sync
    0x01, 0x21, // NAV-TIMEUTC
    0x00, 0x00, // payload length: none
    0x00, 0x00, // checksum
]);

/// NAV-TIMEUTC's class and ID.
const NAV_TIMEUTC: (u8, u8) = (0x01, 0x21);
/// NAV-TIMEUTC's payload length.
const TIME_UTC_LEN: usize = 20;
/// NAV-TIMEUTC `valid`: the time of week is known.
const VALID_TOW: u8 = 1 << 0;
/// NAV-TIMEUTC `valid`: the week number is known.
const VALID_WKN: u8 = 1 << 1;

/// Fill in the 8-bit Fletcher checksum over the class, id, length, and
/// payload, which is every byte but the sync pair and the checksum itself.
const fn with_checksum<const N: usize>(mut frame: [u8; N]) -> [u8; N] {
    let (mut a, mut b) = (0u8, 0u8);
    let mut i = 2;
    while i < N - 2 {
        a = a.wrapping_add(frame[i]);
        b = b.wrapping_add(a);
        i += 1;
    }
    frame[N - 2] = a;
    frame[N - 1] = b;
    frame
}

/// One step through a UBX frame, as [`Framer::push`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// A frame's header completed.
    Header { class: u8, id: u8, len: u16 },
    /// Byte `at` of its payload.
    Payload { at: u16, byte: u8 },
    /// The frame ended: `true` when its checksum matched.
    End(bool),
}

/// Where a frame being read has got to.
#[derive(Clone, Copy)]
enum State {
    /// Not in a frame; `true` once the first sync byte is seen.
    Idle(bool),
    /// The class, the ID, and the payload length, `at` bytes in.
    Header { at: u8, header: [u8; 4] },
    /// The payload, `at` of `len` bytes read.
    Payload { at: u16, len: u16 },
    /// The checksum's first byte, then its second.
    Checksum(Option<u8>),
}

/// Finds UBX frames among whatever else a receiver sends, and checks each.
///
/// A frame is reported a byte at a time rather than buffered, so a reader
/// keeps only the frames it wants, and only the parts of them it wants.
pub struct Framer {
    state: State,
    /// The Fletcher sums over the frame being read.
    sums: (u8, u8),
}

impl Default for Framer {
    fn default() -> Self {
        Self::new()
    }
}

impl Framer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Idle(false),
            sums: (0, 0),
        }
    }

    /// Abandon any frame in progress: bytes it was waiting for were lost.
    pub fn reset(&mut self) {
        self.state = State::Idle(false);
    }

    fn sum(&mut self, byte: u8) {
        self.sums.0 = self.sums.0.wrapping_add(byte);
        self.sums.1 = self.sums.1.wrapping_add(self.sums.0);
    }

    /// Feed one byte, learning what it was to the frame it belongs to.
    pub fn push(&mut self, byte: u8) -> Option<Step> {
        let mut step = None;
        self.state = match self.state {
            State::Idle(false) => State::Idle(byte == 0xB5),
            State::Idle(true) if byte == 0x62 => {
                self.sums = (0, 0);
                State::Header {
                    at: 0,
                    header: [0; 4],
                }
            }
            State::Idle(true) => State::Idle(byte == 0xB5),
            State::Header { at, mut header } => {
                self.sum(byte);
                header[usize::from(at)] = byte;
                if at < 3 {
                    State::Header { at: at + 1, header }
                } else {
                    let len = u16::from_le_bytes([header[2], header[3]]);
                    step = Some(Step::Header {
                        class: header[0],
                        id: header[1],
                        len,
                    });
                    if len == 0 {
                        State::Checksum(None)
                    } else {
                        State::Payload { at: 0, len }
                    }
                }
            }
            State::Payload { at, len } => {
                self.sum(byte);
                step = Some(Step::Payload { at, byte });
                if at + 1 < len {
                    State::Payload { at: at + 1, len }
                } else {
                    State::Checksum(None)
                }
            }
            State::Checksum(None) => State::Checksum(Some(byte)),
            State::Checksum(Some(first)) => {
                step = Some(Step::End((first, byte) == self.sums));
                State::Idle(false)
            }
        };
        step
    }
}

/// What a receiver said in UBX-NAV-TIMEUTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeUtc {
    /// The time, when the receiver vouches for both the time of day and
    /// the date, and the instant is plausible.
    ///
    /// `validUTC` is not required: it says only whether the leap-second
    /// count came from the sky or the receiver's default, which differ by
    /// a few seconds at most.
    pub time: Option<DateTime>,
    /// The receiver's estimate of its error, in nanoseconds.
    pub accuracy_ns: u32,
    /// The `valid` flags as sent.
    pub valid: u8,
}

impl TimeUtc {
    fn parse(payload: &[u8; TIME_UTC_LEN]) -> Self {
        let valid = payload[19];
        let at = DateTime {
            year: i32::from(u16::from_le_bytes([payload[12], payload[13]])),
            month: payload[14],
            day: payload[15],
            hour: payload[16],
            minute: payload[17],
            second: payload[18],
        };
        let vouched = (valid & (VALID_TOW | VALID_WKN)) == (VALID_TOW | VALID_WKN);
        Self {
            time: if vouched { at.plausible() } else { None },
            accuracy_ns: u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
            valid,
        }
    }
}

/// Reads answers to [`POLL_TIME_UTC`] out of whatever else a receiver
/// sends.
pub struct TimeUtcReader {
    framer: Framer,
    /// The frame being read is a NAV-TIMEUTC.
    reading: bool,
    payload: [u8; TIME_UTC_LEN],
}

impl Default for TimeUtcReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeUtcReader {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            framer: Framer::new(),
            reading: false,
            payload: [0; TIME_UTC_LEN],
        }
    }

    /// Abandon any answer in progress: bytes it was waiting for were lost.
    pub fn reset(&mut self) {
        self.framer.reset();
        self.reading = false;
    }

    /// The answer, once `byte` completes an intact one.
    pub fn push(&mut self, byte: u8) -> Option<TimeUtc> {
        match self.framer.push(byte)? {
            Step::Header { class, id, len } => {
                self.reading = (class, id) == NAV_TIMEUTC && usize::from(len) == TIME_UTC_LEN;
            }
            Step::Payload { at, byte } => {
                if self.reading {
                    self.payload[usize::from(at)] = byte;
                }
            }
            Step::End(intact) => {
                let read = core::mem::take(&mut self.reading) && intact;
                return read.then(|| TimeUtc::parse(&self.payload));
            }
        }
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A UBX frame of `class`, `id`, and `payload`, checksummed.
    pub(crate) fn frame(class: u8, id: u8, payload: &[u8]) -> std::vec::Vec<u8> {
        let len = (payload.len() as u16).to_le_bytes();
        let mut frame = std::vec![0xB5, 0x62, class, id, len[0], len[1]];
        frame.extend_from_slice(payload);
        let (mut a, mut b) = (0u8, 0u8);
        for &byte in &frame[2..] {
            a = a.wrapping_add(byte);
            b = b.wrapping_add(a);
        }
        frame.extend_from_slice(&[a, b]);
        frame
    }

    /// A NAV-TIMEUTC answer for `at`, with `valid` flags and a 20 ms
    /// accuracy estimate.
    pub(crate) fn time_utc(at: DateTime, valid: u8) -> std::vec::Vec<u8> {
        let mut payload = [0u8; TIME_UTC_LEN];
        payload[0..4].copy_from_slice(&123_456_000u32.to_le_bytes());
        payload[4..8].copy_from_slice(&20_000_000u32.to_le_bytes());
        payload[12..14].copy_from_slice(&(at.year as u16).to_le_bytes());
        payload[14..19].copy_from_slice(&[at.month, at.day, at.hour, at.minute, at.second]);
        payload[19] = valid;
        frame(0x01, 0x21, &payload)
    }

    pub(crate) const AT: DateTime = DateTime {
        year: 2026,
        month: 11,
        day: 9,
        hour: 18,
        minute: 4,
        second: 51,
    };

    fn read(bytes: &[u8]) -> Option<TimeUtc> {
        let mut reader = TimeUtcReader::new();
        bytes.iter().find_map(|&byte| reader.push(byte))
    }

    #[test]
    fn backup_frame_checksum() {
        assert_eq!(BACKUP[22..], [0x61, 0x6B]);
    }

    #[test]
    fn backup_frame_length_matches_payload() {
        let payload = u16::from_le_bytes([BACKUP[4], BACKUP[5]]) as usize;
        assert_eq!(BACKUP.len(), 6 + payload + 2);
    }

    #[test]
    fn time_poll_frame_checksum() {
        assert_eq!(
            POLL_TIME_UTC,
            [0xB5, 0x62, 0x01, 0x21, 0x00, 0x00, 0x22, 0x67]
        );
    }

    #[test]
    fn a_vouched_answer_among_nmea_gives_the_time() {
        let mut stream = b"$GNGGA,,,,,,0,00,99.99,,,,,,*56\r\n".to_vec();
        stream.extend_from_slice(&time_utc(AT, VALID_TOW | VALID_WKN | 0x04));
        let answer = read(&stream).unwrap();
        assert_eq!(answer.time, Some(AT));
        assert_eq!(answer.accuracy_ns, 20_000_000);
        assert_eq!(answer.valid, 0x07);
    }

    /// The leap seconds known or not, the time is within seconds.
    #[test]
    fn an_answer_without_valid_utc_still_gives_the_time() {
        let answer = read(&time_utc(AT, VALID_TOW | VALID_WKN)).unwrap();
        assert_eq!(answer.time, Some(AT));
    }

    #[test]
    fn an_answer_the_receiver_does_not_vouch_for_gives_no_time() {
        for valid in [0, VALID_TOW, VALID_WKN] {
            let answer = read(&time_utc(AT, valid)).unwrap();
            assert_eq!(answer.time, None, "valid {valid:#04x}");
            assert_eq!(answer.valid, valid);
        }
    }

    /// The same floor as NMEA's: a receiver with no clock reports its
    /// epoch's start, not nothing.
    #[test]
    fn an_implausible_answer_gives_no_time() {
        let at = DateTime { year: 2019, ..AT };
        let answer = read(&time_utc(at, VALID_TOW | VALID_WKN)).unwrap();
        assert_eq!(answer.time, None);
    }

    #[test]
    fn a_damaged_answer_is_not_read() {
        let mut frame = time_utc(AT, 0x07);
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert_eq!(read(&frame), None);
    }

    #[test]
    fn other_frames_are_not_read() {
        assert_eq!(read(&frame(0x01, 0x07, &[0; 92])), None);
        assert_eq!(read(&frame(0x01, 0x21, &[0; 8])), None);
    }

    /// A frame cut short loses only itself once the reader is told.
    #[test]
    fn a_reset_drops_the_answer_in_progress() {
        let frame = time_utc(AT, 0x07);
        let mut reader = TimeUtcReader::new();
        for &byte in &frame[..10] {
            assert_eq!(reader.push(byte), None);
        }
        reader.reset();
        let answer = frame.iter().find_map(|&byte| reader.push(byte));
        assert_eq!(answer.and_then(|answer| answer.time), Some(AT));
    }
}
