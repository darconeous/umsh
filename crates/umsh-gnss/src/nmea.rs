//! NMEA 0183 sentence assembly and parsing.
//!
//! Every receiver in the tree speaks the same handful of sentences, so
//! this is the one parser and each board contributes only its power
//! sequencing. Four sentence types carry everything UMSH wants:
//!
//! * **RMC** — the time, the date, and whether the fix is valid. The only
//!   sentence carrying a *date*, which is why it is the one that can set
//!   a wall clock.
//! * **GGA** — fix quality, altitude, and satellites in use.
//! * **GSA** — whether the solution is two- or three-dimensional, and the
//!   dilution of precision.
//! * **GSV** — satellites in view.
//!
//! # Integers only
//!
//! No floating point anywhere. Latitude and longitude are parsed into
//! `i32` at 1e-7 degrees, which resolves about 11 mm — two orders finer
//! than the 7-byte location encoding needs, and exact, so a position
//! never shifts by a rounding step between the receiver and the wire.
//! Parsing `ddmm.mmmm` in binary floating point would introduce error
//! before the encoder ever saw the value.
//!
//! # What is not checked
//!
//! Sentences whose checksum fails, whose fields are malformed, or whose
//! talker is unknown are dropped silently. A receiver emits a torn line
//! on every power-up and whenever the UART resynchronizes, and treating
//! that as an error condition would mean reporting a fault on every cold
//! start.

/// Longest NMEA sentence accepted, including `$`, the checksum, and the
/// line terminator.
///
/// The standard caps a sentence at 82 characters. Some receivers exceed
/// it on GSV bursts, so this is generous: an over-long line is dropped,
/// and dropping a real sentence costs a fix cycle.
pub const MAX_SENTENCE: usize = 120;

/// Largest number of comma-separated fields kept from one sentence.
///
/// GSV is the widest sentence that matters and uses 20; the rest fit in
/// well under half that.
const MAX_FIELDS: usize = 24;

/// Latitude and longitude scale: 1e-7 degrees per unit.
pub const DEGREE_SCALE: i32 = 10_000_000;

/// One parsed sentence, reduced to what UMSH uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sentence {
    /// Recommended minimum data: position, time, date, and validity.
    Rmc(Rmc),
    /// Fix data: quality, altitude, satellites in use.
    Gga(Gga),
    /// Active satellites and dilution of precision.
    Gsa(Gsa),
    /// Satellites in view.
    Gsv(Gsv),
}

/// The `RMC` sentence.
///
/// The only one that carries a date, and therefore the only one that can
/// establish what day it is. A receiver emits RMC with `status = V`
/// (void) while searching, sometimes already carrying a valid time from
/// its own real-time clock — which is exactly the case the
/// [`valid`](Self::valid) flag separates from a real fix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rmc {
    /// Whether the receiver reports the position as valid (`A`, not `V`).
    pub valid: bool,
    /// UTC instant, when both the time and date fields were present and
    /// in range.
    pub time: Option<crate::DateTime>,
    /// Latitude in 1e-7 degrees, positive north.
    pub latitude: Option<i32>,
    /// Longitude in 1e-7 degrees, positive east.
    pub longitude: Option<i32>,
}

/// The `GGA` sentence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gga {
    /// Fix-quality indicator: 0 invalid, 1 GPS, 2 differential, and so on.
    /// Anything nonzero is a fix of some kind.
    pub quality: u8,
    /// Satellites used in the solution.
    pub sats_used: u8,
    /// Horizontal dilution of precision, in hundredths.
    ///
    /// The same figure `GSA` carries, and worth taking from here as well
    /// because a receiver may emit one sentence and not the other: the
    /// AG3335 ships from some vendors with `GSA` switched off in its own
    /// non-volatile memory, and `GGA` is then the only source of it.
    pub hdop_centi: Option<u16>,
    /// Altitude above mean sea level, in meters.
    pub altitude_m: Option<i32>,
    /// Latitude in 1e-7 degrees, positive north.
    pub latitude: Option<i32>,
    /// Longitude in 1e-7 degrees, positive east.
    pub longitude: Option<i32>,
}

/// The `GSA` sentence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gsa {
    /// 1 no fix, 2 two-dimensional, 3 three-dimensional.
    pub fix_mode: u8,
    /// Horizontal dilution of precision, in hundredths.
    pub hdop_centi: Option<u16>,
}

/// The `GSV` sentence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gsv {
    /// Satellites this constellation has in view.
    pub in_view: u8,
    /// Which message of the burst this is, 1-based. Only the first
    /// carries a count worth reading; the rest repeat it.
    pub message: u8,
    /// The two-character talker prefix that sent it.
    ///
    /// The only sentence whose talker matters: a multi-constellation
    /// receiver emits a separate GSV burst per constellation, each
    /// counting only its own satellites, so summing them needs to know
    /// which is which.
    pub talker: [u8; 2],
}

/// Assembles bytes from a UART into complete sentences.
///
/// Resynchronizing is the normal case, not the exceptional one: a
/// receiver powering up mid-sentence, a UART overrun, and a line longer
/// than [`MAX_SENTENCE`] all leave the assembler mid-line, and all of
/// them recover at the next `$` without any caller involvement.
pub struct Assembler {
    buf: [u8; MAX_SENTENCE],
    len: usize,
    /// False until the first `$`, so the partial line a receiver was
    /// mid-way through when we started listening is discarded rather
    /// than parsed.
    started: bool,
    /// Set when the line overran; the rest of it is discarded and the
    /// next `$` starts fresh.
    overrun: bool,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    /// A fresh assembler, waiting for the first `$`.
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_SENTENCE],
            len: 0,
            started: false,
            overrun: false,
        }
    }

    /// Discard any partial line. Call after powering the receiver, so
    /// bytes from before the power cycle cannot join a sentence from
    /// after it.
    pub fn reset(&mut self) {
        self.len = 0;
        self.started = false;
        self.overrun = false;
    }

    /// Feed one byte, yielding a parsed sentence when one completes.
    ///
    /// Returns `None` for every byte that does not finish a *valid*
    /// sentence — including ones that finish an invalid one, since a bad
    /// checksum and an unrecognized sentence are both simply nothing to
    /// report.
    pub fn push(&mut self, byte: u8) -> Option<Sentence> {
        match byte {
            b'$' => {
                self.len = 0;
                self.started = true;
                self.overrun = false;
                None
            }
            b'\r' | b'\n' => {
                let complete = self.started && !self.overrun && self.len > 0;
                let parsed = complete.then(|| parse(&self.buf[..self.len])).flatten();
                self.len = 0;
                self.started = false;
                parsed
            }
            _ => {
                if !self.started || self.overrun {
                    return None;
                }
                if self.len == MAX_SENTENCE {
                    // Drop the whole line rather than a truncated tail
                    // that might still checksum by coincidence.
                    self.overrun = true;
                    return None;
                }
                self.buf[self.len] = byte;
                self.len += 1;
                None
            }
        }
    }
}

/// Parse one sentence body: everything between the `$` and the line
/// terminator, checksum included.
pub fn parse(body: &[u8]) -> Option<Sentence> {
    let payload = verify_checksum(body)?;
    let mut fields = Fields::split(payload);
    let kind = fields.next()?;
    // The talker prefix is two characters — `GP`, `GN`, `GA`, `BD`, `GL`
    // and others — and says which constellation produced the sentence.
    // UMSH wants the solution, not its provenance, so any talker is
    // accepted and only the three-letter type is dispatched on.
    if kind.len() != 5 {
        return None;
    }
    match &kind[2..] {
        b"RMC" => parse_rmc(fields).map(Sentence::Rmc),
        b"GGA" => parse_gga(fields).map(Sentence::Gga),
        b"GSA" => parse_gsa(fields).map(Sentence::Gsa),
        b"GSV" => parse_gsv(fields, [kind[0], kind[1]]).map(Sentence::Gsv),
        _ => None,
    }
}

/// Strip and check the `*HH` trailer, returning the payload it covers.
///
/// A sentence with no trailer at all is rejected. Some receivers omit it
/// on proprietary sentences, and accepting an unchecked line would mean
/// trusting a position that nothing verified.
fn verify_checksum(body: &[u8]) -> Option<&[u8]> {
    let star = body.iter().rposition(|&byte| byte == b'*')?;
    let (payload, trailer) = body.split_at(star);
    let digits = trailer.get(1..3)?;
    if trailer.len() != 3 {
        return None;
    }
    let expected = (hex_digit(digits[0])? << 4) | hex_digit(digits[1])?;
    let actual = payload.iter().fold(0u8, |sum, &byte| sum ^ byte);
    (actual == expected).then_some(payload)
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// A comma-separated field walker.
///
/// Bounded rather than unbounded: a sentence with more fields than
/// [`MAX_FIELDS`] simply stops yielding, which is what a GSV burst
/// listing more satellites than we care about should do.
struct Fields<'a> {
    rest: &'a [u8],
    yielded: usize,
    done: bool,
}

impl<'a> Fields<'a> {
    fn split(payload: &'a [u8]) -> Self {
        Self {
            rest: payload,
            yielded: 0,
            done: false,
        }
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.done || self.yielded == MAX_FIELDS {
            return None;
        }
        self.yielded += 1;
        match self.rest.iter().position(|&byte| byte == b',') {
            Some(comma) => {
                let (field, rest) = self.rest.split_at(comma);
                self.rest = &rest[1..];
                Some(field)
            }
            None => {
                self.done = true;
                Some(self.rest)
            }
        }
    }

    /// The next field, or an empty slice when the sentence ended early.
    ///
    /// Receivers routinely truncate trailing empty fields, so a missing
    /// tail field means "absent", not "malformed".
    fn next_or_empty(&mut self) -> &'a [u8] {
        self.next().unwrap_or(&[])
    }
}

fn parse_rmc(mut fields: Fields<'_>) -> Option<Rmc> {
    let time = fields.next_or_empty();
    let status = fields.next_or_empty();
    let lat = fields.next_or_empty();
    let lat_hemisphere = fields.next_or_empty();
    let lon = fields.next_or_empty();
    let lon_hemisphere = fields.next_or_empty();
    let _speed = fields.next_or_empty();
    let _course = fields.next_or_empty();
    let date = fields.next_or_empty();

    Some(Rmc {
        valid: status == b"A",
        time: parse_instant(date, time),
        latitude: parse_degrees(lat, lat_hemisphere, 2),
        longitude: parse_degrees(lon, lon_hemisphere, 3),
    })
}

fn parse_gga(mut fields: Fields<'_>) -> Option<Gga> {
    let _time = fields.next_or_empty();
    let lat = fields.next_or_empty();
    let lat_hemisphere = fields.next_or_empty();
    let lon = fields.next_or_empty();
    let lon_hemisphere = fields.next_or_empty();
    let quality = fields.next_or_empty();
    let sats = fields.next_or_empty();
    let hdop = fields.next_or_empty();
    let altitude = fields.next_or_empty();

    Some(Gga {
        quality: parse_u8(quality).unwrap_or(0),
        sats_used: parse_u8(sats).unwrap_or(0),
        hdop_centi: parse_fixed(hdop, 2).map(|value| value as u16),
        // Rounded to whole meters: the identity option and
        // `PROP_GNSS_ALTITUDE` both carry meters, and a receiver's tenths
        // are well inside its own vertical error anyway.
        altitude_m: parse_fixed(altitude, 0).map(|value| value as i32),
        latitude: parse_degrees(lat, lat_hemisphere, 2),
        longitude: parse_degrees(lon, lon_hemisphere, 3),
    })
}

fn parse_gsa(mut fields: Fields<'_>) -> Option<Gsa> {
    let _selection = fields.next_or_empty();
    let mode = fields.next_or_empty();
    // Twelve satellite-identifier slots sit between the mode and the
    // dilution figures, and are always present even when empty.
    for _ in 0..12 {
        let _ = fields.next_or_empty();
    }
    let _pdop = fields.next_or_empty();
    let hdop = fields.next_or_empty();

    Some(Gsa {
        fix_mode: parse_u8(mode).unwrap_or(0),
        hdop_centi: parse_fixed(hdop, 2).and_then(|value| u16::try_from(value).ok()),
    })
}

fn parse_gsv(mut fields: Fields<'_>, talker: [u8; 2]) -> Option<Gsv> {
    let _messages = fields.next_or_empty();
    let message = fields.next_or_empty();
    let in_view = fields.next_or_empty();

    Some(Gsv {
        in_view: parse_u8(in_view).unwrap_or(0),
        message: parse_u8(message).unwrap_or(0),
        talker,
    })
}

/// Combine the `ddmmyy` date field and the `hhmmss.sss` time field into
/// one instant. `None` unless both are present and name a real moment.
fn parse_instant(date: &[u8], time: &[u8]) -> Option<crate::DateTime> {
    if date.len() != 6 || time.len() < 6 {
        return None;
    }
    let day = parse_pair(&date[0..2])?;
    let month = parse_pair(&date[2..4])?;
    let year = parse_pair(&date[4..6])?;
    let hour = parse_pair(&time[0..2])?;
    let minute = parse_pair(&time[2..4])?;
    let second = parse_pair(&time[4..6])?;

    // Two-digit years window on the GPS epoch, 1980–2079 — the convention
    // NMEA receivers themselves use, and the one that matters here because
    // a receiver whose clock has been lost reports 1980 rather than
    // nothing. Mapping that to 2080 instead would turn an obvious fault
    // into a plausible-looking future date, which is the harder failure to
    // notice and the more damaging one to believe.
    let year = if year >= 80 {
        1900 + i32::from(year)
    } else {
        2000 + i32::from(year)
    };

    let at = crate::DateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    };
    if !at.is_valid() {
        return None;
    }
    // A well-formed instant from before this software existed is a
    // receiver telling us it has no clock. See [`MIN_PLAUSIBLE_EPOCH`].
    match at.to_unix() {
        Some(epoch) if epoch >= crate::epoch::MIN_PLAUSIBLE_EPOCH => Some(at),
        _ => None,
    }
}

/// Parse a `ddmm.mmmm` / `dddmm.mmmm` coordinate into 1e-7 degrees.
///
/// `degree_digits` is 2 for latitude and 3 for longitude — the field is
/// positional, not delimited, which is the one genuinely awkward thing
/// about the format.
///
/// Entirely integer: the minutes are read as a scaled integer and divided
/// by 60 in fixed point, so the result is exact to the last digit the
/// receiver sent.
fn parse_degrees(field: &[u8], hemisphere: &[u8], degree_digits: usize) -> Option<i32> {
    if field.len() < degree_digits {
        return None;
    }
    let (degrees, minutes) = field.split_at(degree_digits);
    let degrees = parse_unsigned(degrees)?;
    // Minutes at 1e-7 degrees would overflow, so scale to 1e-5 minutes
    // (0.6 mm) and divide by 60 into the final scale.
    let minutes = parse_fixed(minutes, 5)?;
    if minutes >= 60 * 100_000 {
        return None;
    }
    let scaled = degrees as i64 * DEGREE_SCALE as i64 + (minutes as i64 * 100) / 60;
    let signed = match hemisphere {
        b"N" | b"E" => scaled,
        b"S" | b"W" => -scaled,
        _ => return None,
    };
    i32::try_from(signed).ok()
}

/// Parse a decimal field into a fixed-point integer with `decimals`
/// digits after the point, truncating or zero-extending as needed.
///
/// Handles the leading sign, an absent fractional part, and a bare `.`,
/// all of which appear in the wild.
fn parse_fixed(field: &[u8], decimals: u32) -> Option<i64> {
    let (negative, digits) = match field.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, field),
    };
    if digits.is_empty() {
        return None;
    }
    let (whole, fraction) = match digits.iter().position(|&byte| byte == b'.') {
        Some(point) => (&digits[..point], &digits[point + 1..]),
        None => (digits, &[][..]),
    };
    let mut value = 0i64;
    for &byte in whole {
        value = value
            .checked_mul(10)?
            .checked_add(i64::from(digit(byte)?))?;
    }
    for index in 0..decimals {
        value = value.checked_mul(10)?;
        if let Some(&byte) = fraction.get(index as usize) {
            value = value.checked_add(i64::from(digit(byte)?))?;
        }
    }
    // Digits past the requested precision still have to be digits: a
    // field ending in garbage is a malformed field, not a rounded one.
    for &byte in fraction.iter().skip(decimals as usize) {
        digit(byte)?;
    }
    Some(if negative { -value } else { value })
}

fn parse_unsigned(field: &[u8]) -> Option<u32> {
    if field.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for &byte in field {
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(digit(byte)?))?;
    }
    Some(value)
}

fn parse_u8(field: &[u8]) -> Option<u8> {
    u8::try_from(parse_unsigned(field)?).ok()
}

/// Exactly two digits, as every fixed-width date and time subfield is.
fn parse_pair(field: &[u8]) -> Option<u8> {
    match field {
        [high, low] => Some(digit(*high)? * 10 + digit(*low)?),
        _ => None,
    }
}

const fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    /// Feed a whole line, terminator included, and take what comes out.
    fn feed(assembler: &mut Assembler, line: &str) -> Option<Sentence> {
        let mut last = None;
        for byte in line.bytes() {
            if let Some(sentence) = assembler.push(byte) {
                last = Some(sentence);
            }
        }
        last
    }

    /// Wrap a sentence body — no leading `$`, no trailer — into a
    /// complete line with a correct checksum.
    ///
    /// Fixtures are written without checksums on purpose: a hand-computed
    /// one is a second thing that can be wrong, and a test that fails
    /// because its own fixture is malformed proves nothing about the
    /// parser. The checksum logic itself is pinned by the verbatim
    /// real-world sentences below and by
    /// [`a_bad_checksum_is_dropped_silently`].
    fn line(body: &str) -> heapless::String<MAX_SENTENCE> {
        let checksum = body.bytes().fold(0u8, |sum, byte| sum ^ byte);
        let mut out = heapless::String::new();
        out.push('$').unwrap();
        out.push_str(body).unwrap();
        write!(out, "*{checksum:02X}\r\n").unwrap();
        out
    }

    /// One checksummed sentence body through a fresh assembler.
    fn one(body: &str) -> Option<Sentence> {
        feed(&mut Assembler::new(), &line(body))
    }

    /// One verbatim line — checksum and terminator exactly as given —
    /// through a fresh assembler.
    fn one_raw(raw: &str) -> Option<Sentence> {
        feed(&mut Assembler::new(), raw)
    }

    #[test]
    fn a_valid_rmc_carries_a_position_and_an_instant() {
        let Some(Sentence::Rmc(rmc)) =
            one("GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230326,003.1,W")
        else {
            panic!("RMC did not parse");
        };
        assert!(rmc.valid);
        assert_eq!(
            rmc.time,
            Some(crate::DateTime {
                year: 2026,
                month: 3,
                day: 23,
                hour: 12,
                minute: 35,
                second: 19,
            })
        );
        // 48°07.038' N = 48.1173°, 011°31.000' E = 11.516667°.
        assert_eq!(rmc.latitude, Some(481_173_000));
        assert_eq!(rmc.longitude, Some(115_166_666));
    }

    /// A receiver emits RMC long before it has a fix, and it may already
    /// know the time from its own real-time clock. Both facts have to
    /// survive parsing separately.
    #[test]
    fn a_void_rmc_can_still_carry_a_time() {
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,081836.00,V,,,,,,,130926,,") else {
            panic!("void RMC did not parse");
        };
        assert!(!rmc.valid, "a void fix must not read as valid");
        assert_eq!(rmc.latitude, None);
        assert_eq!(rmc.longitude, None);
        assert_eq!(
            rmc.time.map(|at| (at.year, at.month, at.day, at.hour)),
            Some((2026, 9, 13, 8))
        );
    }

    /// A receiver whose backup domain lost power comes back reporting the
    /// start of its own epoch, in a sentence that is well-formed in every
    /// other respect. Believing it would set the device's clock to 1980 —
    /// or, with the wrong two-digit-year window, to 2080, which looks far
    /// more like a real reading and is no less wrong.
    ///
    /// Observed verbatim on a T1000-E whose AG3335 had been power-cycled.
    #[test]
    fn a_receiver_reporting_its_own_epoch_is_reporting_no_clock() {
        let Some(Sentence::Rmc(rmc)) = one("GNRMC,000346.000,V,,,,,,,060180,,,N,V") else {
            panic!("RMC did not parse");
        };
        assert_eq!(
            rmc.time, None,
            "the GPS epoch was accepted as the current time"
        );
    }

    /// The window is the GPS epoch's, 1980–2079, not a naive `2000 + yy`.
    #[test]
    fn two_digit_years_window_on_the_gps_epoch() {
        // 2026 is inside the plausible range and parses.
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,081836.00,V,,,,,,,130826,,") else {
            panic!("RMC did not parse");
        };
        assert_eq!(rmc.time.map(|at| at.year), Some(2026));

        // 99 is 1999, which is implausible — and would have been 2099
        // under the naive window, which is not.
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,081836.00,V,,,,,,,130899,,") else {
            panic!("RMC did not parse");
        };
        assert_eq!(rmc.time, None);
    }

    /// A cold receiver emits RMC with no time and no date at all.
    #[test]
    fn a_cold_rmc_carries_nothing() {
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,,V,,,,,,,,,,N") else {
            panic!("cold RMC did not parse");
        };
        assert!(!rmc.valid);
        assert_eq!(rmc.time, None);
        assert_eq!(rmc.latitude, None);
    }

    #[test]
    fn gga_carries_quality_altitude_and_satellite_count() {
        let Some(Sentence::Gga(gga)) =
            one("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n")
        else {
            panic!("GGA did not parse");
        };
        assert_eq!(gga.quality, 1);
        assert_eq!(gga.sats_used, 8);
        assert_eq!(gga.altitude_m, Some(545));
        assert_eq!(gga.latitude, Some(481_173_000));
    }

    #[test]
    fn gga_handles_a_negative_altitude_below_sea_level() {
        let Some(Sentence::Gga(gga)) =
            one("GPGGA,123519,3129.000,N,03521.000,E,1,09,0.9,-412.5,M,17.2,M,,")
        else {
            panic!("GGA did not parse");
        };
        assert_eq!(gga.altitude_m, Some(-412));
    }

    #[test]
    fn gsa_reports_the_solution_dimension_and_dilution() {
        let Some(Sentence::Gsa(gsa)) = one("$GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*39\r\n")
        else {
            panic!("GSA did not parse");
        };
        assert_eq!(gsa.fix_mode, 3);
        assert_eq!(gsa.hdop_centi, Some(130));

        let Some(Sentence::Gsa(gsa)) = one("$GPGSA,A,1,,,,,,,,,,,,,,,*1E\r\n") else {
            panic!("no-fix GSA did not parse");
        };
        assert_eq!(gsa.fix_mode, 1);
        assert_eq!(gsa.hdop_centi, None);
    }

    #[test]
    fn gsv_reports_satellites_in_view() {
        let Some(Sentence::Gsv(gsv)) =
            one("$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74\r\n")
        else {
            panic!("GSV did not parse");
        };
        assert_eq!(gsv.in_view, 11);
        assert_eq!(gsv.message, 1);
    }

    /// Every talker prefix names a constellation, and UMSH wants the
    /// solution rather than its provenance.
    #[test]
    fn any_talker_prefix_is_accepted() {
        for body in [
            "GNRMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130926,011.3,E",
            "BDRMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130926,011.3,E",
            "GARMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130926,011.3,E",
        ] {
            assert!(
                matches!(one(body), Some(Sentence::Rmc(_))),
                "talker rejected: {body}"
            );
        }
    }

    #[test]
    fn southern_and_western_hemispheres_are_negative() {
        let Some(Sentence::Rmc(rmc)) =
            one("GPRMC,081836,A,3751.65,S,14507.36,W,000.0,360.0,130926,011.3,E")
        else {
            panic!("RMC did not parse");
        };
        // 37°51.65' S = -37.860833°, 145°07.36' W = -145.122666°.
        assert_eq!(rmc.latitude, Some(-378_608_333));
        assert_eq!(rmc.longitude, Some(-1_451_226_666));
    }

    #[test]
    fn a_bad_checksum_is_dropped_silently() {
        assert_eq!(
            one_raw("$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230326,003.1,W*00\r\n"),
            None
        );
        // Truncated, absent, and non-hex trailers alike.
        assert_eq!(one_raw("$GPRMC,123519,A*6\r\n"), None);
        assert_eq!(one_raw("$GPRMC,123519,A\r\n"), None);
        assert_eq!(one_raw("$GPRMC,123519,A*ZZ\r\n"), None);
    }

    /// The normal case on every cold start: the receiver was mid-line
    /// when the UART came up.
    #[test]
    fn a_torn_leading_line_is_discarded_and_the_next_one_parses() {
        let mut assembler = Assembler::new();
        // Arrives with no leading `$` — the tail of a sentence sent
        // before anyone was listening.
        assert_eq!(feed(&mut assembler, "038,N,01131.000,E*11\r\n"), None);
        assert!(matches!(
            feed(&mut assembler, &line("GPGSA,A,3,04,,,,,,,,,,,,2.5,1.3,2.1")),
            Some(Sentence::Gsa(_))
        ));
    }

    /// A `$` mid-line means the previous line was cut short; the parser
    /// starts over rather than splicing the two together.
    #[test]
    fn a_restart_mid_sentence_abandons_the_partial_line() {
        let mut assembler = Assembler::new();
        assert_eq!(feed(&mut assembler, "$GPRMC,1235"), None);
        assert!(matches!(
            feed(&mut assembler, &line("GPGSV,3,1,11,03,03,111,00")),
            Some(Sentence::Gsv(_))
        ));
    }

    #[test]
    fn an_over_long_line_is_dropped_whole_and_recovery_is_immediate() {
        let mut assembler = Assembler::new();
        let mut body = heapless::String::<{ MAX_SENTENCE * 2 }>::new();
        body.push_str("GPGSV,3,1,11").unwrap();
        while body.len() < MAX_SENTENCE + 20 {
            body.push_str(",03,03,111,00").unwrap();
        }
        body.push_str("*4E\r\n").unwrap();
        assert_eq!(feed(&mut assembler, &body), None);
        assert!(matches!(
            feed(&mut assembler, &line("GPGSV,3,1,11,03,03,111,00")),
            Some(Sentence::Gsv(_))
        ));
    }

    /// Both line terminators, together or alone. Receivers disagree, and
    /// a run of them in a row must not synthesize an empty sentence.
    #[test]
    fn any_line_terminator_ends_a_sentence() {
        for terminator in ["\r\n", "\n", "\r", "\n\r\n"] {
            let mut assembler = Assembler::new();
            let mut raw = line("GPGSA,A,3,04,,,,,,,,,,,,2.5,1.3,2.1");
            // `line` already ends in CRLF; replace it with the one under
            // test.
            raw.truncate(raw.len() - 2);
            raw.push_str(terminator).unwrap();
            assert!(
                matches!(feed(&mut assembler, &raw), Some(Sentence::Gsa(_))),
                "terminator {terminator:?} did not end the sentence"
            );
        }
    }

    #[test]
    fn unknown_sentence_types_are_ignored() {
        // A valid, correctly-checksummed sentence UMSH has no use for.
        assert_eq!(
            one_raw("$GPVTG,054.7,T,034.4,M,005.5,N,010.2,K*48\r\n"),
            None
        );
        // A proprietary sentence, likewise.
        assert_eq!(one_raw("$PAIR001,066,0*3B\r\n"), None);
    }

    #[test]
    fn malformed_numeric_fields_do_not_produce_a_position() {
        // Letters where a coordinate belongs.
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,123519,A,48zz.038,N,01131.000,E,,,230326,,")
        else {
            panic!("RMC did not parse");
        };
        assert_eq!(rmc.latitude, None, "garbage parsed as a latitude");
        assert_eq!(rmc.longitude, Some(115_166_666), "the good field was lost");
    }

    #[test]
    fn an_out_of_range_date_or_time_yields_no_instant() {
        // Month 13.
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,123519,V,,,,,,,231326,,") else {
            panic!("RMC did not parse");
        };
        assert_eq!(rmc.time, None);
        // Hour 25.
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,253519,V,,,,,,,230326,,") else {
            panic!("RMC did not parse");
        };
        assert_eq!(rmc.time, None);
    }

    /// Sixty minutes is a degree; a field claiming it is malformed.
    #[test]
    fn minutes_at_or_past_sixty_are_rejected() {
        let Some(Sentence::Rmc(rmc)) = one("GPRMC,123519,A,4860.000,N,01131.000,E,,,230326,,")
        else {
            panic!("RMC did not parse");
        };
        assert_eq!(rmc.latitude, None);
    }

    #[test]
    fn fixed_point_parsing_truncates_rather_than_rounding() {
        // Truncating keeps the value a lower bound on what the receiver
        // said, which is what makes the location encoding's own
        // truncation property hold end to end.
        assert_eq!(parse_fixed(b"1.29", 1), Some(12));
        assert_eq!(parse_fixed(b"1.2", 3), Some(1_200));
        assert_eq!(parse_fixed(b"1", 2), Some(100));
        assert_eq!(parse_fixed(b"-0.5", 1), Some(-5));
        assert_eq!(parse_fixed(b"", 2), None);
        assert_eq!(parse_fixed(b"1.2x", 1), None);
        assert_eq!(parse_fixed(b"x", 0), None);
    }

    /// The assembler recovers cleanly across a receiver power cycle.
    #[test]
    fn resetting_discards_the_partial_line() {
        let mut assembler = Assembler::new();
        feed(&mut assembler, "$GPRMC,1235");
        assembler.reset();
        // Without the `$` the remainder is not a sentence at all.
        assert_eq!(feed(&mut assembler, "19,A*00\r\n"), None);
        assert!(matches!(
            feed(&mut assembler, &line("GPGSV,3,1,11,03,03,111,00")),
            Some(Sentence::Gsv(_))
        ));
    }
}
