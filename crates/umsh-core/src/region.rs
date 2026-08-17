//! Region-code encoding for the Region Code packet option.
//!
//! A region code is a 2-byte routing-domain tag. It is not an RF band plan:
//! it scopes flood forwarding to a locally agreed area, and repeaters match
//! it against their configured region list.
//!
//! Codes come from two sources, and the encoding keeps them disjoint so a
//! code can be rendered without knowing which one produced it:
//!
//! - **Airport regions** encode a 3-letter IATA code with ARNCE/HAM-16.
//! - **Named regions** take the first two bytes of the SHA-256 of the name,
//!   transformed away from the letter space if they happen to land in it.
//!
//! Because the transform vacates every three-letter encoding, a code that
//! decodes to three letters is always an airport code, and one that does
//! not has no recoverable text form — [`Display`](core::fmt::Display)
//! renders it as `0xXXXX`.

use core::fmt;
use core::str::FromStr;

use hamaddr::{HamAddr, HamAddrType};
use sha2::{Digest, Sha256};

/// Lowest ARNCE index that denotes a letter (`A`).
const LETTER_MIN: u16 = 1;
/// Highest ARNCE index that denotes a letter (`Z`).
const LETTER_MAX: u16 = 26;
/// First code reserved for transformed named regions.
const TRANSFORM_BASE: u16 = 27 * 1600;

/// Longest a region's string form may be, in UTF-8 bytes.
///
/// Names travel on the wire in identity payloads, one option per region, and
/// this bound is what lets a list of them fit
/// (packet-options.md § Region Code Encoding).
pub const REGION_NAME_MAX_LEN: usize = 24;

/// A 2-byte region identifier.
///
/// ```
/// # use umsh_core::RegionCode;
/// let sjc: RegionCode = "SJC".parse().unwrap();
/// assert_eq!(sjc.to_bytes(), [0x78, 0x53]);
/// assert_eq!(sjc.to_string(), "SJC");
///
/// let valley: RegionCode = "Rogue Valley".parse().unwrap();
/// assert_eq!(valley.to_string(), "0xDF6F");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionCode(u16);

impl RegionCode {
    /// Wrap a raw code.
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    /// Return the raw code.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Wrap a code from its two wire bytes.
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// Return the code's two wire bytes.
    pub const fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Encode a 3-letter IATA airport code.
    ///
    /// Case-insensitive. Anything that is not exactly three ASCII letters
    /// is rejected, so that named regions cannot be mistaken for airports.
    pub fn from_iata(code: &str) -> Result<Self, RegionCodeError> {
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(RegionCodeError::NotIata);
        }
        let addr = HamAddr::try_from_callsign(code).map_err(|_| RegionCodeError::NotIata)?;
        Ok(Self(addr.chunk(0)))
    }

    /// Derive the code for a named region.
    ///
    /// The name is hashed verbatim, so callers that want names to compare
    /// equal across operators must agree on the exact spelling.
    pub fn from_name(name: &str) -> Self {
        let digest = Sha256::digest(name.as_bytes());
        Self(transform_letter_chunk(u16::from_be_bytes([
            digest[0], digest[1],
        ])))
    }

    /// Return the three letters this code decodes to, if it decodes to
    /// three letters at all.
    ///
    /// `Some` means the code came from [`from_iata`](Self::from_iata):
    /// named regions are transformed out of this space by construction.
    pub fn letters(self) -> Option<[u8; 3]> {
        let addr = HamAddr::from_chunks([self.0, 0, 0, 0]);
        if !matches!(addr.get_type(), HamAddrType::Callsign) {
            return None;
        }
        let mut sink = Letters::default();
        fmt::write(&mut sink, format_args!("{addr}")).ok()?;
        if sink.len != 3 || !sink.buf.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        Some(sink.buf)
    }
}

/// Move a three-letter encoding into the space reserved for named regions.
///
/// Anything that is not three letters is already outside that space and is
/// returned unchanged.
fn transform_letter_chunk(encoded: u16) -> u16 {
    let a = encoded / 1600;
    let b = (encoded / 40) % 40;
    let c = encoded % 40;

    if ![a, b, c]
        .iter()
        .all(|x| (LETTER_MIN..=LETTER_MAX).contains(x))
    {
        return encoded;
    }

    let rank = (a - 1) * 26 * 26 + (b - 1) * 26 + (c - 1);
    TRANSFORM_BASE + rank
}

/// A fixed-capacity sink for the at-most-three characters a single ARNCE
/// chunk renders to. Overlong writes leave `len` past the buffer and are
/// rejected by the caller.
#[derive(Default)]
struct Letters {
    buf: [u8; 3],
    len: usize,
}

impl fmt::Write for Letters {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = byte;
            }
            self.len += 1;
        }
        Ok(())
    }
}

/// Parse a region code from its textual form.
///
/// Three ASCII letters are an IATA code, `0x` followed by exactly four hex
/// digits is the code it spells, and anything else is a region name. The
/// derivation is total over every string of one to
/// [`REGION_NAME_MAX_LEN`] bytes: a string that merely looks like a literal
/// code — `0x12`, `0xzz` — is not one, and is hashed as the name it is
/// (packet-options.md § Region Code Encoding).
impl FromStr for RegionCode {
    type Err = RegionCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(RegionCodeError::Empty);
        }
        if trimmed.len() > REGION_NAME_MAX_LEN {
            return Err(RegionCodeError::TooLong);
        }
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            && hex.len() == 4
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
            && let Ok(value) = u16::from_str_radix(hex, 16)
        {
            return Ok(Self(value));
        }
        Self::from_iata(trimmed).or_else(|_| Ok(Self::from_name(trimmed)))
    }
}

impl fmt::Display for RegionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.letters().as_ref().map(|l| core::str::from_utf8(l)) {
            Some(Ok(text)) => f.write_str(text),
            _ => write!(f, "0x{:04X}", self.0),
        }
    }
}

impl fmt::Debug for RegionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegionCode({self})")
    }
}

impl From<RegionCode> for [u8; 2] {
    fn from(code: RegionCode) -> Self {
        code.to_bytes()
    }
}

impl From<[u8; 2]> for RegionCode {
    fn from(bytes: [u8; 2]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// Why a string could not be read as a region code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionCodeError {
    /// The input was empty or only whitespace.
    Empty,
    /// The input was longer than [`REGION_NAME_MAX_LEN`] bytes.
    TooLong,
    /// The input was not exactly three ASCII letters.
    NotIata,
}

impl fmt::Display for RegionCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty region code"),
            Self::TooLong => write!(f, "region name longer than {REGION_NAME_MAX_LEN} bytes"),
            Self::NotIata => f.write_str("expected a three-letter IATA code"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RegionCodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_iata_codes_from_the_specification() {
        assert_eq!(RegionCode::from_iata("SJC").unwrap().as_u16(), 0x7853);
        assert_eq!(RegionCode::from_iata("MFR").unwrap().as_u16(), 0x5242);
    }

    #[test]
    fn encodes_iata_codes_case_insensitively() {
        assert_eq!(
            RegionCode::from_iata("sjc").unwrap(),
            RegionCode::from_iata("SJC").unwrap()
        );
    }

    #[test]
    fn rejects_anything_that_is_not_three_letters_as_iata() {
        for input in ["SJ", "SJCA", "SJ1", "SJ-", "", "S J"] {
            assert_eq!(
                RegionCode::from_iata(input),
                Err(RegionCodeError::NotIata),
                "{input:?} should not parse as an IATA code"
            );
        }
    }

    #[test]
    fn derives_named_regions_from_the_hash_prefix() {
        assert_eq!(RegionCode::from_name("Rogue Valley").as_u16(), 0xDF6F);
        assert_eq!(RegionCode::from_name("SF Bay Area").as_u16(), 0x31D9);
    }

    #[test]
    fn transforms_a_named_region_that_lands_on_three_letters() {
        // SHA-256("Southern Oregon") begins 0x6AF2, which decodes to `QDR`.
        assert_eq!(transform_letter_chunk(0x6AF2), 0xD35F);
        assert_eq!(RegionCode::from_name("Southern Oregon").as_u16(), 0xD35F);
    }

    #[test]
    fn leaves_a_named_region_outside_the_letter_space_alone() {
        assert_eq!(transform_letter_chunk(0xDF6F), 0xDF6F);
        assert_eq!(transform_letter_chunk(0x31D9), 0x31D9);
    }

    #[test]
    fn no_named_region_can_collide_with_an_airport_region() {
        // The transform is what guarantees this, so assert the property
        // over the whole 16-bit space rather than trusting the examples.
        for raw in 0..=u16::MAX {
            let transformed = RegionCode::from_u16(transform_letter_chunk(raw));
            assert_eq!(
                transformed.letters(),
                None,
                "0x{raw:04X} transformed to a three-letter code"
            );
        }
    }

    #[test]
    fn every_airport_region_round_trips_through_its_text_form() {
        for a in b'A'..=b'Z' {
            for b in b'A'..=b'Z' {
                for c in b'A'..=b'Z' {
                    let text = core::str::from_utf8(&[a, b, c]).unwrap().to_string();
                    let code = RegionCode::from_iata(&text).unwrap();
                    assert_eq!(code.letters(), Some([a, b, c]));
                    assert_eq!(code.to_string(), text);
                    assert_eq!(text.parse::<RegionCode>().unwrap(), code);
                }
            }
        }
    }

    #[test]
    fn displays_codes_without_a_text_form_as_hex() {
        assert_eq!(RegionCode::from_u16(0xDF6F).to_string(), "0xDF6F");
        // Decodes to `654`, which is not three letters.
        assert_eq!(RegionCode::from_u16(0xD35F).to_string(), "0xD35F");
        // Below the chunk range entirely.
        assert_eq!(RegionCode::from_u16(0x0100).to_string(), "0x0100");
        assert_eq!(RegionCode::from_u16(0).to_string(), "0x0000");
    }

    #[test]
    fn parses_literal_codes_of_exactly_four_hex_digits() {
        assert_eq!("0x7853".parse::<RegionCode>().unwrap().as_u16(), 0x7853);
        assert_eq!("0X7853".parse::<RegionCode>().unwrap().as_u16(), 0x7853);
        assert_eq!("0xdf6f".parse::<RegionCode>().unwrap().as_u16(), 0xDF6F);
        assert_eq!("0x0001".parse::<RegionCode>().unwrap().as_u16(), 1);
    }

    #[test]
    fn hashes_anything_that_only_looks_like_a_literal_code() {
        // Only `0x` plus exactly four hex digits spells a code. Everything
        // else is a name, which keeps the derivation total: there is no such
        // thing as a string with no region.
        for input in ["0x", "0x1", "0x12345", "0xzz", "0x 12", "0x+1"] {
            assert_eq!(
                input.parse::<RegionCode>().unwrap(),
                RegionCode::from_name(input),
                "{input:?} should hash as a name"
            );
        }
    }

    #[test]
    fn rejects_a_name_longer_than_the_wire_allows() {
        let long = "R".repeat(REGION_NAME_MAX_LEN + 1);
        assert_eq!(long.parse::<RegionCode>(), Err(RegionCodeError::TooLong));

        let limit = "R".repeat(REGION_NAME_MAX_LEN);
        assert_eq!(
            limit.parse::<RegionCode>().unwrap(),
            RegionCode::from_name(&limit)
        );
    }

    #[test]
    fn parses_anything_else_as_a_region_name() {
        assert_eq!(
            "Rogue Valley".parse::<RegionCode>().unwrap(),
            RegionCode::from_name("Rogue Valley")
        );
        // Four letters is a name, not an airport.
        assert_eq!(
            "OHIO".parse::<RegionCode>().unwrap(),
            RegionCode::from_name("OHIO")
        );
    }

    #[test]
    fn rejects_an_empty_region_code() {
        assert_eq!("".parse::<RegionCode>(), Err(RegionCodeError::Empty));
        assert_eq!("   ".parse::<RegionCode>(), Err(RegionCodeError::Empty));
    }

    #[test]
    fn round_trips_through_the_wire_bytes() {
        let code = RegionCode::from_iata("SJC").unwrap();
        assert_eq!(code.to_bytes(), [0x78, 0x53]);
        assert_eq!(RegionCode::from_bytes([0x78, 0x53]), code);
    }
}
