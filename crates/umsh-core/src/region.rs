//! Region-code encoding for the Region Code packet option.
//!
//! A region code is a 2-byte routing-domain tag. It is not an RF band plan:
//! it scopes flood forwarding to a locally agreed area, and repeaters match
//! it against their configured region list.
//!
//! Codes come from two sources, and the encoding keeps the letters disjoint
//! from the hashes so a code can be rendered without knowing which one
//! produced it:
//!
//! - **Short codes** encode one to three ASCII letters or digits with
//!   ARNCE/HAM-16. Three letters are conventionally an IATA airport code and
//!   two an ISO 3166-1 country or a bare subdivision code.
//! - **Named regions** take the first two bytes of the SHA-256 of the
//!   ASCII-case-folded name, transformed away from the letter space if they
//!   happen to land in it.
//!
//! Both derivations ignore ASCII case, so a region is the same region
//! however its string was capitalized.
//!
//! Because the transform vacates every all-letter encoding, a code that
//! decodes to letters always came from a short code, and
//! [`Display`](core::fmt::Display) renders it as those letters. A short code
//! bearing a digit is not vacated: it encodes, but it shares its space with
//! the hashes and so has no reading anyone can rely on. Everything else
//! renders as `0xXXXX`.

use core::fmt;
use core::str::FromStr;

use hamaddr::{HamAddr, HamAddrType};
use sha2::{Digest, Sha256};

/// Lowest ARNCE index that denotes a letter (`A`).
const LETTER_MIN: u16 = 1;
/// Highest ARNCE index that denotes a letter (`Z`).
const LETTER_MAX: u16 = 26;
/// How many letters there are to encode.
const LETTERS: u16 = 26;

/// First code reserved for transformed named regions, which is the first
/// code whose leading character is not a letter.
const TRANSFORM_BASE: u16 = 27 * 1600;
/// Where the transformed three-letter codes give way to the two-letter ones.
const TWO_LETTER_BASE: u16 = TRANSFORM_BASE + LETTERS * LETTERS * LETTERS;
/// Where the transformed two-letter codes give way to the one-letter ones.
const ONE_LETTER_BASE: u16 = TWO_LETTER_BASE + LETTERS * LETTERS;

/// Longest a short code may be, in characters.
const SHORT_CODE_MAX_LEN: usize = 3;

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
/// let oregon: RegionCode = "OR".parse().unwrap();
/// assert_eq!(oregon.to_string(), "OR");
///
/// let valley: RegionCode = "Rogue Valley".parse().unwrap();
/// assert_eq!(valley.to_string(), "0xC0F9");
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

    /// Encode a short code: one to three ASCII letters or digits.
    ///
    /// Case-insensitive. Anything longer, or bearing a character ARNCE
    /// spells but a region may not use, is rejected, so that named regions
    /// cannot be mistaken for short codes.
    ///
    /// An all-letter code is exclusive — no named region can derive it — and
    /// so reads back as itself. One bearing a digit encodes just as
    /// faithfully but shares its space with the hashes, so it does not.
    pub fn from_short_code(code: &str) -> Result<Self, RegionCodeError> {
        if code.is_empty()
            || code.len() > SHORT_CODE_MAX_LEN
            || !code.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(RegionCodeError::NotShortCode);
        }
        let addr = HamAddr::try_from_callsign(code).map_err(|_| RegionCodeError::NotShortCode)?;
        Ok(Self(addr.chunk(0)))
    }

    /// Derive the code for a named region.
    ///
    /// ASCII letters are folded to lowercase before hashing, so spellings
    /// that differ only in case are the same region. No other bytes are
    /// altered; a name containing non-ASCII characters hashes those bytes
    /// verbatim.
    pub fn from_name(name: &str) -> Self {
        let mut hasher = Sha256::new();
        for byte in name.bytes() {
            hasher.update([byte.to_ascii_lowercase()]);
        }
        let digest = hasher.finalize();
        Self(transform_letter_chunk(u16::from_be_bytes([
            digest[0], digest[1],
        ])))
    }

    /// Return the letters this code decodes to, if it decodes to letters
    /// at all.
    ///
    /// `Some` means the code came from an all-letter
    /// [short code](Self::from_short_code): named regions are transformed
    /// out of this space by construction. A code decoding to anything else,
    /// digits included, has no reading and returns `None`.
    pub fn letters(self) -> Option<Letters> {
        let addr = HamAddr::from_chunks([self.0, 0, 0, 0]);
        if !matches!(addr.get_type(), HamAddrType::Callsign) {
            return None;
        }
        let mut sink = LetterSink::default();
        fmt::write(&mut sink, format_args!("{addr}")).ok()?;
        let text = sink.buf.get(..sink.len)?;
        if text.is_empty() || !text.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        Some(Letters {
            buf: sink.buf,
            len: sink.len as u8,
        })
    }
}

/// The one to three letters a region code reads as.
///
/// Held inline: a [`RegionCode`] is `Copy`, and this crate has no allocator
/// to lean on.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Letters {
    buf: [u8; SHORT_CODE_MAX_LEN],
    len: u8,
}

impl Letters {
    /// Return the letters as text, uppercase however the code was written.
    pub fn as_str(&self) -> &str {
        // The bytes came from `letters`, which admits only ASCII letters.
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or_default()
    }
}

impl core::ops::Deref for Letters {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Letters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Letters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Move an all-letter encoding into the space reserved for named regions.
///
/// The three lengths land in three consecutive blocks, longest first, so
/// that adding the shorter ones left every code already assigned where it
/// was. Anything that is not all letters — a code bearing a digit among
/// them, or one already outside the letter space — is returned unchanged.
fn transform_letter_chunk(encoded: u16) -> u16 {
    let a = encoded / 1600;
    let b = (encoded / 40) % 40;
    let c = encoded % 40;

    let is_letter = |x: u16| (LETTER_MIN..=LETTER_MAX).contains(&x);
    if !is_letter(a) {
        return encoded;
    }

    match (is_letter(b), b, is_letter(c), c) {
        (true, _, true, _) => {
            TRANSFORM_BASE + (a - 1) * LETTERS * LETTERS + (b - 1) * LETTERS + (c - 1)
        }
        (true, _, false, 0) => TWO_LETTER_BASE + (a - 1) * LETTERS + (b - 1),
        (false, 0, false, 0) => ONE_LETTER_BASE + (a - 1),
        _ => encoded,
    }
}

/// A fixed-capacity sink for the at-most-three characters a single ARNCE
/// chunk renders to. Overlong writes leave `len` past the buffer and are
/// rejected by the caller.
#[derive(Default)]
struct LetterSink {
    buf: [u8; SHORT_CODE_MAX_LEN],
    len: usize,
}

impl fmt::Write for LetterSink {
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
/// `0x` followed by exactly four hex digits is the code it spells, one to
/// three ASCII letters or digits is a short code, and anything else is a
/// region name. The derivation is total over every string of one to
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
        Self::from_short_code(trimmed).or_else(|_| Ok(Self::from_name(trimmed)))
    }
}

impl fmt::Display for RegionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.letters() {
            Some(letters) => f.write_str(&letters),
            None => write!(f, "0x{:04X}", self.0),
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
    /// The input was not one to three ASCII letters or digits.
    NotShortCode,
}

impl fmt::Display for RegionCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty region code"),
            Self::TooLong => write!(f, "region name longer than {REGION_NAME_MAX_LEN} bytes"),
            Self::NotShortCode => f.write_str("expected one to three letters or digits"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RegionCodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_short_codes_from_the_specification() {
        assert_eq!(RegionCode::from_short_code("SJC").unwrap().as_u16(), 0x7853);
        assert_eq!(RegionCode::from_short_code("MFR").unwrap().as_u16(), 0x5242);
        assert_eq!(RegionCode::from_short_code("US").unwrap().as_u16(), 0x8638);
        assert_eq!(RegionCode::from_short_code("WA").unwrap().as_u16(), 0x8FE8);
    }

    #[test]
    fn encodes_short_codes_case_insensitively() {
        for (lower, upper) in [("sjc", "SJC"), ("us", "US"), ("w7", "W7")] {
            assert_eq!(
                RegionCode::from_short_code(lower).unwrap(),
                RegionCode::from_short_code(upper).unwrap(),
                "{lower:?} and {upper:?} should be one code"
            );
        }
    }

    #[test]
    fn rejects_anything_that_is_not_one_to_three_alphanumerics() {
        // `/` and `-` are ARNCE characters, but a region may not spell one:
        // the transformed codes are led by them, and a short code that could
        // reach that space would read as a region it is not.
        for input in ["SJCA", "SJ-", "", "S J", "SJ/", "^SJ", "Rogue"] {
            assert_eq!(
                RegionCode::from_short_code(input),
                Err(RegionCodeError::NotShortCode),
                "{input:?} should not parse as a short code"
            );
        }
    }

    #[test]
    fn encodes_short_codes_bearing_digits_without_making_them_readable() {
        // These are encodable, injective and stable — but not vacated, so
        // they share their space with the hashes and never render.
        for input in ["W7", "5", "0A1"] {
            let code = RegionCode::from_short_code(input).unwrap();
            assert_eq!(
                input.parse::<RegionCode>().unwrap(),
                code,
                "{input:?} should parse as the short code it is"
            );
            assert_eq!(code.letters(), None, "{input:?} should have no reading");
            assert_eq!(code.to_string(), format!("0x{:04X}", code.as_u16()));
        }
    }

    #[test]
    fn distinct_short_codes_never_share_a_region_code() {
        // Injectivity is the whole reason to encode these rather than hash
        // them: two different short codes are always two different regions.
        let mut seen = std::collections::HashMap::new();
        let alphabet: Vec<u8> = (b'A'..=b'Z').chain(b'0'..=b'9').collect();
        let mut push = |text: String| {
            let code = RegionCode::from_short_code(&text).unwrap();
            if let Some(other) = seen.insert(code, text.clone()) {
                panic!("{text:?} and {other:?} both encode to {code:?}");
            }
        };
        for &a in &alphabet {
            push(String::from_utf8(vec![a]).unwrap());
            for &b in &alphabet {
                push(String::from_utf8(vec![a, b]).unwrap());
                for &c in &alphabet {
                    push(String::from_utf8(vec![a, b, c]).unwrap());
                }
            }
        }
        assert_eq!(seen.len(), 36 + 36 * 36 + 36 * 36 * 36);
    }

    #[test]
    fn derives_named_regions_from_the_hash_prefix() {
        assert_eq!(RegionCode::from_name("Willamette Valley").as_u16(), 0xB02D);
        assert_eq!(RegionCode::from_name("East Bay").as_u16(), 0x36E2);
    }

    #[test]
    fn derives_named_regions_case_insensitively() {
        for spelling in ["rogue valley", "ROGUE VALLEY", "RoGuE vAlLeY"] {
            assert_eq!(
                RegionCode::from_name(spelling),
                RegionCode::from_name("Rogue Valley"),
                "{spelling:?} should derive the same region"
            );
            assert_eq!(
                spelling.parse::<RegionCode>().unwrap(),
                "Rogue Valley".parse::<RegionCode>().unwrap(),
                "{spelling:?} should parse to the same region"
            );
        }
    }

    #[test]
    fn transforms_a_named_region_that_lands_on_three_letters() {
        // SHA-256("rogue valley") begins 0x3F56, which decodes to `JEN`.
        assert_eq!(transform_letter_chunk(0x3F56), 0xC0F9);
        assert_eq!(RegionCode::from_name("Rogue Valley").as_u16(), 0xC0F9);
    }

    #[test]
    fn transforms_a_named_region_that_lands_on_two_letters() {
        // SHA-256("wasatch front") begins 0x5FA0, which decodes to `OL` —
        // vacated now that two letters are a short code of their own
        // (packet-options.md § Region Code Encoding).
        assert_eq!(transform_letter_chunk(0x5FA0), 0xEEDF);
        assert_eq!(RegionCode::from_name("Wasatch Front").as_u16(), 0xEEDF);
        assert_eq!(RegionCode::from_u16(0xEEDF).to_string(), "0xEEDF");
    }

    #[test]
    fn the_transform_blocks_sit_where_the_specification_says() {
        assert_eq!(TRANSFORM_BASE, 0xA8C0);
        assert_eq!(TWO_LETTER_BASE, 0xED68);
        assert_eq!(ONE_LETTER_BASE, 0xF00C);
        // The highest code the transform can yield, and the count it vacates.
        assert_eq!(ONE_LETTER_BASE + LETTERS - 1, 0xF025);
        assert_eq!(0xF025 - TRANSFORM_BASE + 1, 18278);
    }

    #[test]
    fn leaves_a_named_region_outside_the_letter_space_alone() {
        assert_eq!(transform_letter_chunk(0xB02D), 0xB02D);
        assert_eq!(transform_letter_chunk(0x36E2), 0x36E2);
    }

    #[test]
    fn no_named_region_can_collide_with_a_letter_region() {
        // The transform is what guarantees this, so assert the property
        // over the whole 16-bit space rather than trusting the examples.
        for raw in 0..=u16::MAX {
            let transformed = RegionCode::from_u16(transform_letter_chunk(raw));
            assert_eq!(
                transformed.letters(),
                None,
                "0x{raw:04X} transformed to a code that reads as letters"
            );
        }
    }

    #[test]
    fn every_letter_region_round_trips_through_its_text_form() {
        let mut cases = Vec::new();
        for a in b'A'..=b'Z' {
            cases.push(vec![a]);
            for b in b'A'..=b'Z' {
                cases.push(vec![a, b]);
                for c in b'A'..=b'Z' {
                    cases.push(vec![a, b, c]);
                }
            }
        }
        assert_eq!(cases.len(), 26 + 26 * 26 + 26 * 26 * 26);
        for bytes in cases {
            let text = String::from_utf8(bytes).unwrap();
            let code = RegionCode::from_short_code(&text).unwrap();
            assert_eq!(code.letters().as_deref(), Some(text.as_str()));
            assert_eq!(code.to_string(), text);
            assert_eq!(text.parse::<RegionCode>().unwrap(), code);
            // Lowercase is the same region, and still reads back uppercase.
            assert_eq!(text.to_lowercase().parse::<RegionCode>().unwrap(), code);
        }
    }

    #[test]
    fn displays_codes_without_a_text_form_as_hex() {
        assert_eq!(RegionCode::from_u16(0xDF6F).to_string(), "0xDF6F");
        // Decodes to `654`, which is not letters.
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
        // `0x` and `0x1` are short codes — one to three alphanumerics — so
        // they are not among these.
        for input in ["0x12345", "0xzz", "0x 12", "0x+1"] {
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
        // Four letters is past the short-code bound, so it is a name.
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
        let code = RegionCode::from_short_code("SJC").unwrap();
        assert_eq!(code.to_bytes(), [0x78, 0x53]);
        assert_eq!(RegionCode::from_bytes([0x78, 0x53]), code);
    }
}
