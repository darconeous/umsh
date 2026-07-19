//! Fixed-width base58 codec for 32-byte addresses.
//!
//! UMSH addresses render as exactly 44 base58 digits (Bitcoin alphabet),
//! left-padded with `1` — the zero digit — so that character positions are
//! stable across all key values. See the "Addressing" chapter of the protocol
//! specification.

use core::fmt::Write;

use crate::error::AddressParseError;

/// Base58 digit alphabet (Bitcoin variant).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Length of the fixed-width base58 encoding of a 32-byte value.
pub const ENCODED_LEN: usize = 44;

/// Encode 32 bytes as exactly [`ENCODED_LEN`] base58 digits.
pub fn encode(bytes: &[u8; 32]) -> [u8; ENCODED_LEN] {
    let mut out = [ALPHABET[0]; ENCODED_LEN];
    let mut num = *bytes;
    for slot in out.iter_mut().rev() {
        let mut rem = 0u32;
        for byte in num.iter_mut() {
            let acc = (rem << 8) | u32::from(*byte);
            *byte = (acc / 58) as u8;
            rem = acc % 58;
        }
        *slot = ALPHABET[rem as usize];
    }
    out
}

/// Decode exactly [`ENCODED_LEN`] base58 digits into 32 bytes.
pub fn decode(digits: &[u8]) -> Result<[u8; 32], AddressParseError> {
    if digits.len() != ENCODED_LEN {
        return Err(AddressParseError::InvalidLength);
    }
    let mut out = [0u8; 32];
    for &digit in digits {
        let mut carry = u32::from(digit_value(digit)?);
        for byte in out.iter_mut().rev() {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = acc as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return Err(AddressParseError::Overflow);
        }
    }
    Ok(out)
}

fn digit_value(digit: u8) -> Result<u8, AddressParseError> {
    ALPHABET
        .iter()
        .position(|&c| c == digit)
        .map(|index| index as u8)
        .ok_or(AddressParseError::InvalidCharacter)
}

/// Write the star-truncated hint rendering defined in the addressing chapter.
///
/// The hint is encoded twice — padded to 32 bytes with 0x00 and with 0xFF —
/// and the longest common prefix of the two encodings is emitted, up to
/// `budget` characters, followed by a single `*` where they diverge. Every
/// emitted non-`*` character is guaranteed to match the full base58 rendering
/// of any public key that matches the hint.
pub(crate) fn fmt_hint(
    f: &mut core::fmt::Formatter<'_>,
    hint: &[u8],
    budget: usize,
) -> core::fmt::Result {
    let mut lo = [0x00u8; 32];
    let mut hi = [0xFFu8; 32];
    lo[..hint.len()].copy_from_slice(hint);
    hi[..hint.len()].copy_from_slice(hint);
    let lo = encode(&lo);
    let hi = encode(&hi);
    for (&a, &b) in lo.iter().zip(hi.iter()).take(budget) {
        if a != b {
            return f.write_char('*');
        }
        f.write_char(char::from(a))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: [u8; 32] = [0u8; 32];
    const MAX: [u8; 32] = [0xFFu8; 32];

    fn leading_zero_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn encode_matches_reference_vectors() {
        assert_eq!(
            &encode(&ZERO),
            b"11111111111111111111111111111111111111111111"
        );
        assert_eq!(
            &encode(&MAX),
            b"JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
        );

        let mut one = ZERO;
        one[31] = 1;
        assert_eq!(
            &encode(&one),
            b"11111111111111111111111111111111111111111112"
        );

        assert_eq!(
            &encode(&leading_zero_key()),
            b"111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"
        );
    }

    #[test]
    fn decode_round_trips() {
        for key in [ZERO, MAX, leading_zero_key()] {
            assert_eq!(decode(&encode(&key)).unwrap(), key);
        }
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode(b"7NeD"), Err(AddressParseError::InvalidLength));
        // '0', 'O', 'I', and 'l' are excluded from the base58 alphabet.
        for bad in [b'0', b'O', b'I', b'l'] {
            let mut digits = *b"11111111111111111111111111111111111111111111";
            digits[10] = bad;
            assert_eq!(decode(&digits), Err(AddressParseError::InvalidCharacter));
        }
        assert_eq!(
            decode(&[b'z'; ENCODED_LEN]),
            Err(AddressParseError::Overflow)
        );
    }
}
