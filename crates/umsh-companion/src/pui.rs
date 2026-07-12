//! Packed Unsigned Integers (PUIs).
//!
//! Little-endian base-128 encoding with a continuation bit, capped at
//! three bytes. See "Packed Unsigned Integers" in the minimal
//! companion-radio spec.

/// Largest value encodable in the three-byte PUI limit.
pub const MAX_VALUE: u32 = 2_097_151;

/// Largest encoded size of a PUI.
pub const MAX_LEN: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value exceeds [`MAX_VALUE`].
    ValueTooLarge,
    /// The output buffer cannot hold the encoded value.
    BufferTooSmall,
    /// The input ended before the final (continuation-clear) byte.
    Truncated,
    /// A third byte carried a continuation bit, exceeding the
    /// three-byte limit.
    TooLong,
}

/// Return the encoded size of `value` in bytes.
pub const fn encoded_len(value: u32) -> usize {
    if value < 1 << 7 {
        1
    } else if value < 1 << 14 {
        2
    } else {
        3
    }
}

/// Encode `value` into `out`, returning the number of bytes written.
pub fn encode(value: u32, out: &mut [u8]) -> Result<usize, Error> {
    if value > MAX_VALUE {
        return Err(Error::ValueTooLarge);
    }
    let len = encoded_len(value);
    if out.len() < len {
        return Err(Error::BufferTooSmall);
    }
    let mut remaining = value;
    for byte in out.iter_mut().take(len - 1) {
        *byte = (remaining as u8 & 0x7F) | 0x80;
        remaining >>= 7;
    }
    out[len - 1] = remaining as u8;
    Ok(len)
}

/// Decode a PUI from the start of `input`.
///
/// Returns the value and the number of bytes consumed.
pub fn decode(input: &[u8]) -> Result<(u32, usize), Error> {
    let mut value = 0u32;
    for (index, &byte) in input.iter().enumerate().take(MAX_LEN) {
        value |= u32::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        if index + 1 == MAX_LEN {
            return Err(Error::TooLong);
        }
    }
    Err(Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn round_trip(value: u32, expected: &[u8]) {
        let mut buf = [0u8; MAX_LEN];
        let len = encode(value, &mut buf).unwrap();
        assert_eq!(&buf[..len], expected, "encoding of {value}");
        assert_eq!(decode(expected).unwrap(), (value, expected.len()));
    }

    #[test]
    fn spec_example() {
        // Worked example from the spec: 1337 => [B9 0A].
        round_trip(1337, &[0xB9, 0x0A]);
    }

    #[test]
    fn boundaries() {
        round_trip(0, &[0x00]);
        round_trip(127, &[0x7F]);
        round_trip(128, &[0x80, 0x01]);
        round_trip(16_383, &[0xFF, 0x7F]);
        round_trip(16_384, &[0x80, 0x80, 0x01]);
        round_trip(MAX_VALUE, &[0xFF, 0xFF, 0x7F]);
    }

    #[test]
    fn known_identifiers() {
        // Property ids used by the minimal spec.
        round_trip(113, &[0x71]);
        round_trip(4820, &[0xD4, 0x25]);
        round_trip(4822, &[0xD6, 0x25]);
    }

    #[test]
    fn errors() {
        let mut buf = [0u8; MAX_LEN];
        assert_eq!(encode(MAX_VALUE + 1, &mut buf), Err(Error::ValueTooLarge));
        assert_eq!(encode(128, &mut buf[..1]), Err(Error::BufferTooSmall));
        assert_eq!(decode(&[]), Err(Error::Truncated));
        assert_eq!(decode(&[0x80]), Err(Error::Truncated));
        assert_eq!(decode(&[0x80, 0x80]), Err(Error::Truncated));
        assert_eq!(decode(&[0x80, 0x80, 0x80]), Err(Error::TooLong));
    }

    #[test]
    fn trailing_bytes_ignored() {
        assert_eq!(decode(&[0x7F, 0xAA, 0xBB]).unwrap(), (127, 1));
    }
}
