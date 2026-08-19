//! Minimal-length signed integers.
//!
//! Two's complement, little-endian, in the fewest octets that hold the
//! value: one octet up to ±128, two up to ±32768, and so on to four. An
//! altitude in meters is the motivating case — most of the world is
//! within a byte of sea level, and the property that carries it is read
//! over LoRa.
//!
//! Decoding accepts any width from one to four octets, so a sender that
//! pads to a fixed width is understood; encoding always produces the
//! minimal form.

/// Largest encoded size of a minimal signed integer.
pub const MAX_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The output buffer cannot hold the encoded value.
    BufferTooSmall,
    /// The input was empty or longer than [`MAX_LEN`].
    Malformed,
}

/// Return the encoded size of `value` in bytes.
pub const fn encoded_len(value: i32) -> usize {
    if value >= i8::MIN as i32 && value <= i8::MAX as i32 {
        1
    } else if value >= i16::MIN as i32 && value <= i16::MAX as i32 {
        2
    } else if value >= -(1 << 23) && value < (1 << 23) {
        3
    } else {
        4
    }
}

/// Encode `value` into `out`, returning the number of bytes written.
pub fn encode(value: i32, out: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(value);
    let dst = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    dst.copy_from_slice(&value.to_le_bytes()[..len]);
    Ok(len)
}

/// Decode a one- to four-octet two's-complement value.
///
/// The high bit of the last octet is the sign, and the value is sign-
/// extended from whatever width arrived.
pub fn decode(input: &[u8]) -> Result<i32, Error> {
    let (&last, rest) = input.split_last().ok_or(Error::Malformed)?;
    if input.len() > MAX_LEN {
        return Err(Error::Malformed);
    }
    let fill = if last & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut bytes = [fill; MAX_LEN];
    bytes[..rest.len()].copy_from_slice(rest);
    bytes[rest.len()] = last;
    Ok(i32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: i32, expected_len: usize) {
        let mut buf = [0u8; MAX_LEN];
        let len = encode(value, &mut buf).expect("encoding fits");
        assert_eq!(len, expected_len, "width of {value}");
        assert_eq!(decode(&buf[..len]), Ok(value));
    }

    #[test]
    fn widths_follow_the_value() {
        roundtrip(0, 1);
        roundtrip(100, 1);
        roundtrip(127, 1);
        roundtrip(-128, 1);
        roundtrip(128, 2);
        roundtrip(-129, 2);
        roundtrip(200, 2);
        roundtrip(32767, 2);
        roundtrip(-32768, 2);
        roundtrip(32768, 3);
        roundtrip(-32769, 3);
        roundtrip(8_388_607, 3);
        roundtrip(-8_388_608, 3);
        roundtrip(8_388_608, 4);
        roundtrip(-8_388_609, 4);
        roundtrip(i32::MAX, 4);
        roundtrip(i32::MIN, 4);
    }

    #[test]
    fn a_padded_encoding_decodes_to_the_same_value() {
        // A sender is free to pad; what comes back is minimal either way.
        assert_eq!(decode(&[0x64]), Ok(100));
        assert_eq!(decode(&[0x64, 0x00]), Ok(100));
        assert_eq!(decode(&[0x64, 0x00, 0x00, 0x00]), Ok(100));
        assert_eq!(decode(&[0x9C, 0xFF]), Ok(-100));
        assert_eq!(decode(&[0x9C, 0xFF, 0xFF, 0xFF]), Ok(-100));
    }

    #[test]
    fn lengths_outside_one_through_four_are_malformed() {
        assert_eq!(decode(&[]), Err(Error::Malformed));
        assert_eq!(decode(&[0; 5]), Err(Error::Malformed));
    }

    #[test]
    fn a_buffer_shorter_than_the_value_is_refused() {
        let mut buf = [0u8; 1];
        assert_eq!(encode(1000, &mut buf), Err(Error::BufferTooSmall));
    }
}
