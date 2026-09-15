//! Minimal-width unsigned little-endian integers. Zero occupies one octet.
pub use crate::sint::Error;
pub const MAX_LEN: usize = 4;

pub const fn encoded_len(value: u32) -> usize {
    if value == 0 {
        1
    } else {
        ((32 - value.leading_zeros()) as usize).div_ceil(8)
    }
}

pub fn encode(value: u32, out: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(value);
    out.get_mut(..len)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(&value.to_le_bytes()[..len]);
    Ok(len)
}

pub fn decode(input: &[u8]) -> Result<u32, Error> {
    if input.is_empty() || input.len() > MAX_LEN {
        return Err(Error::Malformed);
    }
    let mut bytes = [0; MAX_LEN];
    bytes[..input.len()].copy_from_slice(input);
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries_padding_and_invalid_lengths() {
        for (value, len) in [
            (0, 1),
            (255, 1),
            (256, 2),
            (65535, 2),
            (65536, 3),
            (16777215, 3),
            (16777216, 4),
            (u32::MAX, 4),
        ] {
            let mut bytes = [0; 4];
            assert_eq!(encode(value, &mut bytes), Ok(len));
            assert_eq!(decode(&bytes[..len]), Ok(value));
            assert_eq!(decode(&bytes), Ok(value));
        }
        assert_eq!(decode(&[]), Err(Error::Malformed));
        assert_eq!(decode(&[0; 5]), Err(Error::Malformed));
        assert_eq!(encode(256, &mut [0]), Err(Error::BufferTooSmall));
    }
}
