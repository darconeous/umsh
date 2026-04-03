use crate::{EncodeError, ParseError};

pub(crate) fn parse_utf8(input: &[u8]) -> Result<&str, ParseError> {
    core::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)
}

pub(crate) fn fixed<const N: usize>(input: &[u8]) -> Result<&[u8; N], ParseError> {
    input.try_into().map_err(|_| ParseError::InvalidLength {
        expected: N,
        actual: input.len(),
    })
}

pub(crate) fn copy_into(dst: &mut [u8], pos: &mut usize, src: &[u8]) -> Result<(), EncodeError> {
    if dst.len().saturating_sub(*pos) < src.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    dst[*pos..*pos + src.len()].copy_from_slice(src);
    *pos += src.len();
    Ok(())
}

pub(crate) fn push_byte(dst: &mut [u8], pos: &mut usize, byte: u8) -> Result<(), EncodeError> {
    copy_into(dst, pos, &[byte])
}

#[cfg(feature = "chat-rooms")]
pub(crate) fn decode_options_allow_eof<'a>(
    data: &'a [u8],
    mut on_option: impl FnMut(u16, &'a [u8]) -> Result<(), ParseError>,
) -> Result<&'a [u8], ParseError> {
    let mut pos = 0usize;
    let mut last_number = 0u16;

    while pos < data.len() {
        let first = data[pos];
        if first == 0xFF {
            return Ok(&data[pos + 1..]);
        }
        pos += 1;

        let (delta, delta_len) = read_extended(&data[pos..], first >> 4)?;
        pos += delta_len;
        let (len, len_len) = read_extended(&data[pos..], first & 0x0F)?;
        pos += len_len;

        let end = pos.checked_add(len as usize).ok_or(ParseError::InvalidOptionValue)?;
        if end > data.len() {
            return Err(ParseError::Core(umsh_core::ParseError::Truncated));
        }
        let number = last_number.checked_add(delta).ok_or(ParseError::InvalidOptionValue)?;
        on_option(number, &data[pos..end])?;
        pos = end;
        last_number = number;
    }

    Ok(&data[pos..])
}

#[cfg(feature = "chat-rooms")]
fn read_extended(data: &[u8], nibble: u8) -> Result<(u16, usize), ParseError> {
    match nibble {
        0..=12 => Ok((nibble as u16, 0)),
        13 => {
            if data.is_empty() {
                Err(ParseError::Core(umsh_core::ParseError::Truncated))
            } else {
                Ok((data[0] as u16 + 13, 1))
            }
        }
        14 => {
            if data.len() < 2 {
                Err(ParseError::Core(umsh_core::ParseError::Truncated))
            } else {
                Ok((u16::from_be_bytes([data[0], data[1]]) + 269, 2))
            }
        }
        _ => Err(ParseError::Core(umsh_core::ParseError::InvalidOptionNibble)),
    }
}