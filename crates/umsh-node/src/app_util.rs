use crate::{AppEncodeError, AppParseError};

pub(crate) fn parse_utf8(input: &[u8]) -> Result<&str, AppParseError> {
    core::str::from_utf8(input).map_err(|_| AppParseError::InvalidUtf8)
}

pub(crate) fn fixed<const N: usize>(input: &[u8]) -> Result<&[u8; N], AppParseError> {
    input.try_into().map_err(|_| AppParseError::InvalidLength {
        expected: N,
        actual: input.len(),
    })
}

pub(crate) fn copy_into(
    dst: &mut [u8],
    pos: &mut usize,
    src: &[u8],
) -> Result<(), AppEncodeError> {
    if dst.len().saturating_sub(*pos) < src.len() {
        return Err(AppEncodeError::BufferTooSmall);
    }
    dst[*pos..*pos + src.len()].copy_from_slice(src);
    *pos += src.len();
    Ok(())
}

pub(crate) fn push_byte(
    dst: &mut [u8],
    pos: &mut usize,
    byte: u8,
) -> Result<(), AppEncodeError> {
    copy_into(dst, pos, &[byte])
}
