use crate::{EncodeError, ParseError};

/// Incremental encoder for CoAP-style delta/length option blocks.
///
/// The encoder writes directly into a caller-supplied buffer and tracks the last
/// emitted option number so the on-wire delta encoding remains canonical.
#[derive(Debug)]
pub struct OptionEncoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
    last_number: u16,
    wrote_any: bool,
}

impl<'a> OptionEncoder<'a> {
    /// Create an encoder starting at option number `0`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            last_number: 0,
            wrote_any: false,
        }
    }

    /// Create an encoder that continues from an already-emitted option number.
    pub fn with_last_number(buf: &'a mut [u8], last_number: u16) -> Self {
        Self {
            buf,
            pos: 0,
            last_number,
            wrote_any: true,
        }
    }

    /// Encode one option value.
    pub fn put(&mut self, number: u16, value: &[u8]) -> Result<(), EncodeError> {
        if self.wrote_any && number < self.last_number {
            return Err(EncodeError::OptionOutOfOrder);
        }
        let delta = if self.wrote_any {
            number - self.last_number
        } else {
            number
        };
        let delta_len = encoded_len(delta);
        let value_len = encoded_len(value.len() as u16);
        let required = 1 + delta_len + value_len + value.len();
        if self.pos + required > self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }

        let header_pos = self.pos;
        self.pos += 1;
        let delta_nibble = write_extended(&mut self.buf[self.pos..], delta)?;
        self.pos += delta_len;
        let len_nibble = write_extended(&mut self.buf[self.pos..], value.len() as u16)?;
        self.pos += value_len;
        self.buf[header_pos] = (delta_nibble << 4) | len_nibble;
        self.buf[self.pos..self.pos + value.len()].copy_from_slice(value);
        self.pos += value.len();
        self.last_number = number;
        self.wrote_any = true;
        Ok(())
    }

    /// Append the `0xFF` end marker for an option block.
    pub fn end_marker(&mut self) -> Result<(), EncodeError> {
        if self.pos >= self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        self.buf[self.pos] = 0xFF;
        self.pos += 1;
        Ok(())
    }

    /// Encode a `u32` in minimal big-endian form (leading zero bytes stripped).
    pub fn put_u32(&mut self, number: u16, value: u32) -> Result<(), EncodeError> {
        let (bytes, len) = minimal_u32(value);
        self.put(number, &bytes[4 - len..])
    }

    /// Encode an `i32` in minimal big-endian form (leading sign-extension bytes stripped).
    pub fn put_i32(&mut self, number: u16, value: i32) -> Result<(), EncodeError> {
        let (bytes, len) = minimal_i32(value);
        self.put(number, &bytes[4 - len..])
    }

    /// Finish the encoder and return the number of bytes written.
    pub fn finish(self) -> usize {
        self.pos
    }
}

/// Parse a minimal big-endian unsigned integer (leading zero bytes stripped).
///
/// Returns `ParseError::MalformedOption` if `bytes.len() > 4`.
pub fn parse_be_u32(bytes: &[u8]) -> Result<u32, ParseError> {
    if bytes.len() > 4 {
        return Err(ParseError::MalformedOption);
    }
    let mut arr = [0u8; 4];
    arr[4 - bytes.len()..].copy_from_slice(bytes);
    Ok(u32::from_be_bytes(arr))
}

/// Parse a minimal big-endian signed integer (leading sign-extension bytes stripped).
///
/// An empty slice decodes as `0`. Returns `ParseError::MalformedOption` if `bytes.len() > 4`.
pub fn parse_be_i32(bytes: &[u8]) -> Result<i32, ParseError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 4 {
        return Err(ParseError::MalformedOption);
    }
    let sign = if bytes[0] & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut arr = [sign; 4];
    arr[4 - bytes.len()..].copy_from_slice(bytes);
    Ok(i32::from_be_bytes(arr))
}

fn minimal_u32(v: u32) -> ([u8; 4], usize) {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().position(|&b| b != 0).unwrap_or(4);
    (bytes, 4 - skip)
}

fn minimal_i32(v: i32) -> ([u8; 4], usize) {
    if v == 0 {
        return ([0u8; 4], 0);
    }
    let bytes = v.to_be_bytes();
    let mut skip = 0;
    if v > 0 {
        while skip < 3 && bytes[skip] == 0x00 && (bytes[skip + 1] & 0x80 == 0) {
            skip += 1;
        }
    } else {
        while skip < 3 && bytes[skip] == 0xFF && (bytes[skip + 1] & 0x80 != 0) {
            skip += 1;
        }
    }
    (bytes, 4 - skip)
}

/// Incremental decoder for CoAP-style delta/length option blocks.
///
/// This iterator yields absolute option numbers together with borrowed value
/// slices from the original buffer.
#[derive(Clone, Debug)]
pub struct OptionDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    last_number: u16,
    finished: bool,
    errored: bool,
}

impl<'a> OptionDecoder<'a> {
    /// Create a decoder over a complete encoded option block.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            last_number: 0,
            finished: false,
            errored: false,
        }
    }

    /// Byte offset of the next undecoded byte in the underlying buffer.
    ///
    /// Sampled before a call to `next`, this is the offset of that option's
    /// header, allowing higher-level codecs to retain sub-ranges of an option
    /// block verbatim.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The absolute option number in effect for delta decoding.
    pub fn last_number(&self) -> u16 {
        self.last_number
    }

    /// Return the trailing bytes after a consumed end marker.
    ///
    /// This is typically used by higher-level codecs whose options are followed
    /// by payload bytes.
    pub fn remainder(&self) -> &'a [u8] {
        if self.finished {
            &self.data[self.pos..]
        } else {
            &[]
        }
    }
}

impl<'a> Iterator for OptionDecoder<'a> {
    type Item = Result<(u16, &'a [u8]), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.errored {
            return None;
        }
        if self.pos >= self.data.len() {
            self.finished = true;
            return None;
        }

        let first = self.data[self.pos];
        if first == 0xFF {
            self.pos += 1;
            self.finished = true;
            return None;
        }

        self.pos += 1;
        let delta_nibble = first >> 4;
        let len_nibble = first & 0x0F;
        let (delta, delta_len) = match read_extended(&self.data[self.pos..], delta_nibble) {
            Ok(value) => value,
            Err(err) => {
                self.errored = true;
                return Some(Err(err));
            }
        };
        self.pos += delta_len;
        let (len, len_len) = match read_extended(&self.data[self.pos..], len_nibble) {
            Ok(value) => value,
            Err(err) => {
                self.errored = true;
                return Some(Err(err));
            }
        };
        self.pos += len_len;

        if self.pos + len as usize > self.data.len() {
            self.errored = true;
            return Some(Err(ParseError::Truncated));
        }

        let number = self
            .last_number
            .checked_add(delta)
            .ok_or(ParseError::MalformedOption);
        let number = match number {
            Ok(value) => value,
            Err(err) => {
                self.errored = true;
                return Some(Err(err));
            }
        };
        let value = &self.data[self.pos..self.pos + len as usize];
        self.pos += len as usize;
        self.last_number = number;
        Some(Ok((number, value)))
    }
}

fn encoded_len(value: u16) -> usize {
    match value {
        0..=12 => 0,
        13..=268 => 1,
        _ => 2,
    }
}

fn write_extended(buf: &mut [u8], value: u16) -> Result<u8, EncodeError> {
    match value {
        0..=12 => Ok(value as u8),
        13..=268 => {
            if buf.is_empty() {
                return Err(EncodeError::BufferTooSmall);
            }
            buf[0] = (value - 13) as u8;
            Ok(13)
        }
        _ => {
            if buf.len() < 2 {
                return Err(EncodeError::BufferTooSmall);
            }
            let extended = value - 269;
            buf[..2].copy_from_slice(&extended.to_be_bytes());
            Ok(14)
        }
    }
}

fn read_extended(data: &[u8], nibble: u8) -> Result<(u16, usize), ParseError> {
    match nibble {
        0..=12 => Ok((nibble as u16, 0)),
        13 => {
            if data.is_empty() {
                return Err(ParseError::Truncated);
            }
            Ok((data[0] as u16 + 13, 1))
        }
        14 => {
            if data.len() < 2 {
                return Err(ParseError::Truncated);
            }
            let value = u16::from_be_bytes([data[0], data[1]])
                .checked_add(269)
                .ok_or(ParseError::InvalidOptionNibble)?;
            Ok((value, 2))
        }
        _ => Err(ParseError::InvalidOptionNibble),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_be_u32 ──────────────────────────────────────────────────────────

    #[test]
    fn parse_be_u32_values() {
        assert_eq!(parse_be_u32(&[]).unwrap(), 0);
        assert_eq!(parse_be_u32(&[1]).unwrap(), 1);
        assert_eq!(parse_be_u32(&[1, 0]).unwrap(), 256);
        assert_eq!(parse_be_u32(&[1, 0, 0]).unwrap(), 65536);
        assert_eq!(parse_be_u32(&[0, 1, 0]).unwrap(), 256); // non-minimal: still parses
        assert_eq!(parse_be_u32(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap(), u32::MAX);
        assert!(parse_be_u32(&[0; 5]).is_err());
    }

    // ── parse_be_i32 ──────────────────────────────────────────────────────────

    #[test]
    fn parse_be_i32_values() {
        assert_eq!(parse_be_i32(&[]).unwrap(), 0);
        assert_eq!(parse_be_i32(&[0x7F]).unwrap(), 127);
        assert_eq!(parse_be_i32(&[0x00, 0x80]).unwrap(), 128);
        assert_eq!(parse_be_i32(&[0xFF]).unwrap(), -1);
        assert_eq!(parse_be_i32(&[0x80]).unwrap(), -128);
        assert_eq!(parse_be_i32(&[0xFF, 0x7F]).unwrap(), -129);
        assert_eq!(parse_be_i32(&[0x80, 0x00, 0x00, 0x00]).unwrap(), i32::MIN);
        assert_eq!(parse_be_i32(&[0x7F, 0xFF, 0xFF, 0xFF]).unwrap(), i32::MAX);
        assert!(parse_be_i32(&[0; 5]).is_err());
    }

    // ── put_u32 / put_i32 round-trips ─────────────────────────────────────────

    #[test]
    fn put_u32_round_trips() {
        let cases: &[u32] = &[0, 1, 127, 128, 255, 256, u32::MAX];
        for &v in cases {
            let mut buf = [0u8; 16];
            let mut enc = OptionEncoder::new(&mut buf);
            enc.put_u32(1, v).unwrap();
            let len = enc.finish();
            let (_, value) = OptionDecoder::new(&buf[..len]).next().unwrap().unwrap();
            assert_eq!(parse_be_u32(value).unwrap(), v, "failed for u32 {v}");
        }
    }

    #[test]
    fn put_i32_round_trips() {
        let cases: &[i32] = &[0, 1, 127, 128, -1, -128, -129, i32::MIN, i32::MAX];
        for &v in cases {
            let mut buf = [0u8; 16];
            let mut enc = OptionEncoder::new(&mut buf);
            enc.put_i32(1, v).unwrap();
            let len = enc.finish();
            let (_, value) = OptionDecoder::new(&buf[..len]).next().unwrap().unwrap();
            assert_eq!(parse_be_i32(value).unwrap(), v, "failed for i32 {v}");
        }
    }

    // ── wire format ───────────────────────────────────────────────────────────

    // Option 5, value [0xAB]: delta=5 (nibble), len=1 (nibble) → header=0x51, body=[0xAB].
    #[test]
    fn wire_inline_delta_and_length() {
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(5, &[0xAB]).unwrap();
        assert_eq!(enc.finish(), 2);
        assert_eq!(&buf[..2], &[0x51, 0xAB]);
    }

    // Option 0, empty value: header=0x00.
    #[test]
    fn wire_option_zero_empty_value() {
        let mut buf = [0u8; 4];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(0, &[]).unwrap();
        assert_eq!(enc.finish(), 1);
        assert_eq!(buf[0], 0x00);
    }

    // Delta=13 encodes as nibble 13 + 1 extended byte (delta - 13 = 0).
    #[test]
    fn wire_extended_delta_1byte_boundary() {
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(13, &[]).unwrap();
        assert_eq!(enc.finish(), 2);
        // nibble=0xD (13), len_nibble=0 → header=0xD0; ext_delta=13-13=0x00
        assert_eq!(&buf[..2], &[0xD0, 0x00]);
    }

    // Delta=268 is the largest that fits in a 1-byte extended field (268-13=255).
    #[test]
    fn wire_extended_delta_1byte_max() {
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(268, &[]).unwrap();
        assert_eq!(enc.finish(), 2);
        assert_eq!(&buf[..2], &[0xD0, 0xFF]);
    }

    // Delta=269 requires a 2-byte extended field (nibble=14, value-269=0 → [0x00,0x00]).
    #[test]
    fn wire_extended_delta_2byte_boundary() {
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(269, &[]).unwrap();
        assert_eq!(enc.finish(), 3);
        assert_eq!(&buf[..3], &[0xE0, 0x00, 0x00]);
    }

    // Value length=13 encodes in 1 extended length byte.
    #[test]
    fn wire_extended_length_1byte() {
        let mut buf = [0u8; 32];
        let value = [0u8; 13];
        {
            let mut enc = OptionEncoder::new(&mut buf);
            enc.put(0, &value).unwrap();
            assert_eq!(enc.finish(), 15);
        }
        // header: delta_nibble=0, len_nibble=13(0xD) → 0x0D; ext_len=13-13=0x00
        assert_eq!(buf[0], 0x0D);
        assert_eq!(buf[1], 0x00);
        assert_eq!(&buf[2..15], &value);
    }

    // end_marker writes 0xFF.
    #[test]
    fn wire_end_marker() {
        let mut buf = [0u8; 4];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(1, &[0x01]).unwrap();
        enc.end_marker().unwrap();
        let len = enc.finish();
        assert_eq!(buf[len - 1], 0xFF);
    }

    // ── OptionEncoder: multiple options and delta accumulation ────────────────

    #[test]
    fn encoder_multiple_options_sequential() {
        let mut buf = [0u8; 16];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(1, &[0x01]).unwrap();
        enc.put(3, &[0x02]).unwrap(); // delta from 1 → 3 is 2
        enc.put(3, &[0x03]).unwrap(); // delta 0 — same option again
        let len = enc.finish();

        let items: Vec<_> = OptionDecoder::new(&buf[..len])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            items,
            vec![(1, &[0x01u8][..]), (3, &[0x02][..]), (3, &[0x03][..])]
        );
    }

    #[test]
    fn encoder_with_last_number_continues_delta() {
        // Pretend option 10 was already written; encode option 12 (delta=2).
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::with_last_number(&mut buf, 10);
        enc.put(12, &[0xBB]).unwrap();
        let len = enc.finish();
        // delta=2, len=1 → header=0x21, body=0xBB
        assert_eq!(&buf[..len], &[0x21, 0xBB]);
    }

    #[test]
    fn encoder_large_option_number_round_trip() {
        let mut buf = [0u8; 16];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(u16::MAX, &[0xCC]).unwrap();
        let len = enc.finish();
        let (num, val) = OptionDecoder::new(&buf[..len]).next().unwrap().unwrap();
        assert_eq!(num, u16::MAX);
        assert_eq!(val, &[0xCC]);
    }

    // ── OptionEncoder: error paths ────────────────────────────────────────────

    #[test]
    fn encoder_out_of_order_returns_error() {
        let mut buf = [0u8; 16];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(5, &[]).unwrap();
        assert_eq!(enc.put(3, &[]), Err(EncodeError::OptionOutOfOrder));
    }

    #[test]
    fn encoder_buffer_too_small_returns_error() {
        let mut buf = [0u8; 1]; // only 1 byte: enough for header but not body
        let mut enc = OptionEncoder::new(&mut buf);
        assert_eq!(enc.put(0, &[0x01]), Err(EncodeError::BufferTooSmall));
    }

    #[test]
    fn encoder_end_marker_buffer_too_small() {
        let mut buf = [0u8; 0];
        let mut enc = OptionEncoder::new(&mut buf);
        assert_eq!(enc.end_marker(), Err(EncodeError::BufferTooSmall));
    }

    // ── OptionDecoder: basic iteration ────────────────────────────────────────

    #[test]
    fn decoder_empty_input_yields_nothing() {
        assert!(OptionDecoder::new(&[]).next().is_none());
    }

    #[test]
    fn decoder_end_marker_only_yields_nothing() {
        let mut dec = OptionDecoder::new(&[0xFF]);
        assert!(dec.next().is_none());
        assert_eq!(dec.remainder(), &[] as &[u8]);
    }

    #[test]
    fn decoder_remainder_after_end_marker() {
        // Encode one option, write end marker, append trailing bytes manually.
        let mut buf = [0u8; 16];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(1, &[0xAA]).unwrap();
        enc.end_marker().unwrap();
        let opt_len = enc.finish();
        buf[opt_len] = 0xDE;
        buf[opt_len + 1] = 0xAD;

        let mut dec = OptionDecoder::new(&buf[..opt_len + 2]);
        let _ = dec.next().unwrap().unwrap(); // consume the option
        assert!(dec.next().is_none()); // end marker stops iteration
        assert_eq!(dec.remainder(), &[0xDE, 0xAD]);
    }

    #[test]
    fn decoder_remainder_empty_without_end_marker() {
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(1, &[0x01]).unwrap();
        let len = enc.finish();

        let mut dec = OptionDecoder::new(&buf[..len]);
        let _ = dec.next().unwrap().unwrap();
        assert!(dec.next().is_none());
        // No end marker was written, so remainder is empty even after exhaustion.
        assert_eq!(dec.remainder(), &[] as &[u8]);
    }

    #[test]
    fn decoder_remainder_empty_before_exhausted() {
        // remainder() returns empty while the decoder hasn't finished yet.
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(1, &[0x01]).unwrap();
        enc.end_marker().unwrap();
        let len = enc.finish();

        let dec = OptionDecoder::new(&buf[..len]);
        // Haven't called next() yet — not finished.
        assert_eq!(dec.remainder(), &[] as &[u8]);
    }

    // ── OptionDecoder: error paths ────────────────────────────────────────────

    #[test]
    fn decoder_truncated_value_returns_error() {
        // Header says value is 3 bytes long, but only 1 byte follows.
        let data = [0x03, 0xAB]; // delta=0, len=3, but only 1 value byte
        let mut dec = OptionDecoder::new(&data);
        assert!(matches!(dec.next(), Some(Err(ParseError::Truncated))));
        assert!(dec.next().is_none()); // error stops further iteration
    }

    #[test]
    fn decoder_truncated_extended_delta_returns_error() {
        // Nibble 13 means 1 extended delta byte follows, but the buffer is empty after header.
        let data = [0xD0]; // delta_nibble=13 but no ext byte
        let mut dec = OptionDecoder::new(&data);
        assert!(matches!(dec.next(), Some(Err(ParseError::Truncated))));
        assert!(dec.next().is_none());
    }

    #[test]
    fn decoder_invalid_nibble_returns_error() {
        // Nibble value 15 (0xF) is reserved/invalid.
        let data = [0xF0]; // delta_nibble=15
        let mut dec = OptionDecoder::new(&data);
        assert!(matches!(
            dec.next(),
            Some(Err(ParseError::InvalidOptionNibble))
        ));
        assert!(dec.next().is_none());
    }

    #[test]
    fn decoder_option_number_overflow_returns_error() {
        // Two options: first at u16::MAX, second with delta=1 → overflow.
        let mut buf = [0u8; 16];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(u16::MAX, &[]).unwrap();
        let len = enc.finish();

        // Manually append another option with delta=1 encoded inline.
        buf[len] = 0x10; // delta_nibble=1, len_nibble=0
        let mut dec = OptionDecoder::new(&buf[..len + 1]);
        let _ = dec.next().unwrap().unwrap(); // u16::MAX decoded OK
        assert!(matches!(dec.next(), Some(Err(ParseError::MalformedOption))));
        assert!(dec.next().is_none());
    }
}
