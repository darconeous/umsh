//! HDLC-Lite framing for asynchronous serial links (UART, USB-CDC).
//!
//! Same discipline as Spinel's HDLC-Lite: frames are delimited by
//! `0x7E` flag bytes, control bytes inside a frame are escaped with
//! `0x7D` (XOR `0x20`), and each frame carries a trailing 16-bit FCS
//! (CRC-16/X-25 per RFC 1662), least-significant byte first.

/// Frame delimiter.
pub const FLAG: u8 = 0x7E;
/// Escape byte; the following byte is XORed with [`ESCAPE_XOR`].
pub const ESCAPE: u8 = 0x7D;
/// XOR applied to escaped bytes.
pub const ESCAPE_XOR: u8 = 0x20;

const XON: u8 = 0x11;
const XOFF: u8 = 0x13;

const fn needs_escape(byte: u8) -> bool {
    matches!(byte, FLAG | ESCAPE | XON | XOFF)
}

/// RFC 1662 FCS-16 (CRC-16/X-25) over `data`.
pub fn crc16(data: &[u8]) -> u16 {
    let mut fcs = 0xFFFFu16;
    for &byte in data {
        fcs ^= u16::from(byte);
        for _ in 0..8 {
            if fcs & 1 != 0 {
                fcs = (fcs >> 1) ^ 0x8408;
            } else {
                fcs >>= 1;
            }
        }
    }
    !fcs
}

/// Worst-case encoded size for a payload of `payload_len` bytes.
///
/// Two delimiting flags plus the payload and FCS with every byte
/// escaped.
pub const fn max_encoded_len(payload_len: usize) -> usize {
    2 + (payload_len + 2) * 2
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall,
}

struct Sink<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Sink<'_> {
    fn push(&mut self, byte: u8) -> Result<(), EncodeError> {
        if self.len >= self.out.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        self.out[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn push_escaped(&mut self, byte: u8) -> Result<(), EncodeError> {
        if needs_escape(byte) {
            self.push(ESCAPE)?;
            self.push(byte ^ ESCAPE_XOR)
        } else {
            self.push(byte)
        }
    }
}

/// Encode one frame, including both delimiting flags, into `out`.
///
/// Returns the number of bytes written. Size `out` with
/// [`max_encoded_len`] to make overflow impossible.
pub fn encode_frame(payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    let mut sink = Sink { out, len: 0 };
    sink.push(FLAG)?;
    for &byte in payload {
        sink.push_escaped(byte)?;
    }
    for byte in crc16(payload).to_le_bytes() {
        sink.push_escaped(byte)?;
    }
    sink.push(FLAG)?;
    Ok(sink.len)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The FCS did not match; the frame is corrupt.
    Crc,
    /// A complete frame was shorter than the two-byte FCS.
    TooShort,
    /// The frame exceeded the decoder's buffer capacity.
    TooLong,
    /// A flag byte arrived immediately after an escape byte.
    AbortedEscape,
}

/// Streaming decoder with an internal reassembly buffer of `N` bytes.
///
/// `N` bounds the *unescaped* frame size including the two FCS bytes.
/// Feed received bytes one at a time; a completed frame is returned
/// with the FCS already verified and stripped. Errors report a
/// discarded frame; the decoder resynchronizes on the next flag
/// automatically.
pub struct Decoder<const N: usize> {
    buf: [u8; N],
    len: usize,
    escaped: bool,
    overflow: bool,
}

impl<const N: usize> Default for Decoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Decoder<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
            escaped: false,
            overflow: false,
        }
    }

    /// Discard any partially received frame.
    pub fn reset(&mut self) {
        self.len = 0;
        self.escaped = false;
        self.overflow = false;
    }

    /// Process one received byte.
    ///
    /// Returns `Some(Ok(frame))` when `byte` completed a valid frame,
    /// `Some(Err(_))` when it completed or aborted an invalid one, and
    /// `None` otherwise.
    pub fn push(&mut self, byte: u8) -> Option<Result<&[u8], DecodeError>> {
        if byte == FLAG {
            let escaped = core::mem::replace(&mut self.escaped, false);
            let overflow = core::mem::replace(&mut self.overflow, false);
            let len = core::mem::replace(&mut self.len, 0);
            if escaped {
                return Some(Err(DecodeError::AbortedEscape));
            }
            if len == 0 {
                // Back-to-back or idle flags between frames.
                return None;
            }
            if overflow {
                return Some(Err(DecodeError::TooLong));
            }
            if len < 2 {
                return Some(Err(DecodeError::TooShort));
            }
            let payload_len = len - 2;
            let received_fcs = [self.buf[payload_len], self.buf[payload_len + 1]];
            if crc16(&self.buf[..payload_len]).to_le_bytes() != received_fcs {
                return Some(Err(DecodeError::Crc));
            }
            return Some(Ok(&self.buf[..payload_len]));
        }

        let byte = if byte == ESCAPE {
            self.escaped = true;
            return None;
        } else if core::mem::replace(&mut self.escaped, false) {
            byte ^ ESCAPE_XOR
        } else {
            byte
        };

        if self.len < N {
            self.buf[self.len] = byte;
            self.len += 1;
        } else {
            self.overflow = true;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `bytes` expecting exactly one complete frame.
    fn decode_all<const N: usize>(
        decoder: &mut Decoder<N>,
        bytes: &[u8],
    ) -> Option<Result<Vec<u8>, DecodeError>> {
        let mut result = None;
        for &byte in bytes {
            if let Some(outcome) = decoder.push(byte) {
                assert!(result.is_none(), "more than one frame in input");
                result = Some(outcome.map(<[u8]>::to_vec));
            }
        }
        result
    }

    #[test]
    fn crc16_check_value() {
        // CRC catalog check value for CRC-16/X-25.
        assert_eq!(crc16(b"123456789"), 0x906E);
    }

    #[test]
    fn round_trip_plain() {
        let payload = [0x81u8, 0x02, 0x00];
        let mut wire = [0u8; max_encoded_len(3)];
        let len = encode_frame(&payload, &mut wire).unwrap();
        assert_eq!(wire[0], FLAG);
        assert_eq!(wire[len - 1], FLAG);

        let mut decoder = Decoder::<16>::new();
        let frame = decode_all(&mut decoder, &wire[..len]).unwrap().unwrap();
        assert_eq!(frame, payload);
    }

    #[test]
    fn round_trip_escaped_bytes() {
        let payload = [FLAG, ESCAPE, XON, XOFF, 0x00, 0xFF];
        let mut wire = [0u8; max_encoded_len(6)];
        let len = encode_frame(&payload, &mut wire).unwrap();
        // Nothing between the flags may be a bare control byte.
        for &byte in &wire[1..len - 1] {
            assert_ne!(byte, FLAG);
            assert!(!needs_escape(byte) || byte == ESCAPE);
        }

        let mut decoder = Decoder::<16>::new();
        let frame = decode_all(&mut decoder, &wire[..len]).unwrap().unwrap();
        assert_eq!(frame, payload);
    }

    #[test]
    fn round_trip_empty_payload() {
        let mut wire = [0u8; max_encoded_len(0)];
        let len = encode_frame(&[], &mut wire).unwrap();
        let mut decoder = Decoder::<8>::new();
        let frame = decode_all(&mut decoder, &wire[..len]).unwrap().unwrap();
        assert!(frame.is_empty());
    }

    #[test]
    fn escaped_fcs_survives() {
        // Find a payload whose FCS contains a byte needing escape, and
        // make sure it round-trips. Payload [0x7A] -> FCS contains 0x7E
        // for at least one of the candidates below.
        for candidate in 0u8..=255 {
            let payload = [candidate];
            let fcs = crc16(&payload).to_le_bytes();
            if fcs.iter().copied().any(needs_escape) {
                let mut wire = [0u8; max_encoded_len(1)];
                let len = encode_frame(&payload, &mut wire).unwrap();
                let mut decoder = Decoder::<8>::new();
                let frame = decode_all(&mut decoder, &wire[..len]).unwrap().unwrap();
                assert_eq!(frame, payload);
                return;
            }
        }
        panic!("no candidate produced an FCS needing escape");
    }

    #[test]
    fn back_to_back_frames_share_flag() {
        // ...FLAG payload FLAG payload FLAG... with a single flag
        // separating consecutive frames.
        let mut wire = Vec::new();
        let mut scratch = [0u8; 32];
        for payload in [&[0x01u8][..], &[0x02u8][..]] {
            let len = encode_frame(payload, &mut scratch).unwrap();
            wire.extend_from_slice(&scratch[..len]);
        }
        // Also collapse the adjacent closing/opening flags to one.
        let mut collapsed = wire.clone();
        collapsed.dedup_by(|a, b| *a == FLAG && *b == FLAG);

        for input in [wire, collapsed] {
            let mut decoder = Decoder::<8>::new();
            let mut frames = Vec::new();
            for byte in input {
                if let Some(outcome) = decoder.push(byte) {
                    frames.push(outcome.unwrap().to_vec());
                }
            }
            assert_eq!(frames, [[0x01].to_vec(), [0x02].to_vec()]);
        }
    }

    #[test]
    fn corrupt_frame_reports_crc_error() {
        let mut wire = [0u8; max_encoded_len(3)];
        let len = encode_frame(&[0x81, 0x02, 0x00], &mut wire).unwrap();
        wire[1] ^= 0x01;
        let mut decoder = Decoder::<16>::new();
        assert_eq!(
            decode_all(&mut decoder, &wire[..len]),
            Some(Err(DecodeError::Crc))
        );
    }

    #[test]
    fn recovers_after_garbage() {
        let mut decoder = Decoder::<16>::new();
        // Garbage without flags is silently buffered, then aborted by
        // the first flag (as a CRC/short error), after which a valid
        // frame decodes normally.
        for byte in [0xAAu8, 0xBB, 0xCC] {
            assert_eq!(decoder.push(byte), None);
        }
        assert!(matches!(
            decoder.push(FLAG),
            Some(Err(DecodeError::Crc | DecodeError::TooShort))
        ));

        let mut wire = [0u8; max_encoded_len(1)];
        let len = encode_frame(&[0x42], &mut wire).unwrap();
        let frame = decode_all(&mut decoder, &wire[..len]).unwrap().unwrap();
        assert_eq!(frame, [0x42]);
    }

    #[test]
    fn oversized_frame_reports_too_long() {
        let payload = [0u8; 16];
        let mut wire = [0u8; max_encoded_len(16)];
        let len = encode_frame(&payload, &mut wire).unwrap();
        // Decoder buffer smaller than payload + FCS.
        let mut decoder = Decoder::<8>::new();
        assert_eq!(
            decode_all(&mut decoder, &wire[..len]),
            Some(Err(DecodeError::TooLong))
        );
        // And it recovers for the next frame.
        let len = encode_frame(&[0x01], &mut wire).unwrap();
        let frame = decode_all(&mut decoder, &wire[..len]).unwrap().unwrap();
        assert_eq!(frame, [0x01]);
    }

    #[test]
    fn escape_then_flag_aborts() {
        let mut decoder = Decoder::<8>::new();
        assert_eq!(decoder.push(FLAG), None);
        assert_eq!(decoder.push(0x42), None);
        assert_eq!(decoder.push(ESCAPE), None);
        assert_eq!(decoder.push(FLAG), Some(Err(DecodeError::AbortedEscape)));
    }

    #[test]
    fn encode_error_on_small_buffer() {
        let mut wire = [0u8; 4];
        assert_eq!(
            encode_frame(&[0x01, 0x02, 0x03], &mut wire),
            Err(EncodeError::BufferTooSmall)
        );
    }
}
