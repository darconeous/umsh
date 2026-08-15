//! The Node Management payload envelope.
//!
//! ```text
//! +-------+---------+------+----------+
//! | TOKEN | OPTIONS | 0xFF |  FRAME   |
//! +-------+---------+------+----------+
//!   2 B    variable   1 B    variable
//! ```
//!
//! Request and Response payloads share this format; direction lives
//! entirely in the payload type. The frame extends to the end of the
//! payload, so the end marker is always present.

use umsh_core::options::{OptionDecoder, OptionEncoder};
use umsh_core::{EncodeError, ParseError};
use umsh_ulcp::pui;

/// Option 1 — the continuation handle for a read spanning several
/// exchanges. Critical: a device that cannot honor a cursor must say so
/// rather than answer from the beginning.
pub const OPT_CURSOR: u16 = 1;
/// Option 2 — approximate octets not yet returned. Elective: it drives a
/// progress bar and nothing else.
pub const OPT_REMAINING: u16 = 2;

/// Longest cursor the format permits.
pub const CURSOR_MAX: usize = 8;

/// The two-octet token, opaque to everyone but the administrator that
/// chose it.
pub type Token = [u8; 2];

/// A parsed envelope borrowing from the payload it was read out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub token: Token,
    /// The cursor to present in the *next* request, in a response; the
    /// position being continued, in a request.
    pub cursor: Option<&'a [u8]>,
    /// Advisory count of octets not yet returned.
    pub remaining: Option<u32>,
    /// Exactly one ULCP frame, unparsed.
    pub frame: &'a [u8],
}

/// Why an envelope could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The payload ended before the envelope was complete, or the option
    /// block is malformed.
    Malformed(ParseError),
    /// An option this implementation does not recognize, in the critical
    /// (odd-numbered) range. A device answers `STATUS_UNIMPLEMENTED`; an
    /// administrator treats the exchange as failed.
    UnknownCritical(u16),
    /// A recognized option carried a value it cannot hold: a cursor
    /// outside 1–8 octets, or a REMAINING that is not a packed unsigned
    /// integer.
    InvalidOptionValue(u16),
}

impl From<ParseError> for EnvelopeError {
    fn from(error: ParseError) -> Self {
        Self::Malformed(error)
    }
}

impl<'a> Envelope<'a> {
    /// A bare envelope carrying `frame` and nothing else.
    pub const fn new(token: Token, frame: &'a [u8]) -> Self {
        Self {
            token,
            cursor: None,
            remaining: None,
            frame,
        }
    }

    pub const fn with_cursor(mut self, cursor: &'a [u8]) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub const fn with_remaining(mut self, remaining: u32) -> Self {
        self.remaining = Some(remaining);
        self
    }

    /// Read an envelope out of a payload, the payload type byte already
    /// stripped.
    pub fn parse(payload: &'a [u8]) -> Result<Self, EnvelopeError> {
        let [token0, token1, rest @ ..] = payload else {
            return Err(EnvelopeError::Malformed(ParseError::Truncated));
        };

        let mut cursor = None;
        let mut remaining = None;

        let mut decoder = OptionDecoder::new(rest);
        for result in decoder.by_ref() {
            let (number, value) = result?;
            match number {
                OPT_CURSOR => {
                    if value.is_empty() || value.len() > CURSOR_MAX {
                        return Err(EnvelopeError::InvalidOptionValue(number));
                    }
                    cursor = Some(value);
                }
                OPT_REMAINING => {
                    let (parsed, consumed) = pui::decode(value)
                        .map_err(|_| EnvelopeError::InvalidOptionValue(number))?;
                    if consumed != value.len() {
                        return Err(EnvelopeError::InvalidOptionValue(number));
                    }
                    remaining = Some(parsed);
                }
                // Odd is critical, even is elective, as in MAC command
                // options. Skipping the elective ones is the whole point
                // of the distinction.
                _ if number % 2 == 1 => return Err(EnvelopeError::UnknownCritical(number)),
                _ => {}
            }
        }

        // The frame follows the end marker, so a payload that never
        // reached one has no frame at all — an empty frame, which the
        // caller answers `STATUS_PARSE_ERROR`.
        Ok(Self {
            token: [*token0, *token1],
            cursor,
            remaining,
            frame: decoder.remainder(),
        })
    }

    /// Write the envelope, returning its length.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        if buf.len() < 2 {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[0] = self.token[0];
        buf[1] = self.token[1];
        let mut pos = 2;

        {
            let mut enc = OptionEncoder::new(&mut buf[pos..]);
            if let Some(cursor) = self.cursor {
                if cursor.is_empty() || cursor.len() > CURSOR_MAX {
                    return Err(EncodeError::OptionValueTooLarge);
                }
                enc.put(OPT_CURSOR, cursor)?;
            }
            if let Some(remaining) = self.remaining {
                let mut value = [0u8; pui::MAX_LEN];
                let len = pui::encode(remaining, &mut value)
                    .map_err(|_| EncodeError::OptionValueTooLarge)?;
                enc.put(OPT_REMAINING, &value[..len])?;
            }
            // Always present: the frame follows.
            enc.end_marker()?;
            pos += enc.finish();
        }

        if pos + self.frame.len() > buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[pos..pos + self.frame.len()].copy_from_slice(self.frame);
        Ok(pos + self.frame.len())
    }

    /// Octets this envelope costs a payload beyond its frame.
    pub fn overhead(&self) -> usize {
        let mut scratch = [0u8; OVERHEAD_MAX];
        let bare = Self {
            frame: &[],
            ..*self
        };
        // Nothing here can overflow `scratch`: the cursor is bounded at
        // encode time and REMAINING is a packed unsigned integer.
        bare.encode(&mut scratch).unwrap_or(scratch.len())
    }
}

/// Worst-case envelope overhead: token, the longest cursor, the longest
/// REMAINING, and the end marker.
///
/// Sizing a payload budget against this rather than against a particular
/// envelope keeps a fragment that acquires a cursor from overflowing the
/// frame it was measured for.
pub const OVERHEAD_MAX: usize = 2      // token
    + 1 + CURSOR_MAX                   // CURSOR header (delta 1, len 8) + value
    + 1 + pui::MAX_LEN                 // REMAINING header + value
    + 1; // end marker

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: &[u8] = &[0x80, 0x02, 0x01];

    fn round_trip(envelope: &Envelope<'_>) -> ([u8; 64], usize) {
        let mut buf = [0u8; 64];
        let len = envelope.encode(&mut buf).expect("encode");
        let parsed = Envelope::parse(&buf[..len]).expect("parse");
        assert_eq!(&parsed, envelope);
        (buf, len)
    }

    #[test]
    fn a_bare_envelope_is_token_marker_frame() {
        let (buf, len) = round_trip(&Envelope::new([0xAB, 0xCD], FRAME));
        assert_eq!(&buf[..len], &[0xAB, 0xCD, 0xFF, 0x80, 0x02, 0x01]);
    }

    #[test]
    fn options_round_trip() {
        round_trip(&Envelope::new([1, 2], FRAME).with_cursor(&[9, 8, 7]));
        round_trip(&Envelope::new([1, 2], FRAME).with_remaining(0));
        round_trip(&Envelope::new([1, 2], FRAME).with_remaining(pui::MAX_VALUE));
        round_trip(
            &Envelope::new([1, 2], FRAME)
                .with_cursor(&[0; CURSOR_MAX])
                .with_remaining(300),
        );
    }

    #[test]
    fn an_empty_frame_parses_as_an_empty_frame() {
        // The device answers this STATUS_PARSE_ERROR rather than
        // treating the payload itself as malformed.
        let envelope = Envelope::parse(&[1, 2, 0xFF]).expect("parse");
        assert!(envelope.frame.is_empty());
    }

    #[test]
    fn a_payload_shorter_than_a_token_is_malformed() {
        assert_eq!(
            Envelope::parse(&[1]),
            Err(EnvelopeError::Malformed(ParseError::Truncated))
        );
    }

    #[test]
    fn an_unknown_critical_option_is_reported_and_an_elective_one_is_not() {
        let mut buf = [0u8; 32];
        let encoded = {
            let mut enc = OptionEncoder::new(&mut buf[2..]);
            enc.put(3, &[0]).unwrap();
            enc.end_marker().unwrap();
            2 + enc.finish()
        };
        assert_eq!(
            Envelope::parse(&buf[..encoded]),
            Err(EnvelopeError::UnknownCritical(3))
        );

        let mut buf = [0u8; 32];
        let encoded = {
            let mut enc = OptionEncoder::new(&mut buf[2..]);
            enc.put(4, &[0]).unwrap();
            enc.end_marker().unwrap();
            2 + enc.finish()
        };
        let envelope = Envelope::parse(&buf[..encoded]).expect("elective options are skipped");
        assert_eq!(envelope.cursor, None);
    }

    #[test]
    fn a_cursor_outside_one_to_eight_octets_is_rejected() {
        for width in [0usize, CURSOR_MAX + 1] {
            let mut buf = [0u8; 32];
            let encoded = {
                let mut enc = OptionEncoder::new(&mut buf[2..]);
                enc.put(OPT_CURSOR, &[0u8; 16][..width]).unwrap();
                enc.end_marker().unwrap();
                2 + enc.finish()
            };
            assert_eq!(
                Envelope::parse(&buf[..encoded]),
                Err(EnvelopeError::InvalidOptionValue(OPT_CURSOR))
            );
        }
    }

    #[test]
    fn a_remaining_that_is_not_one_whole_pui_is_rejected() {
        for value in [&[][..], &[0xFF, 0xFF, 0xFF, 0x7F][..], &[0x00, 0x00][..]] {
            let mut buf = [0u8; 32];
            let encoded = {
                let mut enc = OptionEncoder::new(&mut buf[2..]);
                enc.put(OPT_REMAINING, value).unwrap();
                enc.end_marker().unwrap();
                2 + enc.finish()
            };
            assert_eq!(
                Envelope::parse(&buf[..encoded]),
                Err(EnvelopeError::InvalidOptionValue(OPT_REMAINING))
            );
        }
    }

    #[test]
    fn a_buffer_one_octet_short_fails_rather_than_truncating() {
        let envelope = Envelope::new([1, 2], FRAME);
        let mut buf = [0u8; 64];
        let len = envelope.encode(&mut buf).unwrap();
        assert_eq!(
            envelope.encode(&mut buf[..len - 1]),
            Err(EncodeError::BufferTooSmall)
        );
    }

    #[test]
    fn overhead_bounds_every_envelope_this_crate_can_write() {
        let worst = Envelope::new([0, 0], &[])
            .with_cursor(&[0; CURSOR_MAX])
            .with_remaining(pui::MAX_VALUE);
        assert_eq!(worst.overhead(), OVERHEAD_MAX);
        assert!(Envelope::new([0, 0], &[]).overhead() <= OVERHEAD_MAX);
    }
}
