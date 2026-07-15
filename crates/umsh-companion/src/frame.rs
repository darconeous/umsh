//! Companion-radio frame grammar.
//!
//! A frame is a one-byte header, a one-byte command identifier, and a
//! command-defined payload. Frame length is provided by the framing
//! layer (see [`crate::hdlc`] for asynchronous serial links).

use crate::pui;
use crate::status::Status;

/// Mask of the two most significant header bits (the `FLG` field).
pub const HEADER_FLG_MASK: u8 = 0xC0;
/// Required value of the `FLG` field (`0b10` in the top two bits).
pub const HEADER_FLG_PATTERN: u8 = 0x80;
/// Mask of the three reserved header bits, which must be zero.
pub const HEADER_RESERVED_MASK: u8 = 0x38;
/// Mask of the three-bit transaction identifier.
pub const HEADER_TID_MASK: u8 = 0x07;

/// TID reserved for unsolicited commands and stream traffic.
pub const TID_UNSOLICITED: u8 = 0;
/// Largest usable transaction identifier.
pub const TID_MAX: u8 = 7;

/// Validated frame header byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header(u8);

impl Header {
    /// Build a header for the given transaction identifier.
    ///
    /// Returns `None` if `tid` exceeds [`TID_MAX`].
    pub const fn new(tid: u8) -> Option<Self> {
        if tid <= TID_MAX {
            Some(Self(HEADER_FLG_PATTERN | tid))
        } else {
            None
        }
    }

    /// Validate a received header byte.
    ///
    /// Returns `None` when the `FLG` pattern does not match (the frame
    /// is not a companion-radio frame) or a reserved bit is set (the
    /// frame must be ignored).
    pub const fn from_byte(byte: u8) -> Option<Self> {
        if byte & HEADER_FLG_MASK == HEADER_FLG_PATTERN && byte & HEADER_RESERVED_MASK == 0 {
            Some(Self(byte))
        } else {
            None
        }
    }

    pub const fn to_byte(self) -> u8 {
        self.0
    }

    pub const fn tid(self) -> u8 {
        self.0 & HEADER_TID_MASK
    }
}

/// Command identifiers defined by the minimal spec.
///
/// Identifiers 4, 5, 7, and 8 are reserved for property insert/remove
/// operations and their notifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    /// No-operation liveness check (host to NCP).
    Nop = 0,
    /// Software reset request (host to NCP).
    Reset = 1,
    /// Get property value (host to NCP).
    PropGet = 2,
    /// Set property value (host to NCP).
    PropSet = 3,
    /// Property value notification (NCP to host).
    PropIs = 6,
    /// Send data to a stream (host to NCP).
    StrSend = 9,
    /// Data received from a stream (NCP to host).
    StrRecv = 10,
}

impl Cmd {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Nop),
            1 => Some(Self::Reset),
            2 => Some(Self::PropGet),
            3 => Some(Self::PropSet),
            6 => Some(Self::PropIs),
            9 => Some(Self::StrSend),
            10 => Some(Self::StrRecv),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended before the structure was complete.
    Truncated,
    /// The header `FLG` pattern did not match; not a companion frame.
    BadFlag,
    /// A reserved header bit was set; the frame must be ignored.
    ReservedBits,
    /// The command identifier had its most significant bit set; the
    /// frame must be ignored.
    BadCommand,
    /// A packed unsigned integer inside the payload was malformed.
    BadPui,
}

impl From<pui::Error> for ParseError {
    fn from(error: pui::Error) -> Self {
        match error {
            pui::Error::Truncated => Self::Truncated,
            _ => Self::BadPui,
        }
    }
}

/// A parsed frame borrowing its payload from the input.
///
/// `cmd` is kept as the raw identifier so receivers can distinguish an
/// unknown-but-well-formed command (respond with
/// `STATUS_INVALID_COMMAND`) from a malformed frame (ignore).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub header: Header,
    pub cmd: u8,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let [header_byte, cmd, payload @ ..] = bytes else {
            return Err(ParseError::Truncated);
        };
        if header_byte & HEADER_FLG_MASK != HEADER_FLG_PATTERN {
            return Err(ParseError::BadFlag);
        }
        let header = Header::from_byte(*header_byte).ok_or(ParseError::ReservedBits)?;
        if cmd & 0x80 != 0 {
            return Err(ParseError::BadCommand);
        }
        Ok(Self {
            header,
            cmd: *cmd,
            payload,
        })
    }

    /// The command, if it is one defined by this crate.
    pub const fn command(&self) -> Option<Cmd> {
        Cmd::from_u8(self.cmd)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The output buffer cannot hold the frame.
    BufferTooSmall,
    /// The transaction identifier exceeds [`TID_MAX`].
    InvalidTid,
    /// A value exceeds the range of its wire representation.
    ValueTooLarge,
}

impl From<pui::Error> for WriteError {
    fn from(error: pui::Error) -> Self {
        match error {
            pui::Error::BufferTooSmall => Self::BufferTooSmall,
            _ => Self::ValueTooLarge,
        }
    }
}

/// Incremental frame builder over a caller-provided buffer.
pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> FrameWriter<'a> {
    /// Start a frame with the given TID and command.
    pub fn new(buf: &'a mut [u8], tid: u8, cmd: Cmd) -> Result<Self, WriteError> {
        let header = Header::new(tid).ok_or(WriteError::InvalidTid)?;
        let mut writer = Self { buf, len: 0 };
        writer.write_u8(header.to_byte())?;
        writer.write_u8(cmd as u8)?;
        Ok(writer)
    }

    pub fn write_u8(&mut self, byte: u8) -> Result<(), WriteError> {
        if self.len >= self.buf.len() {
            return Err(WriteError::BufferTooSmall);
        }
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(WriteError::BufferTooSmall)?;
        if end > self.buf.len() {
            return Err(WriteError::BufferTooSmall);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    pub fn write_pui(&mut self, value: u32) -> Result<(), WriteError> {
        let written = pui::encode(value, &mut self.buf[self.len..])?;
        self.len += written;
        Ok(())
    }

    pub fn write_u16_le(&mut self, value: u16) -> Result<(), WriteError> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_u32_le(&mut self, value: u32) -> Result<(), WriteError> {
        self.write_bytes(&value.to_le_bytes())
    }

    /// Finish the frame, returning its total length in the buffer.
    pub fn finish(self) -> usize {
        self.len
    }
}

/// Encode a `CMD_NOP` frame.
pub fn nop(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::Nop)?.finish())
}

/// Encode a `CMD_RST` frame.
pub fn reset(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::Reset)?.finish())
}

/// Encode a `CMD_PROP_GET` frame.
pub fn prop_get(buf: &mut [u8], tid: u8, key: u32) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropGet)?;
    writer.write_pui(key)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_SET` frame.
pub fn prop_set(buf: &mut [u8], tid: u8, key: u32, value: &[u8]) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropSet)?;
    writer.write_pui(key)?;
    writer.write_bytes(value)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_IS` frame.
pub fn prop_is(buf: &mut [u8], tid: u8, key: u32, value: &[u8]) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropIs)?;
    writer.write_pui(key)?;
    writer.write_bytes(value)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_IS` frame carrying `PROP_LAST_STATUS`.
pub fn last_status(buf: &mut [u8], tid: u8, status: Status) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropIs)?;
    writer.write_pui(crate::ids::prop::LAST_STATUS)?;
    writer.write_pui(status.0)?;
    Ok(writer.finish())
}

fn stream_payload(
    writer: &mut FrameWriter<'_>,
    stream: u32,
    data: &[u8],
    metadata: &[u8],
) -> Result<(), WriteError> {
    let data_len = u16::try_from(data.len()).map_err(|_| WriteError::ValueTooLarge)?;
    writer.write_pui(stream)?;
    writer.write_u16_le(data_len)?;
    writer.write_bytes(data)?;
    writer.write_bytes(metadata)
}

/// Encode a `CMD_STR_SEND` frame.
pub fn str_send(
    buf: &mut [u8],
    tid: u8,
    stream: u32,
    data: &[u8],
    metadata: &[u8],
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::StrSend)?;
    stream_payload(&mut writer, stream, data, metadata)?;
    Ok(writer.finish())
}

/// Encode a `CMD_STR_RECV` frame. Always uses TID zero.
pub fn str_recv(
    buf: &mut [u8],
    stream: u32,
    data: &[u8],
    metadata: &[u8],
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, TID_UNSOLICITED, Cmd::StrRecv)?;
    stream_payload(&mut writer, stream, data, metadata)?;
    Ok(writer.finish())
}

/// Payload of `CMD_PROP_GET`, `CMD_PROP_SET`, and `CMD_PROP_IS`.
///
/// For `CMD_PROP_GET` the value is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropPayload<'a> {
    pub key: u32,
    pub value: &'a [u8],
}

impl<'a> PropPayload<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<Self, ParseError> {
        let (key, consumed) = pui::decode(payload)?;
        Ok(Self {
            key,
            value: &payload[consumed..],
        })
    }
}

/// Payload of `CMD_STR_SEND` and `CMD_STR_RECV`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPayload<'a> {
    pub stream: u32,
    pub data: &'a [u8],
    /// Stream-defined trailing metadata; may be empty.
    pub metadata: &'a [u8],
}

impl<'a> StreamPayload<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<Self, ParseError> {
        let (stream, consumed) = pui::decode(payload)?;
        let rest = &payload[consumed..];
        let [len_lo, len_hi, rest @ ..] = rest else {
            return Err(ParseError::Truncated);
        };
        let data_len = usize::from(u16::from_le_bytes([*len_lo, *len_hi]));
        if rest.len() < data_len {
            return Err(ParseError::Truncated);
        }
        let (data, metadata) = rest.split_at(data_len);
        Ok(Self {
            stream,
            data,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{prop, stream};

    #[test]
    fn header_round_trip() {
        for tid in 0..=TID_MAX {
            let header = Header::new(tid).unwrap();
            assert_eq!(header.tid(), tid);
            assert_eq!(Header::from_byte(header.to_byte()), Some(header));
        }
        assert_eq!(Header::new(TID_MAX + 1), None);
    }

    #[test]
    fn header_rejects_bad_bytes() {
        // Wrong FLG patterns.
        assert_eq!(Header::from_byte(0x00), None);
        assert_eq!(Header::from_byte(0x40), None);
        assert_eq!(Header::from_byte(0xC0), None);
        // Each reserved bit set individually.
        for bit in [0x08u8, 0x10, 0x20] {
            assert_eq!(Header::from_byte(HEADER_FLG_PATTERN | bit), None);
        }
    }

    #[test]
    fn nop_frame() {
        let mut buf = [0u8; 8];
        let len = nop(&mut buf, 3).unwrap();
        assert_eq!(&buf[..len], &[0x83, 0x00]);

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.header.tid(), 3);
        assert_eq!(frame.command(), Some(Cmd::Nop));
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn prop_get_round_trip() {
        let mut buf = [0u8; 8];
        let len = prop_get(&mut buf, 1, prop::PHY_DUTY_LIMIT).unwrap();
        assert_eq!(&buf[..len], &[0x81, 0x02, 0xD6, 0x25]);

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::PropGet));
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.key, prop::PHY_DUTY_LIMIT);
        assert!(payload.value.is_empty());
    }

    #[test]
    fn prop_set_round_trip() {
        let mut buf = [0u8; 16];
        let len = prop_set(&mut buf, 2, prop::PHY_FREQ, &906_875u32.to_le_bytes()).unwrap();

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.header.tid(), 2);
        assert_eq!(frame.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.key, prop::PHY_FREQ);
        assert_eq!(payload.value, &906_875u32.to_le_bytes());
    }

    #[test]
    fn last_status_frame() {
        let mut buf = [0u8; 8];
        let len = last_status(&mut buf, 5, Status::DUTY_LIMIT).unwrap();
        assert_eq!(&buf[..len], &[0x85, 0x06, 0x00, 0x20]);

        let frame = Frame::parse(&buf[..len]).unwrap();
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.key, prop::LAST_STATUS);
        let (code, consumed) = crate::pui::decode(payload.value).unwrap();
        assert_eq!(Status(code), Status::DUTY_LIMIT);
        assert_eq!(consumed, payload.value.len());
    }

    #[test]
    fn stream_round_trip() {
        let mut buf = [0u8; 32];
        let data = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let meta = [0x7Fu8, 0x00];
        let len = str_send(&mut buf, 4, stream::PHY_RAW, &data, &meta).unwrap();

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::StrSend));
        let payload = StreamPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.stream, stream::PHY_RAW);
        assert_eq!(payload.data, &data);
        assert_eq!(payload.metadata, &meta);
    }

    #[test]
    fn stream_without_metadata() {
        let mut buf = [0u8; 16];
        let len = str_recv(&mut buf, stream::PHY_RAW, &[0xAA], &[]).unwrap();

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.header.tid(), TID_UNSOLICITED);
        let payload = StreamPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.data, &[0xAA]);
        assert!(payload.metadata.is_empty());
    }

    #[test]
    fn stream_truncated_data() {
        // Claims 4 data bytes but carries 2.
        let payload = [0x71, 0x04, 0x00, 0xAA, 0xBB];
        assert_eq!(StreamPayload::parse(&payload), Err(ParseError::Truncated));
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(Frame::parse(&[]), Err(ParseError::Truncated));
        assert_eq!(Frame::parse(&[0x80]), Err(ParseError::Truncated));
        assert_eq!(Frame::parse(&[0x00, 0x00]), Err(ParseError::BadFlag));
        assert_eq!(Frame::parse(&[0x88, 0x00]), Err(ParseError::ReservedBits));
        assert_eq!(Frame::parse(&[0x80, 0x80]), Err(ParseError::BadCommand));
    }

    #[test]
    fn unknown_command_is_well_formed() {
        let frame = Frame::parse(&[0x81, 0x04]).unwrap();
        assert_eq!(frame.cmd, 4);
        assert_eq!(frame.command(), None);
    }

    #[test]
    fn writer_reports_overflow() {
        let mut buf = [0u8; 3];
        assert_eq!(
            prop_set(&mut buf, 1, prop::PHY_FREQ, &[0; 8]),
            Err(WriteError::BufferTooSmall)
        );
    }
}
