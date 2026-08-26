//! ULCP frame grammar.
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
    /// is not a ULCP frame) or a reserved bit is set (the
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

/// Command identifiers defined by the minimal and full specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    /// No-operation liveness check (host to device).
    Nop = 0,
    /// Software reset request (host to device).
    Reset = 1,
    /// Get property value (host to device).
    PropGet = 2,
    /// Set property value (host to device).
    PropSet = 3,
    /// Insert an item into a multi-value property (host to device).
    PropInsert = 4,
    /// Remove an item from a multi-value property (host to device).
    PropRemove = 5,
    /// Property value notification (device to host).
    PropIs = 6,
    /// Item-inserted notification (device to host).
    PropInserted = 7,
    /// Item-removed notification (device to host).
    PropRemoved = 8,
    /// Send data to a stream (host to device).
    StrSend = 9,
    /// Data received from a stream (device to host).
    StrRecv = 10,
    /// Deliver queued inbound frames (host to device).
    QueueDrain = 11,
    /// Save state to non-volatile storage (host to device).
    Save = 12,
    /// Erase all saved state (host to device).
    Clear = 13,
    /// Restore state from the saved snapshot (host to device).
    Restore = 14,
    /// Factory reset (host to device): erase ALL mutable state — saved
    /// provisioning, device identity, BLE bonds, pairing PIN, and every
    /// other persisted journal — then reboot. Unlike `CMD_CLEAR` (which
    /// exempts bonds and the PIN and leaves the live session running),
    /// this returns the radio to a blank factory state and does not reply:
    /// the reboot drops the link.
    FactoryReset = 15,
    /// Restart the hardware (host to device): the device reboots as if
    /// power-cycled, keeping every piece of persisted state. Unlike
    /// `CMD_RST` (which returns protocol state to its post-reset values
    /// with the device still running), this drops the link, and like
    /// `CMD_FACTORY_RESET` it does not reply. Requires `CAP_REBOOT`; a
    /// device without it answers `STATUS_UNIMPLEMENTED` instead.
    Reboot = 16,
    /// Get several property values (host to device). Requires
    /// `CAP_CMD_MULTI`.
    PropMultiGet = 21,
    /// Set several property values in order (host to device). Requires
    /// `CAP_CMD_MULTI`.
    PropMultiSet = 22,
    /// Multiple property value notification (device to host), answering
    /// `CMD_PROP_MULTI_GET` or `CMD_PROP_MULTI_SET`. Never unsolicited.
    PropAre = 23,
}

impl Cmd {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Nop),
            1 => Some(Self::Reset),
            2 => Some(Self::PropGet),
            3 => Some(Self::PropSet),
            4 => Some(Self::PropInsert),
            5 => Some(Self::PropRemove),
            6 => Some(Self::PropIs),
            7 => Some(Self::PropInserted),
            8 => Some(Self::PropRemoved),
            9 => Some(Self::StrSend),
            10 => Some(Self::StrRecv),
            11 => Some(Self::QueueDrain),
            12 => Some(Self::Save),
            13 => Some(Self::Clear),
            14 => Some(Self::Restore),
            15 => Some(Self::FactoryReset),
            16 => Some(Self::Reboot),
            21 => Some(Self::PropMultiGet),
            22 => Some(Self::PropMultiSet),
            23 => Some(Self::PropAre),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended before the structure was complete.
    Truncated,
    /// The header `FLG` pattern did not match; not a ULCP frame.
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

    /// Bytes still available in the buffer.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Bytes written so far.
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append one multi-property entry: the combined length of the key
    /// and value, then the key, then the value.
    ///
    /// The entry is written whole or not at all, so a caller that runs
    /// out of room keeps a well-formed frame of the entries that fit.
    pub fn write_entry(&mut self, key: u32, value: &[u8]) -> Result<(), WriteError> {
        let total = entry_len(key, value.len()).ok_or(WriteError::ValueTooLarge)?;
        if self.remaining() < total {
            return Err(WriteError::BufferTooSmall);
        }
        let body = pui::encoded_len(key) + value.len();
        self.write_pui(body as u32)?;
        self.write_pui(key)?;
        self.write_bytes(value)
    }

    /// Append an entry reporting a status in the position of the property
    /// it answers.
    pub fn write_status_entry(&mut self, status: Status) -> Result<(), WriteError> {
        let mut value = [0u8; pui::MAX_LEN];
        let len = pui::encode(status.0, &mut value)?;
        self.write_entry(crate::ids::prop::LAST_STATUS, &value[..len])
    }

    /// Finish the frame, returning its total length in the buffer.
    pub fn finish(self) -> usize {
        self.len
    }
}

/// Space a multi-property entry occupies, its length prefix included.
///
/// Returns `None` when the combined key and value exceed what the length
/// prefix can express.
pub const fn entry_len(key: u32, value_len: usize) -> Option<usize> {
    let body = pui::encoded_len(key) + value_len;
    if body > pui::MAX_VALUE as usize {
        return None;
    }
    Some(pui::encoded_len(body as u32) + body)
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

/// Encode a `CMD_PROP_INSERT` frame. `item` is one item in the
/// property's item form, with no length prefix.
pub fn prop_insert(buf: &mut [u8], tid: u8, key: u32, item: &[u8]) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropInsert)?;
    writer.write_pui(key)?;
    writer.write_bytes(item)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_REMOVE` frame. `selector` is the property's
/// documented item selector, with no length prefix.
pub fn prop_remove(
    buf: &mut [u8],
    tid: u8,
    key: u32,
    selector: &[u8],
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropRemove)?;
    writer.write_pui(key)?;
    writer.write_bytes(selector)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_INSERTED` frame. `digest` is the inserted item in
/// the property's digest form — never in a form containing key material.
pub fn prop_inserted(
    buf: &mut [u8],
    tid: u8,
    key: u32,
    digest: &[u8],
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropInserted)?;
    writer.write_pui(key)?;
    writer.write_bytes(digest)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_REMOVED` frame. `digest` is the removed item in
/// the property's digest form.
pub fn prop_removed(buf: &mut [u8], tid: u8, key: u32, digest: &[u8]) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropRemoved)?;
    writer.write_pui(key)?;
    writer.write_bytes(digest)?;
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_MULTI_GET` frame: the property identifiers one
/// after another, with no delimiters.
pub fn prop_multi_get(buf: &mut [u8], tid: u8, keys: &[u32]) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropMultiGet)?;
    for &key in keys {
        writer.write_pui(key)?;
    }
    Ok(writer.finish())
}

/// Encode a `CMD_PROP_MULTI_SET` frame from key and value pairs.
pub fn prop_multi_set(
    buf: &mut [u8],
    tid: u8,
    entries: &[(u32, &[u8])],
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::PropMultiSet)?;
    for &(key, value) in entries {
        writer.write_entry(key, value)?;
    }
    Ok(writer.finish())
}

/// Begin a `CMD_PROP_ARE` frame, to which the caller appends entries with
/// [`FrameWriter::write_entry`] and [`FrameWriter::write_status_entry`].
pub fn prop_are(buf: &mut [u8], tid: u8) -> Result<FrameWriter<'_>, WriteError> {
    FrameWriter::new(buf, tid, Cmd::PropAre)
}

/// One entry of a `CMD_PROP_MULTI_SET` or `CMD_PROP_ARE` payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiEntry<'a> {
    pub key: u32,
    pub value: &'a [u8],
}

/// Iterator over the entries of a `CMD_PROP_MULTI_SET` or `CMD_PROP_ARE`
/// payload.
///
/// A malformed entry yields one error and ends the iteration: the
/// remaining bytes cannot be located once a length is untrustworthy.
#[derive(Clone, Copy, Debug)]
pub struct MultiEntries<'a> {
    rest: &'a [u8],
}

impl<'a> MultiEntries<'a> {
    pub const fn new(payload: &'a [u8]) -> Self {
        Self { rest: payload }
    }

    /// The bytes not yet consumed, so a caller serving entries across
    /// several calls can record where it stopped.
    pub const fn remainder(&self) -> &'a [u8] {
        self.rest
    }

    fn take_entry(&mut self) -> Result<MultiEntry<'a>, ParseError> {
        let payload = core::mem::take(&mut self.rest);
        let (body_len, consumed) = pui::decode(payload)?;
        let after_len = &payload[consumed..];
        let body_len = body_len as usize;
        if after_len.len() < body_len {
            return Err(ParseError::Truncated);
        }
        let (body, tail) = after_len.split_at(body_len);
        let (key, key_len) = pui::decode(body)?;
        self.rest = tail;
        Ok(MultiEntry {
            key,
            value: &body[key_len..],
        })
    }
}

impl<'a> Iterator for MultiEntries<'a> {
    type Item = Result<MultiEntry<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        Some(self.take_entry())
    }
}

/// Iterator over the property identifiers of a `CMD_PROP_MULTI_GET`
/// payload.
#[derive(Clone, Copy, Debug)]
pub struct MultiGetKeys<'a> {
    rest: &'a [u8],
}

impl<'a> MultiGetKeys<'a> {
    pub const fn new(payload: &'a [u8]) -> Self {
        Self { rest: payload }
    }

    /// The bytes not yet consumed.
    pub const fn remainder(&self) -> &'a [u8] {
        self.rest
    }
}

impl Iterator for MultiGetKeys<'_> {
    type Item = Result<u32, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let payload = core::mem::take(&mut self.rest);
        match pui::decode(payload) {
            Ok((key, consumed)) => {
                self.rest = &payload[consumed..];
                Some(Ok(key))
            }
            Err(error) => Some(Err(error.into())),
        }
    }
}

/// Encode a `CMD_QUEUE_DRAIN` frame (no payload).
pub fn queue_drain(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::QueueDrain)?.finish())
}

/// Encode a `CMD_SAVE` frame (no payload).
pub fn save(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::Save)?.finish())
}

/// Encode a `CMD_CLEAR` frame (no payload).
pub fn clear(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::Clear)?.finish())
}

/// Encode a `CMD_FACTORY_RESET` frame (no payload). The device erases all
/// mutable state and reboots without replying.
pub fn factory_reset(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::FactoryReset)?.finish())
}

/// Encode a `CMD_REBOOT` frame (no payload). The device restarts without
/// replying, keeping everything it has persisted.
pub fn reboot(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::Reboot)?.finish())
}

/// Encode a `CMD_RESTORE` frame (no payload).
pub fn restore(buf: &mut [u8], tid: u8) -> Result<usize, WriteError> {
    Ok(FrameWriter::new(buf, tid, Cmd::Restore)?.finish())
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
        let frame = Frame::parse(&[0x81, 0x11]).unwrap();
        assert_eq!(frame.cmd, 17);
        assert_eq!(frame.command(), None);
    }

    #[test]
    fn every_assigned_command_round_trips() {
        for id in (0..=16u8).chain(21..=23) {
            let cmd = Cmd::from_u8(id).unwrap_or_else(|| panic!("command {id} unassigned"));
            assert_eq!(cmd as u8, id);
        }
        for id in (17..=20u8).chain(24..=127) {
            assert_eq!(Cmd::from_u8(id), None, "command {id} should be unassigned");
        }
    }

    #[test]
    fn insert_remove_round_trip() {
        let mut buf = [0u8; 80];
        let item = [0xA5u8; 33];
        let len = prop_insert(&mut buf, 3, prop::HOST_RX_FILTERS, &item).unwrap();
        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::PropInsert));
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.key, prop::HOST_RX_FILTERS);
        assert_eq!(payload.value, &item);

        let len = prop_remove(&mut buf, 4, prop::HOST_PEER_KEYS, &item[..32]).unwrap();
        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::PropRemove));
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.key, prop::HOST_PEER_KEYS);
        assert_eq!(payload.value, &item[..32]);
    }

    #[test]
    fn inserted_removed_round_trip() {
        let mut buf = [0u8; 48];
        let digest = [0x42u8; 32];
        let len = prop_inserted(&mut buf, 5, prop::HOST_PEER_KEYS, &digest).unwrap();
        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::PropInserted));
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.value, &digest);

        let len = prop_removed(
            &mut buf,
            TID_UNSOLICITED,
            prop::HOST_CHANNEL_KEYS,
            &[0x12, 0x34],
        )
        .unwrap();
        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::PropRemoved));
        assert_eq!(frame.header.tid(), TID_UNSOLICITED);
        let payload = PropPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.key, prop::HOST_CHANNEL_KEYS);
        assert_eq!(payload.value, &[0x12, 0x34]);
    }

    #[test]
    fn payloadless_full_commands() {
        let mut buf = [0u8; 4];
        for (encode, cmd) in [
            (
                queue_drain as fn(&mut [u8], u8) -> Result<usize, WriteError>,
                Cmd::QueueDrain,
            ),
            (save, Cmd::Save),
            (clear, Cmd::Clear),
            (restore, Cmd::Restore),
            (factory_reset, Cmd::FactoryReset),
            (reboot, Cmd::Reboot),
        ] {
            let len = encode(&mut buf, 2).unwrap();
            assert_eq!(len, 2);
            let frame = Frame::parse(&buf[..len]).unwrap();
            assert_eq!(frame.command(), Some(cmd));
            assert!(frame.payload.is_empty());
        }
    }

    #[test]
    fn multi_get_round_trip() {
        let mut buf = [0u8; 32];
        let keys = [prop::CAPS, prop::PHY_DUTY_LIMIT, prop::DEV_ADMINS];
        let len = prop_multi_get(&mut buf, 6, &keys).unwrap();

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.header.tid(), 6);
        assert_eq!(frame.command(), Some(Cmd::PropMultiGet));
        let decoded: Result<std::vec::Vec<_>, _> = MultiGetKeys::new(frame.payload).collect();
        assert_eq!(decoded.unwrap(), keys);
    }

    #[test]
    fn multi_set_round_trip() {
        let mut buf = [0u8; 64];
        let long = [0xA5u8; 32];
        let entries: [(u32, &[u8]); 3] = [
            (prop::PHY_FREQ, &906_875u32.to_le_bytes()),
            (prop::DEV_ADMINS, &long),
            (prop::PHY_TX_POWER, &[]),
        ];
        let len = prop_multi_set(&mut buf, 2, &entries).unwrap();

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.command(), Some(Cmd::PropMultiSet));
        let decoded: std::vec::Vec<_> = MultiEntries::new(frame.payload)
            .map(|entry| entry.unwrap())
            .map(|entry| (entry.key, entry.value))
            .collect();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn are_carries_values_and_statuses() {
        let mut buf = [0u8; 32];
        let mut writer = prop_are(&mut buf, 4).unwrap();
        writer.write_entry(prop::PHY_TX_POWER, &[14]).unwrap();
        writer.write_status_entry(Status::PROP_NOT_FOUND).unwrap();
        let len = writer.finish();

        let frame = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(frame.header.tid(), 4);
        assert_eq!(frame.command(), Some(Cmd::PropAre));
        let entries: std::vec::Vec<_> = MultiEntries::new(frame.payload)
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, prop::PHY_TX_POWER);
        assert_eq!(entries[0].value, &[14]);
        assert_eq!(entries[1].key, prop::LAST_STATUS);
        let (code, _) = crate::pui::decode(entries[1].value).unwrap();
        assert_eq!(Status(code), Status::PROP_NOT_FOUND);
    }

    #[test]
    fn entry_length_matches_what_is_written() {
        let mut buf = [0u8; 512];
        // A value long enough to push the length prefix to two bytes.
        for value_len in [0usize, 1, 125, 126, 127, 300] {
            let value = std::vec![0x5Au8; value_len];
            for key in [prop::CAPS, prop::PHY_DUTY_LIMIT] {
                let mut writer = prop_are(&mut buf, 1).unwrap();
                let before = writer.len();
                writer.write_entry(key, &value).unwrap();
                assert_eq!(
                    writer.len() - before,
                    entry_len(key, value_len).unwrap(),
                    "key {key}, value length {value_len}"
                );
            }
        }
    }

    #[test]
    fn entry_that_does_not_fit_leaves_the_frame_intact() {
        let mut buf = [0u8; 12];
        let mut writer = prop_are(&mut buf, 1).unwrap();
        writer.write_entry(prop::PHY_TX_POWER, &[7]).unwrap();
        let after_first = writer.len();
        assert_eq!(
            writer.write_entry(prop::CAPS, &[0u8; 32]),
            Err(WriteError::BufferTooSmall)
        );
        assert_eq!(writer.len(), after_first);

        let len = writer.finish();
        let frame = Frame::parse(&buf[..len]).unwrap();
        let entries: std::vec::Vec<_> = MultiEntries::new(frame.payload)
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, &[7]);
    }

    #[test]
    fn malformed_entries_end_the_iteration() {
        // Body length 9 with only three bytes behind it.
        let mut entries = MultiEntries::new(&[0x09, 0x71, 0xAA, 0xBB]);
        assert_eq!(entries.next(), Some(Err(ParseError::Truncated)));
        assert_eq!(entries.next(), None);

        // A truncated key PUI inside an otherwise well-framed entry.
        let mut entries = MultiEntries::new(&[0x01, 0x80]);
        assert_eq!(entries.next(), Some(Err(ParseError::Truncated)));
        assert_eq!(entries.next(), None);

        let mut keys = MultiGetKeys::new(&[0x71, 0x80]);
        assert_eq!(keys.next(), Some(Ok(113)));
        assert_eq!(keys.next(), Some(Err(ParseError::Truncated)));
        assert_eq!(keys.next(), None);
    }

    #[test]
    fn empty_multi_payloads_yield_nothing() {
        assert_eq!(MultiEntries::new(&[]).next(), None);
        assert_eq!(MultiGetKeys::new(&[]).next(), None);
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
