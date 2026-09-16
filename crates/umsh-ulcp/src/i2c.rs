//! Raw I2C bus access: `CMD_I2C_TRANSFER`, `CMD_I2C_SCAN`, their common
//! reply `CMD_I2C_RESULT`, and the two tables that describe what a host
//! may address (`PROP_I2C_BUSES`, `PROP_I2C_DEVICES`).
//!
//! A transfer is one bus transaction with the semantics of embedded-hal
//! 1.0's `I2c::transaction`: a START, the address, the operations in
//! order with a repeated START on each change of direction and no
//! restart between consecutive operations of the same direction, and one
//! STOP at the end. The wire form is
//!
//! ```text
//! BUS (UINT8) | ADDR (UINT8) | OP | OP | ...
//! OP = KIND (UINT8: 0 write, 1 read) | LEN (PUI) | [LEN data octets, write only]
//! ```
//!
//! This module validates structure and the protocol's own rules (a
//! 7-bit address, a known kind, no empty operations, at least one
//! operation). The per-bus limits a device advertises—how much data and
//! how many operations one transfer may carry—are the device's to
//! enforce, since only it knows which bus is meant.

use crate::frame::{Cmd, FrameWriter, WriteError};
use crate::items::{self, ItemError};
use crate::pui;
use crate::status::Status;

/// Largest 7-bit address.
pub const ADDRESS_MAX: u8 = 0x7F;
/// First address a scan probes when the request names no range: the
/// addresses below are reserved (general call, START byte, CBUS, and the
/// high-speed master codes).
pub const SCAN_DEFAULT_FIRST: u8 = 0x08;
/// Last address a scan probes when the request names no range: the
/// addresses above are reserved for 10-bit addressing and future use.
pub const SCAN_DEFAULT_LAST: u8 = 0x77;

/// Why a request could not be honored, before any bus was touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cError {
    /// The payload is truncated or its structure cannot be parsed.
    Parse,
    /// The structure parses but a value breaks the protocol's rules: an
    /// address above 7 bits, an unknown operation kind, an empty
    /// operation, no operations at all, or a scan range that is not
    /// ascending or reaches past 0x7F.
    Invalid,
}

impl I2cError {
    /// The status a device answers with.
    pub const fn status(self) -> Status {
        match self {
            Self::Parse => Status::PARSE_ERROR,
            Self::Invalid => Status::INVALID_ARGUMENT,
        }
    }
}

/// The direction of one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpKind {
    Write = 0,
    Read = 1,
}

impl OpKind {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Write),
            1 => Some(Self::Read),
            _ => None,
        }
    }
}

/// One operation of a transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op<'a> {
    /// Write these octets.
    Write(&'a [u8]),
    /// Read this many octets.
    Read(usize),
}

impl Op<'_> {
    pub const fn kind(&self) -> OpKind {
        match self {
            Self::Write(_) => OpKind::Write,
            Self::Read(_) => OpKind::Read,
        }
    }

    /// The octets this operation moves, in either direction.
    pub const fn data_len(&self) -> usize {
        match self {
            Self::Write(data) => data.len(),
            Self::Read(len) => *len,
        }
    }

    /// Space the operation occupies on the wire.
    pub const fn wire_len(&self) -> usize {
        let len = self.data_len();
        let body = match self {
            Self::Write(_) => len,
            Self::Read(_) => 0,
        };
        1 + pui::encoded_len(len as u32) + body
    }

    fn write(&self, writer: &mut FrameWriter<'_>) -> Result<(), WriteError> {
        writer.write_u8(self.kind().code())?;
        let len = u32::try_from(self.data_len()).map_err(|_| WriteError::ValueTooLarge)?;
        writer.write_pui(len)?;
        if let Self::Write(data) = self {
            writer.write_bytes(data)?;
        }
        Ok(())
    }
}

/// The operations of a transfer, decoded one at a time from their wire
/// form. Yields an error and then ends when the list is malformed, so a
/// device validates the whole list before touching the bus.
#[derive(Clone)]
pub struct Ops<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Ops<'a> {
    type Item = Result<Op<'a>, I2cError>;

    fn next(&mut self) -> Option<Self::Item> {
        let [kind, rest @ ..] = self.rest else {
            return None;
        };
        let result = (|| {
            let kind = OpKind::from_code(*kind).ok_or(I2cError::Invalid)?;
            let (len, consumed) = pui::decode(rest).map_err(|_| I2cError::Parse)?;
            let len = usize::try_from(len).map_err(|_| I2cError::Parse)?;
            if len == 0 {
                return Err(I2cError::Invalid);
            }
            let rest = &rest[consumed..];
            match kind {
                OpKind::Read => Ok((Op::Read(len), rest)),
                OpKind::Write => {
                    if rest.len() < len {
                        return Err(I2cError::Parse);
                    }
                    let (data, rest) = rest.split_at(len);
                    Ok((Op::Write(data), rest))
                }
            }
        })();
        match result {
            Ok((op, rest)) => {
                self.rest = rest;
                Some(Ok(op))
            }
            Err(error) => {
                self.rest = &[];
                Some(Err(error))
            }
        }
    }
}

/// What a transfer amounts to, summed over its operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferShape {
    /// Operations in the list.
    pub ops: usize,
    /// Octets written and read together, which the device's `MAX_DATA`
    /// limit bounds.
    pub data_len: usize,
    /// Octets the reply will carry.
    pub read_len: usize,
}

/// A `CMD_I2C_TRANSFER` request whose structure has been validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferRequest<'a> {
    pub bus: u8,
    /// The 7-bit address.
    pub addr: u8,
    ops: &'a [u8],
}

impl<'a> TransferRequest<'a> {
    /// Decode and validate a `CMD_I2C_TRANSFER` payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, I2cError> {
        let [bus, addr, ops @ ..] = payload else {
            return Err(I2cError::Parse);
        };
        if *addr > ADDRESS_MAX {
            return Err(I2cError::Invalid);
        }
        let request = Self {
            bus: *bus,
            addr: *addr,
            ops,
        };
        let mut count = 0usize;
        for op in request.ops() {
            op?;
            count += 1;
        }
        if count == 0 {
            return Err(I2cError::Invalid);
        }
        Ok(request)
    }

    /// Reassemble a request from its parts, for a device that staged the
    /// operation list of a request it already validated.
    pub const fn from_parts(bus: u8, addr: u8, ops: &'a [u8]) -> Self {
        Self { bus, addr, ops }
    }

    /// The operation list in wire form.
    pub const fn encoded_ops(&self) -> &'a [u8] {
        self.ops
    }

    /// The operations, in order.
    pub const fn ops(&self) -> Ops<'a> {
        Ops { rest: self.ops }
    }

    /// Sum the list up. Malformed operations are skipped, so call this
    /// on a request that [`Self::parse`] accepted.
    pub fn shape(&self) -> TransferShape {
        let mut shape = TransferShape::default();
        for op in self.ops().flatten() {
            shape.ops += 1;
            shape.data_len += op.data_len();
            if let Op::Read(len) = op {
                shape.read_len += len;
            }
        }
        shape
    }
}

/// Encode a `CMD_I2C_TRANSFER` frame.
pub fn encode_transfer(
    buf: &mut [u8],
    tid: u8,
    bus: u8,
    addr: u8,
    ops: &[Op<'_>],
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::I2cTransfer)?;
    writer.write_u8(bus)?;
    writer.write_u8(addr)?;
    for op in ops {
        op.write(&mut writer)?;
    }
    Ok(writer.finish())
}

/// A `CMD_I2C_SCAN` request with an absent range resolved to the
/// default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanRequest {
    pub bus: u8,
    pub first: u8,
    pub last: u8,
}

impl ScanRequest {
    /// A scan of the default range.
    pub const fn new(bus: u8) -> Self {
        Self {
            bus,
            first: SCAN_DEFAULT_FIRST,
            last: SCAN_DEFAULT_LAST,
        }
    }

    /// Decode and validate a `CMD_I2C_SCAN` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, I2cError> {
        let request = match payload {
            &[bus] => Self::new(bus),
            &[bus, first, last] => Self { bus, first, last },
            _ => return Err(I2cError::Parse),
        };
        if request.first > request.last || request.last > ADDRESS_MAX {
            return Err(I2cError::Invalid);
        }
        Ok(request)
    }

    /// How many addresses the scan probes, which bounds the reply.
    pub const fn len(&self) -> usize {
        self.last as usize - self.first as usize + 1
    }

    /// Whether `addr` is among the addresses probed.
    pub const fn covers(&self, addr: u8) -> bool {
        self.first <= addr && addr <= self.last
    }
}

/// Encode a `CMD_I2C_SCAN` frame; `range` is `None` for the default.
pub fn encode_scan(
    buf: &mut [u8],
    tid: u8,
    bus: u8,
    range: Option<(u8, u8)>,
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::I2cScan)?;
    writer.write_u8(bus)?;
    if let Some((first, last)) = range {
        writer.write_u8(first)?;
        writer.write_u8(last)?;
    }
    Ok(writer.finish())
}

/// Encode a `CMD_I2C_RESULT` frame carrying `data`: the octets a
/// transfer read, or the addresses a scan found.
pub fn encode_result(buf: &mut [u8], tid: u8, data: &[u8]) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::I2cResult)?;
    writer.write_bytes(data)?;
    Ok(writer.finish())
}

/// Octets a `CMD_I2C_RESULT` frame occupies beyond its payload: the
/// header and the command identifier.
pub const RESULT_OVERHEAD: usize = 2;

/// One `PROP_I2C_BUSES` item.
///
/// ```text
/// BUS (UINT8) | SPEED_KHZ (UINT16) | MAX_DATA (UINT16) | MAX_OPS (UINT8) | NAME (UTF-8)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusInfo<'a> {
    pub bus: u8,
    /// The clock the device drives the bus at.
    pub speed_khz: u16,
    /// The largest sum of write-data and read-length octets one
    /// transfer may carry.
    pub max_data: u16,
    /// The largest operation count one transfer may carry.
    pub max_ops: u8,
    /// Display text for the bus: its controller and pins, typically.
    pub name: &'a str,
}

impl<'a> BusInfo<'a> {
    const FIXED_LEN: usize = 6;

    /// Space the item occupies without its length prefix.
    pub const fn wire_len(&self) -> usize {
        Self::FIXED_LEN + self.name.len()
    }

    /// Append the item with its length prefix, returning the octets
    /// written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ItemError> {
        let mut item = [0u8; Self::FIXED_LEN + NAME_MAX_LEN];
        let len = self.wire_len();
        if len > item.len() {
            return Err(ItemError::BadLength);
        }
        item[0] = self.bus;
        item[1..3].copy_from_slice(&self.speed_khz.to_le_bytes());
        item[3..5].copy_from_slice(&self.max_data.to_le_bytes());
        item[5] = self.max_ops;
        item[6..len].copy_from_slice(self.name.as_bytes());
        items::encode_prefixed_item(&item[..len], out)
    }

    /// Decode one item (without its length prefix).
    pub fn decode(item: &'a [u8]) -> Result<Self, I2cError> {
        let [
            bus,
            speed_lo,
            speed_hi,
            max_data_lo,
            max_data_hi,
            max_ops,
            name @ ..,
        ] = item
        else {
            return Err(I2cError::Parse);
        };
        let name = core::str::from_utf8(name).map_err(|_| I2cError::Invalid)?;
        Ok(Self {
            bus: *bus,
            speed_khz: u16::from_le_bytes([*speed_lo, *speed_hi]),
            max_data: u16::from_le_bytes([*max_data_lo, *max_data_hi]),
            max_ops: *max_ops,
            name,
        })
    }
}

/// Longest bus or device name this crate encodes.
pub const NAME_MAX_LEN: usize = 64;

/// One `PROP_I2C_DEVICES` item.
///
/// ```text
/// BUS (UINT8) | ADDR (UINT8) | NAME (UTF-8)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo<'a> {
    pub bus: u8,
    /// The 7-bit address.
    pub addr: u8,
    /// The part the firmware knows to be there.
    pub name: &'a str,
}

impl<'a> DeviceInfo<'a> {
    const FIXED_LEN: usize = 2;

    /// Space the item occupies without its length prefix.
    pub const fn wire_len(&self) -> usize {
        Self::FIXED_LEN + self.name.len()
    }

    /// Append the item with its length prefix, returning the octets
    /// written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ItemError> {
        let mut item = [0u8; Self::FIXED_LEN + NAME_MAX_LEN];
        let len = self.wire_len();
        if len > item.len() {
            return Err(ItemError::BadLength);
        }
        item[0] = self.bus;
        item[1] = self.addr;
        item[2..len].copy_from_slice(self.name.as_bytes());
        items::encode_prefixed_item(&item[..len], out)
    }

    /// Decode one item (without its length prefix).
    pub fn decode(item: &'a [u8]) -> Result<Self, I2cError> {
        let [bus, addr, name @ ..] = item else {
            return Err(I2cError::Parse);
        };
        let name = core::str::from_utf8(name).map_err(|_| I2cError::Invalid)?;
        Ok(Self {
            bus: *bus,
            addr: *addr,
            name,
        })
    }
}

/// Decode a whole `PROP_I2C_BUSES` value.
pub fn buses(value: &[u8]) -> impl Iterator<Item = Result<BusInfo<'_>, I2cError>> {
    items::prefixed_items(value).map(|item| BusInfo::decode(item.map_err(|_| I2cError::Parse)?))
}

/// Decode a whole `PROP_I2C_DEVICES` value.
pub fn devices(value: &[u8]) -> impl Iterator<Item = Result<DeviceInfo<'_>, I2cError>> {
    items::prefixed_items(value).map(|item| DeviceInfo::decode(item.map_err(|_| I2cError::Parse)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

    fn payload(buf: &[u8], cmd: Cmd, tid: u8) -> &[u8] {
        let frame = Frame::parse(buf).unwrap();
        assert_eq!(frame.command(), Some(cmd));
        assert_eq!(frame.header.tid(), tid);
        frame.payload
    }

    #[test]
    fn a_register_read_round_trips() {
        let mut buf = [0u8; 32];
        let ops = [Op::Write(&[0x08]), Op::Read(2)];
        let len = encode_transfer(&mut buf, 3, 0, 0x55, &ops).unwrap();
        assert_eq!(buf[1], Cmd::I2cTransfer as u8);
        assert_eq!(&buf[2..len], &[0, 0x55, 0, 1, 0x08, 1, 2]);
        let request = TransferRequest::parse(payload(&buf[..len], Cmd::I2cTransfer, 3)).unwrap();
        assert_eq!((request.bus, request.addr), (0, 0x55));
        let decoded: Vec<Op<'_>> = request.ops().collect::<Result<_, _>>().unwrap();
        assert_eq!(decoded, ops);
        assert_eq!(
            request.shape(),
            TransferShape {
                ops: 2,
                data_len: 3,
                read_len: 2,
            }
        );
        // Reassembled from staged parts, the request reads the same.
        let staged = TransferRequest::from_parts(0, 0x55, request.encoded_ops());
        assert_eq!(staged, request);
    }

    #[test]
    fn long_operations_take_a_two_octet_length() {
        let data = [0xA5u8; 200];
        let ops = [Op::Write(&data), Op::Read(150)];
        assert_eq!(ops[0].wire_len(), 1 + 2 + 200);
        assert_eq!(ops[1].wire_len(), 1 + 2);
        let mut buf = [0u8; 256];
        let len = encode_transfer(&mut buf, 0, 1, 0x50, &ops).unwrap();
        assert_eq!(len, 2 + 2 + ops[0].wire_len() + ops[1].wire_len());
        let request = TransferRequest::parse(payload(&buf[..len], Cmd::I2cTransfer, 0)).unwrap();
        let decoded: Vec<Op<'_>> = request.ops().collect::<Result<_, _>>().unwrap();
        assert_eq!(decoded, ops);
        assert_eq!(request.shape().data_len, 350);
        assert_eq!(request.shape().read_len, 150);
    }

    #[test]
    fn invalid_transfers_are_refused_before_the_bus() {
        // Address above 7 bits.
        assert_eq!(
            TransferRequest::parse(&[0, 0x80, 1, 1]),
            Err(I2cError::Invalid)
        );
        // Unknown operation kind.
        assert_eq!(
            TransferRequest::parse(&[0, 0x50, 2, 1]),
            Err(I2cError::Invalid)
        );
        // An empty operation.
        assert_eq!(
            TransferRequest::parse(&[0, 0x50, 1, 0]),
            Err(I2cError::Invalid)
        );
        assert_eq!(
            TransferRequest::parse(&[0, 0x50, 0, 0]),
            Err(I2cError::Invalid)
        );
        // No operations at all.
        assert_eq!(TransferRequest::parse(&[0, 0x50]), Err(I2cError::Invalid));
        // A valid operation followed by an invalid one still fails.
        assert_eq!(
            TransferRequest::parse(&[0, 0x50, 1, 1, 7, 1]),
            Err(I2cError::Invalid)
        );
    }

    #[test]
    fn truncated_transfers_are_parse_errors() {
        assert_eq!(TransferRequest::parse(&[]), Err(I2cError::Parse));
        assert_eq!(TransferRequest::parse(&[0]), Err(I2cError::Parse));
        // A kind with no length.
        assert_eq!(TransferRequest::parse(&[0, 0x50, 1]), Err(I2cError::Parse));
        // Write data shorter than its length.
        assert_eq!(
            TransferRequest::parse(&[0, 0x50, 0, 3, 0xAA]),
            Err(I2cError::Parse)
        );
        // A length whose PUI never ends.
        assert_eq!(
            TransferRequest::parse(&[0, 0x50, 1, 0x80]),
            Err(I2cError::Parse)
        );
        assert_eq!(I2cError::Parse.status(), Status::PARSE_ERROR);
        assert_eq!(I2cError::Invalid.status(), Status::INVALID_ARGUMENT);
    }

    #[test]
    fn scan_requests_default_and_validate_their_range() {
        let mut buf = [0u8; 8];
        let len = encode_scan(&mut buf, 5, 2, None).unwrap();
        assert_eq!(len, 3);
        let request = ScanRequest::parse(payload(&buf[..len], Cmd::I2cScan, 5)).unwrap();
        assert_eq!(request, ScanRequest::new(2));
        assert_eq!(request.len(), 0x70);
        assert!(request.covers(0x08));
        assert!(request.covers(0x77));
        assert!(!request.covers(0x78));

        let len = encode_scan(&mut buf, 5, 0, Some((0x50, 0x57))).unwrap();
        let request = ScanRequest::parse(payload(&buf[..len], Cmd::I2cScan, 5)).unwrap();
        assert_eq!(
            request,
            ScanRequest {
                bus: 0,
                first: 0x50,
                last: 0x57,
            }
        );
        assert_eq!(request.len(), 8);

        assert_eq!(ScanRequest::parse(&[]), Err(I2cError::Parse));
        assert_eq!(ScanRequest::parse(&[0, 0x10]), Err(I2cError::Parse));
        assert_eq!(
            ScanRequest::parse(&[0, 0x10, 0x20, 0]),
            Err(I2cError::Parse)
        );
        assert_eq!(ScanRequest::parse(&[0, 0x20, 0x10]), Err(I2cError::Invalid));
        assert_eq!(ScanRequest::parse(&[0, 0x10, 0x80]), Err(I2cError::Invalid));
        // A single address is a valid range.
        assert!(ScanRequest::parse(&[0, 0x55, 0x55]).is_ok());
    }

    #[test]
    fn results_carry_their_data_verbatim() {
        let mut buf = [0u8; 16];
        let len = encode_result(&mut buf, 6, &[0x20, 0x28, 0x34]).unwrap();
        assert_eq!(len, RESULT_OVERHEAD + 3);
        assert_eq!(payload(&buf[..len], Cmd::I2cResult, 6), &[0x20, 0x28, 0x34]);
        let len = encode_result(&mut buf, 6, &[]).unwrap();
        assert_eq!(payload(&buf[..len], Cmd::I2cResult, 6), &[]);
    }

    #[test]
    fn bus_and_device_tables_round_trip() {
        let bus = BusInfo {
            bus: 0,
            speed_khz: 400,
            max_data: 255,
            max_ops: 16,
            name: "I2C0 SDA GPIO3 SCL GPIO2",
        };
        let mut table = [0u8; 64];
        let len = bus.encode(&mut table).unwrap();
        assert_eq!(len, 1 + bus.wire_len());
        assert_eq!(&table[1..7], &[0, 0x90, 0x01, 0xFF, 0x00, 16]);
        let decoded: Vec<BusInfo<'_>> = buses(&table[..len]).collect::<Result<_, _>>().unwrap();
        assert_eq!(decoded, [bus]);

        let parts = [
            DeviceInfo {
                bus: 0,
                addr: 0x55,
                name: "BQ27220",
            },
            DeviceInfo {
                bus: 0,
                addr: 0x6B,
                name: "",
            },
        ];
        let mut len = 0;
        for part in &parts {
            len += part.encode(&mut table[len..]).unwrap();
        }
        let decoded: Vec<DeviceInfo<'_>> =
            devices(&table[..len]).collect::<Result<_, _>>().unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn malformed_tables_are_refused() {
        // Too short for the fixed fields.
        assert_eq!(BusInfo::decode(&[0, 0x90, 0x01]), Err(I2cError::Parse));
        assert_eq!(DeviceInfo::decode(&[0]), Err(I2cError::Parse));
        // A name that is not UTF-8.
        assert_eq!(
            BusInfo::decode(&[0, 0x90, 0x01, 0xFF, 0x00, 16, 0xFF]),
            Err(I2cError::Invalid)
        );
        assert_eq!(DeviceInfo::decode(&[0, 0x55, 0xC0]), Err(I2cError::Invalid));
        // A truncated item prefix.
        assert_eq!(buses(&[9, 0, 0]).next(), Some(Err(I2cError::Parse)));
        // A name past what this crate encodes.
        let long = [b'x'; NAME_MAX_LEN + 1];
        let bus = BusInfo {
            bus: 0,
            speed_khz: 100,
            max_data: 32,
            max_ops: 4,
            name: core::str::from_utf8(&long).unwrap(),
        };
        assert_eq!(bus.encode(&mut [0u8; 128]), Err(ItemError::BadLength));
    }
}
