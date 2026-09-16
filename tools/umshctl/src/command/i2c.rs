//! `i2c`: raw bus access to a device's I2C peripherals
//! (`PROP_I2C_BUSES`, `PROP_I2C_DEVICES`, `CMD_I2C_TRANSFER`,
//! `CMD_I2C_SCAN`).
//!
//! What the firmware's own drivers would do to a gauge or a charger, done
//! from the host instead: one transaction per command, with the device
//! serializing it against its own traffic. Bus and peripheral tables are
//! queried only by their explicit listing commands.

use std::str::FromStr;

use anyhow::{Result, anyhow, bail};

use umsh::ulcp::{FrameLink, UlcpDevice, UlcpError};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::i2c::{ADDRESS_MAX, Op, SCAN_DEFAULT_FIRST, SCAN_DEFAULT_LAST};

use super::values::{BytesArg, parse_u32};
use crate::output::{field, hex, subfield};

#[derive(Debug, clap::Subcommand)]
pub enum I2cOp {
    /// List the buses the device lets a host drive.
    Buses,
    /// List the peripherals the firmware knows to be on each bus.
    Devices,
    /// Probe a range of addresses and list what acknowledges.
    Scan {
        #[arg(value_name = "BUS", value_parser = parse_bus)]
        bus: u8,
        /// First address to probe (default 0x08).
        #[arg(long, value_name = "ADDR", value_parser = parse_addr)]
        first: Option<u8>,
        /// Last address to probe (default 0x77).
        #[arg(long, value_name = "ADDR", value_parser = parse_addr)]
        last: Option<u8>,
    },
    /// Read octets from a peripheral, optionally after selecting a
    /// register.
    Read {
        #[arg(value_name = "BUS", value_parser = parse_bus)]
        bus: u8,
        #[arg(value_name = "ADDR", value_parser = parse_addr)]
        addr: u8,
        #[arg(value_name = "LEN", value_parser = parse_len)]
        len: u16,
        /// Register (or command) octets written first, with a repeated
        /// START before the read.
        #[arg(long, value_name = "HEX")]
        reg: Option<BytesArg>,
    },
    /// Write octets to a peripheral.
    Write {
        #[arg(value_name = "BUS", value_parser = parse_bus)]
        bus: u8,
        #[arg(value_name = "ADDR", value_parser = parse_addr)]
        addr: u8,
        #[arg(value_name = "HEX")]
        data: BytesArg,
    },
    /// Run an arbitrary operation list in one transaction: `w:HEX`
    /// writes, `r:N` reads N octets.
    Xfer {
        #[arg(value_name = "BUS", value_parser = parse_bus)]
        bus: u8,
        #[arg(value_name = "ADDR", value_parser = parse_addr)]
        addr: u8,
        #[arg(value_name = "OP", required = true)]
        ops: Vec<XferOp>,
    },
}

/// One operand of `xfer`: `w:aabb` or `r:4`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XferOp {
    Write(Vec<u8>),
    Read(u16),
}

impl FromStr for XferOp {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (kind, rest) = text
            .split_once(':')
            .ok_or_else(|| format!("expected w:HEX or r:N, got {text:?}"))?;
        match kind {
            "w" | "W" => {
                let bytes = BytesArg::from_str(rest)?.0;
                if bytes.is_empty() {
                    return Err("a write needs at least one octet".into());
                }
                Ok(Self::Write(bytes))
            }
            "r" | "R" => parse_len(rest).map(Self::Read),
            _ => Err(format!("expected w:HEX or r:N, got {text:?}")),
        }
    }
}

impl XferOp {
    fn as_op(&self) -> Op<'_> {
        match self {
            Self::Write(data) => Op::Write(data),
            Self::Read(len) => Op::Read(usize::from(*len)),
        }
    }
}

fn parse_bus(text: &str) -> Result<u8, String> {
    u8::try_from(parse_u32(text)?).map_err(|_| format!("bus number out of range: {text}"))
}

fn parse_addr(text: &str) -> Result<u8, String> {
    let value = parse_u32(text)?;
    if value > u32::from(ADDRESS_MAX) {
        return Err(format!("{text} is not a 7-bit address (0x00 through 0x7f)"));
    }
    Ok(value as u8)
}

fn parse_len(text: &str) -> Result<u16, String> {
    match u16::try_from(parse_u32(text)?) {
        Ok(0) => Err("a read needs at least one octet".into()),
        Ok(len) => Ok(len),
        Err(_) => Err(format!("length out of range: {text}")),
    }
}

impl I2cOp {
    /// Argument checks clap's grammar cannot express, before a device is
    /// opened.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Scan {
                first: Some(first),
                last: Some(last),
                ..
            } if first > last => bail!("--first must not exceed --last"),
            Self::Read { reg: Some(reg), .. } if reg.0.is_empty() => {
                bail!("--reg needs at least one octet")
            }
            Self::Write { data, .. } if data.0.is_empty() => {
                bail!("a write needs at least one octet")
            }
            _ => Ok(()),
        }
    }
}

pub async fn run<L: FrameLink>(device: &mut UlcpDevice<L>, op: I2cOp) -> Result<()> {
    match op {
        I2cOp::Buses => {
            let buses = device.i2c_buses().await?.ok_or_else(no_bus)?;
            if buses.is_empty() {
                println!("no buses");
            }
            for bus in buses {
                field(&format!("bus {}", bus.bus), &bus.name);
                subfield("speed", format!("{} kHz", bus.speed_khz));
                subfield(
                    "limits",
                    format!(
                        "{} data octets, {} operations per transfer",
                        bus.max_data, bus.max_ops
                    ),
                );
            }
            Ok(())
        }
        I2cOp::Devices => {
            let devices = device.i2c_devices().await?.ok_or_else(no_bus)?;
            if devices.is_empty() {
                println!("no known peripherals");
            }
            for peripheral in devices {
                field(
                    &format!("bus {} 0x{:02x}", peripheral.bus, peripheral.addr),
                    &peripheral.name,
                );
            }
            Ok(())
        }
        I2cOp::Scan { bus, first, last } => {
            let range = match (first, last) {
                (None, None) => None,
                (first, last) => Some((
                    first.unwrap_or(SCAN_DEFAULT_FIRST),
                    last.unwrap_or(SCAN_DEFAULT_LAST),
                )),
            };
            let found = device
                .i2c_scan(bus, range)
                .await
                .map_err(explain)?
                .ok_or_else(no_bus)?;
            if found.is_empty() {
                println!("nothing acknowledged");
            }
            for addr in found {
                println!("0x{addr:02x}");
            }
            Ok(())
        }
        I2cOp::Read {
            bus,
            addr,
            len,
            reg,
        } => {
            let mut ops = Vec::with_capacity(2);
            if let Some(reg) = &reg {
                ops.push(Op::Write(&reg.0));
            }
            ops.push(Op::Read(usize::from(len)));
            let data = transfer(device, bus, addr, &ops).await?;
            println!("{}", hex(&data));
            Ok(())
        }
        I2cOp::Write { bus, addr, data } => {
            transfer(device, bus, addr, &[Op::Write(&data.0)]).await?;
            println!("ok");
            Ok(())
        }
        I2cOp::Xfer { bus, addr, ops } => {
            let ops: Vec<Op<'_>> = ops.iter().map(XferOp::as_op).collect();
            let data = transfer(device, bus, addr, &ops).await?;
            if data.is_empty() {
                println!("ok");
            } else {
                println!("{}", hex(&data));
            }
            Ok(())
        }
    }
}

async fn transfer<L: FrameLink>(
    device: &mut UlcpDevice<L>,
    bus: u8,
    addr: u8,
    ops: &[Op<'_>],
) -> Result<Vec<u8>> {
    device
        .i2c_transfer(bus, addr, ops)
        .await
        .map_err(explain)?
        .ok_or_else(no_bus)
}

fn no_bus() -> anyhow::Error {
    anyhow!("this device does not support the requested I2C operation")
}

/// Put the bus-specific statuses into words; everything else keeps the
/// generic rendering.
fn explain(error: UlcpError) -> anyhow::Error {
    let words = match error {
        UlcpError::Status(Status::NO_DEVICE) => "no peripheral acknowledged the address",
        UlcpError::Status(Status::NACK) => {
            "an octet was not acknowledged; on a controller that cannot tell the two apart \
             this is also what an absent peripheral looks like, so check `i2c scan`"
        }
        UlcpError::Status(Status::BUS_ERROR) => {
            "the bus failed (arbitration lost, timeout, or a stuck line)"
        }
        UlcpError::Status(Status::BUSY) => {
            "the bus or the peripheral is held by the device's own driver; try again"
        }
        UlcpError::Status(Status::NOMEM) => {
            "the result would not fit one reply over this link; read less at a time"
        }
        UlcpError::Status(Status::ITEM_NOT_FOUND) => "no such bus; see `i2c buses`",
        UlcpError::Status(Status::INVALID_STATE) => "the bus is not operable right now",
        _ => return error.into(),
    };
    anyhow!("{words}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xfer_operands_parse_both_directions() {
        assert_eq!(
            XferOp::from_str("w:00ff").unwrap(),
            XferOp::Write(vec![0x00, 0xff])
        );
        assert_eq!(XferOp::from_str("r:4").unwrap(), XferOp::Read(4));
        assert_eq!(XferOp::from_str("R:0x10").unwrap(), XferOp::Read(16));
        assert!(
            XferOp::from_str("r:0").is_err(),
            "a zero-length read is refused"
        );
        assert!(XferOp::from_str("w:").is_err(), "an empty write is refused");
        assert!(XferOp::from_str("x:01").is_err());
        assert!(XferOp::from_str("01").is_err());
    }

    #[test]
    fn addresses_are_seven_bit() {
        assert_eq!(parse_addr("0x55").unwrap(), 0x55);
        assert_eq!(parse_addr("85").unwrap(), 0x55);
        assert!(parse_addr("0x80").is_err());
        assert!(parse_addr("0xA0").is_err());
    }

    #[test]
    fn a_reversed_scan_range_is_caught_before_connecting() {
        let op = I2cOp::Scan {
            bus: 0,
            first: Some(0x50),
            last: Some(0x08),
        };
        assert!(op.validate().is_err());
        let op = I2cOp::Scan {
            bus: 0,
            first: Some(0x08),
            last: None,
        };
        assert!(op.validate().is_ok());
    }
}
