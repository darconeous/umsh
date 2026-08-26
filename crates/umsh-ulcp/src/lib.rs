#![cfg_attr(not(test), no_std)]

//! Wire format for the UMSH Local Control Protocol (ULCP).
//!
//! This crate implements the byte-level grammar specified in
//! `docs/protocol/src/ulcp-core.md`: packed unsigned
//! integers, the frame header and command layer, property/stream/status
//! identifiers, the `STR_PHY_RAW` metadata envelopes
//! (`ulcp-transport.md`), and HDLC-Lite framing for asynchronous serial
//! transports (UART, USB-CDC).
//!
//! It is shared between the host side (a `umsh-hal::Radio`
//! implementation that drives a companion radio over a serial link) and
//! the device firmware side (the session that exposes the local radio).
//! Every wire-format detail lives here and only here.
//!
//! The crate is `no_std`, allocation-free, and has no dependencies.
//! Callers provide byte buffers; encoders return the number of bytes
//! written and decoders borrow from the input.

pub mod airtime;
pub mod alert;
pub mod battery;
pub mod describe;
pub mod frame;
pub mod gatt;
pub mod gnss;
pub mod hdlc;
pub mod host;
pub mod ids;
pub mod items;
pub mod meta;
pub mod profiles;
pub mod pui;
pub mod reply;
pub mod sint;
pub mod status;

pub use alert::AlertState;
pub use battery::{BatteryChargeState, BatteryError, BatteryStatus};
pub use describe::{FrameDescription, capability_name, property_name};
pub use frame::{
    Cmd, Frame, FrameWriter, Header, MultiEntries, MultiEntry, MultiGetKeys, PropPayload,
    StreamPayload,
};
pub use gnss::{FixKind, GnssError, GnssSnapshot};
pub use meta::{BufferedRxMeta, RxMeta, TxMeta};
pub use status::Status;
