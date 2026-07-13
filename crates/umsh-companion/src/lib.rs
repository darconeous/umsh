#![cfg_attr(not(test), no_std)]

//! Wire format for the minimal UMSH companion-radio (NCP) protocol.
//!
//! This crate implements the byte-level grammar specified in
//! `docs/protocol/src/companion-radio-minimal.md`: packed unsigned
//! integers, the frame header and command layer, property/stream/status
//! identifiers, the `STR_PHY_RAW` metadata envelopes, and HDLC-Lite
//! framing for asynchronous serial transports (UART, USB-CDC).
//!
//! It is shared between the host side (a `umsh-hal::Radio`
//! implementation that drives a companion radio over a serial link) and
//! the NCP firmware side (the session that exposes the local radio).
//! Every wire-format detail lives here and only here.
//!
//! The crate is `no_std`, allocation-free, and has no dependencies.
//! Callers provide byte buffers; encoders return the number of bytes
//! written and decoders borrow from the input.

pub mod airtime;
pub mod frame;
pub mod gatt;
pub mod hdlc;
pub mod ids;
pub mod meta;
pub mod pui;
pub mod status;

pub use frame::{Cmd, Frame, FrameWriter, Header, PropPayload, StreamPayload};
pub use meta::{RxMeta, TxMeta};
pub use status::Status;
