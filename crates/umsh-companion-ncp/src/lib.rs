#![cfg_attr(not(test), no_std)]

//! NCP-side session engine for the minimal companion-radio protocol and
//! independently advertised full-profile extensions.
//!
//! [`Session`] is a pure state machine: it consumes decoded
//! companion-link frames (framing such as HDLC-Lite is handled by the
//! caller), emits response frames through a caller-provided sink, and
//! returns radio side effects ([`Effect`]) for the caller to execute.
//! It performs no I/O and takes time as a parameter, so the whole
//! protocol surface is testable on the host; firmware only supplies
//! the byte pipes and the radio.
//!
//! Design constraints from the spec
//! (`docs/protocol/src/companion-radio-minimal.md`):
//!
//! - one confirmed transmit in flight at a time (`STATUS_BUSY`);
//! - transmits never wait for duty-cycle allowance
//!   (`STATUS_DUTY_LIMIT` unless the `NODUTY` flag is set);
//! - `CMD_RST` is a protocol-level reset: all session state returns to
//!   post-reset defaults and the radio is re-applied, but the MCU (and
//!   therefore the USB link) stays up.
//!
//! v0 limitations (all surfaced through defined status codes):
//! `PROP_PHY_RSSI` is unimplemented, the sync word only accepts the
//! value the firmware was built with, and the CCA transmit flag is
//! ignored (frames transmit without a clear-channel check, matching
//! the existing firmware radio path).

pub mod duty;
pub mod session;

pub use duty::DutyTracker;
pub use session::{
    Effect, MAX_DEVICE_NAME_LEN, RadioSettings, SNAPSHOT_MAX, Session, SessionConfig, TxPower,
};
