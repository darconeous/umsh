#![cfg_attr(not(test), no_std)]

//! The Node Management binding: ULCP over the mesh.
//!
//! A node that supports node management is configured and observed over
//! the mesh itself, in the same command grammar and property model
//! [`umsh_ulcp`] defines for the local link. **Node Management Request**
//! (payload type 8) and **Node Management Response** (payload type 9)
//! payloads carry ordinary ULCP frames between an **administrator** — a
//! node listed in the device's `PROP_DEV_ADMINS` — and the **device**.
//! `docs/protocol/src/app-node-management.md` specifies it.
//!
//! The binding relies on exactly what secure unicast guarantees — an
//! authenticated source, confidentiality, and replay protection — and
//! adds what the ULCP grammar needs on a transport that promises neither
//! delivery nor ordering:
//!
//! - a [token](envelope::Token) correlating a response with its request,
//!   in place of the TID of the local bindings;
//! - [retained responses](device::DeviceEngine), so a retransmission is
//!   answered again rather than executed again;
//! - [cursors](device::DeviceEngine::begin), carrying a read larger than
//!   one frame across as many exchanges as it takes, with no per-read
//!   state on the device.
//!
//! Both engines are sans-IO: they own no transport, no clock, and no
//! buffers beyond their own state. The caller sends the payloads they
//! hand out, feeds back the ones that arrive, and supplies the time.
//! Authorization is likewise the caller's: a request reaches
//! [`device::DeviceEngine`] only after its source has been checked
//! against the administrator list.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod admin;
pub mod device;
pub mod envelope;
pub mod fragment;
#[cfg(feature = "node")]
pub mod node_adapter;

pub use admin::{Exchange, Failure, Outcome, Reassembly, Step};
pub use device::{DeviceEngine, Dispatch, DropReason, Ingress, Produced, PublicKey};
pub use envelope::{Envelope, EnvelopeError, Token};
pub use fragment::{continuable, produce, trailing, trailing_offset};
#[cfg(feature = "node")]
pub use node_adapter::{BeginError, ManagementError, NodeManager, Progress};

/// The Node Management payload an administrator sizes its requests
/// against.
///
/// A device derives its own ceiling from the radio it has — see
/// `ADMIN_PAYLOAD_MAX` in `umsh-ulcp-runtime` — and it is the device's
/// number that actually bounds an exchange. An administrator cannot ask
/// what that number is, so it assumes the smallest a device is allowed
/// to have, and the device's derivation is checked against this one at
/// compile time.
pub const PAYLOAD_MAX: usize = 180;

/// The largest request frame that fits a payload once its envelope is
/// accounted for.
pub const REQUEST_MAX: usize = PAYLOAD_MAX - envelope::OVERHEAD_MAX;
