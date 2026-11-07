#![cfg_attr(not(test), no_std)]

//! A ULCP property client: a cached model of a device's settings, kept
//! over an exchange that carries requests to the device and its answers
//! back.
//!
//! - [`exchange`]: what a link to a device does—take a request, hand back
//!   its answer, and pass on whatever the device publishes.
//! - [`local`]: the device's own session, reached in process. A local
//!   binding answers every request exactly once and at once, so a request
//!   left unanswered is given up on after a fixed wait.
//! - [`descriptor`]: the properties the model covers, each with its
//!   codec from [`umsh_ulcp`], its capability gate, and its kind.
//! - [`model`]: the cache, the requests waiting to go out, and the writes
//!   waiting on their answers.
//!
//! Nothing here assumes that an answer arrives at once, or at all: the
//! same model serves a device across the mesh, where a request may take a
//! minute and its answer may never come.

extern crate alloc;

pub mod descriptor;
pub mod exchange;
pub mod local;
pub mod model;

pub use descriptor::{Access, Descriptor, Kind};
pub use exchange::{Arrival, Busy, Exchange, Request, Ticket};
pub use local::{ANSWER_TIMEOUT_MS, LocalExchange, LocalPort, PortBusy, PortFrame};
pub use model::{Event, Freshness, Model, OBSERVED_EVENTS_MAX, Refusal, WriteId, WriteOutcome};
