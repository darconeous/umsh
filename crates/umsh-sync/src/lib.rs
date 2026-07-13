//! Single-threaded async synchronization primitives for UMSH.
//!
//! - [`AsyncCondition`] — a wake-all condition variable with slab-backed
//!   ticketed deregistration.
//! - [`AsyncRefCell`] — an async-aware `RefCell` whose `borrow()` /
//!   `borrow_mut()` futures wait instead of panicking when the cell is in
//!   use.
//!
//! Everything here is `no_std + alloc`, single-threaded, and executor-
//! agnostic: it works under tokio (with a `LocalSet`), embassy, or any
//! custom async runtime that polls futures to completion.

#![no_std]

extern crate alloc;

pub mod async_condition;
pub mod async_refcell;

pub use async_condition::{AsyncCondition, AsyncConditionTicket, AsyncConditionWait};
pub use async_refcell::{AsyncRefCell, Ref, RefMut, ScopedTicket};
