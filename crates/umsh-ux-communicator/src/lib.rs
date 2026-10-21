#![no_std]

//! The standalone messenger interface for communicator-class UMSH devices.
//!
//! A communicator provides the whole UMSH experience on the device: it has
//! a color screen, a text keyboard, and navigation controls, and a phone is
//! optional. The T-LoRa Pager is the first target; its mockup in
//! `docs/ux/src/hardware/mockups/` is the reference design.
//!
//! - [`model`]: what the screens show, filled in by the device.
//! - [`nav`]: moving between screens, and where focus goes.
//! - [`lock`]: locking, and the lock screen's way back.
//! - [`ui`]: the screens themselves, as Buoyant views.
//! - [`input`]: the inputs a board reports, and what they mean.
//! - [`board`]: the board's screen and controls, as the interface needs them.
//! - [`text`]: message text, shared by the screens rather than copied.
//! - [`avatar`]: peer and channel avatars, following the iOS rules.
//! - [`font`], [`icon`], [`theme`]: typefaces, icons, colors, and sizes.
//! - [`fixture`]: stand-in content (the `fixture` feature).
//!
//! [`buoyant`] is re-exported so a device drives the interface with the
//! same version it was built against, and [`heapless`] so a node trades in
//! the strings and vectors [`model::Node`] names.

pub use buoyant;
pub use heapless;

pub mod avatar;
pub mod board;
pub mod clock;
pub mod clock_settings;
#[cfg(feature = "fixture")]
pub mod fixture;
pub mod font;
pub mod icon;
pub mod input;
pub mod keyboard;
pub mod lock;
pub mod model;
pub mod models;
pub mod nav;
pub mod qr;
pub mod text;
pub mod theme;
pub mod ui;
pub mod zones;
