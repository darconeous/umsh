//! Low-level receive view re-exports for the node layer.
//!
//! `umsh-node` intentionally uses the same borrowed packet view as `umsh-mac` for raw receive
//! callbacks. That keeps the application-facing receive boundary close to the accepted on-wire
//! packet instead of inventing a second node-specific event envelope.

pub use umsh_mac::{ChannelInfoRef, PacketFamily, ReceivedPacketRef, RouteHops, RxMetadata, Snr};
