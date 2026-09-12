#![no_std]

//! Transport-independent pieces of the device's authenticated bridge client.
pub mod tls;
pub mod tunnel;

pub const ALPN: &[u8] = b"umsh-bridge/1";
pub const MAX_BODY: usize = 1024;
pub const QUEUE_DEPTH: usize = 8;
pub const MAX_AGE_MS: u64 = 10_000;
pub const KEEPALIVE_MS: u64 = 10_000;
pub const IDLE_MS: u64 = 30_000;
