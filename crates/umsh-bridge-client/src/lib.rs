#![no_std]

//! Transport-independent pieces of the device's authenticated bridge client.
pub mod tls;
pub mod tunnel;

use umsh_ulcp::meta::BufferedRxMeta;

pub const ALPN: &[u8] = b"umsh-bridge/1";
/// Largest tunnel body the decoder accepts.
pub const MAX_BODY: usize = 1024;
/// Largest packet a tunnel record carries to or from the device's radio.
pub const MAX_DATA: usize = 255;
/// What a queued frame keeps of a body: the length prefix, the packet, and
/// the receive metadata this client reads.
pub const FRAME_MAX: usize = 2 + MAX_DATA + BufferedRxMeta::WIRE_LEN;
pub const QUEUE_DEPTH: usize = 8;
pub const MAX_AGE_MS: u64 = 10_000;
pub const KEEPALIVE_MS: u64 = 10_000;
pub const IDLE_MS: u64 = 30_000;
/// Most plaintext a peer may put in one TLS record.
pub const MAX_RECORD_PLAINTEXT: usize = 4096;
/// Smallest record buffers that hold any conforming incoming record and
/// every record this client sends.
pub const TLS_RX_MIN: usize = MAX_RECORD_PLAINTEXT + 256;
pub const TLS_TX_MIN: usize = 1536;
