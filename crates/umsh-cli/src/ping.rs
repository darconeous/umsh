//! Pending outbound pings awaiting an `EchoResponse` MAC command.

use heapless::String;
use umsh_core::PublicKey;

#[derive(Debug, Clone)]
pub struct PendingPing {
    pub nonce: u16,
    pub peer: PublicKey,
    pub alias: Option<String<16>>,
    pub sent_at_ms: u64,
}
