//! Helper for encoding a `MacCommand` as an outbound payload without
//! touching the node crate's public API.
//!
//! Rationale: adding `PeerConnection::send_mac_command` to the node crate
//! would duplicate send-plumbing for a single use case. Instead, we prefix
//! the existing `mac_command::encode` output with `PayloadType::MacCommand`
//! and call the normal `PeerConnection::send`.

use umsh_core::PayloadType;
use umsh_node::{AppEncodeError, MacCommand};

/// Encode `cmd` into `out` as a complete MAC-command payload
/// (`PayloadType::MacCommand` byte + encoded command body). Returns the
/// number of bytes written.
pub fn encode_mac_command(
    cmd: &MacCommand<'_>,
    out: &mut [u8],
) -> Result<usize, AppEncodeError> {
    if out.is_empty() {
        return Err(AppEncodeError::BufferTooSmall);
    }
    out[0] = PayloadType::MacCommand as u8;
    let n = umsh_node::mac_command::encode(cmd, &mut out[1..])?;
    Ok(n + 1)
}
