use alloc::string::String;

use umsh_core::{ChannelId, ChannelKey, NodeHint, PublicKey};

use crate::owned::OwnedMacCommand;
use crate::ticket::SendToken;

/// Typed event delivered to node-level consumers.
///
/// `NodeEvent` implements `Clone` — the dispatcher clones it for each
/// delivery when multiple node sinks are registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeEvent {
    /// Direct text message received.
    TextReceived {
        from: PublicKey,
        body: String,
    },
    /// Channel text message received.
    ChannelTextReceived {
        from: PublicKey,
        channel_id: ChannelId,
        channel_key: ChannelKey,
        body: String,
    },
    /// Node identity advertisement received.
    NodeDiscovered {
        key: PublicKey,
        name: Option<String>,
    },
    /// Beacon received (possibly anonymous).
    BeaconReceived {
        from_hint: NodeHint,
        from_key: Option<PublicKey>,
    },
    /// MAC command received from a peer.
    MacCommandReceived {
        from: PublicKey,
        command: OwnedMacCommand,
    },
    /// Transport ACK received — the destination confirmed receipt.
    AckReceived {
        peer: PublicKey,
        token: SendToken,
    },
    /// Transport ACK timed out — all retransmits exhausted.
    AckTimeout {
        peer: PublicKey,
        token: SendToken,
    },
    /// PFS session established with a peer.
    PfsSessionEstablished {
        peer: PublicKey,
    },
    /// PFS session ended with a peer.
    PfsSessionEnded {
        peer: PublicKey,
    },
}
