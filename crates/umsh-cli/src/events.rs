//! Event queue variants pushed by subscription callbacks and consumed by
//! `CliSession::service_events`.
//!
//! `OwnedMacCommand` is never used as a blanket carrier—only the MAC
//! commands the CLI actually cares about get dedicated variants.

use umsh_core::{NodeHint, PublicKey};

#[derive(Debug)]
pub enum CliEvent {
    // ─── Inbound (deposited by 'static subscription closures) ───────────────
    Received {
        from: PublicKey,
        hops: u8,
        rssi: i16,
        snr: i16,
        payload: Vec<u8>,
    },
    AckReceived {
        peer: PublicKey,
    },
    AckTimeout {
        peer: PublicKey,
    },
    NodeDiscovered {
        from: PublicKey,
        name: Option<String>,
    },
    Beacon {
        /// 3-byte source hint from the packet header—always present.
        hint: NodeHint,
        /// Full source pubkey, when the beacon carried it (some senders only
        /// include the hint to save airtime).
        from: Option<PublicKey>,
    },
    PfsEstablished {
        peer: PublicKey,
    },
    PfsEnded {
        peer: PublicKey,
    },
    PfsFailed {
        peer: PublicKey,
        reason: umsh_node::PfsFailure,
    },
    Pong {
        peer: PublicKey,
        rtt_ms: u64,
    },
    PingTimeout {
        peer: PublicKey,
    },
    UnknownMacCmdIn {
        peer: PublicKey,
        cmd_id: u8,
    },
    RawTx {
        bytes: Vec<u8>,
    },
    RawRx {
        bytes: Vec<u8>,
    },

    // ─── Outbound ────────────────────────────────────────────────────────────
    // TODO: these variants were designed for a model where `execute()` pushes
    // outbound work onto the event queue and `service_events()` drains it.
    // The current implementation calls MAC I/O directly from `execute()` and
    // none of these variants are ever pushed. Either wire them up (enables
    // rate-limiting and cancel hooks) or remove them and the dead arms in
    // `handle_event` to clean up the mismatch.
    OutputLine {
        line: String,
    },
    SendText {
        peer: PublicKey,
        body: String,
    },
    StartPfs {
        peer: PublicKey,
        minutes: u16,
    },
    EndPfs {
        peer: PublicKey,
    },
    ChannelSend {
        channel_slot: u8,
        body: String,
    },
    SendBeacon,
    SendRaw {
        peer: PublicKey,
        bytes: Vec<u8>,
    },
}
