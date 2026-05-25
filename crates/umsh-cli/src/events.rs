//! Event queue variants pushed by subscription callbacks and consumed by
//! `CliSession::service_events`.
//!
//! All variants store bounded data; `OwnedMacCommand` (which contains an
//! unbounded `Vec<u8>`) is never used as a blanket carrier — only the MAC
//! commands the CLI actually cares about get dedicated variants.

use heapless::{String, Vec};
use umsh_core::PublicKey;

/// Maximum payload length recorded in inbound events (per-event cap).
pub const EVENT_PAYLOAD_MAX: usize = 64;
/// Maximum length of a formatted output line buffered for writing.
pub const EVENT_LINE_MAX: usize = 256;

#[derive(Debug)]
pub enum CliEvent {
    // ─── Inbound (deposited by 'static subscription closures) ───────────────
    Received {
        from: PublicKey,
        hops: u8,
        rssi: i16,
        snr: i16,
        prefix: Vec<u8, EVENT_PAYLOAD_MAX>,
    },
    AckReceived {
        peer: PublicKey,
    },
    AckTimeout {
        peer: PublicKey,
    },
    NodeDiscovered {
        from: PublicKey,
        name: Option<String<32>>,
    },
    Beacon {
        from: PublicKey,
    },
    PfsEstablished {
        peer: PublicKey,
    },
    PfsEnded {
        peer: PublicKey,
    },
    EchoResponseIn {
        peer: PublicKey,
        data: Vec<u8, EVENT_PAYLOAD_MAX>,
    },
    UnknownMacCmdIn {
        peer: PublicKey,
        cmd_id: u8,
    },

    // ─── Outbound ────────────────────────────────────────────────────────────
    // TODO: these variants were designed for a model where `execute()` pushes
    // outbound work onto the event queue and `service_events()` drains it.
    // The current implementation calls MAC I/O directly from `execute()` and
    // none of these variants are ever pushed. Either wire them up (enables
    // rate-limiting and cancel hooks) or remove them and the dead arms in
    // `handle_event` to clean up the mismatch.
    OutputLine {
        line: String<EVENT_LINE_MAX>,
    },
    SendText {
        peer: PublicKey,
        body: String<EVENT_LINE_MAX>,
    },
    SendPing {
        peer: PublicKey,
        nonce: u16,
        data: Vec<u8, EVENT_PAYLOAD_MAX>,
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
        body: String<EVENT_LINE_MAX>,
    },
    SendBeacon,
    SendRaw {
        peer: PublicKey,
        bytes: Vec<u8, EVENT_PAYLOAD_MAX>,
    },
}
