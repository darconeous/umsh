//! CLI-local preferences mutated via `/set`. Reset on binary exit — no
//! durable storage.

#[derive(Debug, Clone)]
pub struct SessionSettings {
    /// `FHOPS_REM` value applied to all CLI-issued sends. `0..=15`.
    pub flood_hops: u8,
    /// Whether unicast sends use the ack-requested packet type.
    pub ack_requested: bool,
    /// Display-only: print raw bytes alongside decoded lines.
    pub show_hex: bool,
    /// Display-only: log every TX/RX MAC frame as `tx`/`rx` hex lines.
    pub show_raw: bool,
}

impl Default for SessionSettings {
    fn default() -> Self {
        SessionSettings {
            flood_hops: 5,
            ack_requested: true,
            show_hex: false,
            show_raw: false,
        }
    }
}
