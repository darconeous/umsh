//! CLI-maintained session counters. Not a node-level metrics API — just
//! tallies populated from subscription callbacks and around send calls.

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub acks_ok: u64,
    pub acks_timeout: u64,
    pub beacons_rx: u64,
    pub nodes_discovered: u64,
    pub last_rx_ms: u64,
    pub last_rssi: Option<i16>,
    pub last_snr: Option<i16>,
    pub events_dropped: u64,
}
