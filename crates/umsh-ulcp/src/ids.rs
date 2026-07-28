//! Property, stream, and capability identifiers, plus protocol
//! constants. The complete allocation is in
//! `docs/protocol/src/ulcp-index.md`.

/// Protocol version advertised in `PROP_PROTOCOL_VERSION`.
pub const PROTOCOL_MAJOR_VERSION: u8 = 6;
/// Protocol version advertised in `PROP_PROTOCOL_VERSION`.
pub const PROTOCOL_MINOR_VERSION: u8 = 0;

/// Value of `PROP_INTERFACE_TYPE` for this protocol.
pub const INTERFACE_TYPE: u32 = 8;

/// Property identifiers.
pub mod prop {
    /// Status of the last operation (`PROP_LAST_STATUS`).
    pub const LAST_STATUS: u32 = 0;
    /// Protocol major/minor version (`PROP_PROTOCOL_VERSION`).
    pub const PROTOCOL_VERSION: u32 = 1;
    /// device firmware version string (`PROP_DEV_VERSION`).
    pub const DEV_VERSION: u32 = 2;
    /// Interface type discriminator (`PROP_INTERFACE_TYPE`).
    pub const INTERFACE_TYPE: u32 = 3;
    /// Supported capability list (`PROP_CAPS`).
    pub const CAPS: u32 = 5;
    /// PHY enabled flag (`PROP_PHY_ENABLED`).
    pub const PHY_ENABLED: u32 = 32;
    /// Frequency in kHz (`PROP_PHY_FREQ`).
    pub const PHY_FREQ: u32 = 35;
    /// TX power in dBm (`PROP_PHY_TX_POWER`).
    pub const PHY_TX_POWER: u32 = 37;
    /// Current RSSI in dBm (`PROP_PHY_RSSI`).
    pub const PHY_RSSI: u32 = 38;
    /// LoRa bandwidth in Hz (`PROP_PHY_LORA_BW`).
    pub const PHY_LORA_BW: u32 = 39;
    /// LoRa spreading factor (`PROP_PHY_LORA_SF`).
    pub const PHY_LORA_SF: u32 = 40;
    /// LoRa coding rate (`PROP_PHY_LORA_CR`).
    pub const PHY_LORA_CR: u32 = 41;
    /// Maximum `STR_PHY_RAW` data size in octets (`PROP_PHY_MTU`).
    pub const PHY_MTU: u32 = 42;
    /// LoRa sync word, SX126x-style 16-bit (`PROP_PHY_LORA_SW`).
    pub const PHY_LORA_SW: u32 = 43;
    /// Deliver all received frames, bypassing host receive filtering;
    /// the only session-scoped property (`PROP_MAC_PROMISCUOUS`).
    pub const MAC_PROMISCUOUS: u32 = 48;
    /// Whether a saved snapshot exists (`PROP_SAVED`).
    pub const SAVED: u32 = 49;
    /// Device identity public key (`PROP_DEV_KEY`).
    pub const DEV_KEY: u32 = 64;
    /// Device identity private key, write-only (`PROP_DEV_PRIVATE_KEY`).
    pub const DEV_PRIVATE_KEY: u32 = 65;
    /// Device identity channel keys (`PROP_DEV_CHANNEL_KEYS`).
    pub const DEV_CHANNEL_KEYS: u32 = 66;
    /// Device identity peer list (`PROP_DEV_PEERS`).
    pub const DEV_PEERS: u32 = 67;
    /// Human-readable device name (`PROP_DEV_NAME`).
    pub const DEV_NAME: u32 = 68;
    /// Battery status snapshot (`PROP_BATTERY`).
    pub const BATTERY: u32 = 69;
    /// Autonomous MAC-layer repeater/forwarding enable (`PROP_MAC_REPEATER_ENABLED`).
    ///
    /// First of the device-behavior settings range (70–95), which is
    /// subdivided as 70–79 repeater and identity, 80–87 advertisement
    /// policy, 88–95 positioning. A persisted, device-domain boolean: when
    /// set, the device identity's on-board MAC forwards overheard routable
    /// frames and advertises the `REP` capability bit. The advertised
    /// *role* is a separate matter — see `IDENT_ROLE`.
    pub const MAC_REPEATER_ENABLED: u32 = 70;
    /// The device identity's complete signed node-identity blob
    /// (`PROP_IDENT`), served through a deferred signing effect.
    pub const IDENT: u32 = 71;
    /// Advertised `ROLE` byte of the device identity (`PROP_IDENT_ROLE`).
    /// Empty means "derive it from what the device is actually doing".
    pub const IDENT_ROLE: u32 = 72;
    /// Whether the device identity advertises the `MOB` capability bit
    /// (`PROP_IDENT_MOBILE`) — mobile versus fixed, which is orthogonal
    /// to tethered versus standalone.
    pub const IDENT_MOBILE: u32 = 73;
    /// Region codes the device identity flood-forwards for
    /// (`PROP_MAC_REPEATER_REGIONS`) — concatenated 2-octet codes, empty
    /// for "forward regardless of region code".
    pub const MAC_REPEATER_REGIONS: u32 = 74;
    /// Region code inserted into untagged flood packets
    /// (`PROP_MAC_REPEATER_DEFAULT_REGION`) — one 2-octet code, or empty
    /// to never tag.
    pub const MAC_REPEATER_DEFAULT_REGION: u32 = 75;
    /// Minimum received RSSI in dBm for flood forwarding
    /// (`PROP_MAC_REPEATER_MIN_RSSI`) — INT16, or empty for no threshold.
    pub const MAC_REPEATER_MIN_RSSI: u32 = 76;
    /// Minimum received SNR in whole dB for flood forwarding
    /// (`PROP_MAC_REPEATER_MIN_SNR`) — INT8, or empty for no threshold.
    pub const MAC_REPEATER_MIN_SNR: u32 = 77;
    /// Tethered host identity public key (`PROP_HOST_KEY`).
    pub const HOST_KEY: u32 = 96;
    /// Host channel keys (`PROP_HOST_CHANNEL_KEYS`).
    pub const HOST_CHANNEL_KEYS: u32 = 97;
    /// Host pairwise peer keys (`PROP_HOST_PEER_KEYS`).
    pub const HOST_PEER_KEYS: u32 = 98;
    /// Host receive filter table (`PROP_HOST_RX_FILTERS`).
    pub const HOST_RX_FILTERS: u32 = 99;
    /// Acknowledgement-delegation enable (`PROP_HOST_AUTO_ACK`).
    pub const HOST_AUTO_ACK: u32 = 100;
    /// Frames currently queued (`PROP_HOST_RX_QUEUE_COUNT`).
    pub const HOST_RX_QUEUE_COUNT: u32 = 101;
    /// Inbound queue capacity in frames (`PROP_HOST_RX_QUEUE_CAPACITY`).
    pub const HOST_RX_QUEUE_CAPACITY: u32 = 102;
    /// Cumulative frames dropped from the queue (`PROP_HOST_RX_QUEUE_DROPPED`).
    pub const HOST_RX_QUEUE_DROPPED: u32 = 103;
    /// Transmit duty usage over the past hour (`PROP_PHY_DUTY_NOW`).
    pub const PHY_DUTY_NOW: u32 = 4820;
    /// Duty-cycle limit (`PROP_PHY_DUTY_LIMIT`).
    pub const PHY_DUTY_LIMIT: u32 = 4822;
    /// Persisted, write-only BLE pairing passkey (`PROP_BLE_PAIRING_PIN`).
    pub const BLE_PAIRING_PIN: u32 = 4864;
}

/// `PROP_SAVED` values.
///
/// A snapshot that exists but cannot be read is distinguishable from no
/// snapshot at all, and running on an older generation than the one last
/// written is distinguishable from running on the newest.
pub mod saved {
    /// Nothing is saved.
    pub const NONE: u8 = 0;
    /// The newest saved generation is in effect.
    pub const CURRENT: u8 = 1;
    /// A newer generation was rejected; an older one is in effect.
    pub const FALLBACK: u8 = 2;
    /// A snapshot exists but no generation could be read.
    pub const UNREADABLE: u8 = 3;
}

/// Stream identifiers.
pub mod stream {
    /// Raw radio frame stream (`STR_PHY_RAW`).
    pub const PHY_RAW: u32 = 113;
}

/// Capability codes advertised via `PROP_CAPS`.
pub mod cap {
    /// `CAP_WRITABLE_RAW_STREAM`
    pub const WRITABLE_RAW_STREAM: u32 = 8;
    /// `CAP_PHY_DUTY_LIMIT`
    pub const PHY_DUTY_LIMIT: u32 = 16;
    /// `CAP_PHY_LORA`
    pub const PHY_LORA: u32 = 515;
    /// `CAP_HOST_FILTER`
    pub const HOST_FILTER: u32 = 32;
    /// `CAP_HOST_RX_QUEUE` (requires `CAP_HOST_FILTER`)
    pub const HOST_RX_QUEUE: u32 = 33;
    /// `CAP_HOST_KEYS` (requires `CAP_HOST_FILTER`)
    pub const HOST_KEYS: u32 = 34;
    /// `CAP_HOST_AUTO_ACK` (requires `CAP_HOST_KEYS` and `CAP_HOST_RX_QUEUE`)
    pub const HOST_AUTO_ACK: u32 = 35;
    /// `CAP_SAVE`
    pub const SAVE: u32 = 36;
    /// `CAP_DEV_IDENTITY`
    pub const DEV_IDENTITY: u32 = 37;
    /// `CAP_DEV_NAME`
    pub const DEV_NAME: u32 = 38;
    /// `CAP_BATTERY`
    pub const BATTERY: u32 = 39;
    /// `CAP_REPEATER` — the device can act as an autonomous mesh repeater
    /// (`PROP_MAC_REPEATER_ENABLED`). Requires `CAP_DEV_IDENTITY`.
    pub const REPEATER: u32 = 40;
    /// `CAP_IDENT` — the device serves and configures its own advertised
    /// node identity (`PROP_IDENT`, `PROP_IDENT_ROLE`,
    /// `PROP_IDENT_MOBILE`). Requires `CAP_DEV_IDENTITY`.
    pub const IDENT: u32 = 41;
}

/// Value used in `PROP_PHY_DUTY_LIMIT` to disable duty-cycle limiting.
pub const DUTY_LIMIT_DISABLED: u16 = 0xFFFF;
