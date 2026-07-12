//! Property, stream, and capability identifiers, plus protocol
//! constants, from the minimal companion-radio spec.

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
    /// NCP firmware version string (`PROP_NCP_VERSION`).
    pub const NCP_VERSION: u32 = 2;
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
    /// Transmit duty usage over the past hour (`PROP_PHY_DUTY_NOW`).
    pub const PHY_DUTY_NOW: u32 = 4820;
    /// Duty-cycle limit (`PROP_PHY_DUTY_LIMIT`).
    pub const PHY_DUTY_LIMIT: u32 = 4822;
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
}

/// Value used in `PROP_PHY_DUTY_LIMIT` to disable duty-cycle limiting.
pub const DUTY_LIMIT_DISABLED: u16 = 0xFFFF;
