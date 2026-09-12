//! Credential-free WiFi state for the display and its saved-network picker.

pub const MAX_SAVED_NETWORKS: usize = 4;

/// An SSID is an opaque byte string, even when its displayed label is shortened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkName {
    bytes: [u8; 32],
    len: u8,
}

impl NetworkName {
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > 32 {
            return None;
        }
        let mut name = Self {
            bytes: [0; 32],
            len: bytes.len() as u8,
        };
        name.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(name)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WifiState {
    #[default]
    Off,
    Disconnected,
    Connecting,
    Connected,
}

/// Only names cross into the UI. The station owns credentials and validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WifiMenu {
    pub enabled: bool,
    pub state: WifiState,
    pub network: Option<NetworkName>,
    pub networks: [Option<NetworkName>; MAX_SAVED_NETWORKS],
}

impl WifiMenu {
    pub fn networks(&self) -> impl Iterator<Item = NetworkName> + '_ {
        self.networks.iter().flatten().copied()
    }
}
