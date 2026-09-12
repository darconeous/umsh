//! Saved device-domain configuration for one autonomous bridge connection.
use heapless::String;
use umsh_ulcp::{
    Status,
    bridge::{DEFAULT_PORT, HOST_MAX, valid_host},
    ids::prop,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeConfig {
    pub enabled: bool,
    pub host: String<HOST_MAX>,
    pub port: u16,
    pub server_key: Option<[u8; 32]>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: DEFAULT_PORT,
            server_key: None,
        }
    }
}

impl BridgeConfig {
    pub fn configured(&self) -> bool {
        !self.host.is_empty() && self.server_key.is_some()
    }

    pub fn set(&mut self, key: u32, value: &[u8]) -> Result<(), Status> {
        match key {
            prop::BRIDGE_ENABLED => {
                self.enabled = match value {
                    [0] => false,
                    [1] => true,
                    _ => return Err(Status::INVALID_ARGUMENT),
                }
            }
            prop::BRIDGE_HOST => {
                let bytes = value.strip_suffix(&[0]).ok_or(Status::INVALID_ARGUMENT)?;
                let host = core::str::from_utf8(bytes).map_err(|_| Status::INVALID_ARGUMENT)?;
                if !valid_host(host) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.host = String::try_from(host).map_err(|_| Status::NOMEM)?;
            }
            prop::BRIDGE_PORT => {
                let port =
                    u16::from_le_bytes(value.try_into().map_err(|_| Status::INVALID_ARGUMENT)?);
                if port == 0 {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.port = port;
            }
            prop::BRIDGE_SERVER_KEY => {
                self.server_key = if value.is_empty() {
                    None
                } else {
                    let bytes: [u8; 32] = value.try_into().map_err(|_| Status::INVALID_ARGUMENT)?;
                    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                        .map_err(|_| Status::INVALID_ARGUMENT)?;
                    if key.is_weak() || key.to_edwards().compress().to_bytes() != bytes {
                        return Err(Status::INVALID_ARGUMENT);
                    }
                    Some(bytes)
                };
            }
            _ => return Err(Status::PROP_NOT_FOUND),
        }
        Ok(())
    }

    pub fn encode(&self, key: u32, out: &mut [u8]) -> Option<usize> {
        let bytes: &[u8] = match key {
            prop::BRIDGE_ENABLED => &[self.enabled as u8],
            prop::BRIDGE_PORT => &self.port.to_le_bytes(),
            prop::BRIDGE_SERVER_KEY => self.server_key.as_ref().map_or(&[], |k| k.as_slice()),
            prop::BRIDGE_HOST => {
                let len = self.host.len();
                out.get_mut(..len + 1)?[..len].copy_from_slice(self.host.as_bytes());
                out[len] = 0;
                return Some(len + 1);
            }
            _ => return None,
        };
        out.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(bytes.len())
    }
}
