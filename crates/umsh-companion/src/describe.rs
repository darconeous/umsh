//! Allocation-free human-readable descriptions of companion protocol values.
//!
//! Keeping this layer next to the wire grammar gives native tools, firmware
//! diagnostics, and browser clients one shared vocabulary without requiring
//! any of them to allocate.

use core::fmt;

use crate::{
    Status,
    frame::{Cmd, Frame, PropPayload, StreamPayload},
    ids::{cap, prop},
    pui,
};

/// The spec mnemonic for a known property identifier.
pub const fn property_name(key: u32) -> Option<&'static str> {
    Some(match key {
        prop::LAST_STATUS => "PROP_LAST_STATUS",
        prop::PROTOCOL_VERSION => "PROP_PROTOCOL_VERSION",
        prop::NCP_VERSION => "PROP_NCP_VERSION",
        prop::INTERFACE_TYPE => "PROP_INTERFACE_TYPE",
        prop::CAPS => "PROP_CAPS",
        prop::PHY_ENABLED => "PROP_PHY_ENABLED",
        prop::PHY_FREQ => "PROP_PHY_FREQ",
        prop::PHY_TX_POWER => "PROP_PHY_TX_POWER",
        prop::PHY_RSSI => "PROP_PHY_RSSI",
        prop::PHY_LORA_BW => "PROP_PHY_LORA_BW",
        prop::PHY_LORA_SF => "PROP_PHY_LORA_SF",
        prop::PHY_LORA_CR => "PROP_PHY_LORA_CR",
        prop::PHY_MTU => "PROP_PHY_MTU",
        prop::PHY_LORA_SW => "PROP_PHY_LORA_SW",
        prop::MAC_PROMISCUOUS => "PROP_MAC_PROMISCUOUS",
        prop::SAVED => "PROP_SAVED",
        prop::DEV_KEY => "PROP_DEV_KEY",
        prop::DEV_PRIVATE_KEY => "PROP_DEV_PRIVATE_KEY",
        prop::DEV_CHANNEL_KEYS => "PROP_DEV_CHANNEL_KEYS",
        prop::DEV_PEERS => "PROP_DEV_PEERS",
        prop::DEV_NAME => "PROP_DEV_NAME",
        prop::BATTERY => "PROP_BATTERY",
        prop::HOST_KEY => "PROP_HOST_KEY",
        prop::HOST_CHANNEL_KEYS => "PROP_HOST_CHANNEL_KEYS",
        prop::HOST_PEER_KEYS => "PROP_HOST_PEER_KEYS",
        prop::HOST_RX_FILTERS => "PROP_HOST_RX_FILTERS",
        prop::HOST_AUTO_ACK => "PROP_HOST_AUTO_ACK",
        prop::HOST_RX_QUEUE_COUNT => "PROP_HOST_RX_QUEUE_COUNT",
        prop::HOST_RX_QUEUE_CAPACITY => "PROP_HOST_RX_QUEUE_CAPACITY",
        prop::HOST_RX_QUEUE_DROPPED => "PROP_HOST_RX_QUEUE_DROPPED",
        prop::PHY_DUTY_NOW => "PROP_PHY_DUTY_NOW",
        prop::PHY_DUTY_LIMIT => "PROP_PHY_DUTY_LIMIT",
        prop::BLE_PAIRING_PIN => "PROP_BLE_PAIRING_PIN",
        _ => return None,
    })
}

/// The spec mnemonic for a known capability code.
pub const fn capability_name(code: u32) -> Option<&'static str> {
    Some(match code {
        cap::WRITABLE_RAW_STREAM => "WRITABLE_RAW_STREAM",
        cap::PHY_DUTY_LIMIT => "PHY_DUTY_LIMIT",
        cap::PHY_LORA => "PHY_LORA",
        cap::HOST_FILTER => "HOST_FILTER",
        cap::HOST_RX_QUEUE => "HOST_RX_QUEUE",
        cap::HOST_KEYS => "HOST_KEYS",
        cap::HOST_AUTO_ACK => "HOST_AUTO_ACK",
        cap::SAVE => "SAVE",
        cap::DEV_IDENTITY => "DEV_IDENTITY",
        cap::DEV_NAME => "DEV_NAME",
        cap::BATTERY => "BATTERY",
        _ => return None,
    })
}

/// A display adapter for one companion frame.
///
/// Values are summarized by length and never dumped, so callers can safely use
/// the result in logs even for secret-bearing property writes.
pub struct FrameDescription<'a>(pub &'a [u8]);

impl fmt::Display for FrameDescription<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        let Ok(frame) = Frame::parse(bytes) else {
            return write!(out, "malformed frame ({} bytes)", bytes.len());
        };
        let tid = frame.header.tid();
        let Some(command) = frame.command() else {
            return write!(out, "unknown command tid={tid} ({} bytes)", bytes.len());
        };
        match command {
            Cmd::Nop
            | Cmd::Reset
            | Cmd::QueueDrain
            | Cmd::Save
            | Cmd::Clear
            | Cmd::Restore
            | Cmd::FactoryReset => {
                write!(out, "{command:?} tid={tid}")
            }
            Cmd::PropGet
            | Cmd::PropSet
            | Cmd::PropIs
            | Cmd::PropInsert
            | Cmd::PropRemove
            | Cmd::PropInserted
            | Cmd::PropRemoved => {
                let Ok(payload) = PropPayload::parse(frame.payload) else {
                    return write!(out, "{command:?} tid={tid} (malformed payload)");
                };
                let name = property_name(payload.key);
                if payload.key == prop::LAST_STATUS && command == Cmd::PropIs {
                    let status = pui::decode(payload.value)
                        .map(|(code, _)| Status(code))
                        .unwrap_or(Status::FAILURE);
                    if let Some(name) = name {
                        write!(out, "{command:?} tid={tid} {name} = {status:?}")
                    } else {
                        write!(
                            out,
                            "{command:?} tid={tid} prop {} = {status:?}",
                            payload.key
                        )
                    }
                } else if let Some(name) = name {
                    write!(
                        out,
                        "{command:?} tid={tid} {name} ({} value bytes)",
                        payload.value.len()
                    )
                } else {
                    write!(
                        out,
                        "{command:?} tid={tid} prop {} ({} value bytes)",
                        payload.key,
                        payload.value.len()
                    )
                }
            }
            Cmd::StrSend | Cmd::StrRecv => match StreamPayload::parse(frame.payload) {
                Ok(payload) => write!(
                    out,
                    "{command:?} tid={tid} stream={} ({} data bytes, {} meta bytes)",
                    payload.stream,
                    payload.data.len(),
                    payload.metadata.len()
                ),
                Err(_) => write!(out, "{command:?} tid={tid} (malformed payload)"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    #[test]
    fn describes_known_and_unknown_properties_without_values() {
        let mut buf = [0u8; 16];
        let len = frame::prop_set(&mut buf, 2, prop::PHY_FREQ, &[0x7e, 0x42]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropSet tid=2 PROP_PHY_FREQ (2 value bytes)"
        );

        let len = frame::prop_get(&mut buf, 3, 60_000).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropGet tid=3 prop 60000 (0 value bytes)"
        );
    }

    #[test]
    fn describes_status_and_malformed_frames() {
        let mut buf = [0u8; 8];
        let len = frame::last_status(&mut buf, 4, Status::OK).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropIs tid=4 PROP_LAST_STATUS = Status::OK"
        );
        assert_eq!(
            FrameDescription(&[0x80]).to_string(),
            "malformed frame (1 bytes)"
        );
    }

    #[test]
    fn names_capabilities() {
        assert_eq!(capability_name(cap::HOST_RX_QUEUE), Some("HOST_RX_QUEUE"));
        assert_eq!(capability_name(cap::BATTERY), Some("BATTERY"));
        assert_eq!(capability_name(60_000), None);
    }

    #[test]
    fn describes_battery_snapshots_and_the_empty_form() {
        let mut buf = [0u8; 16];
        let len = frame::prop_is(&mut buf, 5, prop::BATTERY, &[0b101, 0x74, 0x0E, 0]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropIs tid=5 PROP_BATTERY (4 value bytes)"
        );

        let len = frame::prop_is(&mut buf, 6, prop::BATTERY, &[]).unwrap();
        assert_eq!(
            FrameDescription(&buf[..len]).to_string(),
            "PropIs tid=6 PROP_BATTERY (0 value bytes)"
        );
    }
}
