use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;
use umsh_core::options::{OptionDecoder, OptionEncoder, parse_be_i32, parse_be_u32};

use crate::app_util::parse_utf8;
use crate::location::NodeLocation;
use crate::{AppEncodeError, AppParseError};

mod opt {
    pub const NAME: u16 = 0;
    pub const LOCATION: u16 = 1;
    pub const ALTITUDE: u16 = 2;
    pub const TIMESTAMP: u16 = 3;
    pub const UPTIME: u16 = 4;
    pub const CALLSIGN: u16 = 5;
    pub const SUPPORTED_REGIONS: u16 = 6;
    pub const BATTERY: u16 = 7;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    Unspecified,
    Repeater,
    Chat,
    Tracker,
    Sensor,
    Bridge,
    ChatRoom,
    TemporarySession,
    /// A role value not recognized by this implementation; preserved for round-tripping.
    Unknown(u8),
}

impl NodeRole {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::Repeater,
            2 => Self::Chat,
            3 => Self::Tracker,
            4 => Self::Sensor,
            5 => Self::Bridge,
            6 => Self::ChatRoom,
            7 => Self::TemporarySession,
            n => Self::Unknown(n),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::Repeater => 1,
            Self::Chat => 2,
            Self::Tracker => 3,
            Self::Sensor => 4,
            Self::Bridge => 5,
            Self::ChatRoom => 6,
            Self::TemporarySession => 7,
            Self::Unknown(n) => n,
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Capabilities: u8 {
        const REPEATER       = 0x01;
        const MOBILE         = 0x02;
        const TEXT_MESSAGES  = 0x04;
        const TELEMETRY      = 0x08;
        const CHAT_ROOM      = 0x10;
        const COAP           = 0x20;
    }
}

/// Borrowed view of a node identity payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeIdentityRef<'a> {
    pub role: NodeRole,
    pub capabilities: Capabilities,
    /// Option 0 — display name (UTF-8).
    pub name: Option<&'a str>,
    /// Option 1 — geographic position.
    pub location: Option<NodeLocation>,
    /// Option 2 — altitude above mean sea level, in meters.
    pub altitude_m: Option<i32>,
    /// Option 3 — seconds since the Unix epoch (freshness marker).
    pub timestamp: Option<u32>,
    /// Option 4 — minutes since last boot.
    pub uptime_minutes: Option<u32>,
    /// Option 5 — ARNCE/HAM-64 callsign (2, 4, 6, or 8 bytes).
    pub callsign: Option<&'a [u8]>,
    /// Option 6 — concatenated 2-byte region codes this repeater serves.
    pub supported_regions: Option<&'a [u8]>,
    /// Option 7 — raw battery level: 0..=255 maps linearly to 0%..=100%.
    pub battery_raw: Option<u8>,
    /// EdDSA signature over ROLE..=0xFF, present when the identity stands alone.
    pub signature: Option<&'a [u8; 64]>,
}

// --- Parse ---

pub fn parse(payload: &[u8]) -> Result<NodeIdentityRef<'_>, AppParseError> {
    if payload.len() < 2 {
        return Err(AppParseError::Core(umsh_core::ParseError::Truncated));
    }

    let role = NodeRole::from_byte(payload[0]);
    let capabilities = Capabilities::from_bits_truncate(payload[1]);
    let remaining = &payload[2..];

    let mut name = None;
    let mut location = None;
    let mut altitude_m = None;
    let mut timestamp = None;
    let mut uptime_minutes = None;
    let mut callsign = None;
    let mut supported_regions = None;
    let mut battery_raw = None;

    let mut decoder = OptionDecoder::new(remaining);
    for result in decoder.by_ref() {
        let (number, value) = result?;
        match number {
            opt::NAME => name = Some(parse_utf8(value)?),
            opt::LOCATION => {
                // Spec: MUST ignore bytes after the 7th
                location = Some(NodeLocation::from_bytes(value));
            }
            opt::ALTITUDE => altitude_m = Some(parse_be_i32(value)?),
            opt::TIMESTAMP => timestamp = Some(parse_be_u32(value)?),
            opt::UPTIME => uptime_minutes = Some(parse_be_u32(value)?),
            opt::CALLSIGN => {
                if !matches!(value.len(), 2 | 4 | 6 | 8) {
                    return Err(AppParseError::InvalidOptionValue);
                }
                callsign = Some(value);
            }
            opt::SUPPORTED_REGIONS => {
                if value.len() % 2 != 0 {
                    return Err(AppParseError::InvalidOptionValue);
                }
                supported_regions = Some(value);
            }
            opt::BATTERY => {
                if value.len() != 1 {
                    return Err(AppParseError::InvalidOptionValue);
                }
                battery_raw = Some(value[0]);
            }
            _ => {} // unknown options are silently skipped
        }
    }

    let sig_bytes = decoder.remainder();
    let signature = match sig_bytes.len() {
        0 => None,
        64 => Some(sig_bytes.try_into().map_err(|_| AppParseError::InvalidLength {
            expected: 64,
            actual: sig_bytes.len(),
        })?),
        n => {
            return Err(AppParseError::InvalidLength {
                expected: 64,
                actual: n,
            });
        }
    };

    Ok(NodeIdentityRef {
        role,
        capabilities,
        name,
        location,
        altitude_m,
        timestamp,
        uptime_minutes,
        callsign,
        supported_regions,
        battery_raw,
        signature,
    })
}

// --- Encode ---

pub fn encode(id: &NodeIdentityRef<'_>, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
    if buf.len() < 2 {
        return Err(AppEncodeError::BufferTooSmall);
    }
    buf[0] = id.role.as_byte();
    buf[1] = id.capabilities.bits();
    let mut pos = 2;

    {
        let mut enc = OptionEncoder::new(&mut buf[pos..]);
        if let Some(name) = id.name {
            enc.put(opt::NAME, name.as_bytes())?;
        }
        if let Some(loc) = id.location {
            enc.put(opt::LOCATION, loc.as_bytes())?;
        }
        if let Some(alt) = id.altitude_m {
            enc.put_i32(opt::ALTITUDE, alt)?;
        }
        if let Some(ts) = id.timestamp {
            enc.put_u32(opt::TIMESTAMP, ts)?;
        }
        if let Some(uptime) = id.uptime_minutes {
            enc.put_u32(opt::UPTIME, uptime)?;
        }
        if let Some(cs) = id.callsign {
            enc.put(opt::CALLSIGN, cs)?;
        }
        if let Some(regions) = id.supported_regions {
            enc.put(opt::SUPPORTED_REGIONS, regions)?;
        }
        if let Some(battery) = id.battery_raw {
            enc.put(opt::BATTERY, &[battery])?;
        }
        if id.signature.is_some() {
            enc.end_marker()?;
        }
        pos += enc.finish();
    }

    if let Some(sig) = id.signature {
        if pos + 64 > buf.len() {
            return Err(AppEncodeError::BufferTooSmall);
        }
        buf[pos..pos + 64].copy_from_slice(sig);
        pos += 64;
    }

    Ok(pos)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub role: NodeRole,
    pub capabilities: Capabilities,
    pub name: Option<String>,
    pub location: Option<NodeLocation>,
    pub altitude_m: Option<i32>,
    pub timestamp: Option<u32>,
    pub uptime_minutes: Option<u32>,
    pub callsign: Option<Vec<u8>>,
    pub supported_regions: Option<Vec<u8>>,
    pub battery_raw: Option<u8>,
    pub signature: Option<[u8; 64]>,
}

impl NodeIdentity {
    pub fn as_borrowed(&self) -> NodeIdentityRef<'_> {
        NodeIdentityRef {
            role: self.role,
            capabilities: self.capabilities,
            name: self.name.as_deref(),
            location: self.location,
            altitude_m: self.altitude_m,
            timestamp: self.timestamp,
            uptime_minutes: self.uptime_minutes,
            callsign: self.callsign.as_deref(),
            supported_regions: self.supported_regions.as_deref(),
            battery_raw: self.battery_raw,
            signature: self.signature.as_ref(),
        }
    }
}

impl From<NodeIdentityRef<'_>> for NodeIdentity {
    fn from(value: NodeIdentityRef<'_>) -> Self {
        Self {
            role: value.role,
            capabilities: value.capabilities,
            name: value.name.map(String::from),
            location: value.location,
            altitude_m: value.altitude_m,
            timestamp: value.timestamp,
            uptime_minutes: value.uptime_minutes,
            callsign: value.callsign.map(Vec::from),
            supported_regions: value.supported_regions.map(Vec::from),
            battery_raw: value.battery_raw,
            signature: value.signature.copied(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(id: NodeIdentityRef<'_>) -> bool {
        let mut buf = [0u8; 256];
        let len = encode(&id, &mut buf).expect("encode failed");
        let decoded = parse(&buf[..len]).expect("parse failed");
        decoded == id
    }

    #[test]
    fn minimal_two_bytes() {
        let id = NodeIdentityRef {
            role: NodeRole::Chat,
            capabilities: Capabilities::TEXT_MESSAGES,
            name: None,
            location: None,
            altitude_m: None,
            timestamp: None,
            uptime_minutes: None,
            callsign: None,
            supported_regions: None,
            battery_raw: None,
            signature: None,
        };
        let mut buf = [0u8; 16];
        let len = encode(&id, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(buf[0], 2); // Chat role
        assert_eq!(buf[1], Capabilities::TEXT_MESSAGES.bits());
        assert!(round_trip(id));
    }

    #[test]
    fn name_and_battery() {
        let id = NodeIdentityRef {
            role: NodeRole::Unspecified,
            capabilities: Capabilities::empty(),
            name: Some("Alice"),
            location: None,
            altitude_m: None,
            timestamp: None,
            uptime_minutes: None,
            callsign: None,
            supported_regions: None,
            battery_raw: Some(200),
            signature: None,
        };
        assert!(round_trip(id));
    }

    #[test]
    fn all_options() {
        let callsign_bytes = [0xAB, 0xCD, 0xEF, 0x12];
        let region_bytes = [0x00, 0x01, 0x00, 0x02];
        let loc = NodeLocation::from_bytes(&[0x2B, 0x95, 0x51]);
        let id = NodeIdentityRef {
            role: NodeRole::Repeater,
            capabilities: Capabilities::REPEATER | Capabilities::TEXT_MESSAGES,
            name: Some("tower"),
            location: Some(loc),
            altitude_m: Some(1500),
            timestamp: Some(1_700_000_000),
            uptime_minutes: Some(42),
            callsign: Some(&callsign_bytes),
            supported_regions: Some(&region_bytes),
            battery_raw: Some(128),
            signature: None,
        };
        assert!(round_trip(id));
    }

    #[test]
    fn negative_altitude() {
        let id = NodeIdentityRef {
            role: NodeRole::Sensor,
            capabilities: Capabilities::empty(),
            name: None,
            location: None,
            altitude_m: Some(-430), // Dead Sea
            timestamp: None,
            uptime_minutes: None,
            callsign: None,
            supported_regions: None,
            battery_raw: None,
            signature: None,
        };
        assert!(round_trip(id));
    }

    #[test]
    fn altitude_zero() {
        let id = NodeIdentityRef {
            role: NodeRole::Sensor,
            capabilities: Capabilities::empty(),
            name: None,
            location: None,
            altitude_m: Some(0),
            timestamp: None,
            uptime_minutes: None,
            callsign: None,
            supported_regions: None,
            battery_raw: None,
            signature: None,
        };
        assert!(round_trip(id));
    }

    #[test]
    fn with_signature() {
        let sig = [0xAAu8; 64];
        let id = NodeIdentityRef {
            role: NodeRole::Chat,
            capabilities: Capabilities::empty(),
            name: Some("Bob"),
            location: None,
            altitude_m: None,
            timestamp: Some(1_700_000_000),
            uptime_minutes: None,
            callsign: None,
            supported_regions: None,
            battery_raw: None,
            signature: Some(&sig),
        };
        assert!(round_trip(id));
    }
}
