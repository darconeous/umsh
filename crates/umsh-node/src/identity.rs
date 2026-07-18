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
    pub const SUPPORTED_REGIONS: u16 = 4;
    pub const NONCE: u16 = 5;
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
    pub struct NodeCapabilities: u8 {
        const REPEATER       = 0x01;
        const MOBILE         = 0x02;
        const TEXT_MESSAGES  = 0x04;
        const TELEMETRY      = 0x08;
        const CHAT_ROOM      = 0x10;
        const COAP           = 0x20;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentityPayload {
    pub role: NodeRole,
    pub capabilities: NodeCapabilities,
    /// Option 0 — display name (UTF-8).
    pub name: Option<String>,
    /// Option 1 — geographic position.
    pub location: Option<NodeLocation>,
    /// Option 2 — altitude above mean sea level, in meters.
    pub altitude_m: Option<i32>,
    /// Option 3 — seconds since the Unix epoch (freshness marker).
    pub timestamp: Option<u32>,
    /// Option 4 — concatenated 2-byte region codes this repeater serves.
    pub supported_regions: Option<Vec<u8>>,
    /// Option 5 — nonce echoed from a soliciting Advertisement Request.
    /// Present only in solicited advertisements whose request carried one.
    pub nonce: Option<u32>,
    /// EdDSA signature over ROLE..=0xFF, present when the identity stands alone.
    ///
    /// TODO: signing and verification belong outside `NodeIdentityPayload`
    /// (the way the source-address routing hint lives outside the payload).
    /// The eventual rework should remove this field and move the
    /// signed-identity wrapper to a separate type that owns both the encoded
    /// payload bytes and the signature, so the signed-byte range is never
    /// reconstructed at the call site.
    pub signature: Option<[u8; 64]>,
}

impl NodeIdentityPayload {
    pub fn from_bytes(payload: &[u8]) -> Result<NodeIdentityPayload, AppParseError> {
        if payload.len() < 2 {
            return Err(AppParseError::Core(umsh_core::ParseError::Truncated));
        }

        let role = NodeRole::from_byte(payload[0]);
        let capabilities = NodeCapabilities::from_bits_truncate(payload[1]);
        let remaining = &payload[2..];

        let mut name = None;
        let mut location = None;
        let mut altitude_m = None;
        let mut timestamp = None;
        let mut supported_regions = None;
        let mut nonce = None;

        let mut decoder = OptionDecoder::new(remaining);
        for result in decoder.by_ref() {
            let (number, value) = result?;
            match number {
                opt::NAME => name = Some(String::from(parse_utf8(value)?)),
                opt::LOCATION => {
                    // Spec: MUST ignore bytes after the 7th
                    location = Some(NodeLocation::from_bytes(value));
                }
                opt::ALTITUDE => altitude_m = Some(parse_be_i32(value)?),
                opt::TIMESTAMP => timestamp = Some(parse_be_u32(value)?),
                opt::SUPPORTED_REGIONS => {
                    if value.len() % 2 != 0 {
                        return Err(AppParseError::InvalidOptionValue);
                    }
                    supported_regions = Some(Vec::from(value));
                }
                opt::NONCE => {
                    // A verbatim copy of the request's 4-byte field —
                    // fixed-width, unlike the minimally encoded integers.
                    let bytes: [u8; 4] = value
                        .try_into()
                        .map_err(|_| AppParseError::InvalidOptionValue)?;
                    nonce = Some(u32::from_be_bytes(bytes));
                }
                _ => {} // unknown options are silently skipped
            }
        }

        let sig_bytes = decoder.remainder();
        let signature = match sig_bytes.len() {
            0 => None,
            64 => Some(
                sig_bytes
                    .try_into()
                    .map_err(|_| AppParseError::InvalidLength {
                        expected: 64,
                        actual: sig_bytes.len(),
                    })?,
            ),
            n => {
                return Err(AppParseError::InvalidLength {
                    expected: 64,
                    actual: n,
                });
            }
        };

        Ok(NodeIdentityPayload {
            role,
            capabilities,
            name,
            location,
            altitude_m,
            timestamp,
            supported_regions,
            nonce,
            signature,
        })
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
        if buf.len() < 2 {
            return Err(AppEncodeError::BufferTooSmall);
        }
        buf[0] = self.role.as_byte();
        buf[1] = self.capabilities.bits();
        let mut pos = 2;

        {
            let mut enc = OptionEncoder::new(&mut buf[pos..]);
            if let Some(name) = self.name.as_deref() {
                enc.put(opt::NAME, name.as_bytes())?;
            }
            if let Some(loc) = self.location {
                enc.put(opt::LOCATION, loc.as_bytes())?;
            }
            if let Some(alt) = self.altitude_m {
                enc.put_i32(opt::ALTITUDE, alt)?;
            }
            if let Some(ts) = self.timestamp {
                enc.put_u32(opt::TIMESTAMP, ts)?;
            }
            if let Some(regions) = self.supported_regions.as_deref() {
                enc.put(opt::SUPPORTED_REGIONS, regions)?;
            }
            if let Some(nonce) = self.nonce {
                enc.put(opt::NONCE, &nonce.to_be_bytes())?;
            }
            if self.signature.is_some() {
                enc.end_marker()?;
            }
            pos += enc.finish();
        }

        if let Some(sig) = &self.signature {
            if pos + 64 > buf.len() {
                return Err(AppEncodeError::BufferTooSmall);
            }
            buf[pos..pos + 64].copy_from_slice(sig);
            pos += 64;
        }

        Ok(pos)
    }

    /// Encode the signed byte range — `ROLE` through the `0xFF`
    /// options terminator, inclusive — for a detached signing step.
    /// `self.signature` is ignored; the caller signs exactly the
    /// returned bytes and appends the 64-byte signature to produce the
    /// standalone (signed) wire form:
    ///
    /// ```ignore
    /// let len = payload.encode_for_signing(&mut buf)?;
    /// let signature = identity.sign(&buf[..len]).await?;
    /// buf[len..len + 64].copy_from_slice(&signature);
    /// // buf[..len + 64] now parses with `signature: Some(..)`.
    /// ```
    pub fn encode_for_signing(&self, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
        let unsigned = Self {
            signature: None,
            ..self.clone()
        };
        let mut pos = unsigned.encode(buf)?;
        let mut enc = OptionEncoder::new(&mut buf[pos..]);
        enc.end_marker()?;
        pos += enc.finish();
        Ok(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(id: &NodeIdentityPayload) -> bool {
        let mut buf = [0u8; 256];
        let len = id.encode(&mut buf).expect("encode failed");
        let decoded = NodeIdentityPayload::from_bytes(&buf[..len]).expect("parse failed");
        decoded == *id
    }

    #[test]
    fn minimal_two_bytes() {
        let id = NodeIdentityPayload {
            role: NodeRole::Chat,
            capabilities: NodeCapabilities::TEXT_MESSAGES,
            name: None,
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 16];
        let len = id.encode(&mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(buf[0], 2); // Chat role
        assert_eq!(buf[1], NodeCapabilities::TEXT_MESSAGES.bits());
        assert!(round_trip(&id));
    }

    #[test]
    fn name_only() {
        let id = NodeIdentityPayload {
            role: NodeRole::Unspecified,
            capabilities: NodeCapabilities::empty(),
            name: Some("Alice".into()),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        assert!(round_trip(&id));
    }

    #[test]
    fn all_options() {
        let loc = NodeLocation::from_bytes(&[0x2B, 0x95, 0x51]);
        let id = NodeIdentityPayload {
            role: NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER | NodeCapabilities::TEXT_MESSAGES,
            name: Some("tower".into()),
            location: Some(loc),
            altitude_m: Some(1500),
            timestamp: Some(1_700_000_000),
            supported_regions: Some(vec![0x00, 0x01, 0x00, 0x02]),
            nonce: None,
            signature: None,
        };
        assert!(round_trip(&id));
    }

    #[test]
    fn negative_altitude() {
        let id = NodeIdentityPayload {
            role: NodeRole::Sensor,
            capabilities: NodeCapabilities::empty(),
            name: None,
            location: None,
            altitude_m: Some(-430), // Dead Sea
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        assert!(round_trip(&id));
    }

    #[test]
    fn altitude_zero() {
        let id = NodeIdentityPayload {
            role: NodeRole::Sensor,
            capabilities: NodeCapabilities::empty(),
            name: None,
            location: None,
            altitude_m: Some(0),
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        assert!(round_trip(&id));
    }

    #[test]
    fn nonce_round_trips_as_fixed_four_bytes() {
        let id = NodeIdentityPayload {
            role: NodeRole::Tracker,
            capabilities: NodeCapabilities::MOBILE,
            name: Some("UMSH TRACKER 1".into()),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: Some(0x0000_0042), // leading zeros must survive
            signature: None,
        };
        assert!(round_trip(&id));
        // The wire form carries all four bytes even with leading zeros.
        let mut buf = [0u8; 64];
        let len = id.encode(&mut buf).unwrap();
        let window = &buf[..len];
        assert!(
            window.windows(4).any(|w| w == [0x00, 0x00, 0x00, 0x42]),
            "nonce not fixed-width on the wire"
        );
        // A truncated nonce option is rejected, not minimally decoded.
        let mut manual = [0u8; 8];
        manual[0] = 0; // role
        manual[1] = 0; // caps
        // option 5, length 2 (invalid): delta 5 -> nibble 0x5, len 0x2
        manual[2] = 0x52;
        manual[3] = 0xAA;
        manual[4] = 0xBB;
        assert!(NodeIdentityPayload::from_bytes(&manual[..5]).is_err());
    }

    #[test]
    fn encode_for_signing_matches_signed_wire_form() {
        let id = NodeIdentityPayload {
            role: NodeRole::Tracker,
            capabilities: NodeCapabilities::empty(),
            name: Some("advert".into()),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: Some(0xDEAD_BEEF),
            signature: None,
        };
        let mut buf = [0u8; 256];
        let len = id.encode_for_signing(&mut buf).unwrap();
        // The signed range ends with the options terminator.
        assert_eq!(buf[len - 1], 0xFF);
        // Appending a signature yields exactly the wire form `encode`
        // produces for the same payload with `signature: Some(..)`.
        buf[len..len + 64].copy_from_slice(&[0xA5; 64]);
        let mut reference = [0u8; 256];
        let mut signed = id.clone();
        signed.signature = Some([0xA5; 64]);
        let ref_len = signed.encode(&mut reference).unwrap();
        assert_eq!(&buf[..len + 64], &reference[..ref_len]);
        // And the composite parses back with the signature attached.
        let parsed = NodeIdentityPayload::from_bytes(&buf[..len + 64]).unwrap();
        assert_eq!(parsed, signed);
    }

    #[test]
    fn with_signature() {
        let id = NodeIdentityPayload {
            role: NodeRole::Chat,
            capabilities: NodeCapabilities::empty(),
            name: Some("Bob".into()),
            location: None,
            altitude_m: None,
            timestamp: Some(1_700_000_000),
            supported_regions: None,
            nonce: None,
            signature: Some([0xAAu8; 64]),
        };
        assert!(round_trip(&id));
    }
}
