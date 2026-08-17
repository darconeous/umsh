use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;
use umsh_core::REGION_NAME_MAX_LEN as REGION_STRING_MAX_LEN;
use umsh_core::options::{OptionDecoder, OptionEncoder, parse_be_i32, parse_be_u32};

use crate::app_util::parse_utf8;
use crate::location::NodeLocation;
use crate::{AppEncodeError, AppParseError};

/// Most regions one identity payload names.
///
/// The list is a claim about where a repeater forwards, not an inventory, and
/// ten of them is already more than a packet comfortably carries
/// (node-identity.md § Supported Regions).
pub const MAX_SUPPORTED_REGIONS: usize = 10;

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
    /// Option 4 — the regions this repeater floods for, in their string form,
    /// one repetition of the option per region.
    ///
    /// The string travels rather than the derived code because the code is
    /// always recoverable from the string while a hash-derived code cannot be
    /// turned back into a name. A node lists at most
    /// [`MAX_SUPPORTED_REGIONS`], and a list that does not fit its packet is
    /// legitimately shortened, so this names regions the node forwards for
    /// without promising to name them all
    /// (node-identity.md § Supported Regions).
    pub supported_regions: Option<Vec<String>>,
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
                    // Repeated once per region. An entry that is empty,
                    // over-long, or not UTF-8 is skipped rather than taken as
                    // grounds to reject the identity, and so is anything past
                    // the tenth: the list is advisory, and a reader that
                    // throws away a whole advertisement over one bad region
                    // learns nothing about the node instead of nearly
                    // everything.
                    let regions = supported_regions.get_or_insert_with(|| Vec::with_capacity(1));
                    if regions.len() < MAX_SUPPORTED_REGIONS
                        && (1..=REGION_STRING_MAX_LEN).contains(&value.len())
                        && let Ok(text) = core::str::from_utf8(value)
                    {
                        regions.push(String::from(text));
                    }
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
                for region in regions.iter().take(MAX_SUPPORTED_REGIONS) {
                    if !(1..=REGION_STRING_MAX_LEN).contains(&region.len()) {
                        return Err(AppEncodeError::InvalidField);
                    }
                    enc.put(opt::SUPPORTED_REGIONS, region.as_bytes())?;
                }
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

    /// Encode, dropping regions from the end of the list until the result
    /// fits.
    ///
    /// The region list is the one part of an identity that is allowed to
    /// arrive incomplete: it names regions the node forwards for without
    /// promising to name every one (node-identity.md § Supported Regions).
    /// Everything else in the payload is a fact about the node, so a buffer
    /// too small to hold it after the last region is gone is still an error.
    pub fn encode_fitting(&self, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
        fn out_of_room(error: &AppEncodeError) -> bool {
            matches!(
                error,
                AppEncodeError::BufferTooSmall
                    | AppEncodeError::Core(umsh_core::EncodeError::BufferTooSmall)
            )
        }

        match self.encode(buf) {
            Err(error) if out_of_room(&error) => {}
            result => return result,
        }

        let Some(regions) = self.supported_regions.as_deref() else {
            return Err(AppEncodeError::BufferTooSmall);
        };
        let mut shortened = self.clone();
        for keep in (0..regions.len()).rev() {
            shortened.supported_regions = (keep > 0).then(|| Vec::from(&regions[..keep]));
            match shortened.encode(buf) {
                Err(error) if out_of_room(&error) => continue,
                result => return result,
            }
        }
        Err(AppEncodeError::BufferTooSmall)
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
        // Fit-aware, because a standalone identity is framed into a fixed
        // advertisement buffer and the region list is the part that is
        // allowed to arrive short.
        let mut pos = unsigned.encode_fitting(buf)?;
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
            supported_regions: Some(vec!["SJC".into(), "Rogue Valley".into()]),
            nonce: None,
            signature: None,
        };
        assert!(round_trip(&id));
    }

    /// One option per region, so the wire carries the list rather than a
    /// concatenation a reader would have to know how to split.
    #[test]
    fn each_region_is_its_own_option() {
        let id = NodeIdentityPayload {
            role: NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER,
            name: None,
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: Some(vec!["SJC".into(), "MFR".into(), "0x31d9".into()]),
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 64];
        let len = id.encode(&mut buf).unwrap();

        let mut seen = Vec::new();
        for entry in OptionDecoder::new(&buf[2..len]) {
            let (number, value) = entry.unwrap();
            if number == opt::SUPPORTED_REGIONS {
                seen.push(String::from(core::str::from_utf8(value).unwrap()));
            }
        }
        assert_eq!(seen, ["SJC", "MFR", "0x31d9"]);
        assert!(round_trip(&id));
    }

    /// The list is advisory. A reader keeps what it can use and drops the
    /// rest rather than discarding everything else the identity says.
    #[test]
    fn skips_regions_it_cannot_use_and_keeps_the_identity() {
        let mut buf = [0u8; 256];
        buf[0] = NodeRole::Repeater.as_byte();
        buf[1] = NodeCapabilities::REPEATER.bits();
        let long = "R".repeat(REGION_STRING_MAX_LEN + 1);
        let mut pos = 2;
        {
            let mut enc = OptionEncoder::new(&mut buf[pos..]);
            enc.put(opt::NAME, b"tower").unwrap();
            enc.put(opt::SUPPORTED_REGIONS, b"SJC").unwrap();
            enc.put(opt::SUPPORTED_REGIONS, b"").unwrap();
            enc.put(opt::SUPPORTED_REGIONS, long.as_bytes()).unwrap();
            enc.put(opt::SUPPORTED_REGIONS, &[0xFF, 0xFE]).unwrap();
            enc.put(opt::SUPPORTED_REGIONS, b"MFR").unwrap();
            pos += enc.finish();
        }

        let decoded = NodeIdentityPayload::from_bytes(&buf[..pos]).unwrap();
        assert_eq!(decoded.name.as_deref(), Some("tower"));
        assert_eq!(decoded.supported_regions.unwrap(), ["SJC", "MFR"]);
    }

    #[test]
    fn keeps_only_the_first_ten_regions() {
        let mut buf = [0u8; 256];
        buf[0] = NodeRole::Repeater.as_byte();
        buf[1] = NodeCapabilities::REPEATER.bits();
        let mut pos = 2;
        {
            let mut enc = OptionEncoder::new(&mut buf[pos..]);
            for index in 0..MAX_SUPPORTED_REGIONS + 4 {
                let name = alloc::format!("R{index:02}");
                enc.put(opt::SUPPORTED_REGIONS, name.as_bytes()).unwrap();
            }
            pos += enc.finish();
        }

        let regions = NodeIdentityPayload::from_bytes(&buf[..pos])
            .unwrap()
            .supported_regions
            .unwrap();
        assert_eq!(regions.len(), MAX_SUPPORTED_REGIONS);
        assert_eq!(regions[0], "R00");
        assert_eq!(regions[MAX_SUPPORTED_REGIONS - 1], "R09");
    }

    /// A list that does not fit is shortened from the end; the rest of the
    /// identity still goes out.
    #[test]
    fn drops_trailing_regions_to_fit_the_buffer() {
        let id = NodeIdentityPayload {
            role: NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER,
            name: Some("tower".into()),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: Some(vec![
                "Rogue Valley".into(),
                "SF Bay Area".into(),
                "Southern Oregon".into(),
            ]),
            nonce: None,
            signature: None,
        };

        let mut full = [0u8; 128];
        let full_len = id.encode(&mut full).unwrap();

        let mut clipped = [0u8; 128];
        let clipped_len = id.encode_fitting(&mut clipped[..full_len - 8]).unwrap();
        let decoded = NodeIdentityPayload::from_bytes(&clipped[..clipped_len]).unwrap();

        assert_eq!(decoded.name.as_deref(), Some("tower"));
        assert_eq!(
            decoded.supported_regions.unwrap(),
            ["Rogue Valley", "SF Bay Area"],
            "only the entries that did not fit are dropped, and from the end"
        );
    }

    /// Only the regions are optional. A buffer that cannot hold the identity
    /// with every region gone is an encoding failure, not a shorter identity.
    #[test]
    fn refuses_to_shorten_anything_but_the_regions() {
        let id = NodeIdentityPayload {
            role: NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER,
            name: Some("a rather long tower name".into()),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: Some(vec!["SJC".into()]),
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 12];
        assert!(matches!(
            id.encode_fitting(&mut buf),
            Err(AppEncodeError::BufferTooSmall)
        ));
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
