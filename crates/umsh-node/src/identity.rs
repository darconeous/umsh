use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;
use umsh_core::REGION_NAME_MAX_LEN as REGION_STRING_MAX_LEN;
use umsh_core::options::{OptionDecoder, OptionEncoder, parse_be_i32, parse_be_u32};

use crate::location::NodeLocation;
use crate::{AppEncodeError, AppParseError};

/// Most regions one identity payload names.
///
/// The list is a claim about where a repeater forwards, not an inventory, and
/// ten of them is already more than a packet comfortably carries
/// (node-identity.md § Supported Regions).
pub const MAX_SUPPORTED_REGIONS: usize = 10;

/// Longest Name option value, in bytes (UEP-0011 § Identity Options).
pub const IDENTITY_NAME_MAX_LEN: usize = 24;

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

/// Whether a node forwards other nodes' traffic, by what its identity says:
/// the `REP` capability, which advertises repeater duty whatever the role,
/// or a role that is forwarding—a repeater, or a bridge, which is a node
/// with its repeater enabled. An identity is its node's own claim, not
/// proof.
pub fn forwards(role: NodeRole, capabilities: NodeCapabilities) -> bool {
    capabilities.contains(NodeCapabilities::REPEATER)
        || matches!(role, NodeRole::Repeater | NodeRole::Bridge)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentityPayload {
    pub role: NodeRole,
    pub capabilities: NodeCapabilities,
    /// Option 0—display name (UTF-8).
    pub name: Option<String>,
    /// Option 1—geographic position.
    pub location: Option<NodeLocation>,
    /// Option 2—altitude above mean sea level, in meters.
    pub altitude_m: Option<i32>,
    /// Option 3—seconds since the Unix epoch (freshness marker).
    pub timestamp: Option<u32>,
    /// Option 4—the regions this repeater floods for, in their string form,
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
    /// Option 5—nonce echoed from a soliciting Advertisement Request.
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

/// What an identity payload's signature says about its claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentitySignature {
    /// No signature was attached; the claims are only as good as the frame
    /// that carried them.
    Unsigned,
    /// The attached signature verifies against the node's public key.
    Valid,
    /// The attached signature does not verify; the claims must not be
    /// trusted.
    Invalid,
}

impl NodeIdentityPayload {
    /// Check the signature `self` carries against `key`, the node the
    /// payload claims to describe. `payload` is the encoding `self` was
    /// parsed from: the signed range is everything before the trailing
    /// signature.
    #[cfg(feature = "software-crypto")]
    pub fn signature_state(&self, key: &umsh_core::PublicKey, payload: &[u8]) -> IdentitySignature {
        let Some(signature) = &self.signature else {
            return IdentitySignature::Unsigned;
        };
        let signed = &payload[..payload.len().saturating_sub(signature.len())];
        if umsh_crypto::verify_ed25519_signature(key, signed, signature) {
            IdentitySignature::Valid
        } else {
            IdentitySignature::Invalid
        }
    }
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

        // Each single-valued option counts once: a receiver uses the first
        // record and ignores any repeat, whether or not the first one held a
        // value it could use (UEP-0011 § Identity Options).
        let mut seen: u8 = 0;
        let mut first = |number: u16| {
            let bit = 1u8 << number;
            let fresh = seen & bit == 0;
            seen |= bit;
            fresh
        };

        // An option whose value is unusable (over its limit, or a Location
        // of no bytes) is ignored rather than taken as grounds to discard
        // the identity. A malformed options block and a Nonce that is not
        // 4 bytes are the only option faults that discard it.
        let mut decoder = OptionDecoder::new(remaining);
        for result in decoder.by_ref() {
            let (number, value) = result?;
            match number {
                opt::NAME if first(number) => {
                    // A Name that is not valid UTF-8 is displayed with each
                    // undecodable part replaced (UEP-0003 § Strings).
                    if value.len() <= IDENTITY_NAME_MAX_LEN {
                        name = Some(String::from_utf8_lossy(value).into_owned());
                    }
                }
                opt::LOCATION if first(number) => {
                    // Bytes past the seventh are ignored by `from_bytes`.
                    if !value.is_empty() {
                        location = Some(NodeLocation::from_bytes(value));
                    }
                }
                opt::ALTITUDE if first(number) => altitude_m = parse_be_i32(value).ok(),
                opt::TIMESTAMP if first(number) => timestamp = parse_be_u32(value).ok(),
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
                    // A verbatim copy of the request's 4-byte field—
                    // fixed-width, unlike the minimally encoded integers.
                    // Any other length discards the identity, repeat or
                    // not: Signature Domain relies on it to keep a frame
                    // signature's input from parsing as an identity.
                    let bytes: [u8; 4] = value
                        .try_into()
                        .map_err(|_| AppParseError::InvalidOptionValue)?;
                    if first(number) {
                        nonce = Some(u32::from_be_bytes(bytes));
                    }
                }
                // Unknown options, and repeats of a single-valued one, are
                // skipped.
                _ => {}
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

    /// Encode the signed byte range—`ROLE` through the `0xFF`
    /// options terminator, inclusive—for a detached signing step.
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
pub(crate) mod tests {
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

    /// `ROLE`, `CAPS`, and the options `put` writes, unsigned.
    fn raw_identity(put: impl FnOnce(&mut OptionEncoder<'_>)) -> Vec<u8> {
        let mut buf = [0u8; 256];
        buf[0] = NodeRole::Chat.as_byte();
        buf[1] = NodeCapabilities::TEXT_MESSAGES.bits();
        let mut enc = OptionEncoder::new(&mut buf[2..]);
        put(&mut enc);
        let len = 2 + enc.finish();
        buf[..len].to_vec()
    }

    /// A Name that is not valid UTF-8 is shown with its undecodable parts
    /// replaced, not grounds to drop the identity (UEP-0003 § Strings).
    #[test]
    fn a_name_that_is_not_utf8_decodes_lossily() {
        let payload = raw_identity(|enc| {
            enc.put(opt::NAME, b"Al\xFFce\xE2\x82").unwrap();
            enc.put_u32(opt::TIMESTAMP, 1_700_000_000).unwrap();
        });
        let decoded = NodeIdentityPayload::from_bytes(&payload).unwrap();
        assert_eq!(decoded.name.as_deref(), Some("Al\u{FFFD}ce\u{FFFD}"));
        assert_eq!(decoded.timestamp, Some(1_700_000_000));
    }

    /// Values longer than their option's limit, and a Location of no
    /// bytes, are ignored while the rest of the identity is kept.
    #[test]
    fn ignores_option_values_it_cannot_use() {
        let long_name = [b'N'; IDENTITY_NAME_MAX_LEN + 1];
        let payload = raw_identity(|enc| {
            enc.put(opt::NAME, &long_name).unwrap();
            enc.put(opt::LOCATION, &[]).unwrap();
            enc.put(opt::ALTITUDE, &[0x00, 0x00, 0x00, 0x00, 0x2A])
                .unwrap();
            enc.put(opt::TIMESTAMP, &[0x01, 0x65, 0x53, 0xF1, 0x00])
                .unwrap();
            enc.put(opt::NONCE, &0x0102_0304u32.to_be_bytes()).unwrap();
        });
        let decoded = NodeIdentityPayload::from_bytes(&payload).unwrap();
        assert_eq!(decoded.role, NodeRole::Chat);
        assert_eq!(decoded.capabilities, NodeCapabilities::TEXT_MESSAGES);
        assert_eq!(decoded.name, None);
        assert_eq!(decoded.location, None);
        assert_eq!(decoded.altitude_m, None);
        assert_eq!(decoded.timestamp, None);
        assert_eq!(decoded.nonce, Some(0x0102_0304));
    }

    /// A name of exactly the limit is kept, and so are the first seven
    /// bytes of an over-long Location.
    #[test]
    fn keeps_values_at_the_limit() {
        let name = "N".repeat(IDENTITY_NAME_MAX_LEN);
        let payload = raw_identity(|enc| {
            enc.put(opt::NAME, name.as_bytes()).unwrap();
            enc.put(opt::LOCATION, &[1, 2, 3, 4, 5, 6, 7, 8, 9])
                .unwrap();
        });
        let decoded = NodeIdentityPayload::from_bytes(&payload).unwrap();
        assert_eq!(decoded.name.as_deref(), Some(name.as_str()));
        assert_eq!(
            decoded.location,
            Some(NodeLocation::from_bytes(&[1, 2, 3, 4, 5, 6, 7]))
        );
    }

    /// The first record of a single-valued option is the one used; a
    /// repeat is ignored even when the first value was unusable.
    #[test]
    fn uses_the_first_of_any_repeats() {
        let payload = raw_identity(|enc| {
            enc.put(opt::NAME, b"first").unwrap();
            enc.put(opt::NAME, b"second").unwrap();
            enc.put(opt::ALTITUDE, &[0, 0, 0, 0, 1]).unwrap();
            enc.put_i32(opt::ALTITUDE, 42).unwrap();
            enc.put_u32(opt::TIMESTAMP, 7).unwrap();
            enc.put_u32(opt::TIMESTAMP, 9).unwrap();
            enc.put(opt::NONCE, &1u32.to_be_bytes()).unwrap();
            enc.put(opt::NONCE, &2u32.to_be_bytes()).unwrap();
        });
        let decoded = NodeIdentityPayload::from_bytes(&payload).unwrap();
        assert_eq!(decoded.name.as_deref(), Some("first"));
        assert_eq!(decoded.altitude_m, None);
        assert_eq!(decoded.timestamp, Some(7));
        assert_eq!(decoded.nonce, Some(1));
    }

    /// The faults UEP-0011 discards an identity for still fail the parse.
    #[test]
    fn discards_what_the_spec_discards() {
        // Shorter than two bytes.
        assert!(NodeIdentityPayload::from_bytes(&[NodeRole::Chat.as_byte()]).is_err());

        // A Nonce that is not 4 bytes, even as a repeat.
        for nonce in [&[1u8, 2, 3][..], &[1, 2, 3, 4, 5], &[]] {
            let payload = raw_identity(|enc| enc.put(opt::NONCE, nonce).unwrap());
            assert!(NodeIdentityPayload::from_bytes(&payload).is_err());
        }
        let payload = raw_identity(|enc| {
            enc.put(opt::NONCE, &1u32.to_be_bytes()).unwrap();
            enc.put(opt::NONCE, &[1, 2]).unwrap();
        });
        assert!(NodeIdentityPayload::from_bytes(&payload).is_err());

        // A malformed options block: a record that claims more bytes than
        // remain.
        let malformed = [NodeRole::Chat.as_byte(), 0, 0x05, b'A'];
        assert!(NodeIdentityPayload::from_bytes(&malformed).is_err());

        // Bytes after the end marker that are neither absent nor 64.
        let mut trailer = raw_identity(|enc| enc.put(opt::NAME, b"Bob").unwrap());
        trailer.push(0xFF);
        trailer.extend_from_slice(&[0xAA; 63]);
        assert!(NodeIdentityPayload::from_bytes(&trailer).is_err());
    }

    /// The signature covers the bytes on the wire, so a payload whose Name
    /// decodes lossily and whose integers are ignored still verifies.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_leniently_parsed_identity_still_verifies() {
        use umsh_crypto::NodeIdentity as _;
        let signer = umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[0x47; 32]);
        let mut payload = raw_identity(|enc| {
            enc.put(opt::NAME, b"Bo\xC3b").unwrap();
            enc.put(opt::ALTITUDE, &[0, 0, 0, 0, 0x10]).unwrap();
            enc.put(opt::TIMESTAMP, &[0, 0, 0, 0, 0x20]).unwrap();
            enc.end_marker().unwrap();
        });
        let signature = {
            let mut sign = core::pin::pin!(signer.sign(&payload));
            let core::task::Poll::Ready(Ok(signature)) = sign.as_mut().poll(
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            ) else {
                panic!("software signing completes at once");
            };
            signature
        };
        payload.extend_from_slice(&signature);

        let parsed = NodeIdentityPayload::from_bytes(&payload).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("Bo\u{FFFD}b"));
        assert_eq!(parsed.altitude_m, None);
        assert_eq!(parsed.timestamp, None);
        assert_eq!(
            parsed.signature_state(signer.public_key(), &payload),
            IdentitySignature::Valid
        );

        let mut tampered = payload.clone();
        tampered[4] ^= 0x01;
        let parsed = NodeIdentityPayload::from_bytes(&tampered).unwrap();
        assert_eq!(
            parsed.signature_state(signer.public_key(), &tampered),
            IdentitySignature::Invalid
        );
    }

    /// A payload signed by `seed`'s key, with its public key.
    #[cfg(feature = "software-crypto")]
    pub(crate) fn signed_payload(
        seed: u8,
        capabilities: NodeCapabilities,
    ) -> (umsh_core::PublicKey, Vec<u8>) {
        use umsh_crypto::NodeIdentity as _;
        let signer = umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32]);
        let id = NodeIdentityPayload {
            role: NodeRole::Chat,
            capabilities,
            name: None,
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 128];
        let len = id.encode_for_signing(&mut buf).unwrap();
        let signature = {
            let mut sign = core::pin::pin!(signer.sign(&buf[..len]));
            let core::task::Poll::Ready(Ok(signature)) = sign.as_mut().poll(
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            ) else {
                panic!("software signing completes at once");
            };
            signature
        };
        buf[len..len + 64].copy_from_slice(&signature);
        (*signer.public_key(), buf[..len + 64].to_vec())
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_signature_is_checked_against_the_key_the_payload_describes() {
        let (key, payload) = signed_payload(0x31, NodeCapabilities::MOBILE);
        let parsed = NodeIdentityPayload::from_bytes(&payload).unwrap();
        assert_eq!(
            parsed.signature_state(&key, &payload),
            IdentitySignature::Valid
        );

        let other = umsh_core::PublicKey([0x55; 32]);
        assert_eq!(
            parsed.signature_state(&other, &payload),
            IdentitySignature::Invalid
        );

        let mut tampered = payload.clone();
        tampered[1] ^= NodeCapabilities::MOBILE.bits();
        let parsed = NodeIdentityPayload::from_bytes(&tampered).unwrap();
        assert_eq!(
            parsed.signature_state(&key, &tampered),
            IdentitySignature::Invalid
        );

        let unsigned = [NodeRole::Chat.as_byte(), 0];
        let parsed = NodeIdentityPayload::from_bytes(&unsigned).unwrap();
        assert_eq!(
            parsed.signature_state(&key, &unsigned),
            IdentitySignature::Unsigned
        );
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
