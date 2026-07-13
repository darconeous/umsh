use core::ops::Range;

use crate::{EncodeError, ParseError, options::OptionDecoder};

/// Current UMSH packet version encoded in the FCF high bits.
pub const UMSH_VERSION: u8 = 0b11;

/// Packet class encoded in the frame-control field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Broadcast = 0,
    MacAck = 1,
    Unicast = 2,
    UnicastAckReq = 3,
    Multicast = 4,
    Reserved5 = 5,
    BlindUnicast = 6,
    BlindUnicastAckReq = 7,
}

impl PacketType {
    /// Decode a packet type from the three packet-type bits in the FCF.
    pub const fn from_bits(value: u8) -> Self {
        match value & 0x07 {
            0 => Self::Broadcast,
            1 => Self::MacAck,
            2 => Self::Unicast,
            3 => Self::UnicastAckReq,
            4 => Self::Multicast,
            5 => Self::Reserved5,
            6 => Self::BlindUnicast,
            _ => Self::BlindUnicastAckReq,
        }
    }

    /// Return whether packets of this type carry SECINFO and a MIC.
    pub fn is_secure(self) -> bool {
        matches!(
            self,
            Self::Unicast
                | Self::UnicastAckReq
                | Self::Multicast
                | Self::BlindUnicast
                | Self::BlindUnicastAckReq
        )
    }

    /// Return whether this packet type requests a MAC ACK.
    pub fn ack_requested(self) -> bool {
        matches!(self, Self::UnicastAckReq | Self::BlindUnicastAckReq)
    }

    /// Return whether this packet type participates in mesh routing/forwarding.
    pub fn is_routable(self) -> bool {
        !matches!(self, Self::Reserved5)
    }
}

/// Application payload type carried inside the MAC body.
///
/// `Empty` is a special out-of-band value used when the frame carries no
/// application payload bytes at all, meaning there is no payload-type byte on
/// the wire. All other variants correspond to the leading typed-payload byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// No application payload and no payload-type byte on the wire.
    Empty = 0xFF,
    /// Explicit application-agnostic payload type byte `0`.
    Unspecified = 0,
    /// Node-identity payload.
    NodeIdentity = 1,
    /// MAC command payload.
    MacCommand = 2,
    /// Text-message payload.
    TextMessage = 3,
    /// Chat-room management payload.
    ChatRoomMessage = 5,
    /// CoAP-over-UMSH payload.
    CoapOverUmsh = 7,
    /// Node-management payload.
    NodeManagement = 8,
}

impl PayloadType {
    /// Convert a raw payload-type byte into a known payload type.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Unspecified),
            1 => Some(Self::NodeIdentity),
            2 => Some(Self::MacCommand),
            3 => Some(Self::TextMessage),
            5 => Some(Self::ChatRoomMessage),
            7 => Some(Self::CoapOverUmsh),
            8 => Some(Self::NodeManagement),
            _ => None,
        }
    }

    /// Return whether this payload type is valid for the given MAC packet type.
    pub fn allowed_for(self, packet_type: PacketType) -> bool {
        match self {
            Self::Empty | Self::Unspecified | Self::NodeIdentity => {
                !matches!(packet_type, PacketType::MacAck)
            }
            Self::MacCommand => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
                    | PacketType::Multicast
            ),
            Self::TextMessage | Self::CoapOverUmsh | Self::NodeManagement => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
                    | PacketType::Multicast
            ),
            Self::ChatRoomMessage => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
            ),
        }
    }
}

/// Frame-control field wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fcf(pub u8);

impl Fcf {
    /// Build an FCF from structured flags.
    pub const fn new(
        packet_type: PacketType,
        full_source: bool,
        flood_hops_present: bool,
    ) -> Self {
        Self(
            (UMSH_VERSION << 6)
                | ((packet_type as u8) << 3)
                | ((full_source as u8) << 2)
                | flood_hops_present as u8,
        )
    }

    /// Return the encoded protocol version.
    pub const fn version(self) -> u8 {
        self.0 >> 6
    }

    /// Return the encoded packet type.
    pub const fn packet_type(self) -> PacketType {
        PacketType::from_bits((self.0 >> 3) & 0x07)
    }

    /// Return whether the source address is the full 32-byte public key.
    pub const fn full_source(self) -> bool {
        self.0 & 0x04 != 0
    }

    /// Return whether the reserved bit is clear as required by the spec.
    pub const fn reserved_valid(self) -> bool {
        self.0 & 0x02 == 0
    }

    /// Return whether a flood-hop byte is present.
    pub const fn flood_hops_present(self) -> bool {
        self.0 & 0x01 != 0
    }
}

/// Security-control field wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scf(pub u8);

impl Scf {
    /// Build an SCF from structured flags.
    pub const fn new(encrypted: bool, mic_size: MicSize, salt_present: bool) -> Self {
        Self(((encrypted as u8) << 7) | ((mic_size as u8) << 5) | ((salt_present as u8) << 4))
    }

    /// Return whether the body is encrypted in place.
    pub const fn encrypted(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Decode the configured MIC size.
    pub fn mic_size(self) -> Result<MicSize, ParseError> {
        MicSize::from_bits((self.0 >> 5) & 0x03)
    }

    /// Return whether a salt field follows the frame counter.
    pub const fn salt_present(self) -> bool {
        self.0 & 0x10 != 0
    }

    /// Return whether the reserved low nibble is valid for the current spec.
    pub const fn reserved_valid(self) -> bool {
        self.0 & 0x0F == 0
    }
}

/// Authenticator size carried by secured packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicSize {
    Mic4 = 0,
    Mic8 = 1,
    Mic12 = 2,
    Mic16 = 3,
}

impl MicSize {
    /// Return the on-wire byte length of this MIC size.
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Mic4 => 4,
            Self::Mic8 => 8,
            Self::Mic12 => 12,
            Self::Mic16 => 16,
        }
    }

    /// Decode a MIC size from its two SCF bits.
    pub fn from_bits(value: u8) -> Result<Self, ParseError> {
        match value {
            0 => Ok(Self::Mic4),
            1 => Ok(Self::Mic8),
            2 => Ok(Self::Mic12),
            3 => Ok(Self::Mic16),
            other => Err(ParseError::InvalidMicSize(other)),
        }
    }
}

/// Combined remaining/accumulated flood-hop counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloodHops(pub u8);

impl FloodHops {
    /// Construct a flood-hop value if both nibbles fit in four bits.
    pub fn new(remaining: u8, accumulated: u8) -> Option<Self> {
        if remaining <= 0x0F && accumulated <= 0x0F {
            Some(Self((remaining << 4) | accumulated))
        } else {
            None
        }
    }

    /// Remaining forward-hop budget.
    pub const fn remaining(self) -> u8 {
        self.0 >> 4
    }

    /// Number of hops already consumed.
    pub const fn accumulated(self) -> u8 {
        self.0 & 0x0F
    }

    /// Return the next forwarded hop count.
    pub fn decremented(self) -> Self {
        let remaining = self.remaining();
        if remaining == 0 {
            self
        } else {
            Self::new(remaining - 1, self.accumulated().saturating_add(1)).unwrap_or(self)
        }
    }
}

/// Three-byte node hint derived from a public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeHint(pub [u8; 3]);

impl NodeHint {
    /// Derive the hint from the first three public-key bytes.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self([key.0[0], key.0[1], key.0[2]])
    }
}

/// Two-byte router hint used in learned routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouterHint(pub [u8; 2]);

impl RouterHint {
    /// Derive the router hint from the first two public-key bytes.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self([key.0[0], key.0[1]])
    }
}

/// Two-byte multicast channel identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(pub [u8; 2]);

/// Node public key, which also acts as the full network address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Return the node hint associated with this key.
    pub fn hint(&self) -> NodeHint {
        NodeHint::from_public_key(self)
    }

    /// Return the router hint associated with this key.
    pub fn router_hint(&self) -> RouterHint {
        RouterHint::from_public_key(self)
    }
}

/// Raw 32-byte multicast channel secret.
#[derive(Clone, Copy, zeroize::Zeroize)]
pub struct ChannelKey(pub [u8; 32]);

impl PartialEq for ChannelKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ChannelKey {}

impl core::fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChannelKey([redacted])")
    }
}

/// Source address supplied while constructing packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAddr<'a> {
    Hint(NodeHint),
    Full(&'a PublicKey),
}

impl SourceAddr<'_> {
    /// Return the hint form of this address.
    pub fn hint(&self) -> NodeHint {
        match self {
            Self::Hint(hint) => *hint,
            Self::Full(key) => key.hint(),
        }
    }
}

/// Decoded SECINFO structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecInfo {
    pub scf: Scf,
    pub frame_counter: u32,
    pub salt: Option<u16>,
}

impl SecInfo {
    /// Return the SECINFO on-wire length.
    pub fn wire_len(&self) -> usize {
        if self.salt.is_some() { 7 } else { 5 }
    }

    /// Encode SECINFO into `buf` and return the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let needed = self.wire_len();
        if buf.len() < needed {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[0] = self.scf.0;
        buf[1..5].copy_from_slice(&self.frame_counter.to_be_bytes());
        if let Some(salt) = self.salt {
            buf[5..7].copy_from_slice(&salt.to_be_bytes());
        }
        Ok(needed)
    }

    /// Decode SECINFO from the start of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 5 {
            return Err(ParseError::Truncated);
        }
        let scf = Scf(buf[0]);
        if !scf.reserved_valid() {
            return Err(ParseError::InvalidScfReserved);
        }
        let salt = if scf.salt_present() {
            if buf.len() < 7 {
                return Err(ParseError::Truncated);
            }
            Some(u16::from_be_bytes([buf[5], buf[6]]))
        } else {
            None
        };
        Ok(Self {
            scf,
            frame_counter: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            salt,
        })
    }
}

/// Known packet-option numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionNumber {
    RegionCode,
    TraceRoute,
    SourceRoute,
    OperatorCallsign,
    MinRssi,
    RouteRetry,
    StationCallsign,
    MinSnr,
    Unknown(u16),
}

impl OptionNumber {
    /// Return the numeric option number used on the wire.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::RegionCode => 11,
            Self::TraceRoute => 2,
            Self::SourceRoute => 3,
            Self::OperatorCallsign => 4,
            Self::MinRssi => 5,
            Self::RouteRetry => 6,
            Self::StationCallsign => 7,
            Self::MinSnr => 9,
            Self::Unknown(value) => value,
        }
    }

    /// Return whether the option is critical when unknown.
    pub fn is_critical(self) -> bool {
        self.as_u16() & 1 != 0
    }

    /// Return whether the option is considered dynamic for AAD purposes.
    pub fn is_dynamic(self) -> bool {
        self.as_u16() & 2 != 0
    }
}

impl From<u16> for OptionNumber {
    fn from(value: u16) -> Self {
        match value {
            2 => Self::TraceRoute,
            3 => Self::SourceRoute,
            4 => Self::OperatorCallsign,
            5 => Self::MinRssi,
            6 => Self::RouteRetry,
            7 => Self::StationCallsign,
            9 => Self::MinSnr,
            11 => Self::RegionCode,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed source-address location used by zero-copy packet processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAddrRef {
    Hint(NodeHint),
    FullKeyAt { offset: usize },
    Encrypted { offset: usize, len: usize },
    None,
}

/// Parsed packet header with borrowed ranges into the original frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub fcf: Fcf,
    pub options_range: Range<usize>,
    pub flood_hops: Option<FloodHops>,
    pub dst: Option<NodeHint>,
    pub channel: Option<ChannelId>,
    pub ack_dst: Option<NodeHint>,
    pub source: SourceAddrRef,
    pub sec_info: Option<SecInfo>,
    pub body_range: Range<usize>,
    pub mic_range: Range<usize>,
    pub total_len: usize,
}

impl PacketHeader {
    /// Parse a complete on-wire packet header and compute payload/MIC ranges.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.is_empty() {
            return Err(ParseError::Truncated);
        }

        let fcf = Fcf(buf[0]);
        if fcf.version() != UMSH_VERSION {
            return Err(ParseError::InvalidVersion(fcf.version()));
        }
        if !fcf.reserved_valid() {
            return Err(ParseError::InvalidFcfReserved);
        }

        let mut cursor = 1;
        let flood_hops = if fcf.flood_hops_present() {
            if cursor >= buf.len() {
                return Err(ParseError::Truncated);
            }
            let fh = FloodHops(buf[cursor]);
            cursor += 1;
            Some(fh)
        } else {
            None
        };

        let packet_type = fcf.packet_type();
        let mut dst = None;
        let mut channel = None;
        let mut ack_dst = None;
        let mut source = SourceAddrRef::None;
        let mut sec_info = None;

        match packet_type {
            PacketType::Broadcast => {
                let src_len = source_len(fcf.full_source());
                source = if fcf.full_source() {
                    ensure_len(buf, cursor, 32)?;
                    SourceAddrRef::FullKeyAt { offset: cursor }
                } else {
                    ensure_len(buf, cursor, 3)?;
                    SourceAddrRef::Hint(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]))
                };
                cursor += src_len;
                let options_start = cursor;
                let options_end = buf.len();
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..options_end])?;
                let options_range = options_start..options_start + consumed;
                let body_start = options_start + consumed;
                let body_end = if has_marker { buf.len() } else { body_start };
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    ack_dst,
                    source,
                    sec_info,
                    body_range: body_start..body_end,
                    mic_range: buf.len()..buf.len(),
                    total_len: buf.len(),
                })
            }
            PacketType::MacAck => {
                ensure_len(buf, cursor, 3)?;
                ack_dst = Some(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]));
                cursor += 3;
                let options_start = cursor;
                let options_end = buf
                    .len()
                    .checked_sub(8)
                    .ok_or(ParseError::Truncated)?;
                if options_end < options_start {
                    return Err(ParseError::Truncated);
                }
                // MAC ACK has no payload — the options region is bounded by
                // the fixed 8-byte ACK_TAG trailer. The scan must consume
                // the entire region: either the marker is absent (and the
                // scan exhausts the region), or the marker is the last byte
                // (and `consumed` includes it). Any other case means there
                // are bytes between an end-of-options marker and ACK_TAG,
                // which the wire format does not assign meaning to.
                let region = &buf[options_start..options_end];
                let (consumed, _has_marker) = scan_options_bounded(region)?;
                if consumed != region.len() {
                    return Err(ParseError::MalformedOption);
                }
                let options_range = options_start..options_start + consumed;
                let ack_tag_start = options_end;
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    ack_dst,
                    source,
                    sec_info,
                    body_range: ack_tag_start..ack_tag_start + 8,
                    mic_range: ack_tag_start..ack_tag_start + 8,
                    total_len: ack_tag_start + 8,
                })
            }
            PacketType::Unicast | PacketType::UnicastAckReq => {
                ensure_len(buf, cursor, 3)?;
                dst = Some(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]));
                cursor += 3;
                let src_len = source_len(fcf.full_source());
                source = if fcf.full_source() {
                    ensure_len(buf, cursor, 32)?;
                    SourceAddrRef::FullKeyAt { offset: cursor }
                } else {
                    ensure_len(buf, cursor, 3)?;
                    SourceAddrRef::Hint(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]))
                };
                cursor += src_len;
                let parsed_sec = SecInfo::decode(&buf[cursor..])?;
                let sec_len = parsed_sec.wire_len();
                sec_info = Some(parsed_sec);
                cursor += sec_len;
                let mic_len = parsed_sec.scf.mic_size()?.byte_len();
                let mic_start = buf
                    .len()
                    .checked_sub(mic_len)
                    .ok_or(ParseError::Truncated)?;
                if mic_start < cursor {
                    return Err(ParseError::Truncated);
                }
                let options_start = cursor;
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..mic_start])?;
                let options_range = options_start..options_start + consumed;
                let body_start = options_start + consumed;
                let body_end = if has_marker { mic_start } else { body_start };
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    ack_dst,
                    source,
                    sec_info,
                    body_range: body_start..body_end,
                    mic_range: mic_start..buf.len(),
                    total_len: buf.len(),
                })
            }
            PacketType::Multicast => {
                ensure_len(buf, cursor, 2)?;
                channel = Some(ChannelId([buf[cursor], buf[cursor + 1]]));
                cursor += 2;
                let parsed_sec = SecInfo::decode(&buf[cursor..])?;
                let sec_len = parsed_sec.wire_len();
                sec_info = Some(parsed_sec);
                cursor += sec_len;
                let mic_len = parsed_sec.scf.mic_size()?.byte_len();
                let mic_start = buf
                    .len()
                    .checked_sub(mic_len)
                    .ok_or(ParseError::Truncated)?;
                if mic_start < cursor {
                    return Err(ParseError::Truncated);
                }
                let options_start = cursor;
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..mic_start])?;
                let options_range = options_start..options_start + consumed;
                cursor = options_start + consumed;
                if parsed_sec.scf.encrypted() {
                    let src_len = source_len(fcf.full_source());
                    source = SourceAddrRef::Encrypted {
                        offset: cursor,
                        len: src_len,
                    };
                    Ok(Self {
                        fcf,
                        options_range,
                        flood_hops,
                        dst,
                        channel,
                        ack_dst,
                        source,
                        sec_info,
                        body_range: cursor..mic_start,
                        mic_range: mic_start..buf.len(),
                        total_len: buf.len(),
                    })
                } else {
                    let src_len = source_len(fcf.full_source());
                    source = if fcf.full_source() {
                        ensure_len(buf, cursor, 32)?;
                        SourceAddrRef::FullKeyAt { offset: cursor }
                    } else {
                        ensure_len(buf, cursor, 3)?;
                        SourceAddrRef::Hint(NodeHint([
                            buf[cursor],
                            buf[cursor + 1],
                            buf[cursor + 2],
                        ]))
                    };
                    cursor += src_len;
                    let body_start = cursor;
                    let body_end = if has_marker { mic_start } else { body_start };
                    Ok(Self {
                        fcf,
                        options_range,
                        flood_hops,
                        dst,
                        channel,
                        ack_dst,
                        source,
                        sec_info,
                        body_range: body_start..body_end,
                        mic_range: mic_start..buf.len(),
                        total_len: buf.len(),
                    })
                }
            }
            PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
                ensure_len(buf, cursor, 2)?;
                channel = Some(ChannelId([buf[cursor], buf[cursor + 1]]));
                cursor += 2;
                let parsed_sec = SecInfo::decode(&buf[cursor..])?;
                let sec_len = parsed_sec.wire_len();
                sec_info = Some(parsed_sec);
                cursor += sec_len;
                let mic_len = parsed_sec.scf.mic_size()?.byte_len();
                let mic_start = buf
                    .len()
                    .checked_sub(mic_len)
                    .ok_or(ParseError::Truncated)?;
                if mic_start < cursor {
                    return Err(ParseError::Truncated);
                }
                let options_start = cursor;
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..mic_start])?;
                let options_range = options_start..options_start + consumed;
                cursor = options_start + consumed;
                let src_len = source_len(fcf.full_source());
                ensure_len(buf, cursor, 3 + src_len)?;
                if parsed_sec.scf.encrypted() {
                    source = SourceAddrRef::Encrypted {
                        offset: cursor + 3,
                        len: src_len,
                    };
                    cursor += 3 + src_len;
                } else {
                    dst = Some(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]));
                    cursor += 3;
                    source = if fcf.full_source() {
                        ensure_len(buf, cursor, 32)?;
                        SourceAddrRef::FullKeyAt { offset: cursor }
                    } else {
                        ensure_len(buf, cursor, 3)?;
                        SourceAddrRef::Hint(NodeHint([
                            buf[cursor],
                            buf[cursor + 1],
                            buf[cursor + 2],
                        ]))
                    };
                    cursor += src_len;
                }
                let body_start = cursor;
                let body_end = if has_marker { mic_start } else { body_start };
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    ack_dst,
                    source,
                    sec_info,
                    body_range: body_start..body_end,
                    mic_range: mic_start..buf.len(),
                    total_len: buf.len(),
                })
            }
            PacketType::Reserved5 => Err(ParseError::MalformedOption),
        }
    }

    /// Convenience accessor for the decoded packet type.
    pub fn packet_type(&self) -> PacketType {
        self.fcf.packet_type()
    }

    /// Return whether the packet requests a MAC ACK.
    pub fn ack_requested(&self) -> bool {
        self.packet_type().ack_requested()
    }

    /// Return whether the parsed packet is a beacon broadcast with empty body.
    pub fn is_beacon(&self) -> bool {
        self.packet_type() == PacketType::Broadcast && self.body_range.is_empty()
    }
}

/// Default Minimum RSSI threshold (dBm) when the option is present with a
/// zero-length value. Per the spec this value is subject to change.
pub const DEFAULT_MIN_RSSI_DBM: i16 = -100;

/// Default Minimum SNR threshold (dB) when the option is present with a
/// zero-length value. Per the spec this value is subject to change.
pub const DEFAULT_MIN_SNR_DB: i8 = -3;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedOptions {
    pub region_code: Option<[u8; 2]>,
    pub source_route: Option<Range<usize>>,
    pub trace_route: Option<Range<usize>>,
    pub min_rssi: Option<i16>,
    pub min_snr: Option<i8>,
    pub route_retry: bool,
    pub has_unknown_critical: bool,
}

impl ParsedOptions {
    pub fn extract(buf: &[u8], range: Range<usize>) -> Result<Self, ParseError> {
        let mut parsed = Self::default();
        if range.is_empty() {
            return Ok(parsed);
        }
        let options = &buf[range.clone()];
        for entry in OptionDecoder::new(options) {
            let (number, value) = entry?;
            let relative_start = unsafe { value.as_ptr().offset_from(options.as_ptr()) } as usize;
            let value_start = range.start + relative_start;
            let value_range = value_start..value_start + value.len();
            match OptionNumber::from(number) {
                OptionNumber::RegionCode if value.len() == 2 => {
                    parsed.region_code = Some([value[0], value[1]]);
                }
                OptionNumber::TraceRoute => parsed.trace_route = Some(value_range),
                OptionNumber::SourceRoute => parsed.source_route = Some(value_range),
                OptionNumber::RouteRetry if value.is_empty() => parsed.route_retry = true,
                // Minimum RSSI (option 5): unsigned 1-byte value read as a
                // negative dBm threshold (e.g. 130 → -130 dBm). A zero-length
                // value selects the default threshold. Longer values are
                // malformed and ignored.
                OptionNumber::MinRssi if value.len() <= 1 => {
                    parsed.min_rssi = Some(match value.first() {
                        Some(&byte) => -i16::from(byte),
                        None => DEFAULT_MIN_RSSI_DBM,
                    });
                }
                // Minimum SNR (option 9): signed 1-byte value in dB. A
                // zero-length value selects the default threshold.
                OptionNumber::MinSnr if value.len() <= 1 => {
                    parsed.min_snr = Some(match value.first() {
                        Some(&byte) => byte as i8,
                        None => DEFAULT_MIN_SNR_DB,
                    });
                }
                OptionNumber::Unknown(raw) if raw & 1 != 0 => parsed.has_unknown_critical = true,
                _ => {}
            }
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod parsed_options_tests {
    use super::*;

    #[test]
    fn min_rssi_one_byte_is_negated_dbm() {
        // Option 5, length 1, value 130 → -130 dBm.
        let buf = [0x51u8, 130];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_rssi, Some(-130));
    }

    #[test]
    fn min_rssi_zero_len_selects_default() {
        // Option 5, length 0.
        let buf = [0x50u8];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_rssi, Some(DEFAULT_MIN_RSSI_DBM));
    }

    #[test]
    fn min_snr_one_byte_is_signed_db() {
        // Option 9, length 1, value 0xFD (-3).
        let buf = [0x91u8, 0xFD];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_snr, Some(-3));
    }

    #[test]
    fn min_snr_zero_len_selects_default() {
        // Option 9, length 0.
        let buf = [0x90u8];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_snr, Some(DEFAULT_MIN_SNR_DB));
    }

    #[test]
    fn min_rssi_two_bytes_is_ignored() {
        // Length 2 is malformed for Min RSSI; the option is ignored.
        let buf = [0x52u8, 0x00, 0x82];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_rssi, None);
    }
}

pub fn iter_options<'a>(buf: &'a [u8], range: Range<usize>) -> OptionDecoder<'a> {
    OptionDecoder::new(&buf[range])
}

pub fn feed_aad(header: &PacketHeader, packet_buf: &[u8], mut sink: impl FnMut(&[u8])) {
    sink(&packet_buf[..1]);
    for option in iter_options(packet_buf, header.options_range.clone()) {
        let Ok((number, value)) = option else {
            return;
        };
        let option_number = OptionNumber::from(number);
        if option_number.is_dynamic() {
            continue;
        }
        let mut tl = [0u8; 4];
        tl[..2].copy_from_slice(&number.to_be_bytes());
        tl[2..].copy_from_slice(&(value.len() as u16).to_be_bytes());
        sink(&tl);
        sink(value);
    }

    if let Some(dst) = header.dst {
        sink(&dst.0);
    }
    if let Some(channel) = header.channel {
        sink(&channel.0);
    }
    match header.source {
        SourceAddrRef::Hint(hint) => sink(&hint.0),
        SourceAddrRef::FullKeyAt { offset } => sink(&packet_buf[offset..offset + 32]),
        SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => {}
    }
    if let Some(sec_info) = header.sec_info {
        let mut buf = [0u8; 7];
        let Ok(len) = sec_info.encode(&mut buf) else {
            return;
        };
        sink(&buf[..len]);
    }
}

fn ensure_len(buf: &[u8], offset: usize, len: usize) -> Result<(), ParseError> {
    if buf.len() < offset + len {
        Err(ParseError::Truncated)
    } else {
        Ok(())
    }
}

/// Scan an options region that may end with an explicit `0xFF` marker or with
/// the end of the bounded slice.
///
/// Returns the number of bytes consumed (including the terminator byte when
/// present) and a flag indicating whether the terminator was observed. When
/// the terminator is absent, the caller can infer that no payload follows.
fn scan_options_bounded(data: &[u8]) -> Result<(usize, bool), ParseError> {
    let mut pos = 0;
    let mut last_number: u16 = 0;
    while pos < data.len() {
        let first = data[pos];
        if first == 0xFF {
            return Ok((pos + 1, true));
        }
        pos += 1;
        let delta_nibble = first >> 4;
        let len_nibble = first & 0x0F;
        let (delta, delta_len) = read_extended(&data[pos..], delta_nibble)?;
        pos += delta_len;
        let (len, len_len) = read_extended(&data[pos..], len_nibble)?;
        pos += len_len;
        if pos + len as usize > data.len() {
            return Err(ParseError::Truncated);
        }
        let number = last_number
            .checked_add(delta)
            .ok_or(ParseError::MalformedOption)?;
        pos += len as usize;
        last_number = number;
    }
    Ok((pos, false))
}

fn read_extended(data: &[u8], nibble: u8) -> Result<(u16, usize), ParseError> {
    match nibble {
        0..=12 => Ok((nibble as u16, 0)),
        13 => {
            if data.is_empty() {
                return Err(ParseError::Truncated);
            }
            Ok((data[0] as u16 + 13, 1))
        }
        14 => {
            if data.len() < 2 {
                return Err(ParseError::Truncated);
            }
            Ok((u16::from_be_bytes([data[0], data[1]]) + 269, 2))
        }
        _ => Err(ParseError::InvalidOptionNibble),
    }
}

pub(crate) fn source_len(full_source: bool) -> usize {
    if full_source { 32 } else { 3 }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnsealedPacket<'a> {
    buf: &'a mut [u8],
    total_len: usize,
    body_range: Range<usize>,
    blind_addr_range: Option<Range<usize>>,
    mic_range: Range<usize>,
    sec_info_range: Range<usize>,
    aad_static_options: Range<usize>,
}

impl<'a> UnsealedPacket<'a> {
    pub fn new(
        buf: &'a mut [u8],
        total_len: usize,
        body_range: Range<usize>,
        blind_addr_range: Option<Range<usize>>,
        mic_range: Range<usize>,
        sec_info_range: Range<usize>,
        aad_static_options: Range<usize>,
    ) -> Self {
        Self {
            buf,
            total_len,
            body_range,
            blind_addr_range,
            mic_range,
            sec_info_range,
            aad_static_options,
        }
    }

    pub fn header(&self) -> Result<PacketHeader, ParseError> {
        PacketHeader::parse(self.as_bytes())
    }

    pub fn body(&self) -> &[u8] {
        &self.buf[self.body_range.clone()]
    }

    pub fn body_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.body_range.clone()]
    }

    pub fn blind_addr_range(&self) -> Option<Range<usize>> {
        self.blind_addr_range.clone()
    }

    pub fn blind_addr(&self) -> Option<&[u8]> {
        let range = self.blind_addr_range.clone()?;
        Some(&self.buf[range])
    }

    pub fn mic_slot(&mut self) -> &mut [u8] {
        &mut self.buf[self.mic_range.clone()]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.total_len]
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.total_len]
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn sec_info_range(&self) -> Range<usize> {
        self.sec_info_range.clone()
    }

    pub fn aad_static_options(&self) -> Range<usize> {
        self.aad_static_options.clone()
    }
}
