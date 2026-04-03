use core::ops::Range;

use crate::{options::OptionDecoder, EncodeError, ParseError};

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
}

/// Frame-control field wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fcf(pub u8);

impl Fcf {
    /// Build an FCF from structured flags.
    pub const fn new(
        packet_type: PacketType,
        full_source: bool,
        options_present: bool,
        flood_hops_present: bool,
    ) -> Self {
        Self(
            (UMSH_VERSION << 6)
                | ((packet_type as u8) << 3)
                | ((full_source as u8) << 2)
                | ((options_present as u8) << 1)
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

    /// Return whether an option block is present.
    pub const fn options_present(self) -> bool {
        self.0 & 0x02 != 0
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
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ChannelKey(pub [u8; 32]);

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
        if self.salt.is_some() {
            7
        } else {
            5
        }
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
    StationCallsign,
    MinSnr,
    Unknown(u16),
}

impl OptionNumber {
    /// Return the numeric option number used on the wire.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::RegionCode => 1,
            Self::TraceRoute => 2,
            Self::SourceRoute => 3,
            Self::OperatorCallsign => 4,
            Self::MinRssi => 5,
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
            1 => Self::RegionCode,
            2 => Self::TraceRoute,
            3 => Self::SourceRoute,
            4 => Self::OperatorCallsign,
            5 => Self::MinRssi,
            7 => Self::StationCallsign,
            9 => Self::MinSnr,
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

        let mut cursor = 1;
        let options_range = if fcf.options_present() {
            let len = scan_options_field(&buf[cursor..])?;
            let range = cursor..cursor + len;
            cursor += len;
            range
        } else {
            cursor..cursor
        };

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
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    ack_dst,
                    source,
                    sec_info,
                    body_range: cursor..buf.len(),
                    mic_range: buf.len()..buf.len(),
                    total_len: buf.len(),
                })
            }
            PacketType::MacAck => {
                ensure_len(buf, cursor, 3)?;
                ack_dst = Some(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]));
                cursor += 3;
                ensure_len(buf, cursor, 8)?;
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    ack_dst,
                    source,
                    sec_info,
                    body_range: cursor..cursor + 8,
                    mic_range: cursor..cursor + 8,
                    total_len: cursor + 8,
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
                ensure_len(buf, cursor, mic_len)?;
                let mic_start = buf
                    .len()
                    .checked_sub(mic_len)
                    .ok_or(ParseError::Truncated)?;
                if mic_start < cursor {
                    return Err(ParseError::Truncated);
                }
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
                let mic_len = parsed_sec.scf.mic_size()?.byte_len();
                let mic_start = buf
                    .len()
                    .checked_sub(mic_len)
                    .ok_or(ParseError::Truncated)?;
                if mic_start < cursor {
                    return Err(ParseError::Truncated);
                }
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedOptions {
    pub region_code: Option<[u8; 2]>,
    pub source_route: Option<Range<usize>>,
    pub trace_route: Option<Range<usize>>,
    pub min_rssi: Option<i16>,
    pub min_snr: Option<i8>,
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
                OptionNumber::MinRssi if value.len() == 2 => {
                    parsed.min_rssi = Some(i16::from_be_bytes([value[0], value[1]]));
                }
                OptionNumber::MinSnr if value.len() == 1 => parsed.min_snr = Some(value[0] as i8),
                OptionNumber::Unknown(raw) if raw & 1 != 0 => parsed.has_unknown_critical = true,
                _ => {}
            }
        }
        Ok(parsed)
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

fn scan_options_field(data: &[u8]) -> Result<usize, ParseError> {
    let mut decoder = OptionDecoder::new(data);
    while let Some(result) = decoder.next() {
        result?;
    }

    Ok(data.len() - decoder.remainder().len())
}

pub(crate) fn source_len(full_source: bool) -> usize {
    if full_source {
        32
    } else {
        3
    }
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
