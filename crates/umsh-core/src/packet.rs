use core::ops::Range;

use crate::{
    EncodeError, ParseError, SignatureInputError,
    options::{OptionDecoder, TraceRef},
};

/// Current UMSH packet version encoded in the FCF high bits.
pub const UMSH_VERSION: u8 = 0b11;

/// The largest frame any UMSH link carries.
pub const MAX_FRAME_LEN: usize = 255;

/// Length of an Ed25519 frame signature.
pub const SIGNATURE_LEN: usize = 64;

/// Prefix of every frame signature's input. It is never transmitted.
pub const SIGNATURE_LABEL: &[u8] = b"UMSH-SIG";

/// Length of a Frame Signature option's value: `COUNTER (4) ‖ SIG (64)`.
pub const FRAME_SIGNATURE_OPTION_LEN: usize = 4 + SIGNATURE_LEN;

/// The largest signature input any frame the parser accepts can produce.
///
/// The canonical TLV form turns an option record of `h + L` wire bytes
/// (`h ≥ 1`) into `4 + L ≤ 4(h + L)` bytes, and every other field enters at
/// most at its own length. The 2 is the AAD terminator and the 32 the channel
/// commitment.
pub const SIGNATURE_INPUT_MAX: usize = SIGNATURE_LABEL.len() + 2 + 32 + 4 * MAX_FRAME_LEN;

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
    /// Node-management request payload, administrator to device.
    NodeManagementRequest = 8,
    /// Node-management response payload, device to administrator.
    NodeManagementResponse = 9,
    /// Contact-exchange payload between two session identities.
    Meet = 10,
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
            8 => Some(Self::NodeManagementRequest),
            9 => Some(Self::NodeManagementResponse),
            10 => Some(Self::Meet),
            _ => None,
        }
    }

    /// Return whether this payload type is valid for the given MAC packet type.
    pub fn allowed_for(self, packet_type: PacketType) -> bool {
        match self {
            Self::Empty | Self::Unspecified | Self::NodeIdentity => {
                !matches!(packet_type, PacketType::MacAck)
            }
            // Broadcast admission is per-command: this gate only says a MAC
            // command may ride a broadcast at all; receivers act only on the
            // commands whose definitions permit broadcast carriage (currently
            // the Identity Request, with its own flood-management rules).
            Self::MacCommand => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
                    | PacketType::Multicast
                    | PacketType::Broadcast
            ),
            Self::TextMessage | Self::CoapOverUmsh => matches!(
                packet_type,
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
                    | PacketType::Multicast
            ),
            // Only a Hello rides a broadcast; every other Meet message is
            // unicast between the two session identities.
            Self::Meet => matches!(
                packet_type,
                PacketType::Unicast | PacketType::UnicastAckReq | PacketType::Broadcast
            ),
            Self::NodeManagementRequest | Self::NodeManagementResponse | Self::ChatRoomMessage => {
                matches!(
                    packet_type,
                    PacketType::Unicast
                        | PacketType::UnicastAckReq
                        | PacketType::BlindUnicast
                        | PacketType::BlindUnicastAckReq
                )
            }
        }
    }
}

/// Frame-control field wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fcf(pub u8);

impl Fcf {
    /// Build an FCF from structured flags.
    pub const fn new(packet_type: PacketType, full_source: bool, flood_hops_present: bool) -> Self {
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

    /// Return the FCF as it enters the AAD, with the flood-hops-present bit
    /// cleared.
    ///
    /// `FHOPS` is a forwarding budget, excluded from the AAD because repeaters
    /// rewrite it. Whether the byte is present at all is the same budget
    /// expressed one bit up, and a sender that abandons a source route for a
    /// flood adds it to a packet already sealed. Clearing the bit is not a
    /// hole: flipping it on the wire shifts every field the parser reads after
    /// it, so `DST`/`SRC`/`SECINFO` reach the AAD as different values and the
    /// MIC still fails.
    pub const fn aad_byte(self) -> u8 {
        self.0 & !0x01
    }
}

/// Security-control field wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scf(pub u8);

impl Scf {
    /// The `D` bit: the frame carries a signature between payload and MIC.
    pub const SIGNED: u8 = 0x08;

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

    /// Return whether a 64-byte Ed25519 signature precedes the MIC (`D`).
    pub const fn signed(self) -> bool {
        self.0 & Self::SIGNED != 0
    }

    /// The same SCF with `D` set or cleared.
    pub const fn with_signed(self, signed: bool) -> Self {
        if signed {
            Self(self.0 | Self::SIGNED)
        } else {
            Self(self.0 & !Self::SIGNED)
        }
    }

    /// Return whether the reserved low bits are valid for the current spec.
    pub const fn reserved_valid(self) -> bool {
        self.0 & 0x07 == 0
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

impl core::fmt::Display for NodeHint {
    /// Renders up to four base58 characters of the matching address space,
    /// star-truncated where the hint no longer pins down the encoding.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::base58::fmt_hint(f, &self.0, 4)
    }
}

/// Two-byte router hint used in learned routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouterHint(pub [u8; 2]);

impl RouterHint {
    /// The fewest base58 characters that can determine a router hint.
    ///
    /// Three digits carry about 15.8 bits, so they never settle sixteen; four
    /// carry about 21.7, which leaves at most two adjacent hints.
    pub const MIN_BASE58_PREFIX: usize = 4;

    /// Derive the router hint from the first two public-key bytes.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self([key.0[0], key.0[1]])
    }

    /// Every router hint carried by an address that begins with `prefix`.
    ///
    /// The prefix must be at least [`Self::MIN_BASE58_PREFIX`] characters. A
    /// prefix whose completions straddle a hint boundary yields both hints;
    /// a complete address yields its own.
    pub fn candidates_from_base58_prefix(
        prefix: &str,
    ) -> Result<RouterHintCandidates, crate::HintInputError> {
        use crate::{AddressParseError, HintInputError};
        if prefix.len() < Self::MIN_BASE58_PREFIX {
            return Err(HintInputError::TooShort);
        }
        let (low, high) =
            crate::base58::prefix_bounds(prefix.as_bytes()).map_err(|error| match error {
                AddressParseError::InvalidLength => HintInputError::TooLong,
                AddressParseError::InvalidCharacter => HintInputError::InvalidCharacter,
                AddressParseError::Overflow => HintInputError::OutOfRange,
            })?;
        let first = Self([low[0], low[1]]);
        let last = Self([high[0], high[1]]);
        // Four digits span less than one hint bucket, so the two ends are the
        // same hint or neighbors.
        Ok(RouterHintCandidates {
            first,
            second: (last != first).then_some(last),
        })
    }

    /// The hint written as exactly four hexadecimal digits.
    pub fn from_hex(text: &str) -> Result<Self, crate::HintInputError> {
        use crate::HintInputError;
        let digits = text.as_bytes();
        if digits.len() < 4 {
            return Err(HintInputError::TooShort);
        }
        if digits.len() > 4 {
            return Err(HintInputError::TooLong);
        }
        let mut value = 0u16;
        for &digit in digits {
            let nibble = (digit as char)
                .to_digit(16)
                .ok_or(HintInputError::InvalidCharacter)?;
            value = (value << 4) | nibble as u16;
        }
        Ok(Self(value.to_be_bytes()))
    }
}

/// The one or two router hints a typed base58 prefix can mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouterHintCandidates {
    /// The hint of the lowest address beginning with the prefix.
    pub first: RouterHint,
    /// The hint of the highest one, when it differs.
    pub second: Option<RouterHint>,
}

impl RouterHintCandidates {
    /// The candidates in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = RouterHint> + '_ {
        core::iter::once(self.first).chain(self.second)
    }
}

impl core::fmt::Display for RouterHint {
    /// Renders up to three base58 characters of the matching address space,
    /// star-truncated where the hint no longer pins down the encoding.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::base58::fmt_hint(f, &self.0, 3)
    }
}

/// Two-byte multicast channel identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(pub [u8; 2]);

/// Sixteen-byte channel tag: a local identity for a channel, wide enough to
/// distinguish channels that a [`ChannelId`] cannot.
///
/// The two-byte identifier is a hint, and collisions between distinct channel
/// keys are legal—a frame belongs to whichever channel key authenticates it,
/// not to whichever key derives the same identifier. Bookkeeping that has no
/// key at hand to authenticate against therefore needs a wider name; this is
/// that name. Nothing on the wire carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelTag(pub [u8; 16]);

impl ChannelTag {
    /// The channel identifier this tag begins with.
    ///
    /// Both come from the same derivation, so the identifier is the tag's own
    /// first two bytes rather than a separate computation.
    pub fn channel_id(&self) -> ChannelId {
        ChannelId([self.0[0], self.0[1]])
    }
}

/// Thirty-two-byte channel commitment: the first 32 bytes of the same
/// derivation [`ChannelTag`] and [`ChannelId`] begin.
///
/// A signature over a channel frame covers it, so the signature holds only on
/// the channel whose key it was made under, never on another key that shares
/// the two-byte identifier. Nothing on the wire carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelCommitment(pub [u8; 32]);

impl ChannelCommitment {
    /// The channel tag this commitment begins with.
    pub fn channel_tag(&self) -> ChannelTag {
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&self.0[..16]);
        ChannelTag(tag)
    }
}

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

impl core::fmt::Display for PublicKey {
    /// Renders the canonical fixed-width base58 address (always 44 digits).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let encoded = crate::base58::encode(&self.0);
        f.write_str(core::str::from_utf8(&encoded).map_err(|_| core::fmt::Error)?)
    }
}

impl core::fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::UpperHex for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for PublicKey {
    type Err = crate::AddressParseError;

    /// Parses either address form: 44 base58 characters or 64 base16
    /// characters (either case), distinguished by length.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn hex_value(digit: u8) -> Result<u8, crate::AddressParseError> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'a'..=b'f' => Ok(digit - b'a' + 10),
                b'A'..=b'F' => Ok(digit - b'A' + 10),
                _ => Err(crate::AddressParseError::InvalidCharacter),
            }
        }

        let bytes = s.as_bytes();
        match bytes.len() {
            crate::base58::ENCODED_LEN => crate::base58::decode(bytes).map(Self),
            64 => {
                let mut key = [0u8; 32];
                for (slot, pair) in key.iter_mut().zip(bytes.chunks_exact(2)) {
                    *slot = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
                }
                Ok(Self(key))
            }
            _ => Err(crate::AddressParseError::InvalidLength),
        }
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
    FrameSignature,
    RegionCode,
    SourceRoute,
    OperatorCallsign,
    MinRssi,
    RouteRetry,
    Trace,
    AckMic,
    MinSnr,
    StationCallsign,
    Unknown(u16),
}

impl OptionNumber {
    /// Return the numeric option number used on the wire.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::FrameSignature => 0,
            Self::RegionCode => 11,
            Self::SourceRoute => 3,
            Self::OperatorCallsign => 4,
            Self::MinRssi => 5,
            Self::RouteRetry => 6,
            Self::Trace => 7,
            Self::AckMic => 8,
            Self::MinSnr => 9,
            Self::StationCallsign => 15,
            Self::Unknown(value) => value,
        }
    }

    /// Return whether a repeater that does not recognize the option, or
    /// cannot interpret its value, must not forward the frame (bit 0).
    pub fn is_forwarding_critical(self) -> bool {
        self.as_u16() & 1 != 0
    }

    /// Return whether an endpoint that does not recognize the option, or
    /// cannot interpret its value, must not accept, deliver, or acknowledge
    /// the frame: bits 2 and 3 set on a static option. A dynamic option is
    /// never delivery-critical.
    pub fn is_delivery_critical(self) -> bool {
        self.as_u16() & 0xE == 0xC
    }

    /// Return whether the option is considered dynamic for AAD purposes.
    pub fn is_dynamic(self) -> bool {
        self.as_u16() & 2 != 0
    }

    /// Return whether a packet may carry at most one of the option.
    pub fn is_singleton(self) -> bool {
        matches!(
            self,
            Self::Trace | Self::SourceRoute | Self::MinRssi | Self::RouteRetry | Self::MinSnr
        )
    }
}

impl From<u16> for OptionNumber {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::FrameSignature,
            3 => Self::SourceRoute,
            4 => Self::OperatorCallsign,
            5 => Self::MinRssi,
            6 => Self::RouteRetry,
            7 => Self::Trace,
            8 => Self::AckMic,
            9 => Self::MinSnr,
            15 => Self::StationCallsign,
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

/// Where a frame's signature sits, and the counter it signs.
///
/// A secured frame's signature precedes its MIC and signs SECINFO's counter;
/// a broadcast's is the Frame Signature option's value, which carries its own
/// counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameSignatureRef {
    pub counter: u32,
    /// The 64 signature bytes. With `E` set they are ciphertext until the
    /// frame is opened.
    pub range: Range<usize>,
}

/// Parsed packet header with borrowed ranges into the original frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub fcf: Fcf,
    pub options_range: Range<usize>,
    pub flood_hops: Option<FloodHops>,
    pub dst: Option<NodeHint>,
    pub channel: Option<ChannelId>,
    pub source: SourceAddrRef,
    pub sec_info: Option<SecInfo>,
    /// Located only, not verified.
    pub signature: Option<FrameSignatureRef>,
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
                let signature = broadcast_signature(buf, options_range.clone())?;
                let body_start = options_start + consumed;
                let body_end = if has_marker { buf.len() } else { body_start };
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    source,
                    sec_info,
                    signature,
                    body_range: body_start..body_end,
                    mic_range: buf.len()..buf.len(),
                    total_len: buf.len(),
                })
            }
            PacketType::MacAck => {
                // MAC acks carry no destination hint: options follow the
                // header directly, then a fixed 8-byte ack trailer
                // (`ack_mic` || `ack_tag`).
                let options_start = cursor;
                let options_end = buf.len().checked_sub(8).ok_or(ParseError::Truncated)?;
                if options_end < options_start {
                    return Err(ParseError::Truncated);
                }
                // MAC ACK has no payload—the options region is bounded by
                // the fixed 8-byte ack trailer. The scan must consume the
                // entire region: either the marker is absent (and the scan
                // exhausts the region), or the marker is the last byte (and
                // `consumed` includes it). Any other case means there are
                // bytes between an end-of-options marker and the trailer,
                // which the wire format does not assign meaning to.
                let region = &buf[options_start..options_end];
                let (consumed, _has_marker) = scan_options_bounded(region)?;
                if consumed != region.len() {
                    return Err(ParseError::MalformedOption);
                }
                let options_range = options_start..options_start + consumed;
                let trailer_start = options_end;
                let signature = None;
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    source,
                    sec_info,
                    signature,
                    body_range: trailer_start..trailer_start + 8,
                    mic_range: trailer_start..trailer_start + 8,
                    total_len: trailer_start + 8,
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
                let (trailer_start, mic_start, signature) =
                    trailer_bounds(buf.len(), cursor, &parsed_sec)?;
                let options_start = cursor;
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..trailer_start])?;
                let options_range = options_start..options_start + consumed;
                let body_start = options_start + consumed;
                let body_end = if has_marker {
                    trailer_start
                } else {
                    body_start
                };
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    source,
                    sec_info,
                    signature,
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
                let (trailer_start, mic_start, signature) =
                    trailer_bounds(buf.len(), cursor, &parsed_sec)?;
                let options_start = cursor;
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..trailer_start])?;
                // SRC follows the options, so the end-of-options marker is
                // always present (the builder emits it even with no payload).
                if !has_marker {
                    return Err(ParseError::Truncated);
                }
                let options_range = options_start..options_start + consumed;
                cursor = options_start + consumed;
                let src_len = source_len(fcf.full_source());
                ensure_within(cursor, src_len, trailer_start)?;
                if parsed_sec.scf.encrypted() {
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
                        source,
                        sec_info,
                        signature,
                        body_range: cursor..trailer_start,
                        mic_range: mic_start..buf.len(),
                        total_len: buf.len(),
                    })
                } else {
                    source = if fcf.full_source() {
                        SourceAddrRef::FullKeyAt { offset: cursor }
                    } else {
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
                        source,
                        sec_info,
                        signature,
                        body_range: cursor..trailer_start,
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
                let (trailer_start, mic_start, signature) =
                    trailer_bounds(buf.len(), cursor, &parsed_sec)?;
                let options_start = cursor;
                let (consumed, has_marker) =
                    scan_options_bounded(&buf[options_start..trailer_start])?;
                // The address block follows the options, so the end-of-options
                // marker is always present.
                if !has_marker {
                    return Err(ParseError::Truncated);
                }
                let options_range = options_start..options_start + consumed;
                cursor = options_start + consumed;
                let src_len = source_len(fcf.full_source());
                ensure_within(cursor, 3 + src_len, trailer_start)?;
                if parsed_sec.scf.encrypted() {
                    source = SourceAddrRef::Encrypted {
                        offset: cursor + 3,
                        len: src_len,
                    };
                } else {
                    dst = Some(NodeHint([buf[cursor], buf[cursor + 1], buf[cursor + 2]]));
                    source = if fcf.full_source() {
                        SourceAddrRef::FullKeyAt { offset: cursor + 3 }
                    } else {
                        SourceAddrRef::Hint(NodeHint([
                            buf[cursor + 3],
                            buf[cursor + 4],
                            buf[cursor + 5],
                        ]))
                    };
                }
                cursor += 3 + src_len;
                Ok(Self {
                    fcf,
                    options_range,
                    flood_hops,
                    dst,
                    channel,
                    source,
                    sec_info,
                    signature,
                    body_range: cursor..trailer_start,
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

    /// The bytes the MIC's S2 component covers, which encryption also covers
    /// when `E` is set.
    ///
    /// For multicast that is `SRC ‖ PAYLOAD` whether or not it is encrypted:
    /// the source address sits in the same place on the wire either way and
    /// never enters the AAD. For every other type it is the payload. With `D`
    /// set, the signature follows.
    pub fn protected_range(&self) -> Range<usize> {
        let start = match (self.packet_type(), self.source) {
            (PacketType::Multicast, SourceAddrRef::Hint(_) | SourceAddrRef::FullKeyAt { .. }) => {
                self.body_range.start - source_len(self.fcf.full_source())
            }
            _ => self.body_range.start,
        };
        start
            ..self
                .trailing_signature()
                .map_or(self.body_range.end, |sig| sig.range.end)
    }

    /// The frame's signature, located but not verified: the one before the
    /// MIC when SECINFO sets `D`, or a broadcast's Frame Signature option.
    pub fn signature(&self) -> Option<&FrameSignatureRef> {
        self.signature.as_ref()
    }

    /// The signature between payload and MIC, which S2 and encryption cover.
    /// A broadcast's sits in its options instead.
    fn trailing_signature(&self) -> Option<&FrameSignatureRef> {
        self.signature.as_ref().filter(|_| self.sec_info.is_some())
    }

    /// Where a blind unicast's `DST ‖ SRC` address block sits in the frame,
    /// encrypted or not. `None` for every other packet type.
    pub fn blind_addr_range(&self) -> Option<Range<usize>> {
        match self.packet_type() {
            PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
                let len = 3 + source_len(self.fcf.full_source());
                let end = self.body_range.start;
                Some(end.checked_sub(len)?..end)
            }
            _ => None,
        }
    }
}

/// A blind unicast's address block in plaintext: `DST (3) ‖ SRC (3 or 32)`.
///
/// The AAD of a blind unicast covers these bytes in plaintext whether or not
/// they are encrypted on the wire, so [`feed_aad`] takes them as a value
/// rather than reading the frame, where they may still be ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindAddr {
    bytes: [u8; 35],
    len: u8,
}

impl BlindAddr {
    /// Copy a plaintext address block. Returns `None` unless `bytes` is 6 or
    /// 35 bytes long.
    pub fn from_plaintext(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 6 && bytes.len() != 35 {
            return None;
        }
        let mut out = [0u8; 35];
        out[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            bytes: out,
            len: bytes.len() as u8,
        })
    }

    /// The plaintext `DST ‖ SRC` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The destination hint.
    pub fn dst(&self) -> NodeHint {
        NodeHint([self.bytes[0], self.bytes[1], self.bytes[2]])
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
    /// A well-formed Trace option's value; read it through
    /// [`Self::trace`].
    pub trace: Option<Range<usize>>,
    pub min_rssi: Option<i16>,
    pub min_snr: Option<i8>,
    pub route_retry: bool,
    /// Some option, known or not, enters the AAD.
    pub has_static: bool,
    /// An unrecognized forwarding-critical option.
    pub has_unknown_forwarding_critical: bool,
    /// A recognized forwarding-critical option whose value is malformed,
    /// or a forwarding-critical singleton that appears more than once.
    /// Forwarding treats it like an unrecognized one.
    pub has_malformed_forwarding_critical: bool,
    /// An unrecognized delivery-critical option.
    pub has_unknown_delivery_critical: bool,
    /// A recognized delivery-critical option whose value is malformed, or
    /// a delivery-critical singleton that appears more than once.
    pub has_malformed_delivery_critical: bool,
}

impl ParsedOptions {
    /// Whether a repeater must refuse to forward the frame.
    pub fn refuses_forwarding(&self) -> bool {
        self.has_unknown_forwarding_critical || self.has_malformed_forwarding_critical
    }

    /// Whether an endpoint must refuse to accept, deliver, or acknowledge
    /// the frame. MAC acks are exempt.
    pub fn refuses_delivery(&self) -> bool {
        self.has_unknown_delivery_critical || self.has_malformed_delivery_critical
    }

    /// The frame's trace, parsed from `frame`, the buffer these options
    /// were extracted from.
    pub fn trace<'a>(&self, frame: &'a [u8]) -> Option<TraceRef<'a>> {
        TraceRef::parse(frame.get(self.trace.clone()?)?)
    }

    /// Record a recognized option whose value or repetition is malformed,
    /// in each of the option's own classes.
    fn mark_malformed(&mut self, option: OptionNumber) {
        self.has_malformed_forwarding_critical |= option.is_forwarding_critical();
        self.has_malformed_delivery_critical |= option.is_delivery_critical();
    }

    pub fn extract(buf: &[u8], range: Range<usize>) -> Result<Self, ParseError> {
        let mut parsed = Self::default();
        if range.is_empty() {
            return Ok(parsed);
        }
        let options = &buf[range.clone()];
        let mut decoder = OptionDecoder::new(options);
        // Singletons already seen, by option number. Trace and Route Retry
        // are read from their first occurrence (and a forwarder carries only
        // that one); any other repeated singleton is ambiguous and is
        // malformed in its classes.
        let mut seen = 0u16;
        // Driven by hand rather than `for`: the value's offset comes from
        // the decoder's own position, which a `for` loop would move.
        #[allow(clippy::while_let_on_iterator)]
        while let Some(entry) = decoder.next() {
            let (number, value) = entry?;
            // `position` sits just past the value once `next` has yielded
            // it, so backing off its length is the value's start.
            let value_start = range.start + decoder.position() - value.len();
            let value_range = value_start..value_start + value.len();
            let option = OptionNumber::from(number);
            parsed.has_static |= !option.is_dynamic();
            if option.is_singleton() {
                let bit = 1u16 << number;
                if seen & bit != 0 {
                    if !matches!(option, OptionNumber::Trace | OptionNumber::RouteRetry) {
                        parsed.mark_malformed(option);
                    }
                    continue;
                }
                seen |= bit;
            }
            match option {
                OptionNumber::RegionCode if value.len() == 2 => {
                    parsed.region_code = Some([value[0], value[1]]);
                }
                OptionNumber::RegionCode => parsed.mark_malformed(option),
                OptionNumber::Trace if TraceRef::parse(value).is_some() => {
                    parsed.trace = Some(value_range)
                }
                OptionNumber::Trace => parsed.mark_malformed(option),
                OptionNumber::SourceRoute => parsed.source_route = Some(value_range),
                // A flag: its presence is the meaning. Senders send it
                // empty; a value is reserved and does not hide the flag.
                OptionNumber::RouteRetry => parsed.route_retry = true,
                // Minimum RSSI (option 5): unsigned 1-byte value read as a
                // negative dBm threshold (e.g. 130 → -130 dBm). A zero-length
                // value selects the default threshold. Longer values are
                // malformed.
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
                OptionNumber::MinRssi | OptionNumber::MinSnr => parsed.mark_malformed(option),
                OptionNumber::Unknown(_) => {
                    parsed.has_unknown_forwarding_critical |= option.is_forwarding_critical();
                    parsed.has_unknown_delivery_critical |= option.is_delivery_critical();
                }
                _ => {}
            }
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod parsed_options_tests {
    use super::*;
    use crate::options::OptionEncoder;

    #[test]
    fn route_retry_is_a_flag_whatever_its_value() {
        // Option 6, length 1: a reserved value does not hide the flag.
        let buf = [0x61u8, 0x2A];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert!(parsed.route_retry);
        assert!(!parsed.has_malformed_forwarding_critical);
    }

    #[test]
    fn only_static_options_count_as_static() {
        // Trace (7) is dynamic.
        let parsed = ParsedOptions::extract(&[0x70], 0..1).unwrap();
        assert!(!parsed.has_static);
        // Operator Callsign (4) is static.
        let buf = [0x41u8, 0x99];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert!(parsed.has_static);
    }

    #[test]
    fn a_repeated_non_critical_singleton_is_read_from_its_first_occurrence() {
        // Trace (7) twice: delta 7 then delta 0, one record each.
        let buf = [0x74u8, 0xA1, 0xA2, 0x00, 0x00, 0x04, 0xB1, 0xB2, 0x00, 0x00];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.trace, Some(1..5));
        assert!(!parsed.has_malformed_forwarding_critical);
    }

    #[test]
    fn a_repeated_critical_singleton_refuses_forwarding() {
        // Source Route (3) twice.
        let buf = [0x32u8, 0xA1, 0xA2, 0x02, 0xB1, 0xB2];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.source_route, Some(1..3));
        assert!(parsed.has_malformed_forwarding_critical);
        // Region Code (11) is not a singleton: two are a list.
        let buf = [0xB2u8, 0x78, 0x53, 0x02, 0x52, 0x42];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert!(!parsed.has_malformed_forwarding_critical);
    }

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
    fn min_rssi_two_bytes_is_malformed() {
        // Length 2 is malformed for Min RSSI.
        let buf = [0x52u8, 0x00, 0x82];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_rssi, None);
        assert!(parsed.has_malformed_forwarding_critical);
        assert!(!parsed.has_unknown_forwarding_critical);
    }

    #[test]
    fn min_snr_two_bytes_is_malformed() {
        let buf = [0x92u8, 0x00, 0xFD];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.min_snr, None);
        assert!(parsed.has_malformed_forwarding_critical);
    }

    #[test]
    fn region_code_wrong_length_is_malformed() {
        for len in [0usize, 1, 3] {
            let mut buf = [0u8; 16];
            let mut encoder = OptionEncoder::new(&mut buf);
            encoder
                .put(OptionNumber::RegionCode.as_u16(), &[0xAB; 3][..len])
                .unwrap();
            let used = encoder.finish();
            let parsed = ParsedOptions::extract(&buf, 0..used).unwrap();
            assert_eq!(parsed.region_code, None, "len {len}");
            assert!(parsed.has_malformed_forwarding_critical, "len {len}");
        }
    }

    #[test]
    fn criticality_classes_follow_the_low_four_bits() {
        let classes = |n: u16| {
            let option = OptionNumber::Unknown(n);
            (
                option.is_forwarding_critical(),
                option.is_delivery_critical(),
            )
        };
        assert_eq!(classes(1), (true, false));
        assert_eq!(classes(12), (false, true));
        assert_eq!(classes(13), (true, true));
        assert_eq!(
            classes(15),
            (true, false),
            "dynamic, so never delivery-critical"
        );
        for n in [6, 14, 16, 22] {
            assert_eq!(classes(n), (false, false), "option {n}");
        }
        assert_eq!(classes(28), (false, true));
    }

    #[test]
    fn unknown_options_set_each_of_their_classes() {
        // Option 12, empty: delivery-critical only.
        let parsed = ParsedOptions::extract(&[0xC0], 0..1).unwrap();
        assert!(parsed.refuses_delivery() && !parsed.refuses_forwarding());
        // Option 13, empty: both.
        let parsed = ParsedOptions::extract(&[0xD0, 0x00], 0..2).unwrap();
        assert!(parsed.refuses_delivery() && parsed.refuses_forwarding());
        // Option 1, empty: forwarding-critical only.
        let parsed = ParsedOptions::extract(&[0x10], 0..1).unwrap();
        assert!(!parsed.refuses_delivery() && parsed.refuses_forwarding());
    }

    #[test]
    fn a_malformed_trace_refuses_forwarding_but_not_delivery() {
        // Trace (7) with a 2-byte value: neither records nor a sentinel form.
        let buf = [0x72u8, 0xA1, 0xA2];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert_eq!(parsed.trace, None);
        assert!(parsed.refuses_forwarding());
        assert!(!parsed.refuses_delivery());
    }

    #[test]
    fn well_formed_options_are_not_malformed() {
        let buf = [0x51u8, 130, 0x41, 0xFD];
        let parsed = ParsedOptions::extract(&buf, 0..buf.len()).unwrap();
        assert!(!parsed.has_malformed_forwarding_critical);
    }
}

pub fn iter_options<'a>(buf: &'a [u8], range: Range<usize>) -> OptionDecoder<'a> {
    OptionDecoder::new(&buf[range])
}

/// Stream a packet's canonical associated data into `sink`.
///
/// The AAD is the packet's header fields in wire order, without `FHOPS` (and
/// with `H` cleared), then the static options as `number (2) ‖ length (2) ‖
/// value` records, then the two-byte terminator `0xFFFF`:
///
/// | Family | AAD |
/// |---|---|
/// | Broadcast | `FCF ‖ SRC ‖ options ‖ FFFF` |
/// | MAC ack | `FCF ‖ options ‖ FFFF` |
/// | Unicast | `FCF ‖ DST ‖ SRC ‖ SECINFO ‖ options ‖ FFFF` |
/// | Multicast | `FCF ‖ CHANNEL ‖ SECINFO ‖ options ‖ FFFF` |
/// | Blind unicast | `FCF ‖ CHANNEL ‖ SECINFO ‖ options ‖ FFFF ‖ DST ‖ SRC` |
///
/// The packet format is self-describing from left to right, and the
/// terminator restores the delimiter the record re-encoding drops, so the AAD
/// fixes its own end. No static record can begin with `0xFFFF`: that number is
/// dynamic, and dynamic options never enter the AAD. Multicast's `SRC` is
/// never here; it is the start of S2 (see [`PacketHeader::protected_range`]).
///
/// A blind unicast's address block enters in plaintext whether or not it is
/// encrypted on the wire, so it is passed in as `blind_addr` and is required
/// for that family. An option block that fails to decode is an error rather
/// than a silently shortened AAD.
pub fn feed_aad(
    header: &PacketHeader,
    packet_buf: &[u8],
    blind_addr: Option<&BlindAddr>,
    sink: impl FnMut(&[u8]),
) -> Result<(), ParseError> {
    feed_aad_inner(header, packet_buf, blind_addr, false, sink)
}

/// [`feed_aad`], optionally with a broadcast's Frame Signature value fed as
/// its counter followed by zeros, which is how the signature input sees it.
fn feed_aad_inner(
    header: &PacketHeader,
    packet_buf: &[u8],
    blind_addr: Option<&BlindAddr>,
    zero_signature: bool,
    mut sink: impl FnMut(&[u8]),
) -> Result<(), ParseError> {
    sink(&[header.fcf.aad_byte()]);
    let feed_source = |sink: &mut dyn FnMut(&[u8])| -> Result<(), ParseError> {
        match header.source {
            SourceAddrRef::Hint(hint) => sink(&hint.0),
            SourceAddrRef::FullKeyAt { offset } => sink(
                packet_buf
                    .get(offset..offset + 32)
                    .ok_or(ParseError::Truncated)?,
            ),
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => {
                return Err(ParseError::Truncated);
            }
        }
        Ok(())
    };
    let feed_sec_info = |sink: &mut dyn FnMut(&[u8])| -> Result<(), ParseError> {
        let sec_info = header.sec_info.ok_or(ParseError::Truncated)?;
        let mut buf = [0u8; 7];
        let len = sec_info
            .encode(&mut buf)
            .map_err(|_| ParseError::Truncated)?;
        sink(&buf[..len]);
        Ok(())
    };

    let blind = matches!(
        header.packet_type(),
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq
    );
    match header.packet_type() {
        PacketType::Broadcast => feed_source(&mut sink)?,
        PacketType::MacAck => {}
        PacketType::Unicast | PacketType::UnicastAckReq => {
            sink(&header.dst.ok_or(ParseError::Truncated)?.0);
            feed_source(&mut sink)?;
            feed_sec_info(&mut sink)?;
        }
        PacketType::Multicast | PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
            sink(&header.channel.ok_or(ParseError::Truncated)?.0);
            feed_sec_info(&mut sink)?;
        }
        PacketType::Reserved5 => return Err(ParseError::MalformedOption),
    }

    for option in iter_options(packet_buf, header.options_range.clone()) {
        let (number, value) = option?;
        if OptionNumber::from(number).is_dynamic() {
            continue;
        }
        let mut tl = [0u8; 4];
        tl[..2].copy_from_slice(&number.to_be_bytes());
        tl[2..].copy_from_slice(&(value.len() as u16).to_be_bytes());
        sink(&tl);
        // A broadcast's located signature is its only option 0, and only a
        // broadcast's signature lives in its options.
        if zero_signature
            && header.sec_info.is_none()
            && OptionNumber::from(number) == OptionNumber::FrameSignature
        {
            sink(&value[..4]);
            sink(&[0u8; SIGNATURE_LEN]);
        } else {
            sink(value);
        }
    }
    sink(&[0xFF, 0xFF]);

    if blind {
        let addr = blind_addr.ok_or(ParseError::MissingAddressBlock)?;
        if addr.as_bytes().len() != 3 + source_len(header.fcf.full_source()) {
            return Err(ParseError::MissingAddressBlock);
        }
        sink(addr.as_bytes());
    }
    Ok(())
}

/// Write the bytes a frame's signature signs into `out`, returning their
/// length:
///
/// `SIGNATURE_LABEL ‖ AAD ‖ [CHANNEL COMMITMENT] ‖ plaintext`
///
/// - The AAD is [`feed_aad`]'s, except that a broadcast's Frame Signature
///   enters as its counter followed by 64 zeros.
/// - The commitment follows for a frame that names a channel, and only then:
///   `channel` must be present exactly when the header has a channel, since
///   the frame's bytes alone cannot name its channel key.
/// - The plaintext is what S2 covers, without the signature: `SRC ‖ PAYLOAD`
///   for multicast and the payload for every other type. With `E` set the
///   frame must already be open.
///
/// Signing and verifying both use this. The AAD fixes its own end and its
/// FCF says whether a commitment follows, so no two frames share an input.
/// [`SIGNATURE_INPUT_MAX`] bytes always suffice for a frame the parser
/// accepts.
pub fn signature_input(
    header: &PacketHeader,
    packet_buf: &[u8],
    blind_addr: Option<&BlindAddr>,
    channel: Option<&ChannelCommitment>,
    out: &mut [u8],
) -> Result<usize, SignatureInputError> {
    if header.signature.is_none() {
        return Err(SignatureInputError::Unsigned);
    }
    if header.channel.is_some() != channel.is_some() {
        return Err(SignatureInputError::ChannelMismatch);
    }
    let mut len = 0;
    let mut overflow = false;
    let mut sink = |bytes: &[u8]| {
        match out.get_mut(len..len + bytes.len()) {
            Some(dst) if !overflow => dst.copy_from_slice(bytes),
            _ => overflow = true,
        }
        len += bytes.len();
    };
    sink(SIGNATURE_LABEL);
    feed_aad_inner(header, packet_buf, blind_addr, true, &mut sink)?;
    if let Some(commitment) = channel {
        sink(&commitment.0);
    }
    let plaintext = header.protected_range().start..header.body_range.end;
    sink(
        packet_buf
            .get(plaintext)
            .ok_or(SignatureInputError::Parse(ParseError::Truncated))?,
    );
    if overflow {
        return Err(SignatureInputError::BufferTooSmall);
    }
    Ok(len)
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
        match crate::options::decode_record(data, pos, last_number)? {
            crate::options::Record::End { next } => return Ok((next, true)),
            crate::options::Record::Option { number, next, .. } => {
                last_number = number;
                pos = next;
            }
        }
    }
    Ok((pos, false))
}

/// Check that a `len`-byte field at `offset` ends at or before `limit`.
///
/// Fields that follow the options block must fit before the trailer (the MIC),
/// not merely inside the buffer: otherwise a frame without its end-of-options
/// marker would read its source address out of the MIC.
fn ensure_within(offset: usize, len: usize, limit: usize) -> Result<(), ParseError> {
    match offset.checked_add(len) {
        Some(end) if end <= limit => Ok(()),
        _ => Err(ParseError::Truncated),
    }
}

/// Where a secured frame's trailer begins and its MIC begins, and where its
/// signature sits when `D` is set.
///
/// The trailer is `[SIG] ‖ MIC`, and its length is known from SECINFO alone,
/// so nothing after the options is ever read out of it.
fn trailer_bounds(
    len: usize,
    header_end: usize,
    sec_info: &SecInfo,
) -> Result<(usize, usize, Option<FrameSignatureRef>), ParseError> {
    let mic_start = len
        .checked_sub(sec_info.scf.mic_size()?.byte_len())
        .ok_or(ParseError::Truncated)?;
    let (trailer_start, signature) = if sec_info.scf.signed() {
        let sig_start = mic_start
            .checked_sub(SIGNATURE_LEN)
            .ok_or(ParseError::Truncated)?;
        let signature = FrameSignatureRef {
            counter: sec_info.frame_counter,
            range: sig_start..mic_start,
        };
        (sig_start, Some(signature))
    } else {
        (mic_start, None)
    };
    if trailer_start < header_end {
        return Err(ParseError::Truncated);
    }
    Ok((trailer_start, mic_start, signature))
}

/// A broadcast's Frame Signature: its one well-formed option 0.
///
/// A frame carrying more than one option 0 is unsigned, and a value of the
/// wrong length is an unrecognized option, which a non-critical option makes
/// harmless to ignore.
fn broadcast_signature(
    buf: &[u8],
    options: Range<usize>,
) -> Result<Option<FrameSignatureRef>, ParseError> {
    let mut found = None;
    let mut count = 0;
    let mut decoder = OptionDecoder::new(&buf[options.clone()]);
    // Driven by hand: the value's offset comes from the decoder's position.
    #[allow(clippy::while_let_on_iterator)]
    while let Some(entry) = decoder.next() {
        let (number, value) = entry?;
        // Options are in ascending order, so option 0 can only lead.
        if number != OptionNumber::FrameSignature.as_u16() {
            break;
        }
        count += 1;
        if value.len() == FRAME_SIGNATURE_OPTION_LEN {
            let value_start = options.start + decoder.position() - value.len();
            found = Some(FrameSignatureRef {
                counter: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                range: value_start + 4..value_start + FRAME_SIGNATURE_OPTION_LEN,
            });
        }
    }
    Ok(if count == 1 { found } else { None })
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
    signature_range: Option<Range<usize>>,
    mic_range: Range<usize>,
    sec_info_range: Range<usize>,
    aad_static_options: Range<usize>,
}

impl<'a> UnsealedPacket<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        buf: &'a mut [u8],
        total_len: usize,
        body_range: Range<usize>,
        blind_addr_range: Option<Range<usize>>,
        signature_range: Option<Range<usize>>,
        mic_range: Range<usize>,
        sec_info_range: Range<usize>,
        aad_static_options: Range<usize>,
    ) -> Self {
        Self {
            buf,
            total_len,
            body_range,
            blind_addr_range,
            signature_range,
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

    /// The zeroed signature slot of a frame built with `D` set.
    pub fn signature_slot_mut(&mut self) -> Option<&mut [u8]> {
        let range = self.signature_range.clone()?;
        Some(&mut self.buf[range])
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

#[cfg(test)]
mod tests {
    use super::{NodeHint, PacketType, PayloadType, PublicKey, RouterHint};
    use crate::{AddressParseError, HintInputError};

    #[test]
    fn node_management_rides_only_unicast() {
        for payload_type in [
            PayloadType::NodeManagementRequest,
            PayloadType::NodeManagementResponse,
        ] {
            for packet_type in [
                PacketType::Unicast,
                PacketType::UnicastAckReq,
                PacketType::BlindUnicast,
                PacketType::BlindUnicastAckReq,
            ] {
                assert!(payload_type.allowed_for(packet_type));
            }
            for packet_type in [
                PacketType::Multicast,
                PacketType::Broadcast,
                PacketType::MacAck,
            ] {
                assert!(!payload_type.allowed_for(packet_type));
            }
        }
        assert!(PayloadType::TextMessage.allowed_for(PacketType::Multicast));
        assert!(PayloadType::CoapOverUmsh.allowed_for(PacketType::Multicast));
    }

    #[test]
    fn meet_rides_unicast_and_its_hello_rides_broadcast() {
        assert_eq!(PayloadType::from_byte(10), Some(PayloadType::Meet));
        for packet_type in [
            PacketType::Unicast,
            PacketType::UnicastAckReq,
            PacketType::Broadcast,
        ] {
            assert!(PayloadType::Meet.allowed_for(packet_type));
        }
        for packet_type in [
            PacketType::BlindUnicast,
            PacketType::BlindUnicastAckReq,
            PacketType::Multicast,
            PacketType::MacAck,
        ] {
            assert!(!PayloadType::Meet.allowed_for(packet_type));
        }
    }

    #[test]
    fn node_management_directions_are_distinct_payload_types() {
        assert_eq!(
            PayloadType::from_byte(8),
            Some(PayloadType::NodeManagementRequest)
        );
        assert_eq!(
            PayloadType::from_byte(9),
            Some(PayloadType::NodeManagementResponse)
        );
    }

    // Reference address from the addressing chapter discussion; first byte 0x5e.
    const EXAMPLE_B58: &str = "7NeD1xuPGwZgikCNUaPhmMB13miitwoAEYdzhkvQVu9o";

    #[test]
    fn public_key_display_matches_reference_vectors() {
        assert_eq!(
            PublicKey([0u8; 32]).to_string(),
            "11111111111111111111111111111111111111111111"
        );
        assert_eq!(
            PublicKey([0xFFu8; 32]).to_string(),
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
        );
    }

    #[test]
    fn public_key_parses_base58_and_base16() {
        let key: PublicKey = EXAMPLE_B58.parse().unwrap();
        assert_eq!(key.to_string(), EXAMPLE_B58);
        assert_eq!(key.0[0], 0x5E);

        let lower = format!("{key:x}");
        let upper = format!("{key:X}");
        assert_eq!(lower.len(), 64);
        assert_eq!(lower.parse::<PublicKey>().unwrap(), key);
        assert_eq!(upper.parse::<PublicKey>().unwrap(), key);
    }

    #[test]
    fn public_key_parse_rejects_bad_input() {
        assert_eq!(
            "7NeD".parse::<PublicKey>(),
            Err(AddressParseError::InvalidLength)
        );
        let bad_hex = "gg".repeat(32);
        assert_eq!(
            bad_hex.parse::<PublicKey>(),
            Err(AddressParseError::InvalidCharacter)
        );
    }

    #[test]
    fn node_hint_display_matches_reference_vectors() {
        // Unambiguous: all four characters are pinned down.
        assert_eq!(NodeHint([0x00, 0x00, 0x00]).to_string(), "1111");
        assert_eq!(NodeHint([0xFF, 0xFF, 0xFF]).to_string(), "JEKN");
        assert_eq!(NodeHint([0xA1, 0xB2, 0x03]).to_string(), "BtC5");
        assert_eq!(NodeHint([0x5E, 0xA1, 0xB2]).to_string(), "7NQL");
        // Carry case: the third digit is ambiguous (encodings read 9vEz/9vF1).
        assert_eq!(NodeHint([0x84, 0x81, 0x1B]).to_string(), "9v*");
        assert_eq!(NodeHint([0xFF, 0xFF, 0x94]).to_string(), "JE*");
    }

    #[test]
    fn router_hint_display_matches_reference_vectors() {
        assert_eq!(RouterHint([0x00, 0x00]).to_string(), "111");
        assert_eq!(RouterHint([0xA1, 0xB2]).to_string(), "BtC");
        assert_eq!(RouterHint([0x5E, 0xA1]).to_string(), "7N*");
        assert_eq!(RouterHint([0x84, 0x81]).to_string(), "9v*");
        // Carry case: only the first digit is pinned down.
        assert_eq!(RouterHint([0x00, 0x41]).to_string(), "1*");
    }

    #[test]
    fn router_hint_candidates_from_base58_prefix() {
        let one = |prefix: &str| {
            let candidates = RouterHint::candidates_from_base58_prefix(prefix).unwrap();
            assert_eq!(candidates.second, None, "{prefix}");
            candidates.first
        };
        assert_eq!(one("7Nq4"), RouterHint([0x5E, 0xBD]));
        assert_eq!(one("HJC9"), RouterHint([0xF2, 0x22]));
        assert_eq!(one("BtC9"), RouterHint([0xA1, 0xB2]));
        assert_eq!(
            one("HJC9DJaaQEn88tAzbMM7BrYbsepNEB69RK1gZiKEYCPp"),
            RouterHint([0xF2, 0x22])
        );

        // A prefix that straddles a hint boundary: both render as "H1*".
        let straddle = RouterHint::candidates_from_base58_prefix("H12n").unwrap();
        assert_eq!(straddle.first, RouterHint([0xED, 0xBC]));
        assert_eq!(straddle.second, Some(RouterHint([0xED, 0xBD])));
        // A fifth character settles it.
        assert!(
            RouterHint::candidates_from_base58_prefix("H12n2")
                .unwrap()
                .second
                .is_none()
        );

        assert_eq!(
            RouterHint::candidates_from_base58_prefix("HJC"),
            Err(HintInputError::TooShort)
        );
        assert_eq!(
            RouterHint::candidates_from_base58_prefix("HJ0C"),
            Err(HintInputError::InvalidCharacter)
        );
        assert_eq!(
            RouterHint::candidates_from_base58_prefix("Kzzz"),
            Err(HintInputError::OutOfRange)
        );
    }

    #[test]
    fn router_hint_candidates_always_include_the_true_hint() {
        for i in 0..=1023u32 {
            let mut key = [0u8; 32];
            for (j, byte) in key.iter_mut().enumerate() {
                *byte = (i.wrapping_mul(2654435761).rotate_left(j as u32) ^ (j as u32 * 37)) as u8;
            }
            let key = PublicKey(key);
            let encoded = key.to_string();
            let candidates = RouterHint::candidates_from_base58_prefix(&encoded[..4]).unwrap();
            assert!(
                candidates.iter().any(|hint| hint == key.router_hint()),
                "{encoded}"
            );
        }
    }

    #[test]
    fn router_hint_from_hex() {
        assert_eq!(RouterHint::from_hex("5EBD"), Ok(RouterHint([0x5E, 0xBD])));
        assert_eq!(RouterHint::from_hex("a1b2"), Ok(RouterHint([0xA1, 0xB2])));
        assert_eq!(RouterHint::from_hex("a1b"), Err(HintInputError::TooShort));
        assert_eq!(RouterHint::from_hex("a1b23"), Err(HintInputError::TooLong));
        assert_eq!(
            RouterHint::from_hex("a1g2"),
            Err(HintInputError::InvalidCharacter)
        );
    }

    #[test]
    fn hint_renderings_prefix_full_address() {
        // Deterministic sweep: every character before a `*` must match the
        // full base58 rendering of a key that carries the hint.
        for i in 0..=255u32 {
            let mut key = [0u8; 32];
            for (j, byte) in key.iter_mut().enumerate() {
                *byte = (i.wrapping_mul(151).wrapping_add(j as u32 * 91)) as u8;
            }
            let key = PublicKey(key);
            let full = key.to_string();
            for rendered in [key.hint().to_string(), key.router_hint().to_string()] {
                let verified = rendered.strip_suffix('*').unwrap_or(&rendered);
                assert!(
                    full.starts_with(verified),
                    "hint {rendered} does not prefix {full}"
                );
            }
        }
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::PacketBuilder;

    extern crate std;
    use std::vec::Vec;

    const SRC_HINT: NodeHint = NodeHint([0xA1, 0xB2, 0x03]);
    const SRC_FULL: PublicKey = PublicKey([0xA1; 32]);
    const DST: NodeHint = NodeHint([0xC3, 0xD4, 0x25]);
    const CHANNEL: ChannelId = ChannelId([0x7E, 0x5F]);
    const COMMITMENT: ChannelCommitment = ChannelCommitment([0xC0; 32]);

    fn signed_unicast(payload: &[u8], trace: bool) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .unicast(DST)
            .source_hint(SRC_HINT)
            .frame_counter(42)
            .signed();
        let builder = if trace { builder.trace() } else { builder };
        let mut packet = builder.payload(payload).build().unwrap();
        packet.signature_slot_mut().unwrap().fill(0xF0);
        packet.as_bytes().to_vec()
    }

    fn signed_multicast(encrypted: bool) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .multicast(CHANNEL)
            .source_hint(SRC_HINT)
            .frame_counter(7)
            .signed();
        let builder = if encrypted {
            builder.encrypted()
        } else {
            builder
        };
        let mut packet = builder.payload(b"help").build().unwrap();
        packet.signature_slot_mut().unwrap().fill(0xAB);
        packet.as_bytes().to_vec()
    }

    fn signed_broadcast(payload: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(SRC_HINT)
            .signed(0x0102_0304)
            .region_code([0x78, 0x53])
            .payload(payload)
            .build()
            .unwrap()
            .to_vec();
        let mut frame = frame;
        let range = PacketHeader::parse(&frame)
            .unwrap()
            .signature()
            .unwrap()
            .range
            .clone();
        frame[range].fill(0xAB);
        frame
    }

    #[test]
    fn a_signed_unicast_carries_its_signature_before_the_mic() {
        let frame = signed_unicast(b"hi", false);
        let header = PacketHeader::parse(&frame).unwrap();
        let len = frame.len();
        assert!(header.sec_info.unwrap().scf.signed());
        let signature = header.signature().unwrap();
        assert_eq!(signature.counter, 42);
        assert_eq!(signature.range, len - 16 - 64..len - 16);
        assert_eq!(&frame[header.body_range.clone()], b"hi");
        assert_eq!(header.mic_range, len - 16..len);
        assert_eq!(header.protected_range(), header.body_range.start..len - 16);
    }

    /// With no payload there is no end-of-options marker, and the scan stops
    /// at the signature rather than reading it as options.
    #[test]
    fn the_signature_is_never_read_as_options() {
        let frame = signed_unicast(&[], true);
        let header = PacketHeader::parse(&frame).unwrap();
        let sig_start = header.signature().unwrap().range.start;
        assert_eq!(header.options_range.end, sig_start);
        assert!(header.body_range.is_empty());
        assert_eq!(
            header.protected_range(),
            sig_start..sig_start + SIGNATURE_LEN
        );
    }

    /// Setting `D` on a frame too short to hold a signature truncates it.
    #[test]
    fn a_signed_frame_too_short_for_its_signature_is_truncated() {
        let mut buf = [0u8; 256];
        let mut frame = PacketBuilder::new(&mut buf)
            .unicast(DST)
            .source_hint(SRC_HINT)
            .frame_counter(42)
            .payload(&[0x55; 10])
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        let scf = 1 + 3 + 3;
        frame[scf] |= Scf::SIGNED;
        assert_eq!(PacketHeader::parse(&frame), Err(ParseError::Truncated));
    }

    #[test]
    fn reserved_scf_bits_are_the_low_three() {
        assert!(Scf(Scf::SIGNED).reserved_valid());
        for bit in 0..3 {
            assert!(!Scf(1 << bit).reserved_valid());
        }
        assert_eq!(Scf(0).with_signed(true), Scf(Scf::SIGNED));
        assert_eq!(Scf(0xFF).with_signed(false).0, 0xF7);
    }

    /// Multicast's S2 is `SRC ‖ PAYLOAD ‖ SIG` with either `E`.
    #[test]
    fn a_signed_multicast_protects_source_payload_and_signature() {
        for encrypted in [false, true] {
            let frame = signed_multicast(encrypted);
            let header = PacketHeader::parse(&frame).unwrap();
            let len = frame.len();
            let signature = header.signature().unwrap();
            assert_eq!(signature.range, len - 16 - 64..len - 16);
            let protected = header.protected_range();
            assert_eq!(&frame[protected.start..protected.start + 3], &SRC_HINT.0);
            assert_eq!(protected.end, signature.range.end);
            assert_eq!(
                &frame[signature.range.start - 4..signature.range.start],
                b"help"
            );
        }
    }

    #[test]
    fn a_signed_blind_unicast_carries_its_signature_after_the_payload() {
        let mut buf = [0u8; 256];
        let packet = PacketBuilder::new(&mut buf)
            .blind_unicast(CHANNEL, DST)
            .source_full(&SRC_FULL)
            .frame_counter(9)
            .signed()
            .payload(b"hello")
            .build()
            .unwrap();
        let frame = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&frame).unwrap();
        let signature = header.signature().unwrap();
        assert_eq!(signature.counter, 9);
        assert_eq!(header.body_range.end, signature.range.start);
        assert_eq!(&frame[header.body_range.clone()], b"hello");
        assert_eq!(header.blind_addr_range().unwrap().len(), 35);
        assert_eq!(
            header.protected_range(),
            header.body_range.start..signature.range.end
        );
    }

    #[test]
    fn a_broadcast_signature_is_its_frame_signature_option() {
        let frame = signed_broadcast(b"advert");
        let header = PacketHeader::parse(&frame).unwrap();
        let signature = header.signature().unwrap();
        assert_eq!(signature.counter, 0x0102_0304);
        assert_eq!(&frame[signature.range.clone()], &[0xAB; 64]);
        assert!(header.options_range.contains(&signature.range.start));
        // The signature lives in the options, outside the payload.
        assert_eq!(header.protected_range(), header.body_range);
        assert_eq!(&frame[header.body_range.clone()], b"advert");
    }

    fn broadcast_with_options(options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut builder = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(SRC_HINT);
        for &(number, value) in options {
            builder = builder.option(OptionNumber::from(number), value);
        }
        builder.payload(b"x").build().unwrap().to_vec()
    }

    #[test]
    fn a_broadcast_with_more_than_one_frame_signature_is_unsigned() {
        let value = [0u8; FRAME_SIGNATURE_OPTION_LEN];
        let frame = broadcast_with_options(&[(0, &value), (0, &value)]);
        assert_eq!(PacketHeader::parse(&frame).unwrap().signature(), None);
        // One well-formed and one malformed: still more than one.
        let frame = broadcast_with_options(&[(0, &value[..10]), (0, &value)]);
        assert_eq!(PacketHeader::parse(&frame).unwrap().signature(), None);
    }

    #[test]
    fn a_frame_signature_of_the_wrong_length_is_ignored() {
        for len in [0, 4, 67, 69] {
            let value = [0u8; 69];
            let frame = broadcast_with_options(&[(0, &value[..len])]);
            let header = PacketHeader::parse(&frame).unwrap();
            assert_eq!(header.signature(), None, "{len}");
            let options = ParsedOptions::extract(&frame, header.options_range.clone()).unwrap();
            assert!(!options.refuses_forwarding());
            assert!(!options.refuses_delivery());
        }
    }

    /// Option 0 on a frame with SECINFO is not its signature.
    #[test]
    fn a_frame_signature_option_on_a_secured_frame_is_ignored() {
        let mut buf = [0u8; 256];
        let packet = PacketBuilder::new(&mut buf)
            .unicast(DST)
            .source_hint(SRC_HINT)
            .frame_counter(42)
            .option(
                OptionNumber::FrameSignature,
                &[0u8; FRAME_SIGNATURE_OPTION_LEN],
            )
            .payload(b"hi")
            .build()
            .unwrap();
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        assert_eq!(header.signature(), None);
    }

    fn input(header: &PacketHeader, frame: &[u8], channel: Option<&ChannelCommitment>) -> Vec<u8> {
        let mut out = [0u8; SIGNATURE_INPUT_MAX];
        let len = signature_input(header, frame, None, channel, &mut out).unwrap();
        out[..len].to_vec()
    }

    #[test]
    fn a_broadcast_signature_input_zeroes_the_signature_and_keeps_the_counter() {
        let frame = signed_broadcast(b"advert");
        let header = PacketHeader::parse(&frame).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"UMSH-SIG");
        expected.push(frame[0]);
        expected.extend_from_slice(&SRC_HINT.0);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 68]);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.extend_from_slice(&[0u8; 64]);
        // Region Code is dynamic, so it stays out.
        expected.extend_from_slice(&[0xFF, 0xFF]);
        expected.extend_from_slice(b"advert");
        assert_eq!(input(&header, &frame, None), expected);
    }

    /// Multicast's input is `label ‖ AAD ‖ commitment ‖ SRC ‖ PAYLOAD`, the
    /// signature itself left out.
    #[test]
    fn a_multicast_signature_input_covers_the_commitment_and_source() {
        let frame = signed_multicast(false);
        let header = PacketHeader::parse(&frame).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(SIGNATURE_LABEL);
        feed_aad(&header, &frame, None, |bytes| {
            expected.extend_from_slice(bytes)
        })
        .unwrap();
        expected.extend_from_slice(&COMMITMENT.0);
        expected.extend_from_slice(&SRC_HINT.0);
        expected.extend_from_slice(b"help");
        assert_eq!(input(&header, &frame, Some(&COMMITMENT)), expected);
    }

    #[test]
    fn the_signature_input_requires_a_commitment_exactly_for_channel_frames() {
        let mut out = [0u8; SIGNATURE_INPUT_MAX];
        let frame = signed_multicast(false);
        let header = PacketHeader::parse(&frame).unwrap();
        assert_eq!(
            signature_input(&header, &frame, None, None, &mut out),
            Err(SignatureInputError::ChannelMismatch)
        );
        let frame = signed_unicast(b"hi", false);
        let header = PacketHeader::parse(&frame).unwrap();
        assert_eq!(
            signature_input(&header, &frame, None, Some(&COMMITMENT), &mut out),
            Err(SignatureInputError::ChannelMismatch)
        );
        let frame = broadcast_with_options(&[]);
        let header = PacketHeader::parse(&frame).unwrap();
        assert_eq!(
            signature_input(&header, &frame, None, None, &mut out),
            Err(SignatureInputError::Unsigned)
        );
        let frame = signed_unicast(b"hi", false);
        let header = PacketHeader::parse(&frame).unwrap();
        assert_eq!(
            signature_input(&header, &frame, None, None, &mut out[..20]),
            Err(SignatureInputError::BufferTooSmall)
        );
    }

    /// A full-length broadcast of one-byte empty static options expands
    /// fourfold in the AAD and still fits [`SIGNATURE_INPUT_MAX`].
    #[test]
    fn the_largest_signature_input_fits_its_bound() {
        let mut buf = [0u8; 512];
        let mut builder = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(SRC_HINT)
            .signed(1);
        // FCF, SRC, option 0 (70 bytes), the first empty option 16 (2 bytes)
        // and then repeats of it at one byte each.
        let repeats = MAX_FRAME_LEN - 4 - 70 - 2;
        for _ in 0..=repeats {
            builder = builder.option(OptionNumber::Unknown(16), &[]);
        }
        let frame = builder.build().unwrap().to_vec();
        assert_eq!(frame.len(), MAX_FRAME_LEN);
        let header = PacketHeader::parse(&frame).unwrap();
        let len = input(&header, &frame, None).len();
        assert_eq!(len, 8 + 4 + 72 + 4 * (repeats + 1) + 2);
        assert!(len <= SIGNATURE_INPUT_MAX);
    }
}
