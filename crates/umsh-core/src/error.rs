use core::fmt;

/// Errors returned while parsing on-wire UMSH structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended before the expected structure was complete.
    Truncated,
    /// The frame-control version bits do not match the supported protocol.
    InvalidVersion(u8),
    /// Reserved bits in the security-control field were non-zero.
    InvalidScfReserved,
    /// The encoded MIC size is not assigned.
    InvalidMicSize(u8),
    /// A flood-hop byte could not be interpreted.
    InvalidFloodHops,
    /// A CoAP-style option nibble used an invalid extension marker.
    InvalidOptionNibble,
    /// An option block was missing its terminating marker.
    MissingOptionTerminator,
    /// Option numbers were not monotonically increasing.
    OptionOutOfOrder,
    /// The option stream was structurally malformed.
    MalformedOption,
}

/// Errors returned while encoding wire-format values into caller-provided buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The provided buffer could not hold the encoded output.
    BufferTooSmall,
    /// Option numbers were encoded out of order.
    OptionOutOfOrder,
    /// A single option value exceeded the codec's supported length.
    OptionValueTooLarge,
}

/// Errors returned while assembling a full packet with [`crate::PacketBuilder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The destination buffer could not hold the packet.
    BufferTooSmall,
    /// A required source address was not supplied.
    MissingSource,
    /// A required destination field was not supplied.
    MissingDestination,
    /// A required channel identifier was not supplied.
    MissingChannel,
    /// A secured packet was missing its frame counter.
    MissingFrameCounter,
    /// A builder path that requires payload bytes was finalized without payload.
    MissingPayload,
    /// A MAC ACK builder was finalized without an ACK tag.
    MissingAckTag,
    /// Options were added in descending order.
    OptionOutOfOrder,
    /// Builder output failed structural validation.
    InvalidPacket,
}

impl From<EncodeError> for BuildError {
    fn from(value: EncodeError) -> Self {
        match value {
            EncodeError::BufferTooSmall => Self::BufferTooSmall,
            EncodeError::OptionOutOfOrder => Self::OptionOutOfOrder,
            EncodeError::OptionValueTooLarge => Self::BufferTooSmall,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

#[cfg(feature = "std")]
impl std::error::Error for BuildError {}
