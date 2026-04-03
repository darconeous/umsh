use core::fmt;

use umsh_core::{EncodeError as CoreEncodeError, ParseError as CoreParseError, PacketType};

/// Error returned when parsing application-layer payloads or UMSH URIs.
///
/// This type wraps lower-level `umsh-core` parse failures and adds validation
/// errors for application-specific fields such as message kinds, command IDs,
/// UTF-8 bodies, and URI/base58 content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Propagated `umsh-core` parse error.
    Core(CoreParseError),
    /// A field that must be valid UTF-8 was not valid UTF-8.
    InvalidUtf8,
    /// The leading payload-type byte is not assigned by the current protocol.
    InvalidPayloadType(u8),
    /// The payload type is known, but it is invalid for the given packet type.
    PayloadTypeNotAllowed { payload_type: u8, packet_type: PacketType },
    /// The text-message type byte is not one of the registered values.
    InvalidMessageType(u8),
    /// The node-role byte is reserved or otherwise invalid.
    InvalidRole(u8),
    /// The MAC-command byte is not one of the registered values.
    InvalidCommandId(u8),
    /// The chat-room action byte is not one of the registered values.
    InvalidChatAction(u8),
    /// An option payload or fixed-width field had an invalid encoding.
    InvalidOptionValue,
    /// The supplied URI is not a valid `umsh:` URI for this crate.
    InvalidUri,
    /// Base58 decoding failed.
    InvalidBase58,
    /// A field had the wrong byte length.
    InvalidLength { expected: usize, actual: usize },
}

impl From<CoreParseError> for ParseError {
    fn from(value: CoreParseError) -> Self {
        Self::Core(value)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Error returned when encoding application-layer payloads or UMSH URIs.
///
/// Most failures are either buffer-capacity problems or invalid field
/// combinations that cannot be represented on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Propagated `umsh-core` encoding error.
    Core(CoreEncodeError),
    /// The destination buffer was too small for the encoded output.
    BufferTooSmall,
    /// The provided field combination is structurally invalid.
    InvalidField,
}

impl From<CoreEncodeError> for EncodeError {
    fn from(value: CoreEncodeError) -> Self {
        Self::Core(value)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}