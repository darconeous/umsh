use core::fmt;

use umsh_core::{EncodeError as CoreEncodeError, PacketType, ParseError as CoreParseError};

/// Error returned when parsing or validating text payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Propagated `umsh-core` parse error.
    Core(CoreParseError),
    /// A field that must be valid UTF-8 was not valid UTF-8.
    InvalidUtf8,
    /// The leading payload-type byte did not identify a text payload.
    InvalidPayloadType(u8),
    /// The payload type is known, but it is invalid for the given packet type.
    PayloadTypeNotAllowed {
        payload_type: u8,
        packet_type: PacketType,
    },
    /// The text-message type byte is not one of the registered values.
    InvalidMessageType(u8),
    /// An option payload or fixed-width field had an invalid encoding.
    InvalidOptionValue,
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

/// Error returned when encoding text payloads.
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

/// Error returned when sending a text payload through a transport wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextSendError<E> {
    /// Text-payload encoding failed before the transport was called.
    Encode(EncodeError),
    /// The underlying transport send failed.
    Transport(E),
}

impl<E> From<EncodeError> for TextSendError<E> {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

impl<E> fmt::Display for TextSendError<E>
where
    E: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

#[cfg(feature = "std")]
impl<E> std::error::Error for TextSendError<E> where E: fmt::Debug + fmt::Display + 'static {}
