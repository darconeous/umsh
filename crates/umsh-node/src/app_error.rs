use core::fmt;

use umsh_core::{EncodeError as CoreEncodeError, PacketType, ParseError as CoreParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppParseError {
    Core(CoreParseError),
    InvalidUtf8,
    InvalidPayloadType(u8),
    PayloadTypeNotAllowed {
        payload_type: u8,
        packet_type: PacketType,
    },
    InvalidRole(u8),
    InvalidCommandId(u8),
    InvalidOptionValue,
    InvalidLength { expected: usize, actual: usize },
}

impl From<CoreParseError> for AppParseError {
    fn from(value: CoreParseError) -> Self {
        Self::Core(value)
    }
}

impl fmt::Display for AppParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppEncodeError {
    Core(CoreEncodeError),
    BufferTooSmall,
    InvalidField,
}

impl From<CoreEncodeError> for AppEncodeError {
    fn from(value: CoreEncodeError) -> Self {
        Self::Core(value)
    }
}

impl fmt::Display for AppEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AppParseError {}

#[cfg(feature = "std")]
impl std::error::Error for AppEncodeError {}
