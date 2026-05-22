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
    InvalidLength {
        expected: usize,
        actual: usize,
    },
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

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_core::{EncodeError, ParseError};

    #[test]
    fn app_parse_error_from_core() {
        let e = AppParseError::from(ParseError::Truncated);
        assert_eq!(e, AppParseError::Core(ParseError::Truncated));
    }

    #[test]
    fn app_encode_error_from_core() {
        let e = AppEncodeError::from(EncodeError::BufferTooSmall);
        assert_eq!(e, AppEncodeError::Core(EncodeError::BufferTooSmall));
    }

    #[test]
    fn display_delegates_to_debug() {
        let e = AppParseError::InvalidUtf8;
        assert_eq!(alloc::format!("{e}"), alloc::format!("{e:?}"));

        let e = AppEncodeError::BufferTooSmall;
        assert_eq!(alloc::format!("{e}"), alloc::format!("{e:?}"));
    }
}
