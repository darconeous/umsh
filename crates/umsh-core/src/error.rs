use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    InvalidVersion(u8),
    InvalidScfReserved,
    InvalidMicSize(u8),
    InvalidFloodHops,
    InvalidOptionNibble,
    MissingOptionTerminator,
    OptionOutOfOrder,
    MalformedOption,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall,
    OptionOutOfOrder,
    OptionValueTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    BufferTooSmall,
    MissingSource,
    MissingDestination,
    MissingChannel,
    MissingFrameCounter,
    MissingPayload,
    MissingAckTag,
    OptionOutOfOrder,
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
