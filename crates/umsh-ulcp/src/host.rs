//! Transport-independent host transaction primitives.
//!
//! These small state/value types are shared by desktop and mobile hosts so
//! transaction identifiers and property-notification classification cannot
//! drift between otherwise platform-specific session drivers.

use crate::frame::{self, Cmd, Frame, PropPayload};

/// Cyclic allocator for the non-zero ULCP transaction identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TidAllocator {
    next: u8,
}

impl TidAllocator {
    /// Start a fresh protocol session at transaction identifier 1.
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    /// Allocate the next identifier, wrapping from `TID_MAX` back to 1.
    pub fn allocate(&mut self) -> u8 {
        let tid = self.next;
        self.next = if tid >= frame::TID_MAX { 1 } else { tid + 1 };
        tid
    }
}

impl Default for TidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Which property notification command carried a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropertyNotificationKind {
    Is,
    Inserted,
    Removed,
    /// `CMD_PROP_ARE`: several properties at once. Its payload is a
    /// list of entries rather than one key and value, so it has no
    /// [`PropertyNotification`] form — iterate it with
    /// [`crate::frame::MultiEntries`].
    Are,
}

impl PropertyNotificationKind {
    pub const fn from_command(command: Cmd) -> Option<Self> {
        match command {
            Cmd::PropIs => Some(Self::Is),
            Cmd::PropInserted => Some(Self::Inserted),
            Cmd::PropRemoved => Some(Self::Removed),
            Cmd::PropAre => Some(Self::Are),
            _ => None,
        }
    }

    /// The command this kind was decoded from.
    pub const fn command(self) -> Cmd {
        match self {
            Self::Is => Cmd::PropIs,
            Self::Inserted => Cmd::PropInserted,
            Self::Removed => Cmd::PropRemoved,
            Self::Are => Cmd::PropAre,
        }
    }

    /// Whether this notification carries one key and value.
    pub const fn is_single_property(self) -> bool {
        !matches!(self, Self::Are)
    }
}

/// A validated property notification borrowing its value from the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyNotification<'a> {
    pub tid: u8,
    pub kind: PropertyNotificationKind,
    pub key: u32,
    pub value: &'a [u8],
}

impl<'a> PropertyNotification<'a> {
    /// Parse exactly the three property notification commands accepted by a
    /// host session. Requests, streams, and unknown commands are rejected.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PropertyNotificationError> {
        let frame = Frame::parse(bytes).map_err(|_| PropertyNotificationError::MalformedFrame)?;
        Self::from_frame(&frame)
    }

    pub fn from_frame(frame: &Frame<'a>) -> Result<Self, PropertyNotificationError> {
        let kind = frame
            .command()
            .and_then(PropertyNotificationKind::from_command)
            .filter(|kind| kind.is_single_property())
            .ok_or(PropertyNotificationError::UnexpectedCommand)?;
        let payload = PropPayload::parse(frame.payload)
            .map_err(|_| PropertyNotificationError::MalformedPayload)?;
        Ok(Self {
            tid: frame.header.tid(),
            kind,
            key: payload.key,
            value: payload.value,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropertyNotificationError {
    MalformedFrame,
    UnexpectedCommand,
    MalformedPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_ids_never_allocate_zero() {
        let mut allocator = TidAllocator::new();
        let ids: [u8; 10] = core::array::from_fn(|_| allocator.allocate());
        assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 1, 2, 3]);
    }

    #[test]
    fn parses_property_notification() {
        let mut bytes = [0; 16];
        let len = frame::prop_is(&mut bytes, 3, 0x1234, &[5, 6]).unwrap();
        assert_eq!(
            PropertyNotification::parse(&bytes[..len]).unwrap(),
            PropertyNotification {
                tid: 3,
                kind: PropertyNotificationKind::Is,
                key: 0x1234,
                value: &[5, 6],
            }
        );
    }

    #[test]
    fn multi_property_notifications_have_no_single_property_form() {
        let mut bytes = [0; 32];
        let mut writer = frame::prop_are(&mut bytes, 2).unwrap();
        writer.write_entry(0x1234, &[7]).unwrap();
        let len = writer.finish();
        assert_eq!(
            PropertyNotification::parse(&bytes[..len]),
            Err(PropertyNotificationError::UnexpectedCommand)
        );
        assert_eq!(
            PropertyNotificationKind::from_command(Cmd::PropAre),
            Some(PropertyNotificationKind::Are)
        );
        assert!(!PropertyNotificationKind::Are.is_single_property());
    }

    #[test]
    fn rejects_non_property_command() {
        let mut bytes = [0; 8];
        let len = frame::save(&mut bytes, 1).unwrap();
        assert_eq!(
            PropertyNotification::parse(&bytes[..len]),
            Err(PropertyNotificationError::UnexpectedCommand)
        );
    }
}
