//! Reading what a device answered.
//!
//! A device answers a property request with the property, or with
//! `PROP_LAST_STATUS` standing in its place — refused, absent, out of
//! reach. Every reader of a reply has to tell those two apart before it can
//! do anything with the bytes, and a multi-property answer has to do it per
//! position, against the keys that were asked for. That reasoning lives
//! here rather than in each caller.
//!
//! Nothing is copied: an [`Answer`] borrows from the reply it was read out
//! of.

use crate::frame::{Cmd, Frame, MultiEntries, ParseError, PropPayload};
use crate::ids::prop;
use crate::pui;
use crate::status::Status;

/// What occupied one position of a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// The property's value, as the device reports it.
    Value(&'a [u8]),
    /// A status where a value was asked for.
    Refused(Status),
}

impl<'a> Answer<'a> {
    /// The value, or `None` when a status stood in for it.
    pub const fn value(self) -> Option<&'a [u8]> {
        match self {
            Self::Value(value) => Some(value),
            Self::Refused(_) => None,
        }
    }

    /// The status, or `None` when the device answered with a value.
    pub const fn status(self) -> Option<Status> {
        match self {
            Self::Value(_) => None,
            Self::Refused(status) => Some(status),
        }
    }

    /// Read one position: `PROP_LAST_STATUS` where something else was
    /// asked for is a refusal, and anywhere else it is the value.
    fn read(requested: u32, key: u32, value: &'a [u8]) -> Self {
        if key == prop::LAST_STATUS && requested != prop::LAST_STATUS {
            // A malformed status is still a refusal; there is no value
            // here either way.
            let status = pui::decode(value)
                .map(|(code, _)| Status(code))
                .unwrap_or(Status::FAILURE);
            Self::Refused(status)
        } else {
            Self::Value(value)
        }
    }
}

/// The status a bare `PROP_LAST_STATUS` reply reports, if that is what
/// this frame is.
pub fn status_of(reply: &[u8]) -> Option<Status> {
    let parsed = Frame::parse(reply).ok()?;
    if parsed.command() != Some(Cmd::PropIs) {
        return None;
    }
    let payload = PropPayload::parse(parsed.payload).ok()?;
    if payload.key != prop::LAST_STATUS {
        return None;
    }
    Some(Status(pui::decode(payload.value).ok()?.0))
}

/// Read a single-property reply against the property that was asked for.
pub fn property(requested: u32, reply: &[u8]) -> Result<Answer<'_>, ParseError> {
    let parsed = Frame::parse(reply)?;
    let payload = PropPayload::parse(parsed.payload)?;
    Ok(Answer::read(requested, payload.key, payload.value))
}

/// Why a multi-property reply could not be read as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntriesError {
    /// The reply is a well-formed frame, but not a `CMD_PROP_ARE`. A
    /// device without `CAP_CMD_MULTI` declines the whole request this way,
    /// answering with the status [`status_of`] reads.
    NotEntries,
    /// The reply is not a readable frame.
    Unreadable(ParseError),
}

impl From<ParseError> for EntriesError {
    fn from(error: ParseError) -> Self {
        Self::Unreadable(error)
    }
}

/// Split a `CMD_PROP_ARE` into per-position answers, paired with the keys
/// they were asked for.
///
/// A device may answer fewer positions than were asked for — it stops
/// before a reply overflows rather than truncating one — so the iterator
/// simply ends, and the caller reissues whatever is left over.
pub fn entries<'a>(
    requested: &'a [u32],
    reply: &'a [u8],
) -> Result<impl Iterator<Item = Result<(u32, Answer<'a>), ParseError>> + 'a, EntriesError> {
    let parsed = Frame::parse(reply)?;
    if parsed.command() != Some(Cmd::PropAre) {
        return Err(EntriesError::NotEntries);
    }
    Ok(MultiEntries::new(parsed.payload)
        .enumerate()
        .map(move |(position, entry)| {
            let entry = entry?;
            // Past the end of what was asked for, the entry names itself.
            let key = requested.get(position).copied().unwrap_or(entry.key);
            Ok((key, Answer::read(key, entry.key, entry.value)))
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    fn is(key: u32, value: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 128];
        let len = frame::prop_is(&mut buf, 3, key, value).unwrap();
        buf[..len].to_vec()
    }

    #[test]
    fn a_status_in_place_of_a_value_reads_as_a_refusal() {
        let reply = is(prop::LAST_STATUS, &[Status::PROP_NOT_FOUND.0 as u8]);
        assert_eq!(
            property(prop::DEV_NAME, &reply).unwrap(),
            Answer::Refused(Status::PROP_NOT_FOUND)
        );
        // Asked for outright, the status is the value.
        assert_eq!(
            property(prop::LAST_STATUS, &reply).unwrap(),
            Answer::Value(&[Status::PROP_NOT_FOUND.0 as u8])
        );
        assert_eq!(status_of(&reply), Some(Status::PROP_NOT_FOUND));
    }

    #[test]
    fn each_position_is_read_against_the_key_it_answers() {
        let mut buf = [0u8; 128];
        let mut writer = frame::prop_are(&mut buf, 3).unwrap();
        writer.write_entry(prop::DEV_NAME, b"Ridge").unwrap();
        writer.write_status_entry(Status::PROP_NOT_FOUND).unwrap();
        let len = writer.finish();
        let reply = &buf[..len];

        let requested = [prop::DEV_NAME, prop::HOST_KEY];
        let read: Vec<_> = entries(&requested, reply)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            read,
            vec![
                (prop::DEV_NAME, Answer::Value(b"Ridge".as_slice())),
                (prop::HOST_KEY, Answer::Refused(Status::PROP_NOT_FOUND)),
            ]
        );
    }

    #[test]
    fn a_device_that_declined_the_command_is_not_an_entry_list() {
        let reply = is(prop::LAST_STATUS, &[Status::UNIMPLEMENTED.0 as u8]);
        assert!(entries(&[prop::DEV_NAME], &reply).is_err());
        assert_eq!(status_of(&reply), Some(Status::UNIMPLEMENTED));
    }
}
