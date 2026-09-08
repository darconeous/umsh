//! On-demand announcement requests (`CMD_ANNOUNCE`).
//!
//! The payload is an option list in the `CMD_PROP_MULTI_SET` entry form
//! (`LENGTH | OPTION | VALUE`), so an empty payload is a well-formed
//! request carrying every default: an advertisement, broadcast, with no
//! flood budget. Every option the device does not recognize is an error
//! rather than something to ignore—a host that asked for a multicast
//! must not get a broadcast on the air instead.

use crate::frame::{FrameWriter, MultiEntries, WriteError};
use crate::ids::MAX_ANNOUNCE_FLOOD_HOPS;
use crate::items::CHANNEL_IDENTIFIER_LEN;
use crate::status::Status;

/// `CMD_ANNOUNCE` payload options.
pub mod opt {
    /// `ANNOUNCE_KIND`—UINT8, 0 advertisement, 1 beacon.
    pub const KIND: u32 = 1;
    /// `ANNOUNCE_FLOOD_HOPS`—UINT8, the flood budget, 0 to 15.
    pub const FLOOD_HOPS: u32 = 2;
    /// `ANNOUNCE_FULL_SOURCE`—BOOL, whether `SRC` carries the full
    /// public key rather than the node hint.
    pub const FULL_SOURCE: u32 = 3;
    /// `ANNOUNCE_CHANNEL`—the 16-octet channel identifier of the device
    /// channel to send on. Absent, the announcement is a broadcast.
    pub const CHANNEL: u32 = 4;
}

/// What an announcement carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnnouncementKind {
    /// The device's signed node identity.
    #[default]
    Advertisement = 0,
    /// No payload; a beacon publishes a path, not an identity.
    Beacon = 1,
}

impl AnnouncementKind {
    /// The wire code for this kind.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Strict conversion from a decoded wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Advertisement),
            1 => Some(Self::Beacon),
            _ => None,
        }
    }

    /// Whether this kind sends the full public key as `SRC` when the
    /// host does not say.
    ///
    /// An advertisement's detached signature is only checkable against
    /// the full key, so it defaults to carrying one; a beacon has
    /// nothing to check and defaults to the hint.
    pub const fn defaults_to_full_source(self) -> bool {
        matches!(self, Self::Advertisement)
    }
}

/// Why a `CMD_ANNOUNCE` payload could not be honored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnounceError {
    /// An unrecognized or repeated option, or a value of the wrong
    /// length or out of range.
    Invalid,
    /// The entry list itself is malformed.
    Parse,
}

impl AnnounceError {
    /// The status a device answers with.
    pub const fn status(self) -> Status {
        match self {
            Self::Invalid => Status::INVALID_ARGUMENT,
            Self::Parse => Status::PARSE_ERROR,
        }
    }
}

/// A parsed `CMD_ANNOUNCE` request, with absent options resolved to
/// their defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub kind: AnnouncementKind,
    /// The flood budget. Zero reaches only nodes that hear the device
    /// directly.
    pub flood_hops: u8,
    /// Whether `SRC` carries the full public key.
    pub full_source: bool,
    /// The channel to send on, named by its full channel identifier.
    /// `None` is a broadcast.
    pub channel: Option<[u8; CHANNEL_IDENTIFIER_LEN]>,
}

impl Default for Announcement {
    fn default() -> Self {
        Self::new(AnnouncementKind::Advertisement)
    }
}

impl Announcement {
    /// An announcement of `kind` with every other option at its default.
    pub const fn new(kind: AnnouncementKind) -> Self {
        Self {
            kind,
            flood_hops: 0,
            full_source: kind.defaults_to_full_source(),
            channel: None,
        }
    }

    /// Whether this announcement floods beyond the device's neighbors.
    pub const fn floods(&self) -> bool {
        self.flood_hops > 0
    }

    /// Decode a `CMD_ANNOUNCE` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, AnnounceError> {
        let mut request = Self::default();
        let mut seen = 0u32;

        for entry in MultiEntries::new(payload) {
            let entry = entry.map_err(|_| AnnounceError::Parse)?;
            let bit = match entry.key {
                opt::KIND | opt::FLOOD_HOPS | opt::FULL_SOURCE | opt::CHANNEL => 1u32 << entry.key,
                _ => return Err(AnnounceError::Invalid),
            };
            if seen & bit != 0 {
                return Err(AnnounceError::Invalid);
            }
            seen |= bit;

            match (entry.key, entry.value) {
                (opt::KIND, &[code]) => {
                    request.kind =
                        AnnouncementKind::from_code(code).ok_or(AnnounceError::Invalid)?;
                }
                (opt::FLOOD_HOPS, &[hops]) if hops <= MAX_ANNOUNCE_FLOOD_HOPS => {
                    request.flood_hops = hops;
                }
                (opt::FULL_SOURCE, &[0]) => request.full_source = false,
                (opt::FULL_SOURCE, &[1]) => request.full_source = true,
                (opt::CHANNEL, value) => {
                    let identifier = value.try_into().map_err(|_| AnnounceError::Invalid)?;
                    request.channel = Some(identifier);
                }
                _ => return Err(AnnounceError::Invalid),
            }
        }

        if seen & (1 << opt::FULL_SOURCE) == 0 {
            request.full_source = request.kind.defaults_to_full_source();
        }
        Ok(request)
    }

    /// Append this request's options to a frame, omitting those left at
    /// their defaults.
    pub fn write(&self, writer: &mut FrameWriter<'_>) -> Result<(), WriteError> {
        if self.kind != AnnouncementKind::Advertisement {
            writer.write_entry(opt::KIND, &[self.kind.code()])?;
        }
        if self.flood_hops != 0 {
            writer.write_entry(opt::FLOOD_HOPS, &[self.flood_hops])?;
        }
        if self.full_source != self.kind.defaults_to_full_source() {
            writer.write_entry(opt::FULL_SOURCE, &[u8::from(self.full_source)])?;
        }
        if let Some(channel) = &self.channel {
            writer.write_entry(opt::CHANNEL, channel)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{self, Cmd, Frame};

    fn round_trip(request: &Announcement) -> Announcement {
        let mut buf = [0u8; 64];
        let len = frame::announce(&mut buf, 3, request).unwrap();
        let parsed = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::Announce));
        assert_eq!(parsed.header.tid(), 3);
        Announcement::parse(parsed.payload).unwrap()
    }

    #[test]
    fn an_empty_payload_is_a_neighbor_advertisement() {
        let request = Announcement::parse(&[]).unwrap();
        assert_eq!(request.kind, AnnouncementKind::Advertisement);
        assert_eq!(request.flood_hops, 0);
        assert!(request.full_source);
        assert_eq!(request.channel, None);
        assert!(!request.floods());
        assert_eq!(request, Announcement::default());

        // The defaults cost nothing on the wire.
        let mut buf = [0u8; 8];
        assert_eq!(frame::announce(&mut buf, 0, &request).unwrap(), 2);
    }

    #[test]
    fn a_beacon_defaults_to_the_source_hint() {
        let request = Announcement::new(AnnouncementKind::Beacon);
        assert!(!request.full_source);
        assert_eq!(round_trip(&request), request);

        // The kind's default is applied whichever order the options
        // arrive in.
        let mut buf = [0u8; 32];
        let mut writer = FrameWriter::new(&mut buf, 0, Cmd::Announce).unwrap();
        writer.write_entry(opt::FLOOD_HOPS, &[4]).unwrap();
        writer
            .write_entry(opt::KIND, &[AnnouncementKind::Beacon.code()])
            .unwrap();
        let len = writer.finish();
        let parsed = Announcement::parse(Frame::parse(&buf[..len]).unwrap().payload).unwrap();
        assert_eq!(parsed.kind, AnnouncementKind::Beacon);
        assert!(!parsed.full_source);
        assert_eq!(parsed.flood_hops, 4);
    }

    #[test]
    fn every_option_round_trips() {
        let requests = [
            Announcement::default(),
            Announcement {
                kind: AnnouncementKind::Beacon,
                flood_hops: MAX_ANNOUNCE_FLOOD_HOPS,
                full_source: true,
                channel: Some([0xAB; CHANNEL_IDENTIFIER_LEN]),
            },
            Announcement {
                kind: AnnouncementKind::Advertisement,
                flood_hops: 5,
                full_source: false,
                channel: None,
            },
        ];
        for request in requests {
            assert_eq!(round_trip(&request), request);
        }
    }

    #[test]
    fn unknown_and_repeated_options_are_refused() {
        let mut buf = [0u8; 32];

        let mut writer = FrameWriter::new(&mut buf, 0, Cmd::Announce).unwrap();
        writer.write_entry(9, &[0]).unwrap();
        let len = writer.finish();
        assert_eq!(
            Announcement::parse(Frame::parse(&buf[..len]).unwrap().payload),
            Err(AnnounceError::Invalid)
        );

        let mut writer = FrameWriter::new(&mut buf, 0, Cmd::Announce).unwrap();
        writer.write_entry(opt::FLOOD_HOPS, &[1]).unwrap();
        writer.write_entry(opt::FLOOD_HOPS, &[2]).unwrap();
        let len = writer.finish();
        assert_eq!(
            Announcement::parse(Frame::parse(&buf[..len]).unwrap().payload),
            Err(AnnounceError::Invalid)
        );
    }

    #[test]
    fn out_of_range_and_misshaped_values_are_refused() {
        let cases: [(u32, &[u8]); 6] = [
            (opt::KIND, &[2]),
            (opt::KIND, &[]),
            (opt::FLOOD_HOPS, &[MAX_ANNOUNCE_FLOOD_HOPS + 1]),
            (opt::FULL_SOURCE, &[2]),
            (opt::CHANNEL, &[0xAB; 3]),
            (opt::CHANNEL, &[0xAB; CHANNEL_IDENTIFIER_LEN + 1]),
        ];
        for (key, value) in cases {
            let mut buf = [0u8; 32];
            let mut writer = FrameWriter::new(&mut buf, 0, Cmd::Announce).unwrap();
            writer.write_entry(key, value).unwrap();
            let len = writer.finish();
            assert_eq!(
                Announcement::parse(Frame::parse(&buf[..len]).unwrap().payload),
                Err(AnnounceError::Invalid),
                "option {key} value {value:?}"
            );
        }
    }

    #[test]
    fn a_truncated_entry_list_is_a_parse_error() {
        // An entry claiming four bytes with two present.
        assert_eq!(
            Announcement::parse(&[4, opt::FLOOD_HOPS as u8, 1]),
            Err(AnnounceError::Parse)
        );
    }

    #[test]
    fn errors_carry_the_status_the_device_answers() {
        assert_eq!(AnnounceError::Invalid.status(), Status::INVALID_ARGUMENT);
        assert_eq!(AnnounceError::Parse.status(), Status::PARSE_ERROR);
    }
}
