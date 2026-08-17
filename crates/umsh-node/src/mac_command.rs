use alloc::vec::Vec;

use umsh_core::options::{OptionDecoder, OptionEncoder, parse_be_u32};
use umsh_core::{NodeHint, PublicKey};

use crate::app_util::{copy_into, fixed, push_byte};
use crate::identity::{NodeCapabilities, NodeRole};
use crate::{AppEncodeError, AppParseError};

/// Option keys carried in an [`MacCommand::IdentityRequest`] payload.
///
/// Keys follow the CoAP convention: an odd key (least-significant bit set) is
/// **critical**, so a responder that does not understand it MUST NOT respond.
/// All currently defined keys are critical. `NONCE` is a correlation
/// identifier rather than a filter and does not participate in filter matching.
pub mod identity_filter {
    /// Correlation identifier the responder echoes into the identity Nonce
    /// option (identity option 5). 4 bytes. Not a filter.
    pub const NONCE: u16 = 1;
    /// Match only nodes whose own [node hint](umsh_core::NodeHint) starts with
    /// this value. 1 to 3 bytes; a 2-byte value is a
    /// [router hint](umsh_core::RouterHint).
    pub const FILTER_NODE_HINT: u16 = 3;
    /// Match only nodes whose primary role equals this value. 1 byte.
    pub const FILTER_NODE_ROLE: u16 = 5;
    /// Match only nodes whose capability bitmap has every bit set that is set
    /// in this value. 1 byte.
    pub const FILTER_NODE_CAPS: u16 = 7;
}

/// Option keys carried in a [`MacCommand::PeerRepeatersRequest`] payload.
///
/// Both keys are even, so a responder that does not understand one ignores it
/// rather than declining to answer.
pub mod peer_repeaters_request {
    /// Correlation identifier the responder echoes into its response. 2 bytes.
    pub const NONCE: u16 = 0;
    /// Resume token copied verbatim from a previous response's `CURSOR`.
    /// Absent on the first request of an enumeration.
    pub const CURSOR: u16 = 1;
}

/// Option keys carried in a [`MacCommand::PeerRepeatersResponse`]'s leading
/// option block, before the `0xFF` that introduces the entries.
pub mod peer_repeaters_response {
    /// Copied verbatim from the request; present only when the request
    /// carried one. 2 bytes.
    pub const NONCE: u16 = 0;
    /// Opaque resume token for the next page. Absent on the final page.
    pub const CURSOR: u16 = 1;
    /// Entries in the whole list, not the page. 1 byte.
    pub const TOTAL: u16 = 2;
}

/// Option keys carried in one peer-repeater entry.
///
/// An option the responder has no value for is omitted, so every one but the
/// hint is optional.
pub mod peer_repeater_entry {
    /// The peer's node hint: 3 bytes when the responder holds the whole of
    /// it, or the 2-byte router hint when that is all it has observed.
    pub const NODE_HINT: u16 = 0;
    /// The peer's display name, as learned from its identity. UTF-8, at most
    /// 24 bytes.
    pub const NODE_NAME: u16 = 1;
    /// The most recent reception: RSSI as an unsigned negative-dBm value,
    /// then SNR in quarter-dB steps. 2 bytes.
    pub const RSSI_SNR: u16 = 2;
    /// Minutes since the peer was last heard, minimal big-endian. 1–2 bytes.
    pub const LAST_HEARD: u16 = 3;
    /// The peer's position in the variable-precision location format.
    pub const LOCATION: u16 = 4;
    /// The region codes the peer flood-forwards for, n × 2 bytes.
    pub const REGIONS: u16 = 5;
}

/// Length of a [`NodeHint`], the longest a `FILTER_NODE_HINT` value may be.
const NODE_HINT_LEN: usize = 3;

/// The shortest hint a peer-repeater entry may name a peer by: the 2-byte
/// router hint a trace or source route reveals.
const ROUTER_HINT_LEN: usize = 2;

/// Longest peer name a peer-repeater entry carries.
pub const PEER_REPEATER_NAME_MAX_LEN: usize = 24;

/// The shortest `FILTER_NODE_HINT` that names a node rather than a share of
/// the mesh.
///
/// Two bytes is one node in 65,536 and three is one in 16.7 million, either of
/// which is unique across any plausible mesh. One byte is one node in 256 — a
/// fraction, not a name.
const UNIQUE_HINT_PREFIX_LEN: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    IdentityRequest = 1,
    SignalReportRequest = 2,
    SignalReportResponse = 3,
    EchoRequest = 4,
    EchoResponse = 5,
    PfsSessionRequest = 6,
    PfsSessionResponse = 7,
    EndPfsSession = 8,
    Noop = 9,
    PeerRepeatersRequest = 10,
    PeerRepeatersResponse = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacCommand<'a> {
    /// Request that the destination respond with its node identity.
    ///
    /// `options` is a CoAP-style option block of [`identity_filter`] keys,
    /// empty for a plain unicast request. Interpret it with
    /// [`IdentityRequestFilters`].
    IdentityRequest {
        options: &'a [u8],
    },
    SignalReportRequest,
    SignalReportResponse {
        rssi: u8,
        snr: i8,
    },
    EchoRequest {
        data: &'a [u8],
    },
    EchoResponse {
        data: &'a [u8],
    },
    PfsSessionRequest {
        ephemeral_key: umsh_core::PublicKey,
        duration_minutes: u16,
    },
    PfsSessionResponse {
        ephemeral_key: umsh_core::PublicKey,
        duration_minutes: u16,
    },
    EndPfsSession,
    /// Costs a frame and asks for nothing. Useful for keeping a session's
    /// counters moving and for proving a peer is still reachable.
    Noop,
    /// Ask the destination for its list of known peer repeaters.
    ///
    /// `options` is a CoAP-style option block of [`peer_repeaters_request`]
    /// keys, empty for the first page of an unnonced enumeration. Interpret
    /// it with [`PeerRepeatersRequestView`].
    PeerRepeatersRequest {
        options: &'a [u8],
    },
    /// One page of a peer-repeater list.
    ///
    /// `body` is the whole payload after the command id: the response's own
    /// option block, the `0xFF` end marker, then the entries. Interpret it
    /// with [`PeerRepeatersResponseView`].
    PeerRepeatersResponse {
        body: &'a [u8],
    },
}

pub fn parse(payload: &[u8]) -> Result<MacCommand<'_>, AppParseError> {
    let (&command_id, body) = payload
        .split_first()
        .ok_or(AppParseError::Core(umsh_core::ParseError::Truncated))?;

    match command_id {
        1 => {
            // Validate the option block is structurally well-formed CoAP
            // options; individual filter values are interpreted (and tolerated)
            // lazily by IdentityRequestFilters, per receiver tolerance.
            for item in OptionDecoder::new(body) {
                item.map_err(AppParseError::Core)?;
            }
            Ok(MacCommand::IdentityRequest { options: body })
        }
        2 => {
            if body.is_empty() {
                Ok(MacCommand::SignalReportRequest)
            } else {
                Err(AppParseError::InvalidOptionValue)
            }
        }
        3 => match body {
            [rssi, snr] => Ok(MacCommand::SignalReportResponse {
                rssi: *rssi,
                snr: *snr as i8,
            }),
            _ => Err(AppParseError::InvalidLength {
                expected: 2,
                actual: body.len(),
            }),
        },
        4 => Ok(MacCommand::EchoRequest { data: body }),
        5 => Ok(MacCommand::EchoResponse { data: body }),
        6 => parse_pfs(body, true),
        7 => parse_pfs(body, false),
        8 => {
            if body.is_empty() {
                Ok(MacCommand::EndPfsSession)
            } else {
                Err(AppParseError::InvalidOptionValue)
            }
        }
        // Nothing to read and nothing to do, so a body is nothing to reject
        // over either.
        9 => Ok(MacCommand::Noop),
        10 => {
            // Structurally well-formed options; values are interpreted
            // lazily by the view, per receiver tolerance.
            for item in OptionDecoder::new(body) {
                item.map_err(AppParseError::Core)?;
            }
            Ok(MacCommand::PeerRepeatersRequest { options: body })
        }
        // The entry list past the end marker is walked lazily: broken entry
        // framing ends the walk, keeping the entries decoded before it.
        11 => Ok(MacCommand::PeerRepeatersResponse { body }),
        other => Err(AppParseError::InvalidCommandId(other)),
    }
}

fn parse_pfs(payload: &[u8], request: bool) -> Result<MacCommand<'_>, AppParseError> {
    if payload.len() != 34 {
        return Err(AppParseError::InvalidLength {
            expected: 34,
            actual: payload.len(),
        });
    }
    let ephemeral_key = umsh_core::PublicKey(*fixed(&payload[..32])?);
    let duration_minutes = u16::from_be_bytes(*fixed(&payload[32..34])?);
    Ok(if request {
        MacCommand::PfsSessionRequest {
            ephemeral_key,
            duration_minutes,
        }
    } else {
        MacCommand::PfsSessionResponse {
            ephemeral_key,
            duration_minutes,
        }
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedMacCommand {
    IdentityRequest {
        options: Vec<u8>,
    },
    SignalReportRequest,
    SignalReportResponse {
        rssi: u8,
        snr: i8,
    },
    EchoRequest {
        data: Vec<u8>,
    },
    EchoResponse {
        data: Vec<u8>,
    },
    PfsSessionRequest {
        ephemeral_key: PublicKey,
        duration_minutes: u16,
    },
    PfsSessionResponse {
        ephemeral_key: PublicKey,
        duration_minutes: u16,
    },
    EndPfsSession,
    Noop,
    PeerRepeatersRequest {
        options: Vec<u8>,
    },
    PeerRepeatersResponse {
        body: Vec<u8>,
    },
}

impl From<MacCommand<'_>> for OwnedMacCommand {
    fn from(value: MacCommand<'_>) -> Self {
        match value {
            MacCommand::IdentityRequest { options } => Self::IdentityRequest {
                options: Vec::from(options),
            },
            MacCommand::SignalReportRequest => Self::SignalReportRequest,
            MacCommand::SignalReportResponse { rssi, snr } => {
                Self::SignalReportResponse { rssi, snr }
            }
            MacCommand::EchoRequest { data } => Self::EchoRequest {
                data: Vec::from(data),
            },
            MacCommand::EchoResponse { data } => Self::EchoResponse {
                data: Vec::from(data),
            },
            MacCommand::PfsSessionRequest {
                ephemeral_key,
                duration_minutes,
            } => Self::PfsSessionRequest {
                ephemeral_key,
                duration_minutes,
            },
            MacCommand::PfsSessionResponse {
                ephemeral_key,
                duration_minutes,
            } => Self::PfsSessionResponse {
                ephemeral_key,
                duration_minutes,
            },
            MacCommand::EndPfsSession => Self::EndPfsSession,
            MacCommand::Noop => Self::Noop,
            MacCommand::PeerRepeatersRequest { options } => Self::PeerRepeatersRequest {
                options: Vec::from(options),
            },
            MacCommand::PeerRepeatersResponse { body } => Self::PeerRepeatersResponse {
                body: Vec::from(body),
            },
        }
    }
}

pub fn encode(cmd: &MacCommand<'_>, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
    let mut pos = 0usize;
    match cmd {
        MacCommand::IdentityRequest { options } => {
            push_byte(buf, &mut pos, CommandId::IdentityRequest as u8)?;
            copy_into(buf, &mut pos, options)?;
        }
        MacCommand::SignalReportRequest => {
            push_byte(buf, &mut pos, CommandId::SignalReportRequest as u8)?;
        }
        MacCommand::SignalReportResponse { rssi, snr } => {
            push_byte(buf, &mut pos, CommandId::SignalReportResponse as u8)?;
            push_byte(buf, &mut pos, *rssi)?;
            push_byte(buf, &mut pos, *snr as u8)?;
        }
        MacCommand::EchoRequest { data } => {
            push_byte(buf, &mut pos, CommandId::EchoRequest as u8)?;
            copy_into(buf, &mut pos, data)?;
        }
        MacCommand::EchoResponse { data } => {
            push_byte(buf, &mut pos, CommandId::EchoResponse as u8)?;
            copy_into(buf, &mut pos, data)?;
        }
        MacCommand::PfsSessionRequest {
            ephemeral_key,
            duration_minutes,
        } => {
            push_byte(buf, &mut pos, CommandId::PfsSessionRequest as u8)?;
            copy_into(buf, &mut pos, &ephemeral_key.0)?;
            copy_into(buf, &mut pos, &duration_minutes.to_be_bytes())?;
        }
        MacCommand::PfsSessionResponse {
            ephemeral_key,
            duration_minutes,
        } => {
            push_byte(buf, &mut pos, CommandId::PfsSessionResponse as u8)?;
            copy_into(buf, &mut pos, &ephemeral_key.0)?;
            copy_into(buf, &mut pos, &duration_minutes.to_be_bytes())?;
        }
        MacCommand::EndPfsSession => push_byte(buf, &mut pos, CommandId::EndPfsSession as u8)?,
        MacCommand::Noop => push_byte(buf, &mut pos, CommandId::Noop as u8)?,
        MacCommand::PeerRepeatersRequest { options } => {
            push_byte(buf, &mut pos, CommandId::PeerRepeatersRequest as u8)?;
            copy_into(buf, &mut pos, options)?;
        }
        MacCommand::PeerRepeatersResponse { body } => {
            push_byte(buf, &mut pos, CommandId::PeerRepeatersResponse as u8)?;
            copy_into(buf, &mut pos, body)?;
        }
    }
    Ok(pos)
}

/// Interprets the option block of an [`MacCommand::IdentityRequest`].
///
/// Borrows the raw block and decodes its [`identity_filter`] options on demand.
/// A responder uses [`nonce`](Self::nonce) to obtain the correlation value it
/// must echo, and [`selects`](Self::selects) to decide whether it is a target
/// of the request.
#[derive(Clone, Copy, Debug)]
pub struct IdentityRequestFilters<'a> {
    options: &'a [u8],
}

impl<'a> IdentityRequestFilters<'a> {
    /// Wrap the option block carried by an Identity Request.
    pub fn new(options: &'a [u8]) -> Self {
        Self { options }
    }

    /// The correlation nonce the responder must echo into its identity's Nonce
    /// option, or `None` if the request carried no `NONCE` option.
    ///
    /// Returns the first `NONCE` option; tolerates minimal (≤4 byte) encodings.
    pub fn nonce(&self) -> Result<Option<u32>, AppParseError> {
        for item in OptionDecoder::new(self.options) {
            let (number, value) = item.map_err(AppParseError::Core)?;
            if number == identity_filter::NONCE {
                return parse_be_u32(value).map(Some).map_err(AppParseError::Core);
            }
        }
        Ok(None)
    }

    /// Whether the request carries at least one `FILTER_NODE_HINT` filter.
    ///
    /// A hint filter names one node, or with a partial hint a handful, so such
    /// a request solicits few replies however far it travels. Without one the
    /// request selects by role or capability and every node it reaches may
    /// answer, which is what confines a broadcast or multicast solicitation —
    /// and its replies — to the requester's own neighborhood.
    ///
    /// A malformed option block reads as unfiltered, which is the conservative
    /// answer: it keeps the strict rules in force.
    pub fn hint_filtered(&self) -> bool {
        OptionDecoder::new(self.options)
            .map_while(Result::ok)
            .any(|(number, _)| number == identity_filter::FILTER_NODE_HINT)
    }

    /// Whether this request's hint filters name a node rather than a share of
    /// the mesh: at least one `FILTER_NODE_HINT` is present and every one of
    /// them is at least [`UNIQUE_HINT_PREFIX_LEN`] bytes.
    ///
    /// This is the question the reply's random hold turns on. The hold exists
    /// to keep many selected nodes from answering the same frame at once, so a
    /// request only one node can satisfy has nothing to spread and is answered
    /// straight away. A one-byte prefix selects a 256th of everything it
    /// reaches, which is a crowd, so it keeps the hold.
    ///
    /// Stricter than [`hint_filtered`](Self::hint_filtered), which asks only
    /// whether the request is aimed at all. Filters of the same type combine as
    /// OR, so one short filter widens the whole request and the shortest is
    /// what decides.
    ///
    /// A malformed option block reads as unnarrowed — the conservative answer,
    /// since it keeps the hold in force.
    pub fn hint_names_one_node(&self) -> bool {
        let mut named = false;
        for item in OptionDecoder::new(self.options) {
            let Ok((number, value)) = item else {
                return false;
            };
            if number == identity_filter::FILTER_NODE_HINT {
                if value.len() < UNIQUE_HINT_PREFIX_LEN {
                    return false;
                }
                named = true;
            }
        }
        named
    }

    /// Whether a node with the given identity is selected by this request.
    ///
    /// Filters combine as a logical AND across distinct filter types and a
    /// logical OR among repeated filters of the same type. An unknown
    /// **critical** option (odd key) excludes the node; unknown elective
    /// options are ignored. A well-formed request with no filters (a unicast
    /// request) selects every node.
    pub fn selects(
        &self,
        role: NodeRole,
        capabilities: NodeCapabilities,
        hint: &NodeHint,
    ) -> Result<bool, AppParseError> {
        // Per filter type: whether it appeared, and whether any value matched.
        let mut hint_present = false;
        let mut hint_match = false;
        let mut role_present = false;
        let mut role_match = false;
        let mut caps_present = false;
        let mut caps_match = false;

        for item in OptionDecoder::new(self.options) {
            let (number, value) = item.map_err(AppParseError::Core)?;
            match number {
                identity_filter::NONCE => {} // correlation id, not a filter
                identity_filter::FILTER_NODE_HINT => {
                    hint_present = true;
                    // A partial hint matches as a prefix of the node hint. That
                    // is what lets a two-byte router hint — the only name a
                    // route gives an intermediate hop — ask that hop to
                    // identify itself. An empty value matches nothing: it would
                    // otherwise select every node while `hint_filtered` reported
                    // the request narrowed to one.
                    hint_match |=
                        (1..=hint.0.len()).contains(&value.len()) && hint.0.starts_with(value);
                }
                identity_filter::FILTER_NODE_ROLE => {
                    role_present = true;
                    role_match |= value == [role.as_byte()];
                }
                identity_filter::FILTER_NODE_CAPS => {
                    caps_present = true;
                    // Match if the node has every requested bit set.
                    caps_match |= value.len() == 1 && (capabilities.bits() & value[0]) == value[0];
                }
                other if other & 1 == 1 => {
                    // Unknown critical option: assume we are excluded.
                    return Ok(false);
                }
                _ => {} // unknown elective option: ignore
            }
        }

        Ok((!hint_present || hint_match)
            && (!role_present || role_match)
            && (!caps_present || caps_match))
    }
}

/// Builds the option block for an [`MacCommand::IdentityRequest`].
///
/// Options are emitted in ascending key order, so callers must add the nonce
/// before any filters and add filters in key order. No `0xFF` end marker is
/// written: an Identity Request payload is options-only, with no trailing data.
#[derive(Debug, Default)]
pub struct IdentityRequestBuilder {
    buf: Vec<u8>,
    last_number: u16,
}

impl IdentityRequestBuilder {
    /// Start an empty builder (a plain unicast request until options are added).
    pub fn new() -> Self {
        Self::default()
    }

    fn put(mut self, number: u16, value: &[u8]) -> Result<Self, AppEncodeError> {
        // Encode one option into a scratch buffer, continuing the delta chain,
        // then append. Sized for the header plus the largest filter value.
        let mut scratch = [0u8; 8 + 4];
        let mut enc = OptionEncoder::with_last_number(&mut scratch, self.last_number);
        enc.put(number, value).map_err(AppEncodeError::Core)?;
        let n = enc.finish();
        self.buf.extend_from_slice(&scratch[..n]);
        self.last_number = number;
        Ok(self)
    }

    /// Add the `NONCE` correlation option. Add before any filters.
    pub fn nonce(self, nonce: u32) -> Result<Self, AppEncodeError> {
        self.put(identity_filter::NONCE, &nonce.to_be_bytes())
    }

    /// Add a `FILTER_NODE_HINT` filter (repeatable; repeats are OR-combined).
    pub fn filter_hint(self, hint: &NodeHint) -> Result<Self, AppEncodeError> {
        self.put(identity_filter::FILTER_NODE_HINT, &hint.0)
    }

    /// Add a `FILTER_NODE_HINT` filter that matches on a leading part of the
    /// node hint, for a caller that holds less than the whole of one — a route
    /// names its intermediate hops by a two-byte
    /// [router hint](umsh_core::RouterHint) and nothing more.
    ///
    /// Rejects an empty prefix, which would select every node, and one longer
    /// than a node hint, which would select none.
    pub fn filter_hint_prefix(self, prefix: &[u8]) -> Result<Self, AppEncodeError> {
        if !(1..=NODE_HINT_LEN).contains(&prefix.len()) {
            return Err(AppEncodeError::InvalidField);
        }
        self.put(identity_filter::FILTER_NODE_HINT, prefix)
    }

    /// Add a `FILTER_NODE_ROLE` filter (repeatable; repeats are OR-combined).
    pub fn filter_role(self, role: NodeRole) -> Result<Self, AppEncodeError> {
        self.put(identity_filter::FILTER_NODE_ROLE, &[role.as_byte()])
    }

    /// Add a `FILTER_NODE_CAPS` filter (repeatable; repeats are OR-combined).
    pub fn filter_caps(self, caps: NodeCapabilities) -> Result<Self, AppEncodeError> {
        self.put(identity_filter::FILTER_NODE_CAPS, &[caps.bits()])
    }

    /// Finish and return the encoded option block.
    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

/// Interprets the option block of a [`MacCommand::PeerRepeatersRequest`].
///
/// Borrows the raw block and decodes on demand. Both keys are elective, so an
/// option this does not understand is skipped rather than refused.
#[derive(Clone, Copy, Debug)]
pub struct PeerRepeatersRequestView<'a> {
    options: &'a [u8],
}

impl<'a> PeerRepeatersRequestView<'a> {
    pub fn new(options: &'a [u8]) -> Self {
        Self { options }
    }

    /// The correlation nonce to echo, or `None` when the request carried
    /// none. Tolerates a minimal (≤2 byte) encoding.
    pub fn nonce(&self) -> Option<u16> {
        self.find(peer_repeaters_request::NONCE)
            .and_then(parse_minimal_be_u16)
    }

    /// The opaque resume token, or `None` on the first request of an
    /// enumeration.
    pub fn cursor(&self) -> Option<&'a [u8]> {
        self.find(peer_repeaters_request::CURSOR)
    }

    fn find(&self, number: u16) -> Option<&'a [u8]> {
        OptionDecoder::new(self.options)
            .map_while(Result::ok)
            .find(|(key, _)| *key == number)
            .map(|(_, value)| value)
    }
}

/// Interprets the body of a [`MacCommand::PeerRepeatersResponse`]: the page's
/// own options, then the entries that follow the end marker.
#[derive(Clone, Copy, Debug)]
pub struct PeerRepeatersResponseView<'a> {
    body: &'a [u8],
}

impl<'a> PeerRepeatersResponseView<'a> {
    pub fn new(body: &'a [u8]) -> Self {
        Self { body }
    }

    /// The nonce copied from the request, present only when the request
    /// carried one.
    pub fn nonce(&self) -> Option<u16> {
        self.find(peer_repeaters_response::NONCE)
            .and_then(parse_minimal_be_u16)
    }

    /// The resume token for the next page. Absent on the final page, which
    /// is what ends an enumeration.
    pub fn cursor(&self) -> Option<&'a [u8]> {
        self.find(peer_repeaters_response::CURSOR)
    }

    /// Entries in the whole list, not this page. Required on the response to
    /// a cursorless request and optional afterwards.
    pub fn total(&self) -> Option<u8> {
        match self.find(peer_repeaters_response::TOTAL) {
            Some([total]) => Some(*total),
            _ => None,
        }
    }

    /// Walk the entries this page carries.
    ///
    /// A malformed entry ends the walk rather than the page: everything
    /// decoded before it is still an answer.
    pub fn entries(&self) -> PeerRepeaterEntries<'a> {
        let mut decoder = OptionDecoder::new(self.body);
        while decoder.next().is_some() {}
        PeerRepeaterEntries {
            rest: decoder.remainder(),
        }
    }

    fn find(&self, number: u16) -> Option<&'a [u8]> {
        OptionDecoder::new(self.body)
            .map_while(Result::ok)
            .find(|(key, _)| *key == number)
            .map(|(_, value)| value)
    }
}

/// Iterator over the entries of a [`PeerRepeatersResponseView`].
#[derive(Clone, Debug)]
pub struct PeerRepeaterEntries<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for PeerRepeaterEntries<'a> {
    type Item = PeerRepeaterEntryView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let mut decoder = OptionDecoder::new(self.rest);
        while decoder.next().is_some() {}
        // The decoder stops at this entry's `0xFF`; what it leaves is the
        // next entry. The final entry may omit its terminator, in which case
        // the decoder runs to the end and leaves nothing.
        let consumed = self.rest.len() - decoder.remainder().len();
        let (entry, rest) = self.rest.split_at(consumed);
        self.rest = rest;
        Some(PeerRepeaterEntryView { options: entry })
    }
}

/// One peer repeater, as a lazily decoded option list.
///
/// Every accessor returns `None` for an option the responder omitted or wrote
/// in a length this cannot read — a peer that names itself and nothing else is
/// a legitimate entry, and one bad field is not a reason to drop the rest.
#[derive(Clone, Copy, Debug)]
pub struct PeerRepeaterEntryView<'a> {
    options: &'a [u8],
}

impl<'a> PeerRepeaterEntryView<'a> {
    /// The peer's hint: 3 bytes for a whole node hint, 2 for a router hint.
    /// The only required option; an entry without one names nobody.
    pub fn hint(&self) -> Option<&'a [u8]> {
        self.find(peer_repeater_entry::NODE_HINT)
            .filter(|value| (ROUTER_HINT_LEN..=NODE_HINT_LEN).contains(&value.len()))
    }

    /// The peer's display name, as learned from its identity.
    pub fn name(&self) -> Option<&'a str> {
        self.find(peer_repeater_entry::NODE_NAME)
            .filter(|value| !value.is_empty() && value.len() <= PEER_REPEATER_NAME_MAX_LEN)
            .and_then(|value| core::str::from_utf8(value).ok())
    }

    /// The most recent reception: RSSI in dBm and SNR.
    pub fn rssi_snr(&self) -> Option<(i16, umsh_hal::Snr)> {
        match self.find(peer_repeater_entry::RSSI_SNR) {
            Some([rssi, snr]) => Some((
                -i16::from(*rssi),
                umsh_hal::Snr::from_quarter_db_steps(i16::from(*snr as i8)),
            )),
            _ => None,
        }
    }

    /// Minutes since the responder last heard the peer.
    pub fn last_heard_min(&self) -> Option<u16> {
        self.find(peer_repeater_entry::LAST_HEARD)
            .and_then(parse_minimal_be_u16)
    }

    /// The peer's position, in the variable-precision location format.
    pub fn location(&self) -> Option<crate::location::NodeLocation> {
        self.find(peer_repeater_entry::LOCATION)
            .filter(|value| !value.is_empty())
            .map(crate::location::NodeLocation::from_bytes)
    }

    /// The region codes the peer flood-forwards for.
    ///
    /// Codes rather than the strings an identity carries: the entry format is
    /// tighter on space, and the string form is available from the peer's own
    /// identity when one is wanted.
    pub fn regions(&self) -> impl Iterator<Item = [u8; 2]> + 'a {
        self.find(peer_repeater_entry::REGIONS)
            .unwrap_or(&[])
            .chunks_exact(2)
            .map(|code| [code[0], code[1]])
    }

    fn find(&self, number: u16) -> Option<&'a [u8]> {
        OptionDecoder::new(self.options)
            .map_while(Result::ok)
            .find(|(key, _)| *key == number)
            .map(|(_, value)| value)
    }
}

/// Decode a minimal big-endian unsigned integer of up to two octets.
///
/// The wire form drops leading zero octets, so a value under 256 arrives as
/// one byte and an absent value as none at all.
fn parse_minimal_be_u16(value: &[u8]) -> Option<u16> {
    match value {
        [] => Some(0),
        [low] => Some(u16::from(*low)),
        [high, low] => Some(u16::from_be_bytes([*high, *low])),
        _ => None,
    }
}

/// Builds the option block for a [`MacCommand::PeerRepeatersRequest`].
///
/// Options are emitted in ascending key order, so a nonce is added before a
/// cursor. No `0xFF` marker is written: the payload is options-only.
#[derive(Debug, Default)]
pub struct PeerRepeatersRequestBuilder {
    buf: Vec<u8>,
    last_number: u16,
}

impl PeerRepeatersRequestBuilder {
    /// Start an empty builder — the first page of an unnonced enumeration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the correlation nonce the responder echoes.
    pub fn nonce(mut self, nonce: u16) -> Result<Self, AppEncodeError> {
        put_option(
            &mut self.buf,
            &mut self.last_number,
            peer_repeaters_request::NONCE,
            &nonce.to_be_bytes(),
        )?;
        Ok(self)
    }

    /// Resume from a cursor a previous response handed back.
    pub fn cursor(mut self, cursor: &[u8]) -> Result<Self, AppEncodeError> {
        put_option(
            &mut self.buf,
            &mut self.last_number,
            peer_repeaters_request::CURSOR,
            cursor,
        )?;
        Ok(self)
    }

    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

/// Builds the body of a [`MacCommand::PeerRepeatersResponse`] within a byte
/// budget, so a responder packs whatever fits and pages the rest.
///
/// The page's own options are held as values rather than appended as they
/// arrive: they are emitted in key order at [`build`](Self::build), so a
/// responder that learns it needs a cursor only after packing stopped can
/// still add one.
#[derive(Debug)]
pub struct PeerRepeatersResponseBuilder {
    nonce: Option<u16>,
    cursor: Option<Vec<u8>>,
    total: Option<u8>,
    cursor_reserve: usize,
    entries: Vec<u8>,
    budget: usize,
}

impl PeerRepeatersResponseBuilder {
    /// Start a response whose whole body must fit `budget` octets.
    pub fn new(budget: usize) -> Self {
        Self {
            nonce: None,
            cursor: None,
            total: None,
            cursor_reserve: 0,
            entries: Vec::new(),
            budget,
        }
    }

    /// Echo the request's nonce.
    pub fn nonce(mut self, nonce: u16) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Report how many entries the whole list holds.
    pub fn total(mut self, total: u8) -> Self {
        self.total = Some(total);
        self
    }

    /// Hold back room for a cursor of `octets`, whose value is not known
    /// until packing stops. Without it a response that fills its budget has
    /// nowhere left to say where the next page begins.
    pub fn reserve_cursor(mut self, octets: usize) -> Self {
        self.cursor_reserve = match octets {
            0 => 0,
            // The option header is one octet for a cursor this short.
            octets => octets + 1,
        };
        self
    }

    /// Name where a follow-up request should resume. Omit on the final page.
    pub fn cursor(mut self, cursor: &[u8]) -> Self {
        self.cursor = Some(Vec::from(cursor));
        self
    }

    /// Append one entry if it still fits the budget.
    ///
    /// Returns whether it was taken, so a responder stops packing and issues
    /// a cursor at the first refusal rather than at a count it guessed.
    pub fn try_push(&mut self, entry: &PeerRepeaterEntry<'_>) -> Result<bool, AppEncodeError> {
        let encoded = entry.encode()?;
        // Every entry but the last is followed by its terminator, and the
        // last one may omit it — so an entry fits when it and one separator
        // do.
        let separator = usize::from(!self.entries.is_empty());
        let options = self.encode_options()?.len() + self.cursor_reserve;
        if options + 1 + self.entries.len() + separator + encoded.len() > self.budget {
            return Ok(false);
        }
        if separator == 1 {
            self.entries.push(0xFF);
        }
        self.entries.extend_from_slice(&encoded);
        Ok(true)
    }

    fn encode_options(&self) -> Result<Vec<u8>, AppEncodeError> {
        let mut buf = Vec::new();
        let mut last_number = 0u16;
        if let Some(nonce) = self.nonce {
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeaters_response::NONCE,
                &nonce.to_be_bytes(),
            )?;
        }
        if let Some(cursor) = &self.cursor {
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeaters_response::CURSOR,
                cursor,
            )?;
        }
        if let Some(total) = self.total {
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeaters_response::TOTAL,
                &[total],
            )?;
        }
        Ok(buf)
    }

    /// Finish the body: options, `0xFF`, then the entries.
    pub fn build(self) -> Result<Vec<u8>, AppEncodeError> {
        let mut body = self.encode_options()?;
        body.push(0xFF);
        body.extend_from_slice(&self.entries);
        Ok(body)
    }
}

/// One peer repeater to encode into a response, with every field the
/// responder happens to know.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerRepeaterEntry<'a> {
    /// 3 bytes when the whole node hint is known, 2 for a router hint.
    pub hint: &'a [u8],
    pub name: Option<&'a str>,
    /// RSSI in dBm and SNR from the most recent reception.
    pub rssi_snr: Option<(i16, umsh_hal::Snr)>,
    pub last_heard_min: Option<u16>,
    pub location: Option<crate::location::NodeLocation>,
    /// Concatenated 2-octet region codes.
    pub regions: &'a [u8],
}

impl PeerRepeaterEntry<'_> {
    fn encode(&self) -> Result<Vec<u8>, AppEncodeError> {
        if !(ROUTER_HINT_LEN..=NODE_HINT_LEN).contains(&self.hint.len()) {
            return Err(AppEncodeError::InvalidField);
        }
        let mut buf = Vec::new();
        let mut last_number = 0u16;
        put_option(
            &mut buf,
            &mut last_number,
            peer_repeater_entry::NODE_HINT,
            self.hint,
        )?;
        if let Some(name) = self.name {
            if name.len() > PEER_REPEATER_NAME_MAX_LEN {
                return Err(AppEncodeError::InvalidField);
            }
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeater_entry::NODE_NAME,
                name.as_bytes(),
            )?;
        }
        if let Some((rssi_dbm, snr)) = self.rssi_snr {
            // RSSI travels as an unsigned negative-dBm magnitude; a positive
            // reading is not one a receiver can express, and one past −255
            // dBm is below any radio's floor.
            let rssi =
                u8::try_from(-rssi_dbm.clamp(-255, 0)).map_err(|_| AppEncodeError::InvalidField)?;
            let snr = i8::try_from(snr.as_quarter_db_steps().clamp(-128, 127))
                .map_err(|_| AppEncodeError::InvalidField)?;
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeater_entry::RSSI_SNR,
                &[rssi, snr as u8],
            )?;
        }
        if let Some(minutes) = self.last_heard_min {
            let bytes = minutes.to_be_bytes();
            let minimal = match bytes[0] {
                0 => &bytes[1..],
                _ => &bytes[..],
            };
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeater_entry::LAST_HEARD,
                minimal,
            )?;
        }
        if let Some(location) = self.location
            && !location.is_unspecified()
        {
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeater_entry::LOCATION,
                location.as_bytes(),
            )?;
        }
        if !self.regions.is_empty() {
            if self.regions.len() % 2 != 0 {
                return Err(AppEncodeError::InvalidField);
            }
            put_option(
                &mut buf,
                &mut last_number,
                peer_repeater_entry::REGIONS,
                self.regions,
            )?;
        }
        Ok(buf)
    }
}

/// Append one option to a growing block, continuing its delta chain.
fn put_option(
    buf: &mut Vec<u8>,
    last_number: &mut u16,
    number: u16,
    value: &[u8],
) -> Result<(), AppEncodeError> {
    let mut scratch = alloc::vec![0u8; value.len() + 8];
    let mut encoder = OptionEncoder::with_last_number(&mut scratch, *last_number);
    encoder.put(number, value).map_err(AppEncodeError::Core)?;
    let written = encoder.finish();
    buf.extend_from_slice(&scratch[..written]);
    *last_number = number;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_decode(cmd: MacCommand<'_>) {
        let mut buf = [0u8; 64];
        let len = encode(&cmd, &mut buf).expect("encode failed");
        let decoded = parse(&buf[..len]).expect("parse failed");
        assert_eq!(cmd, decoded, "round-trip failed for {cmd:?}");
    }

    // --- round-trips ---

    #[test]
    fn identity_request_unicast_no_options() {
        encode_decode(MacCommand::IdentityRequest { options: &[] });
        let mut buf = [0u8; 4];
        let len = encode(&MacCommand::IdentityRequest { options: &[] }, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x01]);
    }

    #[test]
    fn identity_request_with_options_round_trips() {
        let options = IdentityRequestBuilder::new()
            .nonce(0x12345678)
            .unwrap()
            .filter_hint(&NodeHint([0xAA, 0xBB, 0xCC]))
            .unwrap()
            .filter_role(NodeRole::Repeater)
            .unwrap()
            .build();
        encode_decode(MacCommand::IdentityRequest { options: &options });
    }

    #[test]
    fn identity_request_options_are_appended_verbatim() {
        let options = IdentityRequestBuilder::new()
            .nonce(0x01020304)
            .unwrap()
            .build();
        let mut buf = [0u8; 16];
        let len = encode(&MacCommand::IdentityRequest { options: &options }, &mut buf).unwrap();
        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..len], options.as_slice());
    }

    #[test]
    fn request_identity_framing_carries_readable_nonce() {
        // Mirrors PeerConnection::request_identity: a nonce-only options block
        // framed with a leading PayloadType::MacCommand byte. The receiver
        // dispatches on payload[0], then parses the command body.
        let options = IdentityRequestBuilder::new()
            .nonce(0xCAFEF00D)
            .unwrap()
            .build();
        let mut buf = [0u8; 128];
        buf[0] = umsh_core::PayloadType::MacCommand as u8;
        let n = encode(
            &MacCommand::IdentityRequest { options: &options },
            &mut buf[1..],
        )
        .unwrap()
            + 1;

        assert_eq!(buf[0], umsh_core::PayloadType::MacCommand as u8);
        let decoded = parse(&buf[1..n]).expect("command body should parse");
        let MacCommand::IdentityRequest { options: body } = decoded else {
            panic!("expected IdentityRequest, got {decoded:?}");
        };
        assert_eq!(
            IdentityRequestFilters::new(body).nonce().unwrap(),
            Some(0xCAFEF00D)
        );
    }

    #[test]
    fn identity_filters_nonce_round_trips() {
        let options = IdentityRequestBuilder::new()
            .nonce(0xDEADBEEF)
            .unwrap()
            .build();
        let filters = IdentityRequestFilters::new(&options);
        assert_eq!(filters.nonce().unwrap(), Some(0xDEADBEEF));

        let empty = IdentityRequestFilters::new(&[]);
        assert_eq!(empty.nonce().unwrap(), None);
    }

    #[test]
    fn identity_filters_no_filters_selects_everyone() {
        let filters = IdentityRequestFilters::new(&[]);
        assert!(
            filters
                .selects(
                    NodeRole::Sensor,
                    NodeCapabilities::empty(),
                    &NodeHint([1, 2, 3])
                )
                .unwrap()
        );
    }

    #[test]
    fn identity_filters_hint_match_and_mismatch() {
        let options = IdentityRequestBuilder::new()
            .filter_hint(&NodeHint([0xAA, 0xBB, 0xCC]))
            .unwrap()
            .build();
        let filters = IdentityRequestFilters::new(&options);
        let caps = NodeCapabilities::empty();
        assert!(
            filters
                .selects(NodeRole::Chat, caps, &NodeHint([0xAA, 0xBB, 0xCC]))
                .unwrap()
        );
        assert!(
            !filters
                .selects(NodeRole::Chat, caps, &NodeHint([0xAA, 0xBB, 0xCD]))
                .unwrap()
        );
    }

    #[test]
    fn identity_filters_hint_matches_on_a_prefix() {
        let caps = NodeCapabilities::empty();
        let selects = |prefix: &[u8], hint: NodeHint| {
            let options = IdentityRequestBuilder::new()
                .filter_hint_prefix(prefix)
                .unwrap()
                .build();
            IdentityRequestFilters::new(&options)
                .selects(NodeRole::Chat, caps, &hint)
                .unwrap()
        };

        // Two bytes is the router hint a route names its hops by.
        assert!(selects(&[0xAA, 0xBB], NodeHint([0xAA, 0xBB, 0xCC])));
        assert!(!selects(&[0xAA, 0xBC], NodeHint([0xAA, 0xBB, 0xCC])));
        assert!(selects(&[0xAA], NodeHint([0xAA, 0xBB, 0xCC])));
        assert!(!selects(&[0xAB], NodeHint([0xAA, 0xBB, 0xCC])));

        // A prefix is only ever a prefix: it never matches from the middle.
        assert!(!selects(&[0xBB, 0xCC], NodeHint([0xAA, 0xBB, 0xCC])));
    }

    #[test]
    fn identity_filters_reject_unusable_hint_lengths() {
        // An empty prefix would select every node while `hint_filtered` said
        // the request was narrowed, and an over-long one can select nobody.
        assert!(
            IdentityRequestBuilder::new()
                .filter_hint_prefix(&[])
                .is_err()
        );
        assert!(
            IdentityRequestBuilder::new()
                .filter_hint_prefix(&[0xAA, 0xBB, 0xCC, 0xDD])
                .is_err()
        );

        // Off the wire those lengths are still refused, since nothing stops a
        // peer from encoding one by hand.
        let caps = NodeCapabilities::empty();
        let hint = NodeHint([0xAA, 0xBB, 0xCC]);
        for value in [[].as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD]] {
            let mut options = Vec::new();
            let mut scratch = [0u8; 8];
            let mut enc = OptionEncoder::new(&mut scratch);
            enc.put(identity_filter::FILTER_NODE_HINT, value).unwrap();
            let n = enc.finish();
            options.extend_from_slice(&scratch[..n]);
            let filters = IdentityRequestFilters::new(&options);
            assert!(filters.hint_filtered());
            assert!(!filters.selects(NodeRole::Chat, caps, &hint).unwrap());
        }
    }

    #[test]
    fn identity_filters_report_whether_a_hint_names_one_node() {
        let named = |prefixes: &[&[u8]]| {
            let mut builder = IdentityRequestBuilder::new();
            for prefix in prefixes {
                builder = builder.filter_hint_prefix(prefix).unwrap();
            }
            IdentityRequestFilters::new(&builder.build()).hint_names_one_node()
        };

        // Two bytes is one node in 65,536, three is one in 16.7 million.
        assert!(named(&[&[0xAA, 0xBB, 0xCC]]));
        assert!(named(&[&[0xAA, 0xBB]]));
        // One byte is a 256th of the mesh, which is a crowd, not a name.
        assert!(!named(&[&[0xAA]]));

        // Same-type filters are OR, so the shortest one decides.
        assert!(named(&[&[0xAA, 0xBB], &[0xCC, 0xDD]]));
        assert!(!named(&[&[0xAA, 0xBB], &[0xCC]]));

        // A request with no hint filter at all is narrowed by nothing, however
        // else it selects.
        let by_role = IdentityRequestBuilder::new()
            .filter_role(NodeRole::Chat)
            .unwrap()
            .build();
        assert!(!IdentityRequestFilters::new(&by_role).hint_names_one_node());

        // A block that will not decode reads as unnarrowed, so the reply keeps
        // its hold rather than racing every other answer on a malformed ask.
        // A hint option claiming five bytes of value with none behind it: the
        // case where trusting the decode would drop the hold on a filter whose
        // length is exactly what could not be read.
        let truncated = [0x35u8];
        let filters = IdentityRequestFilters::new(&truncated);
        assert!(
            filters
                .selects(NodeRole::Chat, NodeCapabilities::empty(), &NodeHint([0; 3]))
                .is_err(),
            "the block has to be undecodable for this to test the error path"
        );
        assert!(!filters.hint_names_one_node());
    }

    #[test]
    fn identity_filters_report_hint_presence() {
        let hinted = IdentityRequestBuilder::new()
            .nonce(0x0102_0304)
            .unwrap()
            .filter_hint(&NodeHint([0xAA, 0xBB, 0xCC]))
            .unwrap()
            .build();
        assert!(IdentityRequestFilters::new(&hinted).hint_filtered());

        let by_role = IdentityRequestBuilder::new()
            .filter_role(NodeRole::Repeater)
            .unwrap()
            .build();
        assert!(!IdentityRequestFilters::new(&by_role).hint_filtered());

        // No filters at all, and a truncated block, both read as unfiltered.
        assert!(!IdentityRequestFilters::new(&[]).hint_filtered());
        assert!(!IdentityRequestFilters::new(&[0x33, 0xAA]).hint_filtered());
    }

    #[test]
    fn identity_filters_repeated_type_is_or() {
        let options = IdentityRequestBuilder::new()
            .filter_role(NodeRole::Repeater)
            .unwrap()
            .filter_role(NodeRole::Chat)
            .unwrap()
            .build();
        let filters = IdentityRequestFilters::new(&options);
        let caps = NodeCapabilities::empty();
        let hint = NodeHint([1, 2, 3]);
        assert!(filters.selects(NodeRole::Repeater, caps, &hint).unwrap());
        assert!(filters.selects(NodeRole::Chat, caps, &hint).unwrap());
        assert!(!filters.selects(NodeRole::Sensor, caps, &hint).unwrap());
    }

    #[test]
    fn identity_filters_distinct_types_are_and() {
        let options = IdentityRequestBuilder::new()
            .filter_role(NodeRole::Repeater)
            .unwrap()
            .filter_caps(NodeCapabilities::REPEATER)
            .unwrap()
            .build();
        let filters = IdentityRequestFilters::new(&options);
        let hint = NodeHint([1, 2, 3]);
        // Both must hold.
        assert!(
            filters
                .selects(NodeRole::Repeater, NodeCapabilities::REPEATER, &hint)
                .unwrap()
        );
        // Role matches but caps don't.
        assert!(
            !filters
                .selects(NodeRole::Repeater, NodeCapabilities::empty(), &hint)
                .unwrap()
        );
    }

    #[test]
    fn identity_filters_caps_requires_all_requested_bits() {
        let options = IdentityRequestBuilder::new()
            .filter_caps(NodeCapabilities::REPEATER | NodeCapabilities::TEXT_MESSAGES)
            .unwrap()
            .build();
        let filters = IdentityRequestFilters::new(&options);
        let hint = NodeHint([1, 2, 3]);
        // Superset matches.
        assert!(
            filters
                .selects(
                    NodeRole::Chat,
                    NodeCapabilities::REPEATER
                        | NodeCapabilities::TEXT_MESSAGES
                        | NodeCapabilities::MOBILE,
                    &hint,
                )
                .unwrap()
        );
        // Missing one requested bit does not match.
        assert!(
            !filters
                .selects(NodeRole::Chat, NodeCapabilities::REPEATER, &hint)
                .unwrap()
        );
    }

    #[test]
    fn identity_filters_unknown_critical_option_excludes() {
        // Key 9 is unknown and critical (odd).
        let mut buf = [0u8; 8];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(9, &[0x01]).unwrap();
        let n = enc.finish();
        let filters = IdentityRequestFilters::new(&buf[..n]);
        assert!(
            !filters
                .selects(
                    NodeRole::Chat,
                    NodeCapabilities::empty(),
                    &NodeHint([1, 2, 3])
                )
                .unwrap()
        );
    }

    #[test]
    fn identity_filters_unknown_elective_option_ignored() {
        // Key 8 is unknown and elective (even); alongside a matching role filter.
        let mut buf = [0u8; 16];
        let mut enc = OptionEncoder::new(&mut buf);
        enc.put(5, &[NodeRole::Repeater.as_byte()]).unwrap();
        enc.put(8, &[0xFE]).unwrap();
        let n = enc.finish();
        let filters = IdentityRequestFilters::new(&buf[..n]);
        assert!(
            filters
                .selects(
                    NodeRole::Repeater,
                    NodeCapabilities::empty(),
                    &NodeHint([1, 2, 3])
                )
                .unwrap()
        );
    }

    #[test]
    fn signal_report_request() {
        encode_decode(MacCommand::SignalReportRequest);
    }

    #[test]
    fn signal_report_response() {
        encode_decode(MacCommand::SignalReportResponse {
            rssi: 200,
            snr: -10,
        });
        let mut buf = [0u8; 8];
        let len = encode(
            &MacCommand::SignalReportResponse {
                rssi: 0xAB,
                snr: -1,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..len], &[0x03, 0xAB, 0xFF]);
    }

    #[test]
    fn echo_request() {
        encode_decode(MacCommand::EchoRequest {
            data: &[0x01, 0x02, 0x03],
        });
        encode_decode(MacCommand::EchoRequest { data: &[] });
    }

    #[test]
    fn echo_response() {
        encode_decode(MacCommand::EchoResponse {
            data: &[0xDE, 0xAD],
        });
    }

    #[test]
    fn pfs_session_request() {
        let key = PublicKey([0xABu8; 32]);
        encode_decode(MacCommand::PfsSessionRequest {
            ephemeral_key: key,
            duration_minutes: 60,
        });
        let mut buf = [0u8; 40];
        let len = encode(
            &MacCommand::PfsSessionRequest {
                ephemeral_key: key,
                duration_minutes: 0x0102,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(len, 1 + 32 + 2);
        assert_eq!(buf[0], 0x06);
        assert_eq!(&buf[1..33], &[0xABu8; 32]);
        assert_eq!(&buf[33..35], &[0x01, 0x02]);
    }

    #[test]
    fn pfs_session_response() {
        let key = PublicKey([0x55u8; 32]);
        encode_decode(MacCommand::PfsSessionResponse {
            ephemeral_key: key,
            duration_minutes: 120,
        });
    }

    #[test]
    fn end_pfs_session() {
        encode_decode(MacCommand::EndPfsSession);
        let mut buf = [0u8; 4];
        let len = encode(&MacCommand::EndPfsSession, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x08]);
    }

    #[test]
    fn noop() {
        encode_decode(MacCommand::Noop);
        let mut buf = [0u8; 4];
        let len = encode(&MacCommand::Noop, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x09]);
    }

    #[test]
    fn noop_tolerates_a_body_it_has_no_use_for() {
        assert_eq!(parse(&[0x09, 0xDE, 0xAD]).unwrap(), MacCommand::Noop);
    }

    // --- OwnedMacCommand From conversion ---

    #[test]
    fn owned_from_borrowed_echo() {
        let cmd = MacCommand::EchoRequest {
            data: &[0x01, 0x02],
        };
        let owned = OwnedMacCommand::from(cmd);
        assert_eq!(
            owned,
            OwnedMacCommand::EchoRequest {
                data: alloc::vec![0x01, 0x02]
            }
        );
    }

    // --- parse error cases ---

    #[test]
    fn parse_empty_returns_truncated() {
        assert!(matches!(
            parse(&[]),
            Err(crate::AppParseError::Core(umsh_core::ParseError::Truncated))
        ));
    }

    #[test]
    fn parse_unknown_command_id() {
        assert!(matches!(
            parse(&[0xFF]),
            Err(crate::AppParseError::InvalidCommandId(0xFF))
        ));
    }

    #[test]
    fn parse_command_zero_is_unallocated() {
        assert!(matches!(
            parse(&[0x00]),
            Err(crate::AppParseError::InvalidCommandId(0))
        ));
    }

    #[test]
    fn parse_identity_request_accepts_option_block() {
        // A well-formed option block is accepted as the request payload.
        let decoded = parse(&[0x01, 0x00]).expect("valid options should parse");
        assert!(matches!(decoded, MacCommand::IdentityRequest { .. }));
    }

    #[test]
    fn parse_identity_request_rejects_malformed_options() {
        // 0x41: delta 4, length 1, but no value byte follows -> truncated.
        assert!(parse(&[0x01, 0x41]).is_err());
    }

    #[test]
    fn parse_signal_report_response_wrong_length() {
        assert!(parse(&[0x03, 0x01]).is_err()); // need exactly 2 body bytes
    }

    #[test]
    fn parse_pfs_request_wrong_length() {
        assert!(parse(&[0x06, 0x00]).is_err()); // need exactly 34 body bytes
    }

    #[test]
    fn parse_end_pfs_nonempty_body() {
        assert!(parse(&[0x08, 0x00]).is_err());
    }

    // --- peer repeaters ---

    #[test]
    fn a_cursorless_peer_repeaters_request_is_one_byte() {
        let mut buf = [0u8; 4];
        let len = encode(
            &MacCommand::PeerRepeatersRequest {
                options: &PeerRepeatersRequestBuilder::new().build(),
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..len], &[0x0A], "options-only, so no end marker");
    }

    #[test]
    fn a_peer_repeaters_request_carries_its_nonce_and_cursor() {
        let options = PeerRepeatersRequestBuilder::new()
            .nonce(0xBEEF)
            .unwrap()
            .cursor(&[0x01, 0x02, 0x03])
            .unwrap()
            .build();
        encode_decode(MacCommand::PeerRepeatersRequest { options: &options });

        let view = PeerRepeatersRequestView::new(&options);
        assert_eq!(view.nonce(), Some(0xBEEF));
        assert_eq!(view.cursor(), Some(&[0x01, 0x02, 0x03][..]));

        let empty = PeerRepeatersRequestView::new(&[]);
        assert_eq!(empty.nonce(), None);
        assert_eq!(empty.cursor(), None);
    }

    /// The entry fields are individually optional, so a page has to read
    /// back whatever subset of them the responder happened to know.
    #[test]
    fn a_peer_repeaters_response_round_trips_every_entry_field() {
        let mut builder = PeerRepeatersResponseBuilder::new(200)
            .nonce(0xBEEF)
            .total(2);
        let location = crate::location::NodeLocation::from_lat_lon(44.05, -123.09, 4);
        assert!(
            builder
                .try_push(&PeerRepeaterEntry {
                    hint: &[0xAA, 0xBB, 0xCC],
                    name: Some("Ridge"),
                    rssi_snr: Some((-97, umsh_hal::Snr::from_decibels(-7))),
                    last_heard_min: Some(400),
                    location: Some(location),
                    regions: &[0x78, 0x53, 0x31, 0xD9],
                })
                .unwrap()
        );
        // A hint and nothing else is a legitimate entry: an observation
        // with no identity behind it names a hop and reports what was
        // heard, and here not even that.
        assert!(
            builder
                .try_push(&PeerRepeaterEntry {
                    hint: &[0x11, 0x22],
                    ..PeerRepeaterEntry::default()
                })
                .unwrap()
        );
        let body = builder.build().unwrap();

        let view = PeerRepeatersResponseView::new(&body);
        assert_eq!(view.nonce(), Some(0xBEEF));
        assert_eq!(view.total(), Some(2));
        assert_eq!(view.cursor(), None, "the final page names no resume point");

        let entries: Vec<_> = view.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].hint(), Some(&[0xAA, 0xBB, 0xCC][..]));
        assert_eq!(entries[0].name(), Some("Ridge"));
        assert_eq!(
            entries[0].rssi_snr(),
            Some((-97, umsh_hal::Snr::from_decibels(-7)))
        );
        assert_eq!(entries[0].last_heard_min(), Some(400));
        assert_eq!(entries[0].location(), Some(location));
        assert_eq!(
            entries[0].regions().collect::<Vec<_>>(),
            [[0x78, 0x53], [0x31, 0xD9]]
        );
        assert_eq!(entries[1].hint(), Some(&[0x11, 0x22][..]));
        assert_eq!(entries[1].name(), None);
        assert_eq!(entries[1].rssi_snr(), None);
        assert_eq!(entries[1].last_heard_min(), None);
        assert_eq!(entries[1].location(), None);
        assert_eq!(entries[1].regions().count(), 0);

        encode_decode_long(MacCommand::PeerRepeatersResponse { body: &body });
    }

    /// The last entry may omit its terminator, so the walk cannot rely on
    /// one to know an entry ended.
    #[test]
    fn the_final_entry_needs_no_terminator() {
        let mut builder = PeerRepeatersResponseBuilder::new(64);
        for hint in [[0x11u8, 0x22], [0x33, 0x44]] {
            assert!(
                builder
                    .try_push(&PeerRepeaterEntry {
                        hint: &hint,
                        ..PeerRepeaterEntry::default()
                    })
                    .unwrap()
            );
        }
        let body = builder.build().unwrap();
        assert_ne!(
            body.last(),
            Some(&0xFF),
            "nothing follows the last entry, so nothing marks its end"
        );
        assert_eq!(PeerRepeatersResponseView::new(&body).entries().count(), 2);

        // A responder that writes the terminator anyway is read the same
        // way rather than as an extra empty entry.
        let mut terminated = body.clone();
        terminated.push(0xFF);
        assert_eq!(
            PeerRepeatersResponseView::new(&terminated)
                .entries()
                .count(),
            2
        );
    }

    #[test]
    fn a_response_stops_packing_at_its_budget_rather_than_overrunning_it() {
        // Options (none) plus the end marker leave four octets, which is
        // one four-octet entry and no room for a separator and a second.
        let mut builder = PeerRepeatersResponseBuilder::new(5);
        let entry = PeerRepeaterEntry {
            hint: &[0x11, 0x22, 0x33],
            ..PeerRepeaterEntry::default()
        };
        assert!(builder.try_push(&entry).unwrap());
        assert!(!builder.try_push(&entry).unwrap());
        let body = builder.build().unwrap();
        assert!(body.len() <= 5, "body is {} octets", body.len());
        assert_eq!(PeerRepeatersResponseView::new(&body).entries().count(), 1);
    }

    /// A page that fills its budget is exactly the page that needs a
    /// cursor, so the room for one is held back before packing starts.
    #[test]
    fn a_reserved_cursor_still_fits_after_the_page_is_packed() {
        const BUDGET: usize = 16;
        let mut builder = PeerRepeatersResponseBuilder::new(BUDGET).reserve_cursor(3);
        let entry = PeerRepeaterEntry {
            hint: &[0x11, 0x22, 0x33],
            ..PeerRepeaterEntry::default()
        };
        let mut packed = 0;
        while builder.try_push(&entry).unwrap() {
            packed += 1;
        }
        assert!(packed > 0);
        let body = builder.cursor(&[0x00, 0x01, 0x02]).build().unwrap();
        assert!(body.len() <= BUDGET, "body is {} octets", body.len());
        let view = PeerRepeatersResponseView::new(&body);
        assert_eq!(view.cursor(), Some(&[0x00, 0x01, 0x02][..]));
        assert_eq!(view.entries().count(), packed);
    }

    #[test]
    fn a_paged_response_names_where_to_resume() {
        let body = PeerRepeatersResponseBuilder::new(64)
            .total(9)
            .cursor(&[0x00, 0x07, 0x04])
            .build()
            .unwrap();
        let view = PeerRepeatersResponseView::new(&body);
        assert_eq!(view.total(), Some(9));
        assert_eq!(view.cursor(), Some(&[0x00, 0x07, 0x04][..]));
        assert_eq!(view.entries().count(), 0);
    }

    #[test]
    fn an_entry_without_a_usable_hint_names_nobody() {
        let mut buf = Vec::new();
        let mut last = 0u16;
        // One octet is a 256th of the mesh, not a peer.
        put_option(&mut buf, &mut last, peer_repeater_entry::NODE_HINT, &[0x11]).unwrap();
        let mut body = alloc::vec![0xFFu8];
        body.extend_from_slice(&buf);
        let entries: Vec<_> = PeerRepeatersResponseView::new(&body).entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hint(), None);
    }

    /// Once an entry's framing is broken, the next entry boundary is
    /// unknowable — the terminator is only recognizable through correct
    /// framing, since values may contain `0xFF`. The walk keeps what it
    /// decoded and stops there.
    #[test]
    fn a_broken_entry_ends_the_walk_but_keeps_what_came_before() {
        let mut body = alloc::vec![0xFFu8];
        // A whole entry, then one whose second option claims 253 octets it
        // does not have, then a well-formed entry stranded behind it.
        body.extend_from_slice(&[0x03, 0xAA, 0xBB, 0xCC, 0xFF]);
        body.extend_from_slice(&[0x03, 0x11, 0x22, 0x33, 0x0D, 0xF0, 0xFF]);
        body.extend_from_slice(&[0x03, 0x44, 0x55, 0x66]);
        let entries: Vec<_> = PeerRepeatersResponseView::new(&body).entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].hint(), Some(&[0xAA, 0xBB, 0xCC][..]));
        // The broken entry still answers with the options ahead of the
        // damage; the entry stranded behind it is the cost.
        assert_eq!(entries[1].hint(), Some(&[0x11, 0x22, 0x33][..]));
    }

    #[test]
    fn an_entry_hint_outside_two_or_three_octets_is_refused_at_the_encoder() {
        let mut builder = PeerRepeatersResponseBuilder::new(64);
        for hint in [&[0x11u8][..], &[0x11, 0x22, 0x33, 0x44][..], &[][..]] {
            assert!(
                builder
                    .try_push(&PeerRepeaterEntry {
                        hint,
                        ..PeerRepeaterEntry::default()
                    })
                    .is_err()
            );
        }
    }

    #[test]
    fn last_heard_uses_the_shortest_encoding_that_holds_it() {
        for (minutes, expected) in [(0u16, 1usize), (255, 1), (256, 2), (65535, 2)] {
            let mut builder = PeerRepeatersResponseBuilder::new(64);
            builder
                .try_push(&PeerRepeaterEntry {
                    hint: &[0x11, 0x22],
                    last_heard_min: Some(minutes),
                    ..PeerRepeaterEntry::default()
                })
                .unwrap();
            let body = builder.build().unwrap();
            let view = PeerRepeatersResponseView::new(&body);
            let entry = view.entries().next().unwrap();
            assert_eq!(entry.last_heard_min(), Some(minutes));
            assert_eq!(
                entry.find(peer_repeater_entry::LAST_HEARD).unwrap().len(),
                expected,
                "minutes {minutes}"
            );
        }
    }

    fn encode_decode_long(cmd: MacCommand<'_>) {
        let mut buf = [0u8; 256];
        let len = encode(&cmd, &mut buf).expect("encode failed");
        assert_eq!(parse(&buf[..len]).expect("parse failed"), cmd);
    }
}
