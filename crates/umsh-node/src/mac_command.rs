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

/// Length of a [`NodeHint`], the longest a `FILTER_NODE_HINT` value may be.
const NODE_HINT_LEN: usize = 3;

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
    /// and its replies — to the requester's own neighbourhood.
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
}
