//! Stable, value-oriented facade for native UMSH mobile applications.
//!
//! This crate deliberately exposes application operations instead of mirroring
//! the internal protocol crate graph. Platform bindings should wrap this API;
//! mobile feature code should not depend on `umsh-core` directly.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use lwuri::UriRef;
use umsh_core::{AddressParseError, NodeHint, PublicKey, RouterHint};
use umsh_crypto::{NodeIdentity, software::SoftwareIdentity};
use umsh_uri::UmshUri;
use zeroize::Zeroize;

mod counter_store;
mod mobile_chat;
mod mobile_mesh;
mod ulcp;

pub use counter_store::{CounterStoreError, MobileCounterStore};
pub use mobile_chat::{
    MobileChatArchiveLookupRecord, MobileChatArchiveRecord, MobileChatArchiveResultKind,
    MobileChatCheckpointRecord, MobileChatComposeBatchRecord, MobileChatDeliveryRecord,
    MobileChatDeliveryState, MobileChatDirection, MobileChatMutationKind, MobileChatMutationRecord,
    MobileChatOriginalRef,
};
pub use mobile_mesh::{
    MobileMeshAdvertisementRecord, MobileMeshError, MobileMeshOutboundFrameRecord,
    MobileMeshPeerHeardRecord, MobileMeshPingEventRecord, MobileMeshPingOutcome,
    MobileMeshRouteKind, MobileMeshRouteRecord, MobileMeshRxRecord, MobileMeshSession,
    MobileMeshSessionUpdateRecord,
};
pub use ulcp::{
    GattSegmentRecord, MobileGattReassembler, MobileUlcpSession, UlcpAlertState, UlcpAttachMode,
    UlcpBatteryRecord, UlcpChargeState, UlcpDeviceConfigRecord, UlcpHostOwnership,
    UlcpOperationErrorRecord, UlcpPropertyFrameRecord, UlcpRadioSettingsRecord,
    UlcpReceivedFrameRecord, UlcpRepeaterSettingsRecord, UlcpSessionPhase,
    UlcpSessionSnapshotRecord, UlcpSessionUpdateRecord, UlcpSyncRecord, inspect_ulcp_alert,
    inspect_ulcp_battery, inspect_ulcp_property_frame, inspect_ulcp_status, inspect_ulcp_sync,
    region_code_description, region_code_from_string, ulcp_gatt_segments,
    ulcp_inspection_properties, ulcp_max_dev_channels, ulcp_max_dev_peers, ulcp_prop_get,
    ulcp_prop_set, ulcp_save,
};

uniffi::setup_scaffolding!();

/// Version of the mobile facade contract.
///
/// Increment this when a binding-visible operation, record, or error contract
/// changes incompatibly. It is independent of the UMSH wire version.
pub const MOBILE_API_VERSION: u16 = 36;

/// Stable error categories consumed by platform adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileError {
    InvalidAddressLength,
    InvalidAddressCharacter,
    AddressOverflow,
    InvalidNodeHintLength,
    InvalidRouterHintLength,
    InvalidSecretKeyLength,
    InvalidPublicKeyLength,
    InvalidUri,
    InvalidIdentityData,
    InvalidUlcpFrame,
    InvalidGattSegment,
    /// A tethering operation was attempted on an administrative session.
    AdministrativeSession,
    /// Text could not be read as a region code, or a supplied code was
    /// not exactly two octets.
    InvalidRegionCode,
    /// The operation needs a capability this radio does not advertise.
    UnsupportedCapability,
    /// A public channel name contained a non-ASCII byte. Canonicalization is
    /// an ASCII case fold, so such a name has no defined key.
    ChannelNameNotAscii,
    /// A public channel name exceeded the derivation input limit.
    ChannelNameTooLong,
    /// A channel key was not exactly 32 octets.
    InvalidChannelKeyLength,
}

impl MobileError {
    /// Stable localization key. Rust prose is never shown directly in the UI.
    pub const fn summary_key(self) -> &'static str {
        match self {
            Self::InvalidAddressLength => "mobile.error.address.invalid_length",
            Self::InvalidAddressCharacter => "mobile.error.address.invalid_character",
            Self::AddressOverflow => "mobile.error.address.overflow",
            Self::InvalidNodeHintLength => "mobile.error.node_hint.invalid_length",
            Self::InvalidRouterHintLength => "mobile.error.router_hint.invalid_length",
            Self::InvalidSecretKeyLength => "mobile.error.secret_key.invalid_length",
            Self::InvalidPublicKeyLength => "mobile.error.public_key.invalid_length",
            Self::InvalidUri => "mobile.error.uri.invalid",
            Self::InvalidIdentityData => "mobile.error.identity_data.invalid",
            Self::InvalidUlcpFrame => "mobile.error.ulcp.invalid_frame",
            Self::InvalidGattSegment => "mobile.error.ulcp.invalid_gatt_segment",
            Self::AdministrativeSession => "mobile.error.ulcp.administrative_session",
            Self::InvalidRegionCode => "mobile.error.region_code.invalid",
            Self::UnsupportedCapability => "mobile.error.ulcp.unsupported_capability",
            Self::ChannelNameNotAscii => "mobile.error.channel_name.not_ascii",
            Self::ChannelNameTooLong => "mobile.error.channel_name.too_long",
            Self::InvalidChannelKeyLength => "mobile.error.channel_key.invalid_length",
        }
    }

    /// Redacted diagnostic code suitable for logs and support bundles.
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::InvalidAddressLength => "ADDRESS_INVALID_LENGTH",
            Self::InvalidAddressCharacter => "ADDRESS_INVALID_CHARACTER",
            Self::AddressOverflow => "ADDRESS_OVERFLOW",
            Self::InvalidNodeHintLength => "NODE_HINT_INVALID_LENGTH",
            Self::InvalidRouterHintLength => "ROUTER_HINT_INVALID_LENGTH",
            Self::InvalidSecretKeyLength => "SECRET_KEY_INVALID_LENGTH",
            Self::InvalidPublicKeyLength => "PUBLIC_KEY_INVALID_LENGTH",
            Self::InvalidUri => "URI_INVALID",
            Self::InvalidIdentityData => "IDENTITY_DATA_INVALID",
            Self::InvalidUlcpFrame => "ULCP_INVALID_FRAME",
            Self::InvalidGattSegment => "ULCP_INVALID_GATT_SEGMENT",
            Self::AdministrativeSession => "ULCP_ADMINISTRATIVE_SESSION",
            Self::InvalidRegionCode => "REGION_CODE_INVALID",
            Self::UnsupportedCapability => "ULCP_UNSUPPORTED_CAPABILITY",
            Self::ChannelNameNotAscii => "CHANNEL_NAME_NOT_ASCII",
            Self::ChannelNameTooLong => "CHANNEL_NAME_TOO_LONG",
            Self::InvalidChannelKeyLength => "CHANNEL_KEY_INVALID_LENGTH",
        }
    }
}

impl fmt::Display for MobileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.diagnostic_code())
    }
}

impl std::error::Error for MobileError {}

impl From<AddressParseError> for MobileError {
    fn from(value: AddressParseError) -> Self {
        match value {
            AddressParseError::InvalidLength => Self::InvalidAddressLength,
            AddressParseError::InvalidCharacter => Self::InvalidAddressCharacter,
            AddressParseError::Overflow => Self::AddressOverflow,
        }
    }
}

/// Canonical rendering information for a three-byte node hint.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NodeHintRecord {
    /// Raw hint bytes. Mobile UI uses these bytes as the avatar RGB fill.
    pub bytes: Vec<u8>,
    /// Canonical, possibly star-truncated text rendered by the Rust core.
    pub text: String,
}

/// Canonical rendering information for a two-byte router hint.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RouterHintRecord {
    /// Raw hint bytes, matchable against the first two bytes of a known
    /// node's public key.
    pub bytes: Vec<u8>,
    /// Canonical, possibly star-truncated text rendered by the Rust core.
    pub text: String,
}

/// Public identity information safe to keep in ordinary application models.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicIdentityRecord {
    /// Exact canonical 44-character fixed-width Base58 address.
    pub canonical_address: String,
    pub hint: NodeHintRecord,
}

/// Authentication state of a standalone node-identity bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum IdentitySignatureState {
    /// No signature was attached; the claims are unauthenticated.
    Unsigned,
    /// The attached signature verifies against the node's public key.
    Valid,
    /// The attached signature does not verify; the claims must not be
    /// presented as coming from the key's owner.
    Invalid,
}

/// Decoded advertised node identity (node-identity.md), UI-safe fields only.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NodeIdentityRecord {
    pub role_code: u8,
    /// Canonical English role label; UI may localize by `role_code`.
    pub role_label: String,
    /// Canonical capability labels in wire bit order.
    pub capabilities: Vec<String>,
    pub name: Option<String>,
    /// Center of the advertised location grid cell, in degrees.
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    /// Grid-code precision in bytes (1-7); larger is finer.
    pub location_precision: Option<u8>,
    pub altitude_m: Option<i32>,
    /// Seconds since the Unix epoch (freshness marker).
    pub timestamp: Option<u32>,
    pub signature: IdentitySignatureState,
}

/// Safe, non-mutating preview of a parsed node URI.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NodeUriPreviewRecord {
    pub canonical_address: String,
    pub hint: NodeHintRecord,
    pub has_identity_data: bool,
    /// Decoded identity bundle when the URI carried one that parses.
    pub identity: Option<NodeIdentityRecord>,
    /// Raw identity payload bytes suitable for persistence. Absent when the
    /// bundle is unparseable or its signature fails verification, so callers
    /// never store tampered claims.
    pub identity_payload: Option<Vec<u8>>,
}

/// Parse a node URI locally and return only validated public identity fields.
#[uniffi::export]
pub fn inspect_node_uri(uri: String) -> Result<NodeUriPreviewRecord, MobileError> {
    let reference = UriRef::from_str(&uri).map_err(|_| MobileError::InvalidUri)?;
    let node = match umsh_uri::parse_umsh_uri(reference).map_err(|_| MobileError::InvalidUri)? {
        UmshUri::Node(node) => node,
        _ => return Err(MobileError::InvalidUri),
    };
    let identity = public_identity_record(&node.public_key);
    let (decoded, payload) = match node.identity_data {
        None => (None, None),
        Some(data) => match umsh_uri::decode_base58_bytes(data).ok().and_then(|bytes| {
            node_identity_record(&node.public_key, &bytes)
                .ok()
                .map(|record| (record, bytes))
        }) {
            None => (None, None),
            Some((record, bytes)) => {
                // Tampered bundles are shown as invalid but never persisted.
                let payload =
                    (record.signature != IdentitySignatureState::Invalid).then_some(bytes);
                (Some(record), payload)
            }
        },
    };
    Ok(NodeUriPreviewRecord {
        canonical_address: identity.canonical_address,
        hint: identity.hint,
        has_identity_data: node.identity_data.is_some(),
        identity: decoded,
        identity_payload: payload,
    })
}

/// How a channel's key is established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChannelKindRecord {
    /// Key derived from a canonical ASCII name. Anyone who knows the name can
    /// join, so the name is not a secret.
    NamedPublic,
    /// Key distributed out of band. Possession is membership.
    PrivateKey,
}

/// Safe, non-mutating preview of a channel the user is about to join.
///
/// `key` is secret membership material for a [`ChannelKindRecord::PrivateKey`]
/// channel: callers must store it with identity-key protection and must not
/// place it in ordinary application records.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ChannelPreviewRecord {
    pub kind: ChannelKindRecord,
    /// Canonicalized (ASCII-lowercased) name for a named channel. The UI
    /// should show this when it differs from what the user typed, because it
    /// — not the input — is what determines the key.
    pub canonical_name: Option<String>,
    /// The 32-octet channel key.
    pub key: Vec<u8>,
    /// The two-octet derived channel identifier. This is a hint, not an
    /// identity: distinct keys may derive the same value, and receivers
    /// resolve collisions by trial decryption.
    pub channel_id: Vec<u8>,
    /// Three octets for presentation — a deterministic colour for the
    /// channel. The first two are the identifier above.
    pub tint: Vec<u8>,
    /// Suggested local display name from the invitation (`n=`), decoded.
    pub display_name: Option<String>,
    /// Recommended flood-hop ceiling from the invitation (`mh=`).
    pub max_flood_hops: Option<u8>,
    /// Recommended region from the invitation (`r=`), as a two-octet code.
    /// Absent when the invitation named a region that does not parse.
    pub region: Option<Vec<u8>>,
}

/// Parse a channel URI locally and derive its key and identifier.
///
/// Accepts `umsh:cs:` (named) and `umsh:ck:` (direct key). A node URI is
/// rejected; [`inspect_node_uri`] is its counterpart.
#[uniffi::export]
pub fn inspect_channel_uri(uri: String) -> Result<ChannelPreviewRecord, MobileError> {
    let reference = UriRef::from_str(&uri).map_err(|_| MobileError::InvalidUri)?;
    match umsh_uri::parse_umsh_uri(reference).map_err(|_| MobileError::InvalidUri)? {
        UmshUri::ChannelByName(parsed) => {
            let name =
                umsh_uri::decode_percent(parsed.name).map_err(|_| MobileError::InvalidUri)?;
            let mut record = named_channel_preview(&name)?;
            apply_channel_params(&mut record, &parsed.params)?;
            Ok(record)
        }
        UmshUri::ChannelByKey(parsed) => {
            let channel = umsh_node::Channel::private(parsed.key, "");
            let mut record = ChannelPreviewRecord {
                kind: ChannelKindRecord::PrivateKey,
                canonical_name: None,
                key: channel.key().0.to_vec(),
                channel_id: channel.channel_id().0.to_vec(),
                tint: channel_tint(channel.key()),
                display_name: None,
                max_flood_hops: None,
                region: None,
            };
            apply_channel_params(&mut record, &parsed.params)?;
            Ok(record)
        }
        UmshUri::Node(_) => Err(MobileError::InvalidUri),
    }
}

/// Derive a public channel from a plain name, without a URI.
///
/// This is the join-by-name path. The returned `canonical_name` is the
/// lowercase form the key is actually derived from.
#[uniffi::export]
pub fn inspect_channel_name(name: String) -> Result<ChannelPreviewRecord, MobileError> {
    named_channel_preview(&name)
}

/// Generate a fresh 32-octet key for a new private channel.
///
/// Drawn from the same cryptographic generator the MAC uses for its own key
/// material.
#[uniffi::export]
pub fn generate_channel_key() -> Vec<u8> {
    use rand::Rng;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    let bytes = key.to_vec();
    key.zeroize();
    bytes
}

/// Derive the two-octet channel identifier for a key.
///
/// Used to match a locally held key against the identifiers a device reports,
/// which never include key material.
#[uniffi::export]
pub fn derive_channel_id(key: Vec<u8>) -> Result<Vec<u8>, MobileError> {
    let channel = umsh_node::Channel::private(channel_key_from_bytes(&key)?, "");
    Ok(channel.channel_id().0.to_vec())
}

/// Derive the three presentation octets for a key — the identifier extended by
/// one byte, so a channel's colour is stable wherever it is shown.
#[uniffi::export]
pub fn derive_channel_tint(key: Vec<u8>) -> Result<Vec<u8>, MobileError> {
    Ok(channel_tint(&channel_key_from_bytes(&key)?))
}

fn channel_tint(key: &umsh_core::ChannelKey) -> Vec<u8> {
    use umsh_crypto::software::{SoftwareAes, SoftwareSha256};

    umsh_crypto::CryptoEngine::new(SoftwareAes, SoftwareSha256)
        .derive_channel_tint(key)
        .to_vec()
}

/// The tag a channel's conversation is keyed by.
///
/// Same derivation as the identifier and the tint, run to sixteen bytes: wide
/// enough that two channels can never share one, which the two-byte identifier
/// cannot promise.
pub(crate) fn channel_tag(key: &umsh_core::ChannelKey) -> umsh_core::ChannelTag {
    use umsh_crypto::software::{SoftwareAes, SoftwareSha256};

    umsh_crypto::CryptoEngine::new(SoftwareAes, SoftwareSha256).derive_channel_tag(key)
}

/// The canonical name of the well-known `EMERGENCY` channel.
pub(crate) const EMERGENCY_CHANNEL_NAME: &str = "emergency";

/// The tag of the well-known `EMERGENCY` channel.
///
/// Emergency traffic is singled out by which channel carries it and by nothing
/// on the wire, so recognizing the channel is the whole of the test. Derived
/// from the name rather than written down as a literal, so it cannot drift
/// from the derivation every other channel goes through.
pub(crate) fn emergency_channel_tag() -> umsh_core::ChannelTag {
    static TAG: std::sync::OnceLock<umsh_core::ChannelTag> = std::sync::OnceLock::new();

    *TAG.get_or_init(|| {
        channel_tag(
            umsh_node::Channel::named(EMERGENCY_CHANNEL_NAME)
                .expect("the emergency channel name is short ASCII")
                .key(),
        )
    })
}

/// The address of a channel's group conversation, as the chat records carry it.
///
/// Exported so the platform never has to reproduce the derivation itself and
/// risk disagreeing with the records it is matching against.
#[uniffi::export]
pub fn channel_conversation_address(key: Vec<u8>) -> Result<String, MobileError> {
    Ok(crate::mobile_chat::channel_address(channel_tag(
        &channel_key_from_bytes(&key)?,
    )))
}

/// Build a shareable channel URI.
///
/// Supplying `name` produces the `umsh:cs:` form, which is not a secret;
/// otherwise the `umsh:ck:` form is produced, which carries the channel key
/// and grants full membership to anyone who receives it.
#[uniffi::export]
pub fn format_channel_invitation(
    key: Vec<u8>,
    name: Option<String>,
    display_name: Option<String>,
    max_flood_hops: Option<u8>,
    region: Option<Vec<u8>>,
) -> Result<String, MobileError> {
    let region_text = match region {
        None => None,
        Some(code) => Some(ulcp::region_code_description(code)?),
    };
    let params = umsh_uri::ChannelParams {
        display_name: display_name.as_deref(),
        max_flood_hops,
        region: region_text.as_deref(),
        raw_query: None,
    };

    // Fixed-width scheme, key, and separators plus the escaped free-text
    // parameters, each of which can triple in length.
    let mut buf = alloc_uri_buffer(&params);
    let written = match name.as_deref() {
        Some(name) => umsh_uri::format_channel_name_uri_with_params(name, &params, &mut buf),
        None => umsh_uri::format_channel_key_uri_with_params(
            &channel_key_from_bytes(&key)?,
            &params,
            &mut buf,
        ),
    }
    .map_err(|_| MobileError::InvalidUri)?;

    String::from_utf8(buf[..written].to_vec()).map_err(|_| MobileError::InvalidUri)
}

fn alloc_uri_buffer(params: &umsh_uri::ChannelParams<'_>) -> Vec<u8> {
    let escaped = |value: Option<&str>| value.map_or(0, |text| text.len() * 3);
    let len = 128 + escaped(params.display_name) + escaped(params.region);
    vec![0u8; len]
}

fn named_channel_preview(name: &str) -> Result<ChannelPreviewRecord, MobileError> {
    let channel = umsh_node::Channel::named(name).map_err(|err| match err {
        umsh_crypto::ChannelNameError::NotAscii => MobileError::ChannelNameNotAscii,
        umsh_crypto::ChannelNameError::TooLong => MobileError::ChannelNameTooLong,
    })?;
    Ok(ChannelPreviewRecord {
        kind: ChannelKindRecord::NamedPublic,
        canonical_name: Some(name.to_ascii_lowercase()),
        key: channel.key().0.to_vec(),
        channel_id: channel.channel_id().0.to_vec(),
        tint: channel_tint(channel.key()),
        // Only the canonicalized form derives the key; the casing the name
        // was written with is how people actually refer to the channel, so it
        // is what a display name defaults to.
        display_name: Some(name.to_owned()),
        max_flood_hops: None,
        region: None,
    })
}

/// Overlay a URI's advisory parameters onto a preview.
///
/// These are recommendations from whoever wrote the invitation, not policy: a
/// region that does not parse is dropped rather than failing the import.
fn apply_channel_params(
    record: &mut ChannelPreviewRecord,
    params: &umsh_uri::ChannelParams<'_>,
) -> Result<(), MobileError> {
    if let Some(display_name) = params.display_name {
        record.display_name =
            Some(umsh_uri::decode_percent(display_name).map_err(|_| MobileError::InvalidUri)?);
    }
    record.max_flood_hops = params.max_flood_hops;
    if let Some(region) = params.region {
        record.region = umsh_uri::decode_percent(region)
            .ok()
            .and_then(|text| ulcp::region_code_from_string(text).ok());
    }
    Ok(())
}

fn channel_key_from_bytes(key: &[u8]) -> Result<umsh_core::ChannelKey, MobileError> {
    let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| MobileError::InvalidChannelKeyLength)?;
    Ok(umsh_core::ChannelKey(bytes))
}

/// Decode a persisted advertised-identity payload for display.
///
/// `address` is the canonical Base58 address of the node the payload claims
/// to describe; the signature state is recomputed against it on every call.
#[uniffi::export]
pub fn decode_node_identity(
    address: String,
    payload: Vec<u8>,
) -> Result<NodeIdentityRecord, MobileError> {
    let key = PublicKey(umsh_core::base58::decode(address.as_bytes())?);
    node_identity_record(&key, &payload)
}

fn node_identity_record(
    key: &PublicKey,
    payload: &[u8],
) -> Result<NodeIdentityRecord, MobileError> {
    let identity = umsh_node::NodeIdentityPayload::from_bytes(payload)
        .map_err(|_| MobileError::InvalidIdentityData)?;

    let signature = match identity.signature {
        None => IdentitySignatureState::Unsigned,
        Some(signature) => {
            // The signed range is everything before the trailing signature.
            let signed = &payload[..payload.len() - 64];
            if umsh_crypto::verify_ed25519_signature(key, signed, &signature) {
                IdentitySignatureState::Valid
            } else {
                IdentitySignatureState::Invalid
            }
        }
    };

    let role_label = match identity.role {
        umsh_node::NodeRole::Unspecified => "Unspecified".to_owned(),
        umsh_node::NodeRole::Repeater => "Repeater".to_owned(),
        umsh_node::NodeRole::Chat => "Chat".to_owned(),
        umsh_node::NodeRole::Tracker => "Tracker".to_owned(),
        umsh_node::NodeRole::Sensor => "Sensor".to_owned(),
        umsh_node::NodeRole::Bridge => "Bridge".to_owned(),
        umsh_node::NodeRole::ChatRoom => "Chat room".to_owned(),
        umsh_node::NodeRole::TemporarySession => "Temporary session".to_owned(),
        umsh_node::NodeRole::Unknown(code) => format!("Unknown ({code})"),
    };

    let capabilities = [
        (umsh_node::NodeCapabilities::REPEATER, "Repeater"),
        (umsh_node::NodeCapabilities::MOBILE, "Mobile"),
        (umsh_node::NodeCapabilities::TEXT_MESSAGES, "Text messages"),
        (umsh_node::NodeCapabilities::TELEMETRY, "Telemetry"),
        (umsh_node::NodeCapabilities::CHAT_ROOM, "Chat room"),
        (umsh_node::NodeCapabilities::COAP, "CoAP"),
    ]
    .into_iter()
    .filter(|(bit, _)| identity.capabilities.contains(*bit))
    .map(|(_, label)| label.to_owned())
    .collect();

    let location = identity.location.filter(|loc| !loc.is_unspecified());
    let (latitude, longitude, location_precision) = match location {
        None => (None, None, None),
        Some(location) => {
            let (lon, lat) = location.center();
            (
                Some(f64::from(lat)),
                Some(f64::from(lon)),
                Some(location.precision()),
            )
        }
    };

    Ok(NodeIdentityRecord {
        role_code: identity.role.as_byte(),
        role_label,
        capabilities,
        name: identity.name,
        latitude,
        longitude,
        location_precision,
        altitude_m: identity.altitude_m,
        timestamp: identity.timestamp,
        signature,
    })
}

/// Inspect a pasted peer identity in any user-facing interchange form.
///
/// Accepted input is a node URI, the canonical fixed-width Base58 public
/// address, or exactly 32 public-key bytes written as hexadecimal (with an
/// optional `0x` prefix). The result always returns the canonical Base58 form.
#[uniffi::export]
pub fn inspect_peer_identity(input: String) -> Result<NodeUriPreviewRecord, MobileError> {
    let input = input.trim();
    if input.starts_with("umsh:") {
        return inspect_node_uri(input.to_owned());
    }

    let hex_input = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    let hex = hex_input
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && !matches!(character, ':' | '-'))
        .collect::<String>();
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut public_key = [0u8; 32];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let pair =
                core::str::from_utf8(pair).map_err(|_| MobileError::InvalidAddressCharacter)?;
            public_key[index] =
                u8::from_str_radix(pair, 16).map_err(|_| MobileError::InvalidAddressCharacter)?;
        }
        let identity = public_identity_record(&PublicKey(public_key));
        return Ok(NodeUriPreviewRecord {
            canonical_address: identity.canonical_address,
            hint: identity.hint,
            has_identity_data: false,
            identity: None,
            identity_payload: None,
        });
    }

    let identity = inspect_public_identity(input.to_owned())?;
    Ok(NodeUriPreviewRecord {
        canonical_address: identity.canonical_address,
        hint: identity.hint,
        has_identity_data: false,
        identity: None,
        identity_payload: None,
    })
}

/// Render the canonical shareable node URI for a public identity address.
///
/// The result is the plain `umsh:n:` form without an appended identity
/// bundle, suitable for copying and for QR presentation of the bare key.
#[uniffi::export]
pub fn node_uri_for_address(address: String) -> Result<String, MobileError> {
    let key = PublicKey(umsh_core::base58::decode(address.as_bytes())?);
    let mut buf = [0u8; 64];
    let len = umsh_uri::format_node_uri(&key, &mut buf).map_err(|_| MobileError::InvalidUri)?;
    Ok(core::str::from_utf8(&buf[..len])
        .expect("node URI is ASCII")
        .to_owned())
}

/// Render the shareable node URI carrying a signed identity bundle:
/// `umsh:n:<address>:<base58 bundle>`.
#[uniffi::export]
pub fn node_uri_with_identity(
    address: String,
    identity_payload: Vec<u8>,
) -> Result<String, MobileError> {
    let base = node_uri_for_address(address)?;
    Ok(format!(
        "{base}:{}",
        umsh_uri::encode_base58_bytes(&identity_payload)
    ))
}

/// Return the binding-visible mobile API version.
#[uniffi::export]
pub fn mobile_api_version() -> u16 {
    MOBILE_API_VERSION
}

/// Render a node hint using the protocol's canonical ambiguity rules.
#[uniffi::export]
pub fn render_node_hint(bytes: Vec<u8>) -> Result<NodeHintRecord, MobileError> {
    let bytes: [u8; 3] = bytes
        .try_into()
        .map_err(|_| MobileError::InvalidNodeHintLength)?;
    Ok(render_node_hint_bytes(bytes))
}

/// Render a router hint using the protocol's canonical ambiguity rules.
#[uniffi::export]
pub fn render_router_hint(bytes: Vec<u8>) -> Result<RouterHintRecord, MobileError> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| MobileError::InvalidRouterHintLength)?;
    Ok(RouterHintRecord {
        bytes: bytes.to_vec(),
        text: RouterHint(bytes).to_string(),
    })
}

fn render_node_hint_bytes(bytes: [u8; 3]) -> NodeHintRecord {
    NodeHintRecord {
        bytes: bytes.to_vec(),
        text: NodeHint(bytes).to_string(),
    }
}

/// Parse and canonicalize a complete public identity address.
///
/// The returned record contains public information only. Invalid input is not
/// copied into the error, preventing accidental disclosure through diagnostics.
#[uniffi::export]
pub fn inspect_public_identity(address: String) -> Result<PublicIdentityRecord, MobileError> {
    let key = PublicKey(umsh_core::base58::decode(address.as_bytes())?);
    Ok(public_identity_record(&key))
}

/// Decode a canonical address to the raw public-key bytes carried by ULCP
/// `PROP_HOST_KEY`.
#[uniffi::export]
pub fn public_identity_bytes(address: String) -> Result<Vec<u8>, MobileError> {
    Ok(umsh_core::base58::decode(address.as_bytes())?.to_vec())
}

/// Inspect a raw 32-byte Ed25519 public identity received from a trusted wire
/// decoder, returning the same canonical UI-safe representation as an address.
#[uniffi::export]
pub fn inspect_public_identity_bytes(
    public_key: Vec<u8>,
) -> Result<PublicIdentityRecord, MobileError> {
    let bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| MobileError::InvalidPublicKeyLength)?;
    Ok(public_identity_record(&PublicKey(bytes)))
}

/// Identity secret retained by the Rust engine after one controlled unlock
/// transfer. Swift receives only public identity records from this object.
#[derive(uniffi::Object)]
pub struct MobileIdentity {
    identity: Mutex<Option<SoftwareIdentity>>,
    public_identity: PublicIdentityRecord,
}

#[uniffi::export]
impl MobileIdentity {
    #[uniffi::constructor]
    pub fn unlock(mut secret_key: Vec<u8>) -> Result<Arc<Self>, MobileError> {
        let result = (|| {
            let mut bytes: [u8; 32] = secret_key
                .as_slice()
                .try_into()
                .map_err(|_| MobileError::InvalidSecretKeyLength)?;
            let identity = SoftwareIdentity::from_secret_bytes(&bytes);
            let public_identity = public_identity_record(identity.public_key());
            bytes.zeroize();
            Ok(Arc::new(Self {
                identity: Mutex::new(Some(identity)),
                public_identity,
            }))
        })();
        secret_key.zeroize();
        result
    }

    pub fn public_identity(&self) -> PublicIdentityRecord {
        self.public_identity.clone()
    }
}

impl MobileIdentity {
    fn take_for_session(&self) -> Result<SoftwareIdentity, MobileMeshError> {
        self.identity
            .lock()
            .map_err(|_| MobileMeshError::SessionUnavailable)?
            .take()
            .ok_or(MobileMeshError::SessionUnavailable)
    }
}

fn public_identity_record(key: &PublicKey) -> PublicIdentityRecord {
    let canonical_address = umsh_core::base58::encode(&key.0)
        .into_iter()
        .map(char::from)
        .collect();

    PublicIdentityRecord {
        canonical_address,
        hint: render_node_hint_bytes(NodeHint::from_public_key(&key).0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_node_hints_match_protocol_vectors() {
        for (bytes, expected) in [
            ([0x00, 0x00, 0x00], "1111"),
            ([0xFF, 0xFF, 0xFF], "JEKN"),
            ([0xA1, 0xB2, 0x03], "BtC5"),
            ([0x84, 0x81, 0x1B], "9v*"),
        ] {
            assert_eq!(
                render_node_hint(bytes.to_vec()).unwrap(),
                NodeHintRecord {
                    bytes: bytes.to_vec(),
                    text: expected.to_owned(),
                }
            );
        }
    }

    #[test]
    fn reference_router_hints_match_protocol_vectors() {
        for (bytes, expected) in [
            ([0x00, 0x00], "111"),
            ([0xA1, 0xB2], "BtC"),
            ([0x5E, 0xA1], "7N*"),
            ([0x00, 0x41], "1*"),
        ] {
            assert_eq!(
                render_router_hint(bytes.to_vec()).unwrap(),
                RouterHintRecord {
                    bytes: bytes.to_vec(),
                    text: expected.to_owned(),
                }
            );
        }

        assert_eq!(
            render_router_hint(vec![0x00, 0x01, 0x02]),
            Err(MobileError::InvalidRouterHintLength)
        );
    }

    #[test]
    fn public_identity_is_canonical_and_derives_hint_in_rust() {
        let address = "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE";
        let identity = inspect_public_identity(address.to_owned()).unwrap();

        assert_eq!(identity.canonical_address, address);
        assert_eq!(identity.hint.bytes, [0, 1, 2]);
        assert_eq!(identity.hint.text, "111t");
    }

    #[test]
    fn node_uri_preview_is_typed_and_non_mutating() {
        let address = "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE";
        let preview = inspect_node_uri(format!("umsh:n:{address}")).unwrap();
        assert_eq!(preview.canonical_address, address);
        assert!(!preview.has_identity_data);

        let with_metadata = inspect_node_uri(format!("umsh:n:{address}:signed-data")).unwrap();
        assert!(with_metadata.has_identity_data);
        assert_eq!(
            inspect_node_uri("umsh:cs:public".to_owned()),
            Err(MobileError::InvalidUri)
        );
    }

    #[test]
    fn channel_and_node_uri_inspection_reject_each_other() {
        let address = "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE";
        assert_eq!(
            inspect_channel_uri(format!("umsh:n:{address}")),
            Err(MobileError::InvalidUri)
        );
        assert!(inspect_channel_uri("umsh:cs:public".to_owned()).is_ok());
    }

    #[test]
    fn named_channel_key_follows_the_canonical_lowercase_name() {
        let typed = inspect_channel_name("Public".to_owned()).unwrap();
        let canonical = inspect_channel_name("public".to_owned()).unwrap();

        assert_eq!(typed.kind, ChannelKindRecord::NamedPublic);
        assert_eq!(typed.canonical_name.as_deref(), Some("public"));
        // The fold is what makes these one channel, so the UI can show the
        // canonical form as the thing actually being joined.
        assert_eq!(typed.key, canonical.key);
        assert_eq!(typed.channel_id, canonical.channel_id);
        assert_eq!(typed.key.len(), 32);
        assert_eq!(typed.channel_id.len(), 2);
    }

    #[test]
    fn named_channel_uri_and_plain_name_agree() {
        let from_uri = inspect_channel_uri("umsh:cs:EMERGENCY".to_owned()).unwrap();
        let from_name = inspect_channel_name("EMERGENCY".to_owned()).unwrap();
        assert_eq!(from_uri.key, from_name.key);
        assert_eq!(from_uri.canonical_name.as_deref(), Some("emergency"));
    }

    #[test]
    fn channel_names_outside_the_derivation_domain_are_typed_errors() {
        assert_eq!(
            inspect_channel_name("café".to_owned()),
            Err(MobileError::ChannelNameNotAscii)
        );
        assert_eq!(
            inspect_channel_name("x".repeat(65)),
            Err(MobileError::ChannelNameTooLong)
        );
    }

    #[test]
    fn private_channel_invitation_round_trips_through_a_uri() {
        let key = generate_channel_key();
        let region = ulcp::region_code_from_string("SJC".to_owned()).unwrap();
        let uri = format_channel_invitation(
            key.clone(),
            None,
            Some("Trail Crew".to_owned()),
            Some(3),
            Some(region.clone()),
        )
        .unwrap();
        assert!(uri.starts_with("umsh:ck:"));

        let preview = inspect_channel_uri(uri).unwrap();
        assert_eq!(preview.kind, ChannelKindRecord::PrivateKey);
        assert_eq!(preview.key, key);
        assert_eq!(preview.canonical_name, None);
        assert_eq!(preview.display_name.as_deref(), Some("Trail Crew"));
        assert_eq!(preview.max_flood_hops, Some(3));
        assert_eq!(preview.region, Some(region));
        assert_eq!(preview.channel_id, derive_channel_id(key).unwrap());
    }

    #[test]
    fn named_channel_invitation_keeps_the_name_out_of_the_key_slot() {
        let key = inspect_channel_name("trail-crew".to_owned()).unwrap().key;
        let uri =
            format_channel_invitation(key.clone(), Some("trail-crew".to_owned()), None, None, None)
                .unwrap();
        assert_eq!(uri, "umsh:cs:trail-crew");

        let preview = inspect_channel_uri(uri).unwrap();
        assert_eq!(preview.kind, ChannelKindRecord::NamedPublic);
        assert_eq!(preview.key, key);
    }

    #[test]
    fn a_named_channel_invitation_carries_the_name_as_written() {
        // The name is a URI path segment, so anything outside the unreserved
        // set has to be escaped or the invitation will not parse back. Casing
        // travels as written; canonicalization happens after percent-decoding,
        // on the way in.
        let key = inspect_channel_name("Trail Crew".to_owned()).unwrap().key;
        let uri =
            format_channel_invitation(key.clone(), Some("Trail Crew".to_owned()), None, None, None)
                .unwrap();
        assert_eq!(uri, "umsh:cs:Trail%20Crew");

        let back = inspect_channel_uri(uri).unwrap();
        assert_eq!(back.key, key);
        assert_eq!(back.canonical_name.as_deref(), Some("trail crew"));
        // …and the recipient still sees it written the way the sender wrote it.
        assert_eq!(back.display_name.as_deref(), Some("Trail Crew"));
    }

    #[test]
    fn a_named_channel_preview_keeps_the_written_casing_beside_the_canonical_form() {
        let preview = inspect_channel_name("EMERGENCY".to_owned()).unwrap();
        assert_eq!(preview.canonical_name.as_deref(), Some("emergency"));
        assert_eq!(preview.display_name.as_deref(), Some("EMERGENCY"));
        // Same channel either way — only the folded form reaches the key.
        assert_eq!(
            preview.key,
            inspect_channel_name("emergency".to_owned()).unwrap().key
        );
    }

    #[test]
    fn generated_channel_keys_are_distinct_and_full_length() {
        let first = generate_channel_key();
        let second = generate_channel_key();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
        assert_ne!(first, vec![0u8; 32]);
    }

    #[test]
    fn a_channels_tint_extends_its_identifier() {
        let preview = inspect_channel_name("Public".to_owned()).unwrap();
        assert_eq!(preview.tint.len(), 3);
        // The interface colours a channel from the tint and labels it with the
        // identifier; they have to agree about which channel they describe.
        assert_eq!(&preview.tint[..2], &preview.channel_id[..]);
        assert_eq!(derive_channel_tint(preview.key).unwrap(), preview.tint);
    }

    #[test]
    fn channel_id_derivation_rejects_a_wrong_length_key() {
        assert_eq!(
            derive_channel_id(vec![0u8; 31]),
            Err(MobileError::InvalidChannelKeyLength)
        );
    }

    #[test]
    fn an_unparseable_region_recommendation_does_not_fail_the_import() {
        // Advisory parameters are the sender's suggestion, not policy, so a
        // corrupted one is dropped rather than blocking the join.
        let address = umsh_uri::encode_channel_key_base58(&umsh_core::ChannelKey([0x21; 32]));
        let preview = inspect_channel_uri(format!("umsh:ck:{address}?n=Camp;r=0xZZZZ")).unwrap();
        assert_eq!(preview.display_name.as_deref(), Some("Camp"));
        assert_eq!(preview.region, None);
    }

    #[test]
    fn a_region_named_rather_than_coded_survives_the_invitation_round_trip() {
        // Display of a hashed name is `0xXXXX`, which must read back as the
        // same code or a shared invitation would silently retarget.
        let key = generate_channel_key();
        let region = ulcp::region_code_from_string("Willamette Valley".to_owned()).unwrap();
        let uri = format_channel_invitation(key, None, None, None, Some(region.clone())).unwrap();
        assert_eq!(inspect_channel_uri(uri).unwrap().region, Some(region));
    }

    #[tokio::test]
    async fn signed_identity_bundle_round_trips_through_uri_inspection() {
        let identity = SoftwareIdentity::from_secret_bytes(&[7u8; 32]);
        let payload = umsh_node::NodeIdentityPayload {
            role: umsh_node::NodeRole::Chat,
            capabilities: umsh_node::NodeCapabilities::TEXT_MESSAGES
                | umsh_node::NodeCapabilities::MOBILE,
            name: Some("Basecamp".into()),
            location: Some(umsh_node::location::NodeLocation::from_lat_lon(
                -123.09, 44.05, 4,
            )),
            altitude_m: Some(72),
            timestamp: Some(1_760_000_000),
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 256];
        let len = payload.encode_for_signing(&mut buf).unwrap();
        let signature = identity.sign(&buf[..len]).await.unwrap();
        buf[len..len + 64].copy_from_slice(&signature);
        let bundle = &buf[..len + 64];

        let address = public_identity_record(identity.public_key()).canonical_address;
        let uri = format!("umsh:n:{address}:{}", umsh_uri::encode_base58_bytes(bundle));
        let preview = inspect_node_uri(uri).unwrap();
        assert!(preview.has_identity_data);
        assert_eq!(preview.identity_payload.as_deref(), Some(bundle));
        let record = preview.identity.unwrap();
        assert_eq!(record.signature, IdentitySignatureState::Valid);
        assert_eq!(record.role_label, "Chat");
        assert_eq!(record.name.as_deref(), Some("Basecamp"));
        assert_eq!(
            record.capabilities,
            vec!["Mobile".to_owned(), "Text messages".to_owned()]
        );
        assert_eq!(record.altitude_m, Some(72));
        assert_eq!(record.timestamp, Some(1_760_000_000));
        assert_eq!(record.location_precision, Some(4));
        // A 4-byte grid cell is ~610 x 305 m; the center must land nearby.
        assert!((record.latitude.unwrap() - 44.05).abs() < 0.01);
        assert!((record.longitude.unwrap() + 123.09).abs() < 0.01);

        // Tampering with the signed range must flag the bundle and withhold
        // the persistable payload.
        let mut tampered = bundle.to_vec();
        tampered[0] ^= 0x01;
        let uri = format!(
            "umsh:n:{address}:{}",
            umsh_uri::encode_base58_bytes(&tampered)
        );
        let preview = inspect_node_uri(uri).unwrap();
        assert_eq!(
            preview.identity.unwrap().signature,
            IdentitySignatureState::Invalid
        );
        assert!(preview.identity_payload.is_none());

        // An unsigned bundle stays displayable and persistable, but is
        // explicitly marked unauthenticated.
        let unsigned_len = {
            let unsigned = umsh_node::NodeIdentityPayload {
                signature: None,
                ..payload.clone()
            };
            unsigned.encode(&mut buf).unwrap()
        };
        let uri = format!(
            "umsh:n:{address}:{}",
            umsh_uri::encode_base58_bytes(&buf[..unsigned_len])
        );
        let preview = inspect_node_uri(uri).unwrap();
        assert_eq!(
            preview.identity.unwrap().signature,
            IdentitySignatureState::Unsigned
        );
        assert!(preview.identity_payload.is_some());
    }

    #[test]
    fn node_uri_round_trips_through_inspection() {
        let address = "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE";
        let uri = node_uri_for_address(address.to_owned()).unwrap();

        assert_eq!(uri, format!("umsh:n:{address}"));
        let preview = inspect_node_uri(uri).unwrap();
        assert_eq!(preview.canonical_address, address);
    }

    #[test]
    fn errors_are_stable_and_do_not_echo_input() {
        let error = inspect_public_identity("secret-ish-invalid-input".to_owned()).unwrap_err();

        assert_eq!(error, MobileError::InvalidAddressLength);
        assert_eq!(error.summary_key(), "mobile.error.address.invalid_length");
        assert_eq!(error.to_string(), "ADDRESS_INVALID_LENGTH");
        assert!(!error.to_string().contains("secret-ish"));
    }

    #[test]
    fn distinguishes_invalid_character_from_overflow() {
        let invalid = "11111111111111111111111111111111111111111110";
        assert_eq!(
            inspect_public_identity(invalid.to_owned()).unwrap_err(),
            MobileError::InvalidAddressCharacter
        );

        assert_eq!(
            inspect_public_identity("z".repeat(44)).unwrap_err(),
            MobileError::AddressOverflow
        );
    }

    #[test]
    fn binding_hint_input_requires_exactly_three_bytes() {
        let error = render_node_hint(vec![0, 1]).unwrap_err();
        assert_eq!(error, MobileError::InvalidNodeHintLength);
        assert_eq!(error.to_string(), "NODE_HINT_INVALID_LENGTH");
    }

    #[test]
    fn raw_public_identity_uses_the_canonical_renderer() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let identity = inspect_public_identity_bytes(bytes.clone()).unwrap();
        let address = umsh_core::base58::encode(&bytes.try_into().unwrap())
            .into_iter()
            .map(char::from)
            .collect::<String>();
        assert_eq!(identity, inspect_public_identity(address).unwrap());
        assert_eq!(
            inspect_public_identity_bytes(vec![0; 31]).unwrap_err(),
            MobileError::InvalidPublicKeyLength
        );
    }

    #[test]
    fn public_identity_bytes_round_trip_canonical_address() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let identity = inspect_public_identity_bytes(bytes.clone()).unwrap();
        assert_eq!(
            public_identity_bytes(identity.canonical_address).unwrap(),
            bytes
        );
    }

    #[test]
    fn peer_identity_accepts_uri_base58_and_hex() {
        let key = [0xAB; 32];
        let canonical = public_identity_record(&PublicKey(key)).canonical_address;
        let hex = key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let colon_hex = key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        for input in [
            canonical.clone(),
            format!("0x{hex}"),
            colon_hex,
            format!("umsh:n:{canonical}"),
        ] {
            let preview = inspect_peer_identity(input).unwrap();
            assert_eq!(preview.canonical_address, canonical);
        }
    }

    #[test]
    fn peer_identity_rejects_wrong_length_hex() {
        assert!(inspect_peer_identity("ab12".into()).is_err());
    }

    #[test]
    fn secret_identity_derivation_returns_only_valid_public_material() {
        let identity = MobileIdentity::unlock(vec![7; 32])
            .unwrap()
            .public_identity();
        assert_eq!(identity.canonical_address.len(), 44);
        assert_eq!(
            inspect_public_identity(identity.canonical_address.clone()).unwrap(),
            identity
        );

        assert!(matches!(
            MobileIdentity::unlock(vec![7; 31]),
            Err(MobileError::InvalidSecretKeyLength)
        ));
    }
}
