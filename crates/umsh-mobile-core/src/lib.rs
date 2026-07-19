//! Stable, value-oriented facade for native UMSH mobile applications.
//!
//! This crate deliberately exposes application operations instead of mirroring
//! the internal protocol crate graph. Platform bindings should wrap this API;
//! mobile feature code should not depend on `umsh-core` directly.

use std::fmt;

use umsh_core::{AddressParseError, NodeHint, PublicKey};
use umsh_crypto::{NodeIdentity, software::SoftwareIdentity};
use zeroize::Zeroize;

mod companion;
mod counter_store;

pub use companion::{
    CompanionBatteryRecord, CompanionPropertyFrameRecord, CompanionSyncRecord, GattSegmentRecord,
    MobileGattReassembler, companion_gatt_segments, companion_inspection_properties,
    companion_prop_get, companion_prop_set, companion_save, inspect_companion_battery,
    inspect_companion_property_frame, inspect_companion_status, inspect_companion_sync,
};
pub use counter_store::{CounterStoreError, MobileCounterStore};

uniffi::setup_scaffolding!();

/// Version of the mobile facade contract.
///
/// Increment this when a binding-visible operation, record, or error contract
/// changes incompatibly. It is independent of the UMSH wire version.
pub const MOBILE_API_VERSION: u16 = 6;

/// Stable error categories consumed by platform adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileError {
    InvalidAddressLength,
    InvalidAddressCharacter,
    AddressOverflow,
    InvalidNodeHintLength,
    InvalidSecretKeyLength,
    InvalidPublicKeyLength,
    InvalidCompanionFrame,
    InvalidGattSegment,
}

impl MobileError {
    /// Stable localization key. Rust prose is never shown directly in the UI.
    pub const fn summary_key(self) -> &'static str {
        match self {
            Self::InvalidAddressLength => "mobile.error.address.invalid_length",
            Self::InvalidAddressCharacter => "mobile.error.address.invalid_character",
            Self::AddressOverflow => "mobile.error.address.overflow",
            Self::InvalidNodeHintLength => "mobile.error.node_hint.invalid_length",
            Self::InvalidSecretKeyLength => "mobile.error.secret_key.invalid_length",
            Self::InvalidPublicKeyLength => "mobile.error.public_key.invalid_length",
            Self::InvalidCompanionFrame => "mobile.error.companion.invalid_frame",
            Self::InvalidGattSegment => "mobile.error.companion.invalid_gatt_segment",
        }
    }

    /// Redacted diagnostic code suitable for logs and support bundles.
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::InvalidAddressLength => "ADDRESS_INVALID_LENGTH",
            Self::InvalidAddressCharacter => "ADDRESS_INVALID_CHARACTER",
            Self::AddressOverflow => "ADDRESS_OVERFLOW",
            Self::InvalidNodeHintLength => "NODE_HINT_INVALID_LENGTH",
            Self::InvalidSecretKeyLength => "SECRET_KEY_INVALID_LENGTH",
            Self::InvalidPublicKeyLength => "PUBLIC_KEY_INVALID_LENGTH",
            Self::InvalidCompanionFrame => "COMPANION_INVALID_FRAME",
            Self::InvalidGattSegment => "COMPANION_INVALID_GATT_SEGMENT",
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

/// Public identity information safe to keep in ordinary application models.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicIdentityRecord {
    /// Exact canonical 44-character fixed-width Base58 address.
    pub canonical_address: String,
    pub hint: NodeHintRecord,
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

/// Decode a canonical address to the raw public-key bytes carried by companion
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

/// Derive public identity information from a 32-byte Ed25519 secret.
///
/// This is the one binding operation used by the platform identity vault when
/// creating or unlocking an identity. The secret is consumed and erased before
/// returning; only the public record crosses back to Swift.
#[uniffi::export]
pub fn derive_public_identity(
    mut secret_key: Vec<u8>,
) -> Result<PublicIdentityRecord, MobileError> {
    let result = (|| {
        let mut bytes: [u8; 32] = secret_key
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidSecretKeyLength)?;
        let identity = SoftwareIdentity::from_secret_bytes(&bytes);
        bytes.zeroize();
        Ok(public_identity_record(identity.public_key()))
    })();
    secret_key.zeroize();
    result
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
    fn public_identity_is_canonical_and_derives_hint_in_rust() {
        let address = "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE";
        let identity = inspect_public_identity(address.to_owned()).unwrap();

        assert_eq!(identity.canonical_address, address);
        assert_eq!(identity.hint.bytes, [0, 1, 2]);
        assert_eq!(identity.hint.text, "111t");
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
    fn secret_identity_derivation_returns_only_valid_public_material() {
        let identity = derive_public_identity(vec![7; 32]).unwrap();
        assert_eq!(identity.canonical_address.len(), 44);
        assert_eq!(
            inspect_public_identity(identity.canonical_address.clone()).unwrap(),
            identity
        );

        assert_eq!(
            derive_public_identity(vec![7; 31]).unwrap_err(),
            MobileError::InvalidSecretKeyLength
        );
    }
}
