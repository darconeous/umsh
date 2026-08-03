//! The tunnel's TLS 1.3 layer: mutual authentication by UMSH identity.
//!
//! Every participant holds an Ed25519 identity — the server's is the
//! bridge's node identity, and a client's is its own, ready to become a
//! mesh-addressable management identity later. Each side is configured
//! with the peer public keys it will accept, written as canonical UMSH
//! addresses.
//!
//! X.509 never enters the trust decision. TLS requires a certificate, so
//! each endpoint mints a throwaway self-signed one around its identity
//! key at startup; what the verifier actually checks is the TLS 1.3
//! handshake signature — proof of possession of the identity key over a
//! transcript both sides contributed randomness to — against the pinned
//! public key. A certificate is a formality here: nothing it claims is
//! believed, nothing about it is stored, and revoking a client is an
//! edit to the server's configuration rather than a PKI operation.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{
    self, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use umsh_core::PublicKey;

use crate::identity::BridgeIdentity;

/// ALPN identifier from the spec. A future revision of the tunnel wire
/// protocol picks a new one and fails the handshake against this one
/// rather than misparsing its frames.
pub const ALPN: &[u8] = b"umsh-bridge/1";

/// A participant's identity in its public form: an Ed25519 public key,
/// written and parsed as the canonical UMSH address (fixed-width base58,
/// or 64 hex digits).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub PublicKey);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let key: PublicKey = text
            .trim()
            .parse()
            .map_err(|error| anyhow!("not a UMSH address: {error:?}"))?;
        // Refused now rather than at connection time: a corrupted
        // address can never verify a signature, so the config that
        // carries it is broken however plausible it looks.
        if !umsh_crypto::is_valid_ed25519_public_key(&key) {
            bail!("not a valid Ed25519 public key");
        }
        Ok(Self(key))
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// The credential this participant presents: its identity key wrapped in
/// a certificate minted in memory. Nothing here touches the filesystem.
pub struct Credential {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub address: Address,
}

impl Credential {
    pub fn for_identity(identity: &BridgeIdentity) -> Result<Self> {
        let pkcs8 = pkcs8_of_seed(identity.seed());
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
            &rcgen::PKCS_ED25519,
        )
        .context("wrapping the identity key for certificate issuance")?;

        let address = Address(*identity.public_key());
        // rcgen's default validity window is 1975 to 4096; since the
        // verifier never consults it, wider is better — a window that
        // could expire would only ever be a scheduled outage.
        let mut params = rcgen::CertificateParams::new(vec!["umsh-bridge.invalid".to_string()])
            .context("building certificate params")?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, address.to_string());
        let certificate = params
            .self_signed(&key_pair)
            .context("self-signing the identity certificate")?;

        Ok(Self {
            chain: vec![certificate.der().clone().into_owned()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
            address,
        })
    }
}

/// PKCS#8 v1 encoding of an Ed25519 seed — the fixed 16-byte prefix is
/// the whole ASN.1 structure for a key this shape.
fn pkcs8_of_seed(seed: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + seed.len());
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(seed);
    der
}

/// The Ed25519 SubjectPublicKeyInfo is a fixed 44-byte structure whose
/// 12-byte prefix is distinctive enough to scan for, which keeps a
/// hostile certificate's DER out of any real parser. If a crafted
/// certificate carries the pattern more than once, the first match wins
/// — harmless, because the handshake signature must verify against the
/// extracted key, so *naming* a key is worthless without holding it.
pub fn certificate_key(cert: &CertificateDer<'_>) -> Option<Address> {
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let der = cert.as_ref();
    let start = der
        .windows(SPKI_PREFIX.len())
        .position(|window| window == SPKI_PREFIX)?
        + SPKI_PREFIX.len();
    let key: [u8; 32] = der.get(start..start + 32)?.try_into().ok()?;
    Some(Address(PublicKey(key)))
}

/// Server side: accept exactly the identities in `accepted`.
pub fn server_config(credential: &Credential, accepted: Vec<Address>) -> Result<Arc<ServerConfig>> {
    let verifier = Arc::new(IdentityClientVerifier { accepted });
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 is not available in this build")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(credential.chain.clone(), credential.key.clone_key())
        .context("the minted certificate and identity key do not go together")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Client side: accept exactly the server identity pinned in config.
pub fn client_config(credential: &Credential, server: Address) -> Result<Arc<ClientConfig>> {
    let verifier = Arc::new(IdentityServerVerifier { accepted: server });
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 is not available in this build")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(credential.chain.clone(), credential.key.clone_key())
        .context("the minted certificate and identity key do not go together")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The name presented in SNI. The pinned identity authenticates the
/// server, so this is only a routing hint for a server that multiplexes
/// on it — but rustls requires *some* name, and an IP literal is not
/// one.
pub fn server_name(name: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(name.to_string())
        .map_err(|_| anyhow!("\"{name}\" is not a usable TLS server name"))
}

/// The load-bearing check, shared by both directions: the handshake
/// signature must verify against `expected` — the pinned identity, not
/// whatever key the certificate happens to carry. `message` already
/// binds the whole transcript, so a passing signature is live proof of
/// possession, not a replayable artifact.
fn verify_identity_signature(
    expected: &Address,
    message: &[u8],
    scheme: SignatureScheme,
    signature: &[u8],
) -> Result<HandshakeSignatureValid, rustls::Error> {
    if scheme != SignatureScheme::ED25519 {
        return Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ));
    }
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| rustls::Error::General("malformed Ed25519 signature".into()))?;
    if umsh_crypto::verify_ed25519_signature(&expected.0, message, signature) {
        Ok(HandshakeSignatureValid::assertion())
    } else {
        Err(rustls::Error::General(
            "the handshake signature does not verify against the pinned identity".into(),
        ))
    }
}

#[derive(Debug)]
struct IdentityClientVerifier {
    accepted: Vec<Address>,
}

impl IdentityClientVerifier {
    /// The certificate's key, if it is one this bridge pins. The
    /// signature check is what makes the answer trustworthy; this only
    /// selects which pinned key that check must pass against.
    fn accepted_key(&self, cert: &CertificateDer<'_>) -> Result<Address, rustls::Error> {
        let key = certificate_key(cert).ok_or_else(|| {
            rustls::Error::General("the certificate carries no Ed25519 key".into())
        })?;
        if self.accepted.contains(&key) {
            Ok(key)
        } else {
            Err(rustls::Error::General(
                "client identity is not configured on this bridge".into(),
            ))
        }
    }

    /// The signature is checked against the key extracted from the
    /// *same certificate* the connection is attributed to later — that
    /// binding is what stops one pinned client from wearing another's
    /// address.
    fn check_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        scheme: SignatureScheme,
        signature: &[u8],
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let key = self.accepted_key(cert)?;
        verify_identity_signature(&key, message, scheme, signature)
    }
}

impl ClientCertVerifier for IdentityClientVerifier {
    /// Empty: naming acceptable issuers would only help a client choose
    /// among several certificates, and each client holds exactly one.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.accepted_key(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.check_signature(message, cert, dss.scheme, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
struct IdentityServerVerifier {
    accepted: Address,
}

impl IdentityServerVerifier {
    /// Deliberately ignores any certificate: whatever it says, the
    /// transcript must be signed by the one identity this client pins.
    fn check_signature(
        &self,
        message: &[u8],
        scheme: SignatureScheme,
        signature: &[u8],
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_identity_signature(&self.accepted, message, scheme, signature)
    }
}

impl ServerCertVerifier for IdentityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Only for a better error while the wrong end is still
        // reachable; the signature check below is the decision.
        match certificate_key(end_entity) {
            Some(key) if key == self.accepted => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::General(
                "the server is not the identity this client pins".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.check_signature(message, dss.scheme, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_crypto::NodeIdentity as _;

    fn identity(seed: u8) -> BridgeIdentity {
        BridgeIdentity::from_seed(&[seed; 32])
    }

    #[test]
    fn an_address_round_trips_through_both_canonical_forms() {
        let id = identity(0x42);
        let address = Address(*id.public_key());
        let base58 = address.to_string();
        assert_eq!(base58.len(), 44, "fixed-width base58");
        assert_eq!(base58.parse::<Address>().unwrap(), address);
        let hex = format!("{:x}", address.0);
        assert_eq!(hex.parse::<Address>().unwrap(), address, "hex form");
    }

    #[test]
    fn a_mistyped_or_invalid_address_is_rejected() {
        assert!("not-an-address".parse::<Address>().is_err());
        // 32 bytes that decode fine but are not a curve point — found by
        // search, since which y-coordinates decompress is not obvious.
        let junk = (0u8..=255)
            .map(|byte| {
                let mut key = [0u8; 32];
                key[0] = byte;
                PublicKey(key)
            })
            .find(|key| !umsh_crypto::is_valid_ed25519_public_key(key))
            .expect("roughly half of all y-coordinates are not on the curve");
        assert!(
            format!("{junk:x}").parse::<Address>().is_err(),
            "not a curve point"
        );
    }

    #[test]
    fn the_minted_certificate_carries_the_identity_key() {
        let id = identity(0x42);
        let credential = Credential::for_identity(&id).unwrap();
        assert_eq!(
            certificate_key(&credential.chain[0]).unwrap().0,
            *id.public_key(),
            "the SPKI scan finds the key the certificate was minted around"
        );
        assert_eq!(credential.address.0, *id.public_key());
    }

    #[test]
    fn the_pkcs8_wrapper_is_the_key_ring_expects() {
        // If the hand-rolled DER ever drifts, config building is the
        // first consumer to notice.
        let credential = Credential::for_identity(&identity(0x42)).unwrap();
        server_config(&credential, vec![credential.address]).unwrap();
        client_config(&credential, credential.address).unwrap();
    }

    async fn signed(by: &BridgeIdentity, message: &[u8]) -> [u8; 64] {
        by.signer().sign(message).await.unwrap()
    }

    #[tokio::test]
    async fn a_pinned_client_that_holds_its_key_verifies() {
        let client = identity(0x11);
        let verifier = IdentityClientVerifier {
            accepted: vec![Address(*client.public_key())],
        };
        let cert = Credential::for_identity(&client).unwrap().chain.remove(0);
        let message = b"transcript";
        let signature = signed(&client, message).await;
        verifier
            .check_signature(message, &cert, SignatureScheme::ED25519, &signature)
            .unwrap();
    }

    #[tokio::test]
    async fn one_pinned_client_cannot_wear_anothers_address() {
        // Mallory is a legitimate, pinned client — but presents a
        // certificate naming Alice's key. The signature is Mallory's, so
        // the binding check must refuse it.
        let alice = identity(0x11);
        let mallory = identity(0x22);
        let verifier = IdentityClientVerifier {
            accepted: vec![Address(*alice.public_key()), Address(*mallory.public_key())],
        };
        let alices_cert = Credential::for_identity(&alice).unwrap().chain.remove(0);
        let message = b"transcript";
        let signature = signed(&mallory, message).await;
        assert!(
            verifier
                .check_signature(message, &alices_cert, SignatureScheme::ED25519, &signature)
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_unpinned_client_is_refused_before_and_after_signing() {
        let stranger = identity(0x33);
        let verifier = IdentityClientVerifier {
            accepted: vec![Address(*identity(0x11).public_key())],
        };
        let cert = Credential::for_identity(&stranger).unwrap().chain.remove(0);
        assert!(
            verifier
                .verify_client_cert(&cert, &[], UnixTime::now())
                .is_err()
        );
        let signature = signed(&stranger, b"transcript").await;
        assert!(
            verifier
                .check_signature(b"transcript", &cert, SignatureScheme::ED25519, &signature)
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_client_verifies_the_server_by_pin_not_by_certificate() {
        let server = identity(0x11);
        let impostor = identity(0x22);
        let verifier = IdentityServerVerifier {
            accepted: Address(*server.public_key()),
        };
        // Whatever certificate is presented, the transcript signature is
        // checked against the pin — an impostor's signature fails, the
        // pinned server's passes.
        let message = b"transcript";
        let signature = signed(&impostor, message).await;
        assert!(
            verifier
                .check_signature(message, SignatureScheme::ED25519, &signature)
                .is_err()
        );
        let signature = signed(&server, message).await;
        verifier
            .check_signature(message, SignatureScheme::ED25519, &signature)
            .unwrap();
    }

    #[tokio::test]
    async fn a_non_ed25519_signature_scheme_is_refused() {
        let client = identity(0x11);
        let verifier = IdentityServerVerifier {
            accepted: Address(*client.public_key()),
        };
        let message = b"transcript";
        let signature = signed(&client, message).await;
        assert!(
            verifier
                .check_signature(message, SignatureScheme::RSA_PSS_SHA256, &signature)
                .is_err()
        );
    }
}
