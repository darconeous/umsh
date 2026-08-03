//! The tunnel's TLS 1.3 layer: pinned mutual certificates.
//!
//! The spec allows either external PSKs or "mutually authenticated
//! certificates with pinned or locally trusted roots". This is the
//! second: every participant holds one self-signed certificate, and each
//! side is configured with the SHA-256 of the certificates it will
//! accept. There is no CA, no name validation, and no expiry check — the
//! pin is the whole of the trust decision, which makes revoking a client
//! an edit to the server's config rather than a PKI operation.

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{CryptoProvider, verify_tls13_signature};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{
    self, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};

/// ALPN identifier from the spec. A future revision of the tunnel wire
/// protocol picks a new one and fails the handshake against this one
/// rather than misparsing its frames.
pub const ALPN: &[u8] = b"umsh-bridge/1";

/// SHA-256 of a certificate in DER form — the name a bridge participant
/// is known by.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(cert: &CertificateDer<'_>) -> Self {
        Self(Sha256::digest(cert.as_ref()).into())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Fingerprint {
    type Err = anyhow::Error;

    /// Accepts `sha256:<64 hex>`, or the bare hex; colons and spaces
    /// inside the digest are ignored, so a fingerprint pasted from
    /// another tool's colon-separated output still parses.
    fn from_str(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix("sha256:")
            .or_else(|| text.trim().strip_prefix("SHA256:"))
            .unwrap_or(text.trim());
        let hex: String = body
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '-'))
            .collect();
        if hex.len() != 64 {
            bail!(
                "a certificate fingerprint is 64 hex digits (a SHA-256); got {}",
                hex.len()
            );
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| anyhow!("fingerprint contains a non-hex digit"))?;
        }
        Ok(Self(bytes))
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// The credential this participant presents.
pub struct Credential {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: Fingerprint,
}

impl Credential {
    pub fn load(cert_file: &Path, key_file: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_file)
            .with_context(|| format!("reading certificate {}", cert_file.display()))?;
        let key_pem = std::fs::read_to_string(key_file)
            .with_context(|| format!("reading private key {}", key_file.display()))?;

        let chain = parse_certificates(&cert_pem)
            .with_context(|| format!("parsing certificate {}", cert_file.display()))?;
        let end_entity = chain
            .first()
            .ok_or_else(|| anyhow!("{} contains no certificate", cert_file.display()))?;
        let fingerprint = Fingerprint::of(end_entity);

        let key = parse_private_key(&key_pem)
            .with_context(|| format!("parsing private key {}", key_file.display()))?;

        Ok(Self {
            chain,
            key,
            fingerprint,
        })
    }
}

/// DER of the first certificate in a PEM file.
pub fn first_certificate(pem: &str) -> Result<Vec<u8>> {
    pem_blocks(pem, "CERTIFICATE")
        .next()
        .ok_or_else(|| anyhow!("no CERTIFICATE block found"))?
}

fn parse_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut out = Vec::new();
    for block in pem_blocks(pem, "CERTIFICATE") {
        out.push(CertificateDer::from(block?));
    }
    if out.is_empty() {
        bail!("no CERTIFICATE block found");
    }
    Ok(out)
}

fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    for (label, wrap) in [
        (
            "PRIVATE KEY",
            (|der| PrivateKeyDer::Pkcs8(der.into())) as fn(Vec<u8>) -> PrivateKeyDer<'static>,
        ),
        ("EC PRIVATE KEY", |der| PrivateKeyDer::Sec1(der.into())),
        ("RSA PRIVATE KEY", |der| PrivateKeyDer::Pkcs1(der.into())),
    ] {
        if let Some(block) = pem_blocks(pem, label).next() {
            return Ok(wrap(block?));
        }
    }
    bail!("no PRIVATE KEY block found")
}

/// Minimal PEM reader. Pulling in a parser crate to read two files this
/// tool wrote itself is not worth the dependency.
fn pem_blocks<'a>(pem: &'a str, label: &'a str) -> impl Iterator<Item = Result<Vec<u8>>> + use<'a> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut rest = pem;
    std::iter::from_fn(move || {
        let start = rest.find(&begin)? + begin.len();
        let body_end = rest[start..].find(&end)? + start;
        let body: String = rest[start..body_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        rest = &rest[body_end + end.len()..];
        Some(base64_decode(&body))
    })
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .ok_or_else(|| anyhow!("invalid base64 in PEM body"))? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Server side: accept exactly the certificates in `accepted`.
pub fn server_config(
    credential: &Credential,
    accepted: Vec<Fingerprint>,
) -> Result<Arc<ServerConfig>> {
    let provider = provider();
    let verifier = Arc::new(PinnedClientVerifier {
        accepted,
        provider: provider.clone(),
    });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 is not available in this build")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(credential.chain.clone(), credential.key.clone_key())
        .context("the certificate and private key do not go together")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Client side: accept exactly the server certificate pinned in config.
pub fn client_config(credential: &Credential, server: Fingerprint) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let verifier = Arc::new(PinnedServerVerifier {
        accepted: server,
        provider: provider.clone(),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 is not available in this build")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(credential.chain.clone(), credential.key.clone_key())
        .context("the certificate and private key do not go together")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// The name presented in SNI. The pin authenticates the server, so this
/// is only a routing hint for a server that multiplexes on it — but
/// rustls requires *some* name, and an IP literal is not one.
pub fn server_name(name: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(name.to_string())
        .map_err(|_| anyhow!("\"{name}\" is not a usable TLS server name"))
}

#[derive(Debug)]
struct PinnedClientVerifier {
    accepted: Vec<Fingerprint>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientVerifier {
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
        if self.accepted.contains(&Fingerprint::of(end_entity)) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate is not pinned by this bridge".into(),
            ))
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedServerVerifier {
    accepted: Fingerprint,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Fingerprint::of(end_entity) == self.accepted {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the configured fingerprint".into(),
            ))
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "9f2a1b0c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829304a5b6c7d8";

    #[test]
    fn a_fingerprint_round_trips_through_its_text_form() {
        let parsed: Fingerprint = format!("sha256:{HEX}").parse().unwrap();
        assert_eq!(parsed.to_string(), format!("sha256:{HEX}"));
        assert_eq!(HEX.parse::<Fingerprint>().unwrap(), parsed, "bare hex");
    }

    #[test]
    fn a_colon_separated_digest_from_another_tool_parses() {
        let spaced: String = HEX
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            spaced.parse::<Fingerprint>().unwrap(),
            HEX.parse::<Fingerprint>().unwrap()
        );
    }

    #[test]
    fn a_wrong_length_or_non_hex_digest_is_rejected() {
        assert!("sha256:abcd".parse::<Fingerprint>().is_err());
        assert!(format!("sha256:{HEX}ff").parse::<Fingerprint>().is_err());
        let bad = format!("{}zz", &HEX[..62]);
        assert!(bad.parse::<Fingerprint>().is_err());
    }

    #[test]
    fn base64_decodes_with_and_without_padding() {
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert!(base64_decode("TW*u").is_err());
    }
}
