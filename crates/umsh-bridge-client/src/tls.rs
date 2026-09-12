//! TLS proof of possession uses the device's Ed25519 identity, without PKI trust.
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use embedded_tls::{
    Aes128GcmSha256, Certificate, CertificateRef, CertificateVerifyRef, CryptoProvider,
    SignatureScheme, TlsError, TlsVerifier,
};
use heapless::Vec;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use signature::Signer;

/// Classify authentication refusals when the TLS library preserves their cause.
/// Post-handshake alerts collapsed into InternalError remain TLS failures.
pub fn failure_reason(error: &TlsError) -> umsh_ulcp::bridge::Reason {
    use embedded_tls::alert::AlertDescription as Alert;
    use umsh_ulcp::bridge::Reason;
    match error {
        TlsError::InvalidSignature | TlsError::InvalidCertificate | TlsError::InvalidPrivateKey => {
            Reason::Authentication
        }
        TlsError::HandshakeAborted(
            _,
            Alert::BadCertificate
            | Alert::UnsupportedCertificate
            | Alert::CertificateRevoked
            | Alert::CertificateExpired
            | Alert::CertificateUnknown
            | Alert::UnknownCa
            | Alert::AccessDenied
            | Alert::CertificateRequired
            | Alert::DecryptError,
        ) => Reason::Authentication,
        TlsError::IoError | TlsError::Io(_) => Reason::Tcp,
        _ => Reason::Tls,
    }
}

/// Private to the client task. Never expose this value through ULCP or logging.
pub struct IdentityProvider<R> {
    rng: R,
    key: SigningKey,
    certificate: Vec<u8, 512>,
    verifier: PinnedVerifier,
    signed: bool,
}

impl<R: CryptoRngCore> IdentityProvider<R> {
    pub fn new(seed: &[u8; 32], server: &[u8; 32], rng: R) -> Result<Self, TlsError> {
        let key = SigningKey::from_bytes(seed);
        let certificate = certificate(&key);
        Ok(Self {
            rng,
            key,
            certificate,
            verifier: PinnedVerifier::new(server)?,
            signed: false,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Check after `open`: an abbreviated handshake must not bypass mutual auth.
    pub fn authenticated(&self) -> bool {
        self.signed && self.verifier.verified
    }

    pub fn authentication_failed(&self) -> bool {
        self.verifier.failed
    }
}

impl<R: CryptoRngCore> CryptoProvider for IdentityProvider<R> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = [u8; 64];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<[u8; 64]>, SignatureScheme), TlsError> {
        Ok((
            DeviceSigner {
                key: &self.key,
                signed: &mut self.signed,
            },
            SignatureScheme::Ed25519,
        ))
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        Some(Certificate::X509(self.certificate.as_slice()))
    }
}

struct DeviceSigner<'a> {
    key: &'a SigningKey,
    signed: &'a mut bool,
}

impl signature::SignerMut<[u8; 64]> for DeviceSigner<'_> {
    fn try_sign(&mut self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        let signature: Signature = self.key.try_sign(message)?;
        *self.signed = true;
        Ok(signature.to_bytes())
    }
}

pub struct PinnedVerifier {
    key: VerifyingKey,
    transcript: Option<[u8; 32]>,
    verified: bool,
    failed: bool,
}

impl PinnedVerifier {
    pub fn new(key: &[u8; 32]) -> Result<Self, TlsError> {
        let key = VerifyingKey::from_bytes(key).map_err(|_| TlsError::InvalidSignature)?;
        if key.is_weak() || key.to_edwards().compress().to_bytes() != key.to_bytes() {
            return Err(TlsError::InvalidSignature);
        }
        Ok(Self {
            key,
            transcript: None,
            verified: false,
            failed: false,
        })
    }
}

impl TlsVerifier<Aes128GcmSha256> for PinnedVerifier {
    fn set_hostname_verification(&mut self, _: &str) -> Result<(), TlsError> {
        // The hostname supplies SNI; the pin supplies authentication.
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &Sha256,
        _: CertificateRef,
    ) -> Result<(), TlsError> {
        self.transcript = Some(transcript.clone().finalize().into());
        self.verified = false;
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        self.failed = true;
        self.verified = false;
        if verify.signature_scheme != SignatureScheme::Ed25519 {
            return Err(TlsError::InvalidSignatureScheme);
        }
        let hash = self.transcript.take().ok_or(TlsError::InvalidSignature)?;
        // RFC 8446 section 4.4.3: spaces || context || zero || transcript hash.
        let mut message = Vec::<u8, 130>::new();
        message.extend_from_slice(&[0x20; 64]).unwrap();
        message
            .extend_from_slice(b"TLS 1.3, server CertificateVerify\0")
            .unwrap();
        message.extend_from_slice(&hash).unwrap();
        let signature =
            Signature::from_slice(verify.signature).map_err(|_| TlsError::InvalidSignature)?;
        self.key
            .verify_strict(&message, &signature)
            .map_err(|_| TlsError::InvalidSignature)?;
        self.verified = true;
        self.failed = false;
        Ok(())
    }
}

// A fixed-shape, self-signed X.509 v1 certificate. No untrusted DER is parsed
// here. Lengths depend only on these constants and fixed-size keys/signatures.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8, 512> {
    let mut out = Vec::new();
    out.push(tag).unwrap();
    if body.len() < 128 {
        out.push(body.len() as u8).unwrap();
    } else if body.len() < 256 {
        out.extend_from_slice(&[0x81, body.len() as u8]).unwrap();
    } else {
        out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8])
            .unwrap();
    }
    out.extend_from_slice(body).unwrap();
    out
}

fn certificate(key: &SigningKey) -> Vec<u8, 512> {
    const ALGORITHM: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    const NAME: &[u8] = &[
        0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, b'U', b'M',
        b'S', b'H',
    ];
    let mut validity = Vec::<u8, 512>::new();
    validity
        .extend_from_slice(&tlv(0x17, b"240101000000Z"))
        .unwrap();
    validity
        .extend_from_slice(&tlv(0x17, b"491231235959Z"))
        .unwrap();
    let mut public = Vec::<u8, 512>::new();
    public.push(0).unwrap();
    public
        .extend_from_slice(&key.verifying_key().to_bytes())
        .unwrap();
    let mut spki = Vec::<u8, 512>::from_slice(ALGORITHM).unwrap();
    spki.extend_from_slice(&tlv(0x03, &public)).unwrap();
    let mut tbs = Vec::<u8, 512>::from_slice(&[0x02, 0x01, 0x01]).unwrap();
    for part in [
        ALGORITHM,
        NAME,
        &tlv(0x30, &validity),
        NAME,
        &tlv(0x30, &spki),
    ] {
        tbs.extend_from_slice(part).unwrap();
    }
    let tbs = tlv(0x30, &tbs);
    let signature: Signature = key.sign(&tbs);
    let mut bits = Vec::<u8, 512>::new();
    bits.push(0).unwrap();
    bits.extend_from_slice(&signature.to_bytes()).unwrap();
    let mut body = tbs;
    body.extend_from_slice(ALGORITHM).unwrap();
    body.extend_from_slice(&tlv(0x03, &bits)).unwrap();
    tlv(0x30, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_verifier_rejects_forgery_and_wrong_handshake_context() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut verifier = PinnedVerifier::new(&key.verifying_key().to_bytes()).unwrap();
        let hash = [8; 32];
        let mut message = Vec::<u8, 130>::from_slice(&[0x20; 64]).unwrap();
        message
            .extend_from_slice(b"TLS 1.3, server CertificateVerify\0")
            .unwrap();
        message.extend_from_slice(&hash).unwrap();
        let signature = key.sign(&message).to_bytes();
        verifier.transcript = Some(hash);
        verifier
            .verify_signature(CertificateVerifyRef {
                signature_scheme: SignatureScheme::Ed25519,
                signature: &signature,
            })
            .unwrap();
        assert!(verifier.verified);
        // Proof cannot be reused without a fresh Certificate transcript.
        assert!(
            verifier
                .verify_signature(CertificateVerifyRef {
                    signature_scheme: SignatureScheme::Ed25519,
                    signature: &signature
                })
                .is_err()
        );
        verifier.transcript = Some([9; 32]);
        assert!(
            verifier
                .verify_signature(CertificateVerifyRef {
                    signature_scheme: SignatureScheme::Ed25519,
                    signature: &signature
                })
                .is_err()
        );
        verifier.transcript = Some(hash);
        let mut forged = signature;
        forged[0] ^= 1;
        assert!(
            verifier
                .verify_signature(CertificateVerifyRef {
                    signature_scheme: SignatureScheme::Ed25519,
                    signature: &forged
                })
                .is_err()
        );
        assert!(verifier.failed);
    }
}
