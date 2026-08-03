//! Credential issuance, so a deployment needs nothing but this binary.
//!
//! Two kinds of key exist and they are unrelated: the bridge's node
//! identity, which is an Ed25519 seed and lives only on the server, and
//! a TLS certificate, which every participant has one of.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls_pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

use crate::identity::{BridgeIdentity, format_seed};
use crate::tls::Fingerprint;

/// Certificates are issued long. The pin is the trust decision and
/// nothing consults the validity window, so an expiry date would only
/// ever be a scheduled outage; rotation here is an operator action —
/// issue a new certificate, add its fingerprint, remove the old one.
const VALIDITY_YEARS: i64 = 10;

pub fn write_identity(path: &Path, force: bool) -> Result<()> {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let identity = BridgeIdentity::from_seed(&seed);

    write_secret(path, &format!("{}\n", format_seed(&seed)), force)?;

    println!("identity key: {}", path.display());
    println!("address:      {}", identity.public_key());
    println!("node hint:    {}", identity.node_hint());
    println!("router hint:  {}", identity.router_hint());
    Ok(())
}

pub fn write_certificate(name: &str, cert_path: &Path, key_path: &Path, force: bool) -> Result<()> {
    let key_pair = KeyPair::generate().context("generating a certificate key pair")?;

    // A self-signed certificate that will be pinned needs no subject
    // alternative name to be reachable by, but rustls declines to build
    // a certificate with an empty subject, and a name is what makes a
    // directory of ten of these readable.
    let mut params =
        CertificateParams::new(vec![sanitized_san(name)]).context("building certificate params")?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.distinguished_name.push(
        DnType::OrganizationName,
        "UMSH bridge (self-signed, pinned)",
    );
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = OffsetDateTime::now_utc();
    // Backdated a day so a participant whose clock trails the issuer's
    // does not see a not-yet-valid certificate.
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365 * VALIDITY_YEARS);

    let certificate = params
        .self_signed(&key_pair)
        .context("self-signing the certificate")?;

    write_public(cert_path, &certificate.pem(), force)?;
    write_secret(key_path, &key_pair.serialize_pem(), force)?;

    let fingerprint = Fingerprint::of(certificate.der());
    println!("certificate: {}", cert_path.display());
    println!("private key: {}", key_path.display());
    println!("fingerprint: {fingerprint}");
    Ok(())
}

/// Print the fingerprint of an already-issued certificate — what the
/// operator copies into the other end's config.
pub fn print_fingerprint(cert_path: &Path) -> Result<()> {
    let pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let der = crate::tls::first_certificate(&pem)
        .with_context(|| format!("parsing {}", cert_path.display()))?;
    println!("{}", Fingerprint::of(&CertificateDer::from(der)));
    Ok(())
}

/// A SAN must be a DNS name; a human-chosen interface name is not.
fn sanitized_san(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "bridge.invalid".to_string()
    } else {
        format!("{trimmed}.umsh-bridge.invalid")
    }
}

fn write_public(path: &Path, contents: &str, force: bool) -> Result<()> {
    guard_existing(path, force)?;
    create_parent(path)?;
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

fn write_secret(path: &Path, contents: &str, force: bool) -> Result<()> {
    guard_existing(path, force)?;
    create_parent(path)?;
    write_owner_only(path, contents).with_context(|| format!("writing {}", path.display()))
}

#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Mode goes on `open`, not a later `chmod`: between the two the key
    // would exist world-readable.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

fn guard_existing(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it (every peer pinning it must be \
             updated)",
            path.display()
        );
    }
    Ok(())
}

fn create_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issued_certificate_loads_back_with_the_fingerprint_that_was_printed() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("a.crt");
        let key = dir.path().join("a.key");
        write_certificate("cabin", &cert, &key, false).unwrap();

        let credential = crate::tls::Credential::load(&cert, &key).unwrap();
        let pem = std::fs::read_to_string(&cert).unwrap();
        let der = crate::tls::first_certificate(&pem).unwrap();
        assert_eq!(
            credential.fingerprint,
            Fingerprint::of(&CertificateDer::from(der))
        );
    }

    #[test]
    fn an_existing_file_is_not_replaced_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("a.crt");
        let key = dir.path().join("a.key");
        write_certificate("cabin", &cert, &key, false).unwrap();
        assert!(write_certificate("cabin", &cert, &key, false).is_err());
        assert!(write_certificate("cabin", &cert, &key, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_written_private_key_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.key");
        write_identity(&identity, false).unwrap();
        let mode = std::fs::metadata(&identity).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity key mode");
        // And the loader accepts what the generator wrote.
        BridgeIdentity::load(&identity).unwrap();
    }

    #[test]
    fn a_name_that_is_not_a_dns_label_still_yields_a_certificate() {
        assert_eq!(
            sanitized_san("Summit Repeater"),
            "summit-repeater.umsh-bridge.invalid"
        );
        assert_eq!(sanitized_san("!!"), "bridge.invalid");
        let dir = tempfile::tempdir().unwrap();
        write_certificate(
            "Cabin / west ridge",
            &dir.path().join("a.crt"),
            &dir.path().join("a.key"),
            false,
        )
        .unwrap();
    }
}
