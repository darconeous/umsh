//! A participant's Ed25519 identity.
//!
//! Every endpoint has one, and it is the credential the tunnel
//! authenticates with (see [`crate::tls`]) — nothing more. A bridge has
//! no presence on the mesh: it addresses nothing, signs nothing, and
//! appears in no route. The nodes it carries traffic for are the ones
//! behind each participant's radio, and they hold their own identities.
//! It is a full UMSH identity all the same, so that a participant can
//! become individually addressable for management without re-keying
//! anything.

use std::path::Path;

use anyhow::{Context, Result, bail};
use umsh_core::PublicKey;
use umsh_crypto::software::SoftwareIdentity;

pub struct BridgeIdentity {
    inner: SoftwareIdentity,
    seed: [u8; 32],
    public: PublicKey,
}

impl BridgeIdentity {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = SoftwareIdentity::from_secret_bytes(seed);
        let public = *umsh_crypto::NodeIdentity::public_key(&inner);
        Self {
            inner,
            seed: *seed,
            public,
        }
    }

    /// Read the 64-hex seed from `path`.
    ///
    /// A key file readable by anyone but its owner is refused rather
    /// than warned about: the bridge is long-running unattended
    /// infrastructure, and a warning at start-up is a warning nobody
    /// reads.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading identity key {}", path.display()))?;
        check_permissions(path)?;
        let seed = parse_seed(text.trim())
            .with_context(|| format!("parsing identity key {}", path.display()))?;
        Ok(Self::from_seed(&seed))
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The raw seed, for wrapping the identity key into the formats the
    /// TLS stack expects.
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The signing identity. The TLS handshake is what it signs.
    pub fn signer(&self) -> &SoftwareIdentity {
        &self.inner
    }
}

pub fn parse_seed(text: &str) -> Result<[u8; 32]> {
    let hex: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.len() != 64 {
        bail!(
            "an identity key is 64 hex digits (a 32-byte Ed25519 seed); got {}",
            hex.len()
        );
    }
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .ok()
            .context("identity key contains a non-hex digit")?;
    }
    Ok(seed)
}

pub fn format_seed(seed: &[u8; 32]) -> String {
    seed.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {mode:o}; a private key must not be readable by group or other \
             (chmod 600)",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_round_trips_through_its_written_form() {
        let seed = [0x42u8; 32];
        assert_eq!(parse_seed(&format_seed(&seed)).unwrap(), seed);

        // The same seed always names the same address, which is what an
        // operator pins at the other end of the tunnel.
        let key = BridgeIdentity::from_seed(&seed).public_key().0;
        assert_eq!(BridgeIdentity::from_seed(&seed).public_key().0, key);
    }

    #[test]
    fn a_malformed_seed_is_rejected() {
        assert!(parse_seed("").is_err());
        assert!(parse_seed(&"ab".repeat(31)).is_err());
        assert!(parse_seed(&format!("{}zz", "ab".repeat(31))).is_err());
        // Whitespace is the one thing a hand-edited file is likely to
        // pick up, and it is not an error.
        assert!(parse_seed(&format!("{}\n  ", "ab".repeat(32))).is_ok());
    }
}
