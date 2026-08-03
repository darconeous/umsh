//! A participant's Ed25519 identity.
//!
//! Every endpoint has one, and it is the credential the tunnel
//! authenticates with (see [`crate::tls`]). The server's doubles as the
//! bridge's node identity: forwarding needs its router hint — what
//! source routes match against and trace routes are prepended with — and
//! a later bridge that originates its own traffic will sign with it. A
//! client's is only a tunnel credential today, but it is a full identity
//! so that a client can become individually addressable for management
//! without re-keying anything.

use std::path::Path;

use anyhow::{Context, Result, bail};
use umsh_core::{NodeHint, PublicKey, RouterHint};
use umsh_crypto::software::SoftwareIdentity;

pub struct BridgeIdentity {
    inner: SoftwareIdentity,
    seed: [u8; 32],
    public: PublicKey,
    node_hint: NodeHint,
    router_hint: RouterHint,
}

impl BridgeIdentity {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = SoftwareIdentity::from_secret_bytes(seed);
        let public = *umsh_crypto::NodeIdentity::public_key(&inner);
        Self {
            inner,
            seed: *seed,
            public,
            node_hint: public.hint(),
            router_hint: public.router_hint(),
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

    pub fn node_hint(&self) -> NodeHint {
        self.node_hint
    }

    pub fn router_hint(&self) -> RouterHint {
        self.router_hint
    }

    /// The raw seed, for wrapping the identity key into the formats the
    /// TLS stack expects.
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The signing identity, for the node logic a forwarding-only bridge
    /// does not yet have.
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
    fn a_seed_round_trips_and_pins_the_hints_to_the_public_key() {
        let seed = [0x42u8; 32];
        assert_eq!(parse_seed(&format_seed(&seed)).unwrap(), seed);

        let identity = BridgeIdentity::from_seed(&seed);
        let key = identity.public_key().0;
        assert_eq!(identity.node_hint().0, [key[0], key[1], key[2]]);
        assert_eq!(identity.router_hint().0, [key[0], key[1]]);
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
