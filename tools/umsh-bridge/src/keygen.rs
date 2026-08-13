//! Identity issuance, so a deployment needs nothing but this binary.
//!
//! An identity's Ed25519 seed is the only credential a participant
//! holds. Its public half — the UMSH address — is what the other end of
//! the tunnel pins, and it is public: sharing it needs no confidential
//! channel. The TLS certificates the handshake requires are minted in
//! memory from the identity at startup and never stored.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::identity::{BridgeIdentity, format_seed};

pub fn write_identity(path: &Path, force: bool) -> Result<()> {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let identity = BridgeIdentity::from_seed(&seed);

    write_secret(path, &format!("{}\n", format_seed(&seed)), force)?;

    println!("identity key: {}", path.display());
    println!("address:      {}", identity.public_key());
    println!();
    println!("The address is public: configure it at the other end of the tunnel.");
    Ok(())
}

/// Print the address of an existing identity — what the operator copies
/// into the other end's configuration.
pub fn print_address(path: &Path) -> Result<()> {
    let identity = BridgeIdentity::load(path)?;
    println!("{}", identity.public_key());
    Ok(())
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
            "{} already exists; pass --force to replace it (the identity's address changes, \
             and every peer pinning it must be updated)",
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
    fn an_existing_identity_is_not_replaced_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        write_identity(&path, false).unwrap();
        let first = *BridgeIdentity::load(&path).unwrap().public_key();
        assert!(write_identity(&path, false).is_err());
        assert_eq!(
            *BridgeIdentity::load(&path).unwrap().public_key(),
            first,
            "a refused overwrite leaves the identity untouched"
        );
        assert!(write_identity(&path, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_written_identity_key_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.key");
        write_identity(&identity, false).unwrap();
        let mode = std::fs::metadata(&identity).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity key mode");
        // And the loader accepts what the generator wrote.
        BridgeIdentity::load(&identity).unwrap();
        print_address(&identity).unwrap();
    }
}
