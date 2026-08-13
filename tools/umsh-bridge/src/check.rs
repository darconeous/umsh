//! `umsh-bridge check`: everything that can go wrong before a frame
//! moves, reported at once rather than one restart at a time.
//!
//! It reads the identity key for real and mints the TLS credential the
//! daemon would present — a configuration that parses but names a key
//! the daemon cannot read or use is not a configuration that works —
//! but opens no socket and touches no radio, so it is safe to run
//! against a live deployment's config.

use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::config::Config;
use crate::identity::BridgeIdentity;
use crate::tls::Credential;

pub fn check(path: &Path) -> Result<()> {
    let config = Config::load(path)?;

    let identity = BridgeIdentity::load(
        &config
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("validated config has an identity"))?
            .key_file,
    )?;
    Credential::for_identity(&identity).context("minting the TLS credential")?;

    if let Some(server) = &config.server {
        println!("role:        server");
        println!("address:     {}", identity.public_key());
        println!("  clients pin this address as server_address");
        for address in &server.listen {
            println!("listen:      {address}");
        }
        println!("radio:       {}", server.radio.describe());
        match server.limits.exit_clamp {
            Some(clamp) => println!("exit clamp:  {clamp} hop(s)"),
            None => println!("exit clamp:  off"),
        }
        for client in &server.clients {
            let fan_out = match &client.allow_to {
                Some(names) => names.join(", "),
                None => other_interfaces(&server.interface_names(), &client.name).join(", "),
            };
            let rate = match client.max_frames_per_minute {
                Some(limit) => format!("{limit}/min"),
                None => "unlimited".to_string(),
            };
            println!(
                "client:      {} [{}] -> {fan_out} ({rate})",
                client.name, client.address
            );
            if client.address.0 == *identity.public_key() {
                // The same condition refuses to start the server.
                anyhow::bail!(
                    "client \"{}\" lists this bridge's own identity as its address",
                    client.name
                );
            }
            if client.max_frames_per_minute.is_none() {
                println!(
                    "  warning: no rate limit; an authenticated but misbehaving client is the \
                     realistic failure mode"
                );
            }
        }
        if server.clients.is_empty() {
            println!("  warning: no clients configured; the server bridges its radio to nothing");
        }
    }

    if let Some(client) = &config.client {
        println!("role:        client");
        println!("address:     {}", identity.public_key());
        println!("  register this address in the server's [[server.clients]]");
        println!("server:      {}", client.server);
        println!("server pin:  {}", client.server_address);
        println!("radio:       {}", client.radio.describe());
    }

    println!("ok: {}", path.display());
    Ok(())
}

fn other_interfaces(all: &[String], mine: &str) -> Vec<String> {
    all.iter()
        .filter(|name| name.as_str() != mine)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole deployment's worth of files, generated the way an
    /// operator would generate them.
    fn deployment(dir: &Path) -> (String, String) {
        crate::keygen::write_identity(&dir.join("server.key"), false).unwrap();
        crate::keygen::write_identity(&dir.join("client.key"), false).unwrap();

        let server_address = BridgeIdentity::load(&dir.join("server.key"))
            .unwrap()
            .public_key()
            .to_string();
        let client_address = BridgeIdentity::load(&dir.join("client.key"))
            .unwrap()
            .public_key()
            .to_string();
        let d = dir.display();
        (
            format!(
                "[identity]\nkey_file = \"{d}/server.key\"\n\
                 [server]\nlisten = [\"127.0.0.1:0\"]\n\
                 [server.radio]\ntype = \"udp-multicast\"\n\
                 [[server.clients]]\nname = \"myclient\"\naddress = \"{client_address}\"\n\
                 max_frames_per_minute = 60\n"
            ),
            format!(
                "[identity]\nkey_file = \"{d}/client.key\"\n\
                 [client]\nserver = \"127.0.0.1:21837\"\n\
                 server_address = \"{server_address}\"\n\
                 [client.radio]\ntype = \"udp-multicast\"\nport = 7374\n"
            ),
        )
    }

    #[test]
    fn a_generated_deployment_checks_clean_at_both_ends() {
        let dir = tempfile::tempdir().unwrap();
        let (server, client) = deployment(dir.path());

        let server_path = dir.path().join("server.toml");
        std::fs::write(&server_path, server).unwrap();
        check(&server_path).unwrap();

        let client_path = dir.path().join("client.toml");
        std::fs::write(&client_path, client).unwrap();
        check(&client_path).unwrap();
    }

    #[test]
    fn an_identity_the_daemon_cannot_read_fails_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let (server, _) = deployment(dir.path());
        std::fs::remove_file(dir.path().join("server.key")).unwrap();

        let path = dir.path().join("server.toml");
        std::fs::write(&path, server).unwrap();
        assert!(check(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_identity_key_fails_the_check() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let (server, _) = deployment(dir.path());
        std::fs::set_permissions(
            dir.path().join("server.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let path = dir.path().join("server.toml");
        std::fs::write(&path, server).unwrap();
        assert!(check(&path).is_err());
    }
}
