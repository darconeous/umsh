//! `umsh-bridge check`: everything that can go wrong before a frame
//! moves, reported at once rather than one restart at a time.
//!
//! It reads the credentials and the identity key for real — a
//! configuration that parses but names a key the daemon cannot read is
//! not a configuration that works — but opens no socket and touches no
//! radio, so it is safe to run against a live deployment's config.

use std::path::Path;

use anyhow::{Context, Result};

use crate::config::Config;
use crate::identity::BridgeIdentity;
use crate::tls::Credential;

pub fn check(path: &Path) -> Result<()> {
    let config = Config::load(path)?;

    if let Some(identity) = &config.identity {
        let loaded = BridgeIdentity::load(&identity.key_file)?;
        if config.server.is_some() {
            println!("identity:    {}", loaded.public_key());
            println!("router hint: {}", loaded.router_hint());
        } else {
            println!(
                "note: [identity] is ignored for a client; the bridge identity lives at the server"
            );
        }
    }

    if let Some(server) = &config.server {
        let credential = Credential::load(&server.tls.cert_file, &server.tls.key_file)
            .context("loading the server's TLS credential")?;
        println!("role:        server");
        println!("fingerprint: {}", credential.fingerprint);
        for address in &server.listen {
            println!("listen:      {address}");
        }
        println!("radio:       {}", server.radio.describe());
        println!("exit clamp:  {} hop(s)", server.forwarding.exit_clamp);
        if server.forwarding.regions.is_empty() {
            println!("regions:     any");
        } else {
            let regions: Vec<String> = server
                .forwarding
                .regions
                .iter()
                .map(|region| region.0.to_string())
                .collect();
            println!("regions:     {}", regions.join(", "));
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
                client.name, client.fingerprint
            );
            if client.max_frames_per_minute.is_none() {
                println!(
                    "  warning: no rate limit; an authenticated but misbehaving client is the \
                     realistic failure mode"
                );
            }
            if client.suppress_flood_confirmations {
                println!(
                    "  flood confirmation copies suppressed (the device runs its own repeater \
                     role); source-routed confirmations still sent"
                );
            }
        }
        if server.clients.is_empty() {
            println!("  warning: no clients configured; the server bridges its radio to nothing");
        }
    }

    if let Some(client) = &config.client {
        let credential = Credential::load(&client.tls.cert_file, &client.tls.key_file)
            .context("loading the client's TLS credential")?;
        println!("role:        client");
        println!("fingerprint: {}", credential.fingerprint);
        println!("  register this fingerprint in the server's [[server.clients]]");
        println!("server:      {}", client.server);
        println!("server pin:  {}", client.tls.server_fingerprint);
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
        crate::keygen::write_identity(&dir.join("identity.key"), false).unwrap();
        crate::keygen::write_certificate(
            "server",
            &dir.join("server.crt"),
            &dir.join("server.key"),
            false,
        )
        .unwrap();
        crate::keygen::write_certificate(
            "cabin",
            &dir.join("cabin.crt"),
            &dir.join("cabin.key"),
            false,
        )
        .unwrap();

        let server_fp = Credential::load(&dir.join("server.crt"), &dir.join("server.key"))
            .unwrap()
            .fingerprint;
        let cabin_fp = Credential::load(&dir.join("cabin.crt"), &dir.join("cabin.key"))
            .unwrap()
            .fingerprint;
        let d = dir.display();
        (
            format!(
                "[identity]\nkey_file = \"{d}/identity.key\"\n\
                 [server]\nlisten = [\"127.0.0.1:0\"]\n\
                 [server.tls]\ncert_file = \"{d}/server.crt\"\nkey_file = \"{d}/server.key\"\n\
                 [server.radio]\ntype = \"udp-multicast\"\n\
                 [[server.clients]]\nname = \"cabin\"\nfingerprint = \"{cabin_fp}\"\n\
                 max_frames_per_minute = 60\n"
            ),
            format!(
                "[client]\nserver = \"127.0.0.1:21837\"\n\
                 [client.tls]\ncert_file = \"{d}/cabin.crt\"\nkey_file = \"{d}/cabin.key\"\n\
                 server_fingerprint = \"{server_fp}\"\n\
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
    fn a_credential_the_daemon_cannot_read_fails_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let (server, _) = deployment(dir.path());
        std::fs::remove_file(dir.path().join("server.key")).unwrap();

        let path = dir.path().join("server.toml");
        std::fs::write(&path, server).unwrap();
        let error = check(&path).unwrap_err().to_string();
        assert!(error.contains("TLS credential"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_identity_key_fails_the_check() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let (server, _) = deployment(dir.path());
        std::fs::set_permissions(
            dir.path().join("identity.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let path = dir.path().join("server.toml");
        std::fs::write(&path, server).unwrap();
        assert!(check(&path).is_err());
    }
}
