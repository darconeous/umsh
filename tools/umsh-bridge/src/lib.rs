//! `umsh-bridge`: one end of a UMSH internet bridge.
//!
//! A bridge is a single virtual repeater whose radios sit in different
//! places, joined by a TLS tunnel. One process is the **server** — it
//! owns the bridge's node identity, holds the shared duplicate cache,
//! and makes every forwarding decision — and the others are **clients**,
//! which relay frames byte for byte between their radio and the tunnel
//! and apply no forwarding logic at all.
//!
//! The protocol is specified in the [Internet Bridging appendix].
//!
//! This is a library only so that the integration tests can stand a
//! whole bridge up in one process; the binary is its only consumer.
//!
//! [Internet Bridging appendix]: https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html

pub mod check;
pub mod cli;
pub mod client;
pub mod config;
pub mod device;
pub mod engine;
pub mod identity;
pub mod iface;
pub mod keygen;
pub mod policy;
pub mod rewrite;
pub mod server;
pub mod tls;
pub mod tunnel;
pub mod udp_radio;

use std::path::Path;

use anyhow::{Context, Result};

use cli::{Command, KeygenCommand, ToolArgs};

pub fn run(args: ToolArgs) -> Result<()> {
    match args.command {
        Command::Check(run_args) => check::check(&run_args.config),
        Command::Run(run_args) => run_bridge(&run_args.config),
        Command::Keygen(KeygenCommand::Identity { path, force }) => {
            keygen::write_identity(&path, force)
        }
        Command::Keygen(KeygenCommand::Cert {
            name,
            cert,
            key,
            force,
        }) => keygen::write_certificate(&name, &cert, &key, force),
        Command::Keygen(KeygenCommand::Fingerprint { cert }) => keygen::print_fingerprint(&cert),
    }
}

/// Run until interrupted.
///
/// A single-threaded runtime with a `LocalSet`: the work is at LoRa
/// packet rates, the engine's state is deliberately not shared, and a
/// BLE or serial device handle need not be `Send` to be spawned
/// alongside everything else.
fn run_bridge(path: &Path) -> Result<()> {
    let config = config::Config::load(path)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the async runtime")?;
    let local = tokio::task::LocalSet::new();

    runtime.block_on(local.run_until(async move {
        tokio::select! {
            result = server::run_config(config) => result,
            result = tokio::signal::ctrl_c() => {
                result.context("waiting for an interrupt")?;
                tracing::info!("interrupted; shutting down");
                Ok(())
            }
        }
    }))
}
