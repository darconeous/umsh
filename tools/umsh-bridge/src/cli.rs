//! Command-line surface.
//!
//! Deliberately thin: everything that describes a deployment lives in
//! the config file, so the unit file, the `check` a change is validated
//! with, and the process that runs all name the same artifact.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "umsh-bridge",
    version,
    about = "Join the radios of one virtual UMSH repeater over an authenticated tunnel",
    long_about = "\
Runs one end of a UMSH internet bridge: a server, which owns the bridge's
node identity and makes every forwarding decision, or a client, which
relays frames byte for byte between its own radio and the server.

Which end this is comes from the configuration file, not the command
line, so one unit file fits either role and `umsh-bridge check` validates
the exact artifact that will run.

Credentials are issued by this binary: `keygen identity` for the server's
node identity, and `keygen cert` for the TLS certificate each participant
presents. Each side pins the SHA-256 of the other's certificate, which
makes revoking a client an edit to the server's configuration."
)]
pub struct ToolArgs {
    #[command(subcommand)]
    pub command: Command,

    /// Raise the logging level; repeat for more (info, debug, trace).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Log warnings and errors only; repeat for errors only.
    #[arg(short = 'q', long, action = clap::ArgAction::Count, global = true)]
    pub quiet: u8,

    /// Per-target log filter, in `tracing-subscriber` syntax
    /// (`umsh_bridge::engine=trace,info`). Overrides -v/-q entirely.
    #[arg(long, value_name = "FILTER", env = "UMSH_BRIDGE_LOG", global = true)]
    pub log_filter: Option<String>,
}

impl ToolArgs {
    /// The filter -v/-q ask for, unless an explicit one was given.
    pub fn log_filter(&self) -> String {
        if let Some(filter) = &self.log_filter {
            return filter.clone();
        }
        // Third-party crates are noisy at debug and above and none of
        // their detail is about this bridge, so verbosity is spent on
        // this crate first and the rest of the world stays at warn.
        let level = match (self.verbose, self.quiet) {
            (_, 2..) => return "error".into(),
            (_, 1) => return "warn".into(),
            (0, _) => "info",
            (1, _) => "debug",
            (2.., _) => "trace",
        };
        format!("warn,umsh_bridge={level}")
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the bridge until interrupted.
    Run(RunArgs),

    /// Load and validate a configuration, reading the keys and
    /// certificates it names, without opening a socket or touching a
    /// radio.
    Check(RunArgs),

    /// Issue the keys and certificates a deployment needs.
    #[command(subcommand)]
    Keygen(KeygenCommand),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Configuration file.
    #[arg(
        short = 'c',
        long,
        value_name = "PATH",
        env = "UMSH_BRIDGE_CONFIG",
        default_value = "/etc/umsh-bridge/config.toml"
    )]
    pub config: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum KeygenCommand {
    /// Generate the bridge's node identity. Server only, and generated
    /// once for the life of the bridge: it is the address the mesh knows
    /// the bridge by.
    Identity {
        /// Where to write the 64-hex Ed25519 seed.
        #[arg(default_value = "/etc/umsh-bridge/identity.key")]
        path: PathBuf,

        /// Replace an existing key. The bridge's address changes.
        #[arg(long)]
        force: bool,
    },

    /// Issue a self-signed TLS certificate and its key, and print the
    /// fingerprint to pin at the other end.
    Cert {
        /// Name to put in the certificate, and the client name to use in
        /// the server's configuration.
        name: String,

        /// Where to write the certificate.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,

        /// Where to write the private key.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,

        /// Replace existing files. Every peer pinning the old
        /// certificate must be updated.
        #[arg(long)]
        force: bool,
    },

    /// Print the fingerprint of an existing certificate.
    Fingerprint {
        /// The certificate to read.
        cert: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_grammar_is_internally_consistent() {
        ToolArgs::command().debug_assert();
    }

    #[test]
    fn verbosity_maps_to_a_filter_that_spares_the_rest_of_the_world() {
        let filter = |argv: &[&str]| {
            let mut args = vec!["umsh-bridge"];
            args.extend_from_slice(argv);
            ToolArgs::try_parse_from(args).unwrap().log_filter()
        };
        assert_eq!(filter(&["check"]), "warn,umsh_bridge=info");
        assert_eq!(filter(&["check", "-v"]), "warn,umsh_bridge=debug");
        assert_eq!(filter(&["check", "-vv"]), "warn,umsh_bridge=trace");
        assert_eq!(filter(&["check", "-vvv"]), "warn,umsh_bridge=trace");
        assert_eq!(filter(&["check", "-q"]), "warn");
        assert_eq!(filter(&["check", "-qq"]), "error");
        // An explicit filter is the whole answer, whatever else was
        // asked for.
        assert_eq!(
            filter(&["check", "-vv", "--log-filter", "umsh_bridge::tunnel=trace"]),
            "umsh_bridge::tunnel=trace"
        );
    }

    #[test]
    fn global_flags_work_before_or_after_the_command() {
        let before = ToolArgs::try_parse_from(["umsh-bridge", "-v", "run", "-c", "a.toml"]);
        let after = ToolArgs::try_parse_from(["umsh-bridge", "run", "-c", "a.toml", "-v"]);
        assert_eq!(before.unwrap().verbose, after.unwrap().verbose);
    }

    #[test]
    fn keygen_cert_needs_both_output_paths() {
        assert!(ToolArgs::try_parse_from(["umsh-bridge", "keygen", "cert", "cabin"]).is_err());
        assert!(
            ToolArgs::try_parse_from([
                "umsh-bridge",
                "keygen",
                "cert",
                "cabin",
                "--cert",
                "a.crt",
                "--key",
                "a.key",
            ])
            .is_ok()
        );
    }

    #[test]
    fn a_command_is_required() {
        assert!(ToolArgs::try_parse_from(["umsh-bridge"]).is_err());
    }
}
