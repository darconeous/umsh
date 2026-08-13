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
    about = "Carry UMSH frames between radios that cannot hear each other",
    long_about = "\
Runs one end of a UMSH internet bridge: a server, which copies each frame
it receives to every other participant, or a client, which relays frames
byte for byte between its own radio and the server.

Which end this is comes from the configuration file, not the command
line, so one unit file fits either role and `umsh-bridge check` validates
the exact artifact that will run.

Every participant's radio runs in backhaul mode, which makes the node
behind it a repeater whose point-to-point neighbor is the bridge. Hop
accounting, duplicate suppression, and forwarding policy are that node's;
the bridge has no opinion about what it carries and no presence on the
mesh.

Every participant holds an Ed25519 identity, issued once by `keygen
identity`, which is what the tunnel authenticates with. Each side is
configured with the other's public key — the UMSH address that `address`
prints — which makes revoking a client an edit to the server's
configuration. The TLS certificates the handshake requires are minted in
memory from the identity at startup; none are stored or exchanged."
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
    /// (`umsh_bridge::hub=trace,info`). Overrides -v/-q entirely.
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

    /// Load and validate a configuration, reading the identity key it
    /// names, without opening a socket or touching a radio.
    Check(RunArgs),

    /// Print the address of an identity key — the public name the
    /// other end of the tunnel pins. Safe to share anywhere.
    Address {
        /// The identity key to read.
        #[arg(default_value = "/etc/umsh-bridge/identity.key")]
        path: PathBuf,
    },

    /// Issue the identity a participant needs.
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
    /// Generate this participant's identity, once for its life: its
    /// address is what the other end pins, and for a server it is also
    /// the address the mesh knows the bridge by.
    Identity {
        /// Where to write the 64-hex Ed25519 seed.
        #[arg(default_value = "/etc/umsh-bridge/identity.key")]
        path: PathBuf,

        /// Replace an existing key. The identity's address changes, and
        /// every peer pinning it must be updated.
        #[arg(long)]
        force: bool,
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
    fn identity_paths_default_to_the_deployment_location() {
        let parsed = ToolArgs::try_parse_from(["umsh-bridge", "address"]).unwrap();
        let Command::Address { path } = parsed.command else {
            panic!("parsed as the wrong command");
        };
        assert_eq!(path, PathBuf::from("/etc/umsh-bridge/identity.key"));

        assert!(ToolArgs::try_parse_from(["umsh-bridge", "keygen", "identity"]).is_ok());
        assert!(
            ToolArgs::try_parse_from(["umsh-bridge", "keygen", "identity", "a.key", "--force"])
                .is_ok()
        );
    }

    #[test]
    fn a_command_is_required() {
        assert!(ToolArgs::try_parse_from(["umsh-bridge"]).is_err());
    }
}
