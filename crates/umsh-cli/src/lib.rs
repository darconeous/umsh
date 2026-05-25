#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod commands;
pub mod events;
pub mod io;
pub mod logger;
pub mod mac_cmd;
pub mod peer_ref;
pub mod ping;
pub mod session;
pub mod settings;
pub mod stats;

pub use events::CliEvent;
pub use io::{CliInput, CliOutput};
pub use logger::{CliLogger, LogLevel, NullLogger};
pub use session::{CliError, CliSession};

/// [`CliSession`] sized for typical desktop and tracker-class targets.
///
/// Capacity defaults: 16 peers, 16 aliases, 8 channels, 64 events, 8 pending
/// pings, 256-byte command line. Replace with an explicit
/// `CliSession<…>` when these defaults are wrong for the target.
pub type DefaultCliSession<M, OUT, LOG> = CliSession<
    M,
    OUT,
    LOG,
    16,  // N_PEERS
    16,  // N_ALIASES
    8,   // N_CHANNELS
    64,  // N_EVENTS
    8,   // N_PENDING_PINGS
    256, // LINE_MAX
>;
