//! Interactive CLI over a UDP multicast fake-radio.
//!
//! Usage:
//!   cargo run --example cli_udp --features cli -- \
//!     --identity /tmp/alice.key \
//!     [--group 239.0.0.1] [--port 7373] \
//!     [--peer <b58key>[:alias]] ...
//!
//! Two terminals with different `--identity` files share the same
//! multicast group and can exchange messages with the full CLI command
//! set: /msg, /ping, /pfs, /channel, /stats, etc.

use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use umsh_sync::AsyncRefCell;

use rand::{Rng as _, rng};

use umsh::{
    crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    hal::Radio,
    mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig},
    node::Host,
    tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform, UdpMulticastRadio},
};
use umsh_cli::{
    DefaultCliSession, NoChannelStore, NoPeerStore, NoPowerControl,
    io::{StdioOutput, stdio_split},
    logger::{CliLogger, LogLevel},
};

// ─── MAC type aliases (same sizes as desktop_chat) ───────────────────────────

const IDENTITIES: usize = 4;
const PEERS: usize = 16;
const CHANNELS: usize = 8;
const ACKS: usize = 16;
const TX: usize = 16;
const FRAME: usize = 256;
const DUP: usize = 64;

type P<R> = TokioPlatform<R, TokioFileCounterStore, TokioFileKeyValueStore>;
type CliMac<R> = Mac<P<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type CliHandle<'a, R> = MacHandle<'a, P<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type CliHost<'a, R> = Host<'a, P<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

// ─── Session type alias ───────────────────────────────────────────────────────

type Session<'a, R> = DefaultCliSession<CliHandle<'a, R>, StdioOutput, StderrLogger>;

// ─── StderrLogger ─────────────────────────────────────────────────────────────

struct StderrLogger {
    level: LogLevel,
}

impl StderrLogger {
    fn new(level: LogLevel) -> Self {
        Self { level }
    }
}

impl CliLogger for StderrLogger {
    fn level(&self) -> LogLevel { self.level }
    fn set_level(&mut self, level: LogLevel) { self.level = level; }
    fn log(&mut self, level: LogLevel, args: core::fmt::Arguments<'_>) {
        if level <= self.level {
            eprintln!("[{:?}] {}", level, args);
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = parse_args(args)?;

    // Load or generate identity.
    let identity = load_or_create_identity(&cfg.identity)?;
    let local_key = *identity.public_key();

    // Wire up MAC.
    let counter_root = counter_store_root(&cfg.identity);
    let radio = UdpMulticastRadio::bind_v4(cfg.group, cfg.port)
        .await
        .map_err(|e| std::io::Error::other(format!("udp bind: {e:?}")))?;
    let local_mac = AsyncRefCell::new(build_mac(radio, counter_root)?);
    let handle = MacHandle::new(&local_mac);
    let identity_id = handle
        .add_identity(identity)
        .await
        .expect("identity should fit");
    let mut host: CliHost<'_, _> = Host::new(handle.clone());
    let node = host.add_node(identity_id);

    // Build CLI session.
    let (mut stdin_in, stdout_out) = stdio_split();
    let logger = StderrLogger::new(LogLevel::Info);
    let mut cli: Session<'_, _> = Session::new(
        node,
        local_key,
        stdout_out,
        logger,
        NoPeerStore,
        NoChannelStore,
        NoPowerControl,
    );

    // Pre-register peers from --peer args.
    for (key, alias) in cfg.peers {
        if !cli.register_peer(key, alias.as_deref()).await {
            eprintln!("warning: peer table full, skipping peer");
        }
    }

    // Print banner.
    println!("UMSH CLI (UDP multicast)");
    println!("local: {}", encode_hex(&local_key.0));
    println!("group: {}:{}", cfg.group, cfg.port);
    println!("type /help for commands, /quit to exit");

    // Drive host + CLI concurrently. Both are infinite loops; select! exits
    // when the first one returns (CLI on /quit or EOF, host on fatal error).
    let local = tokio::task::LocalSet::new();
    local.run_until(async {
        tokio::select! {
            r = host.run() => {
                if let Err(e) = r {
                    eprintln!("host error: {e:?}");
                }
            }
            r = cli.run(&mut stdin_in) => {
                if let Err(e) = r {
                    eprintln!("cli error: {e:?}");
                }
            }
        }
    }).await;

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

struct Config {
    identity: PathBuf,
    group: Ipv4Addr,
    port: u16,
    peers: Vec<(umsh::core::PublicKey, Option<String>)>,
}

fn parse_args(args: Vec<String>) -> Result<Config, Box<dyn std::error::Error>> {
    let mut identity: Option<PathBuf> = None;
    let mut group = Ipv4Addr::new(239, 255, 42, 42);
    let mut port: u16 = 7373;
    let mut peers = Vec::new();

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--identity" => {
                identity = Some(PathBuf::from(it.next().ok_or("--identity needs a path")?));
            }
            "--group" => {
                let s = it.next().ok_or("--group needs an IPv4 address")?;
                group = s.parse()?;
            }
            "--port" => {
                let s = it.next().ok_or("--port needs a number")?;
                port = s.parse()?;
            }
            "--peer" => {
                let s = it.next().ok_or("--peer needs <b58key>[:alias]")?;
                let (key_str, alias) = match s.find(':') {
                    Some(idx) => (&s[..idx], Some(s[idx + 1..].to_owned())),
                    None => (s.as_str(), None),
                };
                let key = umsh_cli::peer_ref::try_parse_pubkey(key_str)
                    .ok_or_else(|| format!("invalid pubkey: {key_str}"))?;
                peers.push((key, alias));
            }
            other => return Err(format!("unknown flag: {other}").into()),
        }
    }
    Ok(Config {
        identity: identity.ok_or("--identity <path> is required")?,
        group,
        port,
        peers,
    })
}

fn build_mac<R: Radio>(
    radio: R,
    counter_root: PathBuf,
) -> Result<CliMac<R>, Box<dyn std::error::Error>> {
    Ok(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rng(),
        TokioFileCounterStore::new(counter_root)?,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    ))
}

fn load_or_create_identity(
    path: &Path,
) -> Result<SoftwareIdentity, Box<dyn std::error::Error>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "identity file must be exactly 32 bytes")?;
            Ok(SoftwareIdentity::from_secret_bytes(&secret))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut secret = [0u8; 32];
            rand::rng().fill_bytes(&mut secret);
            std::fs::write(path, secret)?;
            Ok(SoftwareIdentity::from_secret_bytes(&secret))
        }
        Err(e) => Err(Box::new(e)),
    }
}

fn counter_store_root(identity_path: &Path) -> PathBuf {
    let mut root = identity_path.to_path_buf();
    let file_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("identity");
    root.set_file_name(format!("{file_name}.counters"));
    root
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
