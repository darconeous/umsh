//! Interactive CLI over a real companion radio (BLE or serial).
//!
//! The full CLI command set (/msg, /ping, /pfs, /channel, /stats, …)
//! with the host owning the MAC and an NCP board supplying the LoRa
//! PHY — `cli_udp` with the fake radio swapped for the real one.
//!
//! Usage:
//!   cargo run --example cli_companion --features cli,ble-radio -- \
//!     --identity /tmp/alice.key --ble [name-or-address-substring] \
//!     [--peer <b58key>[:alias]] ...
//!
//!   cargo run --example cli_companion --features cli,serial-radio -- \
//!     --identity /tmp/alice.key --serial /dev/cu.usbmodemXXXX \
//!     [--baud 115200] [--peer <b58key>[:alias]] ...
//!
//! RF profile flags (defaults are the MeshCore-US bringup profile the
//! NCP firmware also defaults to): --freq-khz, --bw-hz, --sf, --cr.
//!
//! First-time BLE use requires a bond: put the board in pairing mode
//! (T-Echo display menu → start pairing; T-1000E one-second startup
//! hold) and accept the OS pairing prompt. On Linux, pair/trust via a
//! `bluetoothctl` agent first.

use std::path::{Path, PathBuf};

use umsh_sync::AsyncRefCell;

use rand::{Rng as _, rng};

#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig, CompanionRadioError, FrameLink};
use umsh::{
    crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    hal::Radio,
    mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig},
    node::Host,
    tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform},
};
use umsh_cli::{
    DefaultCliSession, NoChannelStore, NoPeerStore, NoPowerControl,
    io::{StdioOutput, stdio_split},
    logger::{CliLogger, LogLevel},
};

// ─── MAC type aliases (same sizes as cli_udp/desktop_chat) ──────────────────

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
type CliHost<'a, R> = Host<CliHandle<'a, R>>;

type Session<'a, R> = DefaultCliSession<CliHandle<'a, R>, StdioOutput, StderrLogger>;

// ─── StderrLogger ────────────────────────────────────────────────────────────

struct StderrLogger {
    level: LogLevel,
}

impl CliLogger for StderrLogger {
    fn level(&self) -> LogLevel {
        self.level
    }
    fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }
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

    match cfg.transport.clone() {
        Transport::Ble(selector) => {
            #[cfg(feature = "ble-radio")]
            {
                #[cfg(target_os = "linux")]
                eprintln!(
                    "Linux pairing is OS-mediated. Pair/trust with `bluetoothctl` and an \
                     enabled agent if the security-gated subscription is rejected."
                );
                println!("discovering BLE companion radio ...");
                let mut radio =
                    CompanionRadio::open_ble(selector.as_deref(), cfg.radio_config()).await?;
                prepare_companion(&mut radio).await?;
                return run_cli(cfg, radio).await;
            }
            #[cfg(not(feature = "ble-radio"))]
            {
                let _ = selector;
                return Err("the ble-radio feature is required for --ble".into());
            }
        }
        Transport::Serial(path, baud) => {
            #[cfg(feature = "serial-radio")]
            {
                println!("attaching to {path} ...");
                let mut radio =
                    CompanionRadio::open_serial(&path, baud, cfg.radio_config()).await?;
                prepare_companion(&mut radio).await?;
                return run_cli(cfg, radio).await;
            }
            #[cfg(not(feature = "serial-radio"))]
            {
                let _ = (path, baud);
                return Err("the serial-radio feature is required for --serial".into());
            }
        }
    }
}

/// This host owns the MAC and does its own address/channel filtering,
/// so a provisioned NCP's host-domain receive filters must not gate
/// live delivery: enable the session-scoped promiscuous mode (it
/// reverts on detach and touches no provisioning). NCPs predating the
/// property refuse the set; delivery then follows their filtering.
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
async fn prepare_companion<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("companion radio: {}", radio.ncp_version());
    match radio
        .set_prop(umsh::companion::ids::prop::MAC_PROMISCUOUS, &[1])
        .await
    {
        Ok(_) => {}
        Err(CompanionRadioError::Status(status)) => eprintln!(
            "warning: NCP refused promiscuous mode ({status:?}); reception is limited \
             to the NCP's provisioned receive filtering"
        ),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn run_cli<R: Radio>(cfg: Config, radio: R) -> Result<(), Box<dyn std::error::Error>>
where
    R::Error: core::fmt::Debug,
{
    // Load or generate identity.
    let identity = load_or_create_identity(&cfg.identity)?;
    let local_key = *identity.public_key();

    // Wire up MAC.
    let counter_root = counter_store_root(&cfg.identity);
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
    let logger = StderrLogger {
        level: LogLevel::Info,
    };
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
    println!("UMSH CLI (companion radio)");
    println!("local: {}", local_key);
    println!(
        "rf: {} kHz, BW {} Hz, SF{}, CR 4/{}",
        cfg.freq_khz, cfg.bw_hz, cfg.sf, cfg.cr
    );
    println!("type /help for commands, /quit to exit");

    // Drive host + CLI concurrently. Both are infinite loops; select! exits
    // when the first one returns (CLI on /quit or EOF, host on fatal error).
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
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
        })
        .await;

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum Transport {
    Ble(Option<String>),
    Serial(String, u32),
}

struct Config {
    identity: PathBuf,
    transport: Transport,
    freq_khz: u32,
    bw_hz: u32,
    sf: u8,
    cr: u8,
    tx_power_dbm: i8,
    peers: Vec<(umsh::core::PublicKey, Option<String>)>,
}

impl Config {
    #[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
    fn radio_config(&self) -> CompanionRadioConfig {
        let mut config = CompanionRadioConfig::new(self.freq_khz, self.bw_hz, self.sf, self.cr);
        config.tx_power_dbm = self.tx_power_dbm;
        config
    }
}

fn parse_args(args: Vec<String>) -> Result<Config, Box<dyn std::error::Error>> {
    let mut identity: Option<PathBuf> = None;
    let mut transport: Option<Transport> = None;
    let mut baud: u32 = 115_200;
    // MeshCore-US bringup profile, matching the NCP firmware defaults.
    let mut freq_khz: u32 = 910_525;
    let mut bw_hz: u32 = 62_500;
    let mut sf: u8 = 7;
    let mut cr: u8 = 5;
    let mut tx_power_dbm: i8 = 14;
    let mut peers = Vec::new();

    let mut it = args.into_iter().peekable();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--identity" => {
                identity = Some(PathBuf::from(it.next().ok_or("--identity needs a path")?));
            }
            "--ble" => {
                // Optional selector: consume the next arg unless it is a flag.
                let selector = match it.peek() {
                    Some(next) if !next.starts_with("--") => it.next(),
                    _ => None,
                };
                transport = Some(Transport::Ble(selector));
            }
            "--serial" => {
                let path = it.next().ok_or("--serial needs a port path")?;
                transport = Some(Transport::Serial(path, baud));
            }
            "--baud" => {
                baud = it.next().ok_or("--baud needs a number")?.parse()?;
                if let Some(Transport::Serial(_, stored)) = &mut transport {
                    *stored = baud;
                }
            }
            "--freq-khz" => freq_khz = it.next().ok_or("--freq-khz needs a number")?.parse()?,
            "--bw-hz" => bw_hz = it.next().ok_or("--bw-hz needs a number")?.parse()?,
            "--sf" => sf = it.next().ok_or("--sf needs a number")?.parse()?,
            "--cr" => cr = it.next().ok_or("--cr needs a number")?.parse()?,
            "--tx-power" => {
                tx_power_dbm = it.next().ok_or("--tx-power needs a number")?.parse()?;
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
        transport: transport.ok_or("--ble [selector] or --serial <port> is required")?,
        freq_khz,
        bw_hz,
        sf,
        cr,
        tx_power_dbm,
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

fn load_or_create_identity(path: &Path) -> Result<SoftwareIdentity, Box<dyn std::error::Error>> {
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
