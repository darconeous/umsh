use std::{
    cell::RefCell,
    env,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rng, Rng};
use tokio::io::{self, AsyncBufReadExt, BufReader};

#[cfg(feature = "serial-radio")]
#[path = "support/draft_serial_radio.rs"]
mod draft_serial_radio;

use umsh::{
    core::PublicKey,
    crypto::{
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
        CryptoEngine, NodeIdentity, PairwiseKeys,
    },
    hal::Radio,
    mac::{test_support::SimulatedNetwork, Mac, MacHandle, OperatingPolicy, RepeaterConfig},
    node::{DeferredAction, Endpoint, EndpointConfig, EndpointEvent, EventAction},
    tokio_support::{
        StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform,
        UdpMulticastRadio,
    },
};

#[cfg(feature = "serial-radio")]
use draft_serial_radio::DraftSerialRadio;

const IDENTITIES: usize = 4;
const PEERS: usize = 16;
const CHANNELS: usize = 8;
const ACKS: usize = 16;
const TX: usize = 16;
const FRAME: usize = 256;
const DUP: usize = 64;

type ChatPlatform<R> = TokioPlatform<R, TokioFileCounterStore, TokioFileKeyValueStore>;

type ChatMac<R> = Mac<
    ChatPlatform<R>,
    IDENTITIES,
    PEERS,
    CHANNELS,
    ACKS,
    TX,
    FRAME,
    DUP,
>;

type ChatHandle<'a, R> = MacHandle<
    'a,
    ChatPlatform<R>,
    IDENTITIES,
    PEERS,
    CHANNELS,
    ACKS,
    TX,
    FRAME,
    DUP,
>;

type ChatEndpoint<'a, R> = Endpoint<ChatHandle<'a, R>, TokioFileKeyValueStore>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = CliConfig::parse(env::args().skip(1).collect::<Vec<_>>())?;
    match config.mode {
        Mode::PrintPublicKey => print_public_key(config.identity_path)?,
        Mode::Simulated => run_simulated_chat(config).await?,
        Mode::Udp { group, port, peer } => run_udp_chat(config.identity_path, group, port, peer).await?,
        Mode::Serial { path, baud, peer } => run_serial_chat(config.identity_path, path, baud, peer).await?,
    }
    Ok(())
}

fn print_public_key(identity_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_create_identity(&identity_path)?;
    println!("{}", hex_encode(&identity.public_key().0));
    Ok(())
}

async fn run_udp_chat(
    identity_path: PathBuf,
    group: Ipv4Addr,
    port: u16,
    peer_key: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let local_identity = load_or_create_identity(&identity_path)?;
    let local_key = *local_identity.public_key();
    let pairwise = derive_pairwise_keys(&local_identity, &peer_key)?;

    let session_root = unique_session_root("desktop-chat-udp");
    let radio = UdpMulticastRadio::bind_v4(group, port)
        .await
        .map_err(|error| std::io::Error::other(format!("udp bind failed: {error:?}")))?;
    let local_mac = RefCell::new(build_mac(radio, session_root.join("counters"))?);
    let local_handle = MacHandle::new(&local_mac);
    let local_id = local_handle.add_identity(local_identity).expect("local identity should fit");
    let peer_id = local_handle.add_peer(peer_key).expect("peer should fit");
    local_handle
        .install_pairwise_keys(local_id, peer_id, pairwise)
        .expect("pairwise keys should install");

    let mut endpoint = Endpoint::new(local_id, local_handle, EndpointConfig::default())
        .with_kv_store(TokioFileKeyValueStore::new(session_root.join("kv"))?);
    let mut deferred = Vec::<DeferredAction>::new();
    let mut ready = Vec::<EndpointEvent>::new();

    print_banner("udp-multicast", local_key, Some(peer_key));
    println!("group: {group}:{port}");
    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("Type a message and press enter. Use /pfs [minutes] to start PFS, or /quit to exit.");

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        match handle_user_input(&mut endpoint, &peer_key, &line)? {
                            UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                            UserInputOutcome::Continue(None) => {}
                            UserInputOutcome::Quit => break,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            result = run_mac_event(&local_mac, &mut endpoint, &mut deferred, &mut ready) => {
                result?;
            }
        }

        handle_deferred_and_ready(&mut endpoint, &mut deferred, &mut ready).await;
    }

    Ok(())
}

async fn run_simulated_chat(config: CliConfig) -> Result<(), Box<dyn std::error::Error>> {
    let local_identity = load_or_create_identity(&config.identity_path)?;
    let remote_identity = SoftwareIdentity::from_secret_bytes(&[0x55; 32]);
    let local_key = *local_identity.public_key();
    let remote_key = *remote_identity.public_key();
    let local_pairwise = derive_pairwise_keys(&local_identity, &remote_key)?;
    let remote_pairwise = derive_pairwise_keys(&remote_identity, &local_key)?;

    let network = SimulatedNetwork::new();
    let local_radio = network.add_radio();
    let remote_radio = network.add_radio();
    network.connect_bidirectional(local_radio.id(), remote_radio.id());

    let session_root = unique_session_root("desktop-chat-sim");
    let local_mac = RefCell::new(build_mac(local_radio, session_root.join("local-counters"))?);
    let remote_mac = RefCell::new(build_mac(remote_radio, session_root.join("remote-counters"))?);

    let local_handle = MacHandle::new(&local_mac);
    let local_id = local_handle.add_identity(local_identity).expect("local identity should fit");
    let remote_handle = MacHandle::new(&remote_mac);
    let remote_id = remote_handle.add_identity(remote_identity).expect("remote identity should fit");

    let remote_peer = local_handle.add_peer(remote_key).expect("remote peer should fit");
    local_handle
        .install_pairwise_keys(local_id, remote_peer, local_pairwise)
        .expect("local pairwise keys should install");
    let local_peer = remote_handle.add_peer(local_key).expect("local peer should fit for remote side");
    remote_handle
        .install_pairwise_keys(remote_id, local_peer, remote_pairwise)
        .expect("remote pairwise keys should install");

    let mut local_endpoint = Endpoint::new(local_id, local_handle, EndpointConfig::default())
        .with_kv_store(TokioFileKeyValueStore::new(session_root.join("local-kv"))?);
    let mut remote_endpoint = Endpoint::new(remote_id, remote_handle, EndpointConfig::default())
        .with_kv_store(TokioFileKeyValueStore::new(session_root.join("remote-kv"))?);
    let mut local_deferred = Vec::<DeferredAction>::new();
    let mut remote_deferred = Vec::<DeferredAction>::new();
    let mut local_ready = Vec::<EndpointEvent>::new();
    let mut remote_ready = Vec::<EndpointEvent>::new();

    print_banner("simulated", local_key, Some(remote_key));
    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("Type a message and press enter. Use /pfs [minutes] to start PFS, or /quit to exit.");

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        match handle_user_input(&mut local_endpoint, &remote_key, &line)? {
                            UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                            UserInputOutcome::Continue(None) => {}
                            UserInputOutcome::Quit => break,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            result = run_mac_event(&local_mac, &mut local_endpoint, &mut local_deferred, &mut local_ready) => {
                result?;
            }
            result = run_mac_event(&remote_mac, &mut remote_endpoint, &mut remote_deferred, &mut remote_ready) => {
                result?;
            }
        }

        for event in remote_ready.drain(..) {
            if let EndpointEvent::TextReceived { message, .. } = event {
                remote_endpoint
                    .send_text(&local_key, &format!("echo: {}", message.body))
                    .map_err(|error| std::io::Error::other(format!("echo send failed: {error:?}")))?;
            }
        }

        handle_deferred_and_ready(&mut local_endpoint, &mut local_deferred, &mut local_ready).await;
        handle_deferred_and_ready(&mut remote_endpoint, &mut remote_deferred, &mut remote_ready).await;
    }

    Ok(())
}

async fn run_serial_chat(
    identity_path: PathBuf,
    serial_path: String,
    baud_rate: u32,
    peer_key: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "serial-radio")]
    {
        let local_identity = load_or_create_identity(&identity_path)?;
        let local_key = *local_identity.public_key();
        let pairwise = derive_pairwise_keys(&local_identity, &peer_key)?;
        let session_root = unique_session_root("desktop-chat-serial");
        let radio = DraftSerialRadio::open_tokio(serial_path, baud_rate)
            .await
            .map_err(|error| std::io::Error::other(format!("serial open failed: {error:?}")))?;
        let local_mac = RefCell::new(build_mac(radio, session_root.join("counters"))?);
        let local_handle = MacHandle::new(&local_mac);
        let local_id = local_handle.add_identity(local_identity).expect("local identity should fit");
        let peer_id = local_handle.add_peer(peer_key).expect("peer should fit");
        local_handle
            .install_pairwise_keys(local_id, peer_id, pairwise)
            .expect("pairwise keys should install");
        let mut endpoint = Endpoint::new(local_id, local_handle, EndpointConfig::default())
            .with_kv_store(TokioFileKeyValueStore::new(session_root.join("kv"))?);
        let mut deferred = Vec::<DeferredAction>::new();
        let mut ready = Vec::<EndpointEvent>::new();

        print_banner("serial-draft", local_key, Some(peer_key));
        let mut stdin = BufReader::new(io::stdin()).lines();
        println!("Type a message and press enter. Use /pfs [minutes] to start PFS, or /quit to exit.");
        println!("This serial mode uses an example-only draft transport shim and is not a specified UMSH companion-radio protocol.");

        loop {
            tokio::select! {
                line = stdin.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            match handle_user_input(&mut endpoint, &peer_key, &line)? {
                                UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                                UserInputOutcome::Continue(None) => {}
                                UserInputOutcome::Quit => break,
                            }
                        }
                        Ok(None) => break,
                        Err(error) => return Err(Box::new(error)),
                    }
                }
                result = run_mac_event(&local_mac, &mut endpoint, &mut deferred, &mut ready) => {
                    result?;
                }
            }

            handle_deferred_and_ready(&mut endpoint, &mut deferred, &mut ready).await;
        }

        return Ok(());
    }

    #[cfg(not(feature = "serial-radio"))]
    {
        let _ = (identity_path, serial_path, baud_rate, peer_key);
        Err("serial-radio feature is required for the example-only serial draft mode".into())
    }
}

enum UserInputOutcome {
    Continue(Option<String>),
    Quit,
}

fn handle_user_input<R>(
    endpoint: &mut ChatEndpoint<'_, R>,
    peer_key: &PublicKey,
    line: &str,
) -> Result<UserInputOutcome, Box<dyn std::error::Error>>
where
    R: Radio,
{
    let trimmed = line.trim();
    if trimmed == "/quit" {
        return Ok(UserInputOutcome::Quit);
    }

    if let Some(args) = trimmed.strip_prefix("/pfs") {
        let duration_minutes = parse_pfs_minutes(args)?;
        endpoint
            .request_pfs_session(peer_key, duration_minutes)
            .map_err(|error| std::io::Error::other(format!("pfs request failed: {error:?}")))?;
        return Ok(UserInputOutcome::Continue(Some(format!(
            "requested PFS with {} for {duration_minutes} minute(s)",
            hex_encode(&peer_key.0[..4])
        ))));
    }

    endpoint
        .send_text(peer_key, line)
        .map_err(|error| std::io::Error::other(format!("send failed: {error:?}")))?;
    Ok(UserInputOutcome::Continue(None))
}

fn parse_pfs_minutes(args: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return Ok(60);
    }

    let minutes = trimmed.parse::<u16>()?;
    if minutes == 0 {
        return Err("/pfs duration must be at least 1 minute".into());
    }
    Ok(minutes)
}

async fn run_mac_event<R>(
    mac: &RefCell<ChatMac<R>>,
    endpoint: &mut ChatEndpoint<'_, R>,
    deferred: &mut Vec<DeferredAction>,
    ready: &mut Vec<EndpointEvent>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Radio,
    R::Error: core::fmt::Debug,
{
    mac.borrow_mut()
        .next_event(|_, event| match endpoint.handle_event(event) {
            EventAction::Handled(Some(endpoint_event)) => ready.push(endpoint_event),
            EventAction::Handled(None) => {}
            EventAction::NeedsAsync(action) => deferred.push(action),
        })
        .await
        .map_err(|error| format!("mac error: {error:?}"))?;
    Ok(())
}

async fn handle_deferred_and_ready<R>(
    endpoint: &mut ChatEndpoint<'_, R>,
    deferred: &mut Vec<DeferredAction>,
    ready: &mut Vec<EndpointEvent>,
) where
    R: Radio,
{
    for action in deferred.drain(..) {
        if let Some(endpoint_event) = endpoint.handle_deferred(action).await {
            ready.push(endpoint_event);
        }
    }
    for event in ready.drain(..) {
        println!("{}", format_event(&event));
    }
}

fn build_mac<R>(radio: R, counter_root: PathBuf) -> Result<ChatMac<R>, Box<dyn std::error::Error>>
where
    R: Radio,
{
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut secret = [0u8; 32];
            rng().fill_bytes(&mut secret);
            std::fs::write(path, secret)?;
            Ok(SoftwareIdentity::from_secret_bytes(&secret))
        }
        Err(error) => Err(Box::new(error)),
    }
}

fn derive_pairwise_keys(
    identity: &SoftwareIdentity,
    peer_key: &PublicKey,
) -> Result<PairwiseKeys, Box<dyn std::error::Error>> {
    let shared = identity
        .shared_secret_with(peer_key)
        .map_err(|error| std::io::Error::other(format!("shared secret failed: {error:?}")))?;
    Ok(CryptoEngine::new(SoftwareAes, SoftwareSha256).derive_pairwise_keys(&shared))
}

fn format_event(event: &EndpointEvent) -> String {
    match event {
        EndpointEvent::TextReceived { from, message } => {
            format!("[{}] {}", hex_encode(&from.0[..4]), message.body)
        }
        EndpointEvent::ChannelTextReceived {
            from,
            channel_id,
            message,
        } => format!(
            "[{} @ {}] {}",
            hex_encode(&from.0[..4]),
            hex_encode(&channel_id.0),
            message.body
        ),
        EndpointEvent::AckReceived { peer, .. } => {
            format!("ack received from {}", hex_encode(&peer.0[..4]))
        }
        EndpointEvent::AckTimeout { peer, .. } => {
            format!("ack timeout waiting for {}", hex_encode(&peer.0[..4]))
        }
        EndpointEvent::PfsSessionEstablished { peer } => {
            format!("pfs established with {}", hex_encode(&peer.0[..4]))
        }
        EndpointEvent::PfsSessionEnded { peer } => {
            format!("pfs ended with {}", hex_encode(&peer.0[..4]))
        }
        EndpointEvent::BeaconReceived { from_hint, .. } => {
            format!("beacon from {}", hex_encode(&from_hint.0))
        }
        EndpointEvent::NodeDiscovered { key, .. } => {
            format!("node discovered {}", hex_encode(&key.0[..4]))
        }
        EndpointEvent::MacCommand { from, command } => {
            format!("mac command {:?} from {}", command, hex_encode(&from.0[..4]))
        }
    }
}

fn print_banner(mode: &str, local_key: PublicKey, peer_key: Option<PublicKey>) {
    println!("UMSH desktop chat ({mode} mode)");
    println!("local: {}", hex_encode(&local_key.0));
    if let Some(peer_key) = peer_key {
        println!("peer:  {}", hex_encode(&peer_key.0));
    }
}

fn unique_session_root(prefix: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("umsh-{prefix}-{unique}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_public_key(input: &str) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let input = input.trim();
    if input.len() != 64 {
        return Err("public key must be 64 hex characters".into());
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(PublicKey(bytes))
}

fn decode_hex_nibble(byte: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".into()),
    }
}

struct CliConfig {
    identity_path: PathBuf,
    mode: Mode,
}

enum Mode {
    PrintPublicKey,
    Simulated,
    Udp {
        group: Ipv4Addr,
        port: u16,
        peer: PublicKey,
    },
    Serial {
        path: String,
        baud: u32,
        peer: PublicKey,
    },
}

impl CliConfig {
    fn parse(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut identity_path = PathBuf::from(".umsh/desktop-chat.identity");
        let mut mode = Mode::Simulated;
        let mut peer = None;
        let mut baud = 115_200u32;
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--print-public-key" => {
                    mode = Mode::PrintPublicKey;
                }
                "--identity" => {
                    index += 1;
                    identity_path = PathBuf::from(args.get(index).ok_or("missing value for --identity")?);
                }
                "--simulate" => {
                    mode = Mode::Simulated;
                }
                "--udp" => {
                    index += 1;
                    let endpoint = args.get(index).ok_or("missing value for --udp")?;
                    let (group, port) = parse_multicast_endpoint(endpoint)?;
                    mode = Mode::Udp {
                        group,
                        port,
                        peer: PublicKey([0u8; 32]),
                    };
                }
                "--serial" => {
                    index += 1;
                    let path = args.get(index).ok_or("missing value for --serial")?.clone();
                    mode = Mode::Serial {
                        path,
                        baud,
                        peer: PublicKey([0u8; 32]),
                    };
                }
                "--baud" => {
                    index += 1;
                    baud = args.get(index).ok_or("missing value for --baud")?.parse()?;
                }
                "--peer" => {
                    index += 1;
                    peer = Some(decode_public_key(args.get(index).ok_or("missing value for --peer")?)?);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
            index += 1;
        }

        mode = match mode {
            Mode::PrintPublicKey => Mode::PrintPublicKey,
            Mode::Simulated => Mode::Simulated,
            Mode::Udp { group, port, .. } => Mode::Udp {
                group,
                port,
                peer: peer.ok_or("--peer is required in udp mode")?,
            },
            Mode::Serial { path, .. } => Mode::Serial {
                path,
                baud,
                peer: peer.ok_or("--peer is required in serial mode")?,
            },
        };

        Ok(Self {
            identity_path,
            mode,
        })
    }
}

fn parse_multicast_endpoint(input: &str) -> Result<(Ipv4Addr, u16), Box<dyn std::error::Error>> {
    let (group, port) = input
        .split_once(':')
        .ok_or("multicast endpoint must be GROUP:PORT")?;
    let group: Ipv4Addr = group.parse()?;
    if !group.is_multicast() {
        return Err("multicast group must be an IPv4 multicast address".into());
    }
    Ok((group, port.parse()?))
}