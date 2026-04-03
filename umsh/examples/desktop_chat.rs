use std::{
    cell::RefCell,
    env,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rng, Rng};
use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    time::{sleep, Duration},
};

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
    tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform},
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
        Mode::Simulated => run_simulated_chat(config).await?,
        Mode::Serial { path, baud, peer } => run_serial_chat(config.identity_path, path, baud, peer).await?,
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
    println!("Type a message and press enter. Use /quit to exit.");

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        if line.trim() == "/quit" {
                            break;
                        }
                        local_endpoint
                            .send_text(&remote_key, &line)
                            .map_err(|error| std::io::Error::other(format!("send failed: {error:?}")))?;
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            _ = sleep(Duration::from_millis(20)) => {}
        }

        poll_endpoint(&local_mac, &mut local_endpoint, &mut local_deferred, &mut local_ready).await?;
        poll_endpoint(&remote_mac, &mut remote_endpoint, &mut remote_deferred, &mut remote_ready).await?;

        for event in remote_ready.drain(..) {
            if let EndpointEvent::TextReceived { message, .. } = event {
                remote_endpoint
                    .send_text(&local_key, &format!("echo: {}", message.body))
                    .map_err(|error| std::io::Error::other(format!("echo send failed: {error:?}")))?;
            }
        }

        for event in local_ready.drain(..) {
            println!("{}", format_event(&event));
        }
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
        println!("Type a message and press enter. Use /quit to exit.");
        println!("This serial mode uses an example-only draft transport shim and is not a specified UMSH companion-radio protocol.");

        loop {
            tokio::select! {
                line = stdin.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            if line.trim() == "/quit" {
                                break;
                            }
                            endpoint
                                .send_text(&peer_key, &line)
                                .map_err(|error| std::io::Error::other(format!("send failed: {error:?}")))?;
                        }
                        Ok(None) => break,
                        Err(error) => return Err(Box::new(error)),
                    }
                }
                _ = sleep(Duration::from_millis(20)) => {}
            }

            poll_endpoint(&local_mac, &mut endpoint, &mut deferred, &mut ready).await?;
            for event in ready.drain(..) {
                println!("{}", format_event(&event));
            }
        }

        return Ok(());
    }

    #[cfg(not(feature = "serial-radio"))]
    {
        let _ = (identity_path, serial_path, baud_rate, peer_key);
        Err("serial-radio feature is required for the example-only serial draft mode".into())
    }
}

async fn poll_endpoint<R>(
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
        .poll_cycle(|_, event| match endpoint.handle_event(event) {
            EventAction::Handled(Some(endpoint_event)) => ready.push(endpoint_event),
            EventAction::Handled(None) => {}
            EventAction::NeedsAsync(action) => deferred.push(action),
        })
        .await
        .map_err(|error| format!("mac error: {error:?}"))?;

    for action in deferred.drain(..) {
        if let Some(endpoint_event) = endpoint.handle_deferred(action).await {
            ready.push(endpoint_event);
        }
    }
    Ok(())
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
    Simulated,
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
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--identity" => {
                    index += 1;
                    identity_path = PathBuf::from(args.get(index).ok_or("missing value for --identity")?);
                }
                "--simulate" => {
                    mode = Mode::Simulated;
                }
                "--serial" => {
                    index += 1;
                    let path = args.get(index).ok_or("missing value for --serial")?.clone();
                    let mut baud = 115_200u32;
                    let mut peer = None;
                    let mut lookahead = index + 1;
                    while lookahead < args.len() {
                        match args[lookahead].as_str() {
                            "--baud" => {
                                lookahead += 1;
                                baud = args.get(lookahead).ok_or("missing value for --baud")?.parse()?;
                            }
                            "--peer" => {
                                lookahead += 1;
                                peer = Some(decode_public_key(args.get(lookahead).ok_or("missing value for --peer")?)?);
                            }
                            _ => break,
                        }
                        lookahead += 1;
                    }
                    mode = Mode::Serial {
                        path,
                        baud,
                        peer: peer.ok_or("--peer is required in serial mode")?,
                    };
                    index = lookahead.saturating_sub(1);
                }
                "--baud" | "--peer" => {}
                other => return Err(format!("unknown argument: {other}").into()),
            }
            index += 1;
        }
        Ok(Self {
            identity_path,
            mode,
        })
    }
}