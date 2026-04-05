use std::{
    cell::RefCell,
    env,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{Rng, rng};
use tokio::io::{self, AsyncBufReadExt, BufReader};

#[cfg(feature = "serial-radio")]
#[path = "support/draft_serial_radio.rs"]
mod draft_serial_radio;

use umsh::{
    core::PublicKey,
    crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    hal::Radio,
    mac::{
        Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions,
        test_support::SimulatedNetwork,
    },
    node::{Host, PeerConnection, UnicastTextChatWrapper},
    tokio_support::{
        StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform, UdpMulticastRadio,
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

type ChatMac<R> = Mac<ChatPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

type ChatHandle<'a, R> =
    MacHandle<'a, ChatPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

type ChatHost<'a, R> = Host<'a, ChatPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

type ChatPeer<'a, R> = PeerConnection<umsh::node::LocalNode<ChatHandle<'a, R>>>;
type ChatText<'a, R> = UnicastTextChatWrapper<umsh::node::LocalNode<ChatHandle<'a, R>>>;

struct OutputQueue {
    lines: Rc<RefCell<Vec<String>>>,
}

impl OutputQueue {
    fn new() -> Self {
        Self {
            lines: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn sink(&self) -> Rc<RefCell<Vec<String>>> {
        self.lines.clone()
    }

    fn flush(&self) {
        for line in self.lines.borrow_mut().drain(..) {
            println!("{line}");
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = CliConfig::parse(env::args().skip(1).collect::<Vec<_>>())?;
    match config.mode {
        Mode::PrintPublicKey => print_public_key(config.identity_path)?,
        Mode::Simulated => run_simulated_chat(config).await?,
        Mode::Udp { group, port, peer } => {
            run_udp_chat(config.identity_path, group, port, peer).await?
        }
        Mode::Serial { path, baud, peer } => {
            run_serial_chat(config.identity_path, path, baud, peer).await?
        }
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

    let session_root = unique_session_root("desktop-chat-udp");
    let radio = UdpMulticastRadio::bind_v4(group, port)
        .await
        .map_err(|error| std::io::Error::other(format!("udp bind failed: {error:?}")))?;
    let local_mac = RefCell::new(build_mac(radio, session_root.join("counters"))?);
    let local_handle = MacHandle::new(&local_mac);
    let local_id = local_handle
        .add_identity(local_identity)
        .expect("local identity should fit");
    let mut host = ChatHost::new(local_handle);
    let node = host.add_node(local_id);
    let peer = node
        .peer(peer_key)
        .map_err(|error| std::io::Error::other(format!("peer setup failed: {error:?}")))?;
    let chat = ChatText::from_peer(&peer);
    let outputs = OutputQueue::new();
    register_peer_callbacks(&chat, &peer, outputs.sink());

    print_banner("udp-multicast", local_key, Some(peer_key));
    println!("group: {group}:{port}");
    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("Type a message and press enter, or /quit to exit.");
    println!("Use /pfs, /pfs <minutes>, /pfs status, or /pfs end.");

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        match handle_user_input(&chat, &peer, &line).await? {
                            UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                            UserInputOutcome::Continue(None) => {}
                            UserInputOutcome::Quit => break,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            result = host.pump_once() => {
                result.map_err(|error| std::io::Error::other(format!("host pump failed: {error:?}")))?;
            }
        }
        outputs.flush();
    }

    Ok(())
}

async fn run_simulated_chat(config: CliConfig) -> Result<(), Box<dyn std::error::Error>> {
    let local_identity = load_or_create_identity(&config.identity_path)?;
    let remote_identity = SoftwareIdentity::from_secret_bytes(&[0x55; 32]);
    let local_key = *local_identity.public_key();
    let remote_key = *remote_identity.public_key();

    let network = SimulatedNetwork::new();
    let local_radio = network.add_radio();
    let remote_radio = network.add_radio();
    network.connect_bidirectional(local_radio.id(), remote_radio.id());

    let session_root = unique_session_root("desktop-chat-sim");
    let local_mac = RefCell::new(build_mac(local_radio, session_root.join("local-counters"))?);
    let remote_mac = RefCell::new(build_mac(
        remote_radio,
        session_root.join("remote-counters"),
    )?);

    let local_handle = MacHandle::new(&local_mac);
    let local_id = local_handle
        .add_identity(local_identity)
        .expect("local identity should fit");
    let remote_handle = MacHandle::new(&remote_mac);
    let remote_id = remote_handle
        .add_identity(remote_identity)
        .expect("remote identity should fit");

    let mut local_host = ChatHost::new(local_handle);
    let mut remote_host = ChatHost::new(remote_handle);
    let local_node = local_host.add_node(local_id);
    let remote_node = remote_host.add_node(remote_id);
    let local_peer = local_node
        .peer(remote_key)
        .map_err(|error| std::io::Error::other(format!("local peer setup failed: {error:?}")))?;
    let remote_peer = remote_node
        .peer(local_key)
        .map_err(|error| std::io::Error::other(format!("remote peer setup failed: {error:?}")))?;
    let local_chat = ChatText::from_peer(&local_peer);
    let remote_chat = ChatText::from_peer(&remote_peer);
    let outputs = OutputQueue::new();
    let remote_echoes = Rc::new(RefCell::new(Vec::<String>::new()));
    register_peer_callbacks(&local_chat, &local_peer, outputs.sink());
    {
        let remote_echoes = remote_echoes.clone();
        remote_chat.on_text(move |body| {
            remote_echoes.borrow_mut().push(body.to_string());
        });
    }

    print_banner("simulated", local_key, Some(remote_key));
    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("Type a message and press enter, or /quit to exit.");
    println!("Use /pfs, /pfs <minutes>, /pfs status, or /pfs end.");

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        match handle_user_input(&local_chat, &local_peer, &line).await? {
                            UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                            UserInputOutcome::Continue(None) => {}
                            UserInputOutcome::Quit => break,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            result = local_host.pump_once() => {
                result.map_err(|error| std::io::Error::other(format!("local host pump failed: {error:?}")))?;
            }
            result = remote_host.pump_once() => {
                result.map_err(|error| std::io::Error::other(format!("remote host pump failed: {error:?}")))?;
            }
        }

        for body in remote_echoes.borrow_mut().drain(..) {
            let _ = remote_chat
                .send_text(&format!("echo: {body}"), &default_chat_options())
                .await;
        }
        outputs.flush();
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
        let session_root = unique_session_root("desktop-chat-serial");
        let radio = DraftSerialRadio::open_tokio(serial_path, baud_rate)
            .await
            .map_err(|error| std::io::Error::other(format!("serial open failed: {error:?}")))?;
        let local_mac = RefCell::new(build_mac(radio, session_root.join("counters"))?);
        let local_handle = MacHandle::new(&local_mac);
        let local_id = local_handle
            .add_identity(local_identity)
            .expect("local identity should fit");
        let mut host = ChatHost::new(local_handle);
        let node = host.add_node(local_id);
        let peer = node
            .peer(peer_key)
            .map_err(|error| std::io::Error::other(format!("peer setup failed: {error:?}")))?;
        let chat = ChatText::from_peer(&peer);
        let outputs = OutputQueue::new();
        register_peer_callbacks(&chat, &peer, outputs.sink());

        print_banner("serial-draft", local_key, Some(peer_key));
        let mut stdin = BufReader::new(io::stdin()).lines();
        println!("Type a message and press enter, or /quit to exit.");
        println!("Use /pfs, /pfs <minutes>, /pfs status, or /pfs end.");
        println!(
            "This serial mode uses an example-only draft transport shim and is not a specified UMSH companion-radio protocol."
        );

        loop {
            tokio::select! {
                line = stdin.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            match handle_user_input(&chat, &peer, &line).await? {
                                UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                                UserInputOutcome::Continue(None) => {}
                                UserInputOutcome::Quit => break,
                            }
                        }
                        Ok(None) => break,
                        Err(error) => return Err(Box::new(error)),
                    }
                }
                result = host.pump_once() => {
                    result.map_err(|error| std::io::Error::other(format!("host pump failed: {error:?}")))?;
                }
            }
            outputs.flush();
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

async fn handle_user_input<'a, R: Radio>(
    chat: &ChatText<'a, R>,
    peer: &ChatPeer<'a, R>,
    line: &str,
) -> Result<UserInputOutcome, Box<dyn std::error::Error>> {
    let trimmed = line.trim();
    if trimmed == "/quit" {
        return Ok(UserInputOutcome::Quit);
    }

    if let Some(command) = trimmed.strip_prefix("/pfs") {
        return handle_pfs_command(peer, command.trim()).await;
    }

    chat.send_text(line, &default_chat_options())
        .await
        .map_err(|error| std::io::Error::other(format!("send failed: {error:?}")))?;
    Ok(UserInputOutcome::Continue(None))
}

async fn handle_pfs_command<'a, R: Radio>(
    peer: &ChatPeer<'a, R>,
    args: &str,
) -> Result<UserInputOutcome, Box<dyn std::error::Error>> {
    match args {
        "" => {
            let _ = peer
                .request_pfs(60, &default_chat_options())
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("pfs request failed: {error:?}"))
                })?;
            Ok(UserInputOutcome::Continue(Some(format!(
                "requested pfs with {} for 60 minutes",
                hex_encode(&peer.peer().0[..4])
            ))))
        }
        "end" => {
            peer.end_pfs(&default_chat_options())
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("end pfs failed: {error:?}"))
                })?;
            Ok(UserInputOutcome::Continue(Some(format!(
                "ended pfs with {}",
                hex_encode(&peer.peer().0[..4])
            ))))
        }
        "status" => {
            let message = match peer
                .pfs_status()
                .map_err(|error| std::io::Error::other(format!("pfs status failed: {error:?}")))?
            {
                umsh::node::PfsStatus::Inactive => String::from("pfs inactive"),
                umsh::node::PfsStatus::Requested => String::from("pfs requested"),
                umsh::node::PfsStatus::Active {
                    local_ephemeral_id,
                    peer_ephemeral,
                    ..
                } => format!(
                    "pfs active: local slot {} -> {}",
                    local_ephemeral_id.0,
                    hex_encode(&peer_ephemeral.0[..4])
                ),
            };
            Ok(UserInputOutcome::Continue(Some(message)))
        }
        minutes => {
            let duration_minutes: u16 = minutes.parse()?;
            let _ = peer
                .request_pfs(duration_minutes, &default_chat_options())
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("pfs request failed: {error:?}"))
                })?;
            Ok(UserInputOutcome::Continue(Some(format!(
                "requested pfs with {} for {duration_minutes} minutes",
                hex_encode(&peer.peer().0[..4])
            ))))
        }
    }
}

fn default_chat_options() -> SendOptions {
    SendOptions::default()
        .with_ack_requested(true)
        .with_flood_hops(5)
}

fn register_peer_callbacks<'a, R: Radio>(
    chat: &ChatText<'a, R>,
    peer: &ChatPeer<'a, R>,
    lines: Rc<RefCell<Vec<String>>>,
) {
    let peer_key = *peer.peer();
    let text_lines = lines.clone();
    chat.on_text(move |body| {
        text_lines.borrow_mut().push(format!(
            "[{}] {}",
            hex_encode(&peer_key.0[..4]),
            body
        ));
    });

    let peer_key = *peer.peer();
    let pfs_lines = lines.clone();
    peer.on_pfs_established(move || {
        pfs_lines.borrow_mut().push(format!(
            "pfs established with {}",
            hex_encode(&peer_key.0[..4])
        ));
    });

    let peer_key = *peer.peer();
    peer.on_pfs_ended(move || {
        lines.borrow_mut().push(format!(
            "pfs ended with {}",
            hex_encode(&peer_key.0[..4])
        ));
    });
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
                    identity_path =
                        PathBuf::from(args.get(index).ok_or("missing value for --identity")?);
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
                    peer = Some(decode_public_key(
                        args.get(index).ok_or("missing value for --peer")?,
                    )?);
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
