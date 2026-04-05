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
        LocalIdentityId, Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions,
        test_support::SimulatedNetwork,
    },
    node::{
        EventSink, LocalNode, NodeEvent, NodeRuntime, OwnedMacCommand, PfsSessionManager,
        Transport,
    },
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

/// Simple EventSink that stores events in a shared Vec.
struct VecSink {
    events: Rc<RefCell<Vec<NodeEvent>>>,
}

impl EventSink for VecSink {
    fn send_event(&mut self, event: NodeEvent) {
        self.events.borrow_mut().push(event);
    }
}

struct ExamplePfs<'a, R: Radio> {
    parent_id: LocalIdentityId,
    manager: PfsSessionManager,
    session_nodes: Vec<(LocalIdentityId, LocalNode<ChatHandle<'a, R>>)>,
}

impl<'a, R: Radio> ExamplePfs<'a, R> {
    fn new(parent_id: LocalIdentityId) -> Self {
        Self {
            parent_id,
            manager: PfsSessionManager::new(),
            session_nodes: Vec::new(),
        }
    }

    fn active_route(
        &self,
        handle: &ChatHandle<'a, R>,
        peer: &PublicKey,
    ) -> Result<Option<(LocalIdentityId, PublicKey)>, Box<dyn std::error::Error>> {
        let now_ms = handle
            .now_ms()
            .map_err(|_| std::io::Error::other("clock lookup failed"))?;
        Ok(self.manager.active_route(peer, now_ms))
    }

    fn sync_active_nodes(
        &mut self,
        runtime: &NodeRuntime<ChatHandle<'a, R>>,
        events: &Rc<RefCell<Vec<NodeEvent>>>,
    ) {
        for session in self.manager.sessions() {
            if session.state != umsh::node::PfsState::Active {
                continue;
            }
            if self
                .session_nodes
                .iter()
                .any(|(id, _)| *id == session.local_ephemeral_id)
            {
                continue;
            }
            let sink = VecSink {
                events: events.clone(),
            };
            let node = runtime.create_node(session.local_ephemeral_id, Box::new(sink));
            self.session_nodes.push((session.local_ephemeral_id, node));
        }
    }

    async fn handle_command(
        &mut self,
        handle: &ChatHandle<'a, R>,
        runtime: &NodeRuntime<ChatHandle<'a, R>>,
        events: &Rc<RefCell<Vec<NodeEvent>>>,
        from: PublicKey,
        command: &OwnedMacCommand,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let options = default_chat_options();
        match *command {
            OwnedMacCommand::PfsSessionRequest {
                ephemeral_key,
                duration_minutes,
            } => {
                self.manager
                    .accept_request(
                        handle,
                        self.parent_id,
                        from,
                        ephemeral_key,
                        duration_minutes,
                        &options,
                    )
                    .await
                    .map_err(|error| {
                        std::io::Error::other(format!("accept pfs request failed: {error:?}"))
                    })?;
                self.sync_active_nodes(runtime, events);
                Ok(Some(format!(
                    "accepted pfs request from {}",
                    hex_encode(&from.0[..4])
                )))
            }
            OwnedMacCommand::PfsSessionResponse {
                ephemeral_key,
                duration_minutes,
            } => {
                let activated = self
                    .manager
                    .accept_response(
                        handle,
                        self.parent_id,
                        from,
                        ephemeral_key,
                        duration_minutes,
                    )
                    .map_err(|error| {
                        std::io::Error::other(format!("accept pfs response failed: {error:?}"))
                    })?;
                if activated {
                    self.sync_active_nodes(runtime, events);
                    Ok(Some(format!(
                        "pfs established with {}",
                        hex_encode(&from.0[..4])
                    )))
                } else {
                    Ok(None)
                }
            }
            OwnedMacCommand::EndPfsSession => {
                let _ = self
                    .manager
                    .end_session(handle, self.parent_id, &from, false, &options)
                    .await
                    .map_err(|error| {
                        std::io::Error::other(format!("end pfs session failed: {error:?}"))
                    })?;
                Ok(Some(format!("pfs ended with {}", hex_encode(&from.0[..4]))))
            }
            _ => Ok(None),
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
    let _peer_id = local_handle.add_peer(peer_key).expect("peer should fit");

    let runtime = NodeRuntime::new(local_handle);
    let events = Rc::new(RefCell::new(Vec::new()));
    let sink = VecSink {
        events: events.clone(),
    };
    let node = runtime.create_node(local_id, Box::new(sink));
    let mut pfs = ExamplePfs::new(local_id);

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
                        match handle_user_input(
                            &local_handle,
                            &runtime,
                            &events,
                            &node,
                            &mut pfs,
                            &peer_key,
                            &line,
                        )
                        .await? {
                            UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                            UserInputOutcome::Continue(None) => {}
                            UserInputOutcome::Quit => break,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            result = run_mac_event(&local_mac, &runtime) => {
                result?;
            }
        }

        for event in drain_events(&local_handle, &runtime, &events, &mut pfs).await? {
            println!("{}", format_event(&event));
        }
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

    let _remote_peer = local_handle
        .add_peer(remote_key)
        .expect("remote peer should fit");
    let _local_peer = remote_handle
        .add_peer(local_key)
        .expect("local peer should fit for remote side");

    let local_runtime = NodeRuntime::new(local_handle);
    let remote_runtime = NodeRuntime::new(remote_handle);
    let local_events = Rc::new(RefCell::new(Vec::new()));
    let remote_events = Rc::new(RefCell::new(Vec::new()));
    let local_sink = VecSink {
        events: local_events.clone(),
    };
    let remote_sink = VecSink {
        events: remote_events.clone(),
    };
    let local_node = local_runtime.create_node(local_id, Box::new(local_sink));
    let remote_node = remote_runtime.create_node(remote_id, Box::new(remote_sink));
    let mut local_pfs = ExamplePfs::new(local_id);
    let mut remote_pfs = ExamplePfs::new(remote_id);

    print_banner("simulated", local_key, Some(remote_key));
    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("Type a message and press enter, or /quit to exit.");
    println!("Use /pfs, /pfs <minutes>, /pfs status, or /pfs end.");

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        match handle_user_input(
                            &local_handle,
                            &local_runtime,
                            &local_events,
                            &local_node,
                            &mut local_pfs,
                            &remote_key,
                            &line,
                        )
                        .await? {
                            UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                            UserInputOutcome::Continue(None) => {}
                            UserInputOutcome::Quit => break,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => return Err(Box::new(error)),
                }
            }
            result = run_mac_event(&local_mac, &local_runtime) => {
                result?;
            }
            result = run_mac_event(&remote_mac, &remote_runtime) => {
                result?;
            }
        }

        // Echo received messages back from the remote side.
        for event in drain_events(&remote_handle, &remote_runtime, &remote_events, &mut remote_pfs).await? {
            if let NodeEvent::TextReceived { body, .. } = &event {
                let echo_payload = encode_text_payload(&format!("echo: {body}"));
                let _ = send_payload(
                    &remote_handle,
                    &remote_node,
                    &remote_pfs,
                    &local_key,
                    &echo_payload,
                    &default_chat_options(),
                )
                .await;
            }
        }

        for event in drain_events(&local_handle, &local_runtime, &local_events, &mut local_pfs).await? {
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
        let session_root = unique_session_root("desktop-chat-serial");
        let radio = DraftSerialRadio::open_tokio(serial_path, baud_rate)
            .await
            .map_err(|error| std::io::Error::other(format!("serial open failed: {error:?}")))?;
        let local_mac = RefCell::new(build_mac(radio, session_root.join("counters"))?);
        let local_handle = MacHandle::new(&local_mac);
        let local_id = local_handle
            .add_identity(local_identity)
            .expect("local identity should fit");
        let _peer_id = local_handle.add_peer(peer_key).expect("peer should fit");

        let runtime = NodeRuntime::new(local_handle);
        let events = Rc::new(RefCell::new(Vec::new()));
        let sink = VecSink {
            events: events.clone(),
        };
        let node = runtime.create_node(local_id, Box::new(sink));
        let mut pfs = ExamplePfs::new(local_id);

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
                            match handle_user_input(
                                &local_handle,
                                &runtime,
                                &events,
                                &node,
                                &mut pfs,
                                &peer_key,
                                &line,
                            )
                            .await? {
                                UserInputOutcome::Continue(Some(message)) => println!("{message}"),
                                UserInputOutcome::Continue(None) => {}
                                UserInputOutcome::Quit => break,
                            }
                        }
                        Ok(None) => break,
                        Err(error) => return Err(Box::new(error)),
                    }
                }
                result = run_mac_event(&local_mac, &runtime) => {
                    result?;
                }
            }

            for event in drain_events(&local_handle, &runtime, &events, &mut pfs).await? {
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

enum UserInputOutcome {
    Continue(Option<String>),
    Quit,
}

async fn handle_user_input<'a, R: Radio>(
    handle: &ChatHandle<'a, R>,
    runtime: &NodeRuntime<ChatHandle<'a, R>>,
    events: &Rc<RefCell<Vec<NodeEvent>>>,
    node: &LocalNode<ChatHandle<'a, R>>,
    pfs: &mut ExamplePfs<'a, R>,
    peer_key: &PublicKey,
    line: &str,
) -> Result<UserInputOutcome, Box<dyn std::error::Error>> {
    let trimmed = line.trim();
    if trimmed == "/quit" {
        return Ok(UserInputOutcome::Quit);
    }

    if let Some(command) = trimmed.strip_prefix("/pfs") {
        return handle_pfs_command(handle, runtime, events, pfs, peer_key, command.trim()).await;
    }

    let payload = encode_text_payload(line);
    send_payload(handle, node, pfs, peer_key, &payload, &default_chat_options()).await?;
    Ok(UserInputOutcome::Continue(None))
}

async fn handle_pfs_command<'a, R: Radio>(
    handle: &ChatHandle<'a, R>,
    runtime: &NodeRuntime<ChatHandle<'a, R>>,
    events: &Rc<RefCell<Vec<NodeEvent>>>,
    pfs: &mut ExamplePfs<'a, R>,
    peer_key: &PublicKey,
    args: &str,
) -> Result<UserInputOutcome, Box<dyn std::error::Error>> {
    match args {
        "" => {
            pfs.manager
                .request_session(
                    handle,
                    pfs.parent_id,
                    peer_key,
                    60,
                    &default_chat_options(),
                )
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("pfs request failed: {error:?}"))
                })?;
            Ok(UserInputOutcome::Continue(Some(format!(
                "requested pfs with {} for 60 minutes",
                hex_encode(&peer_key.0[..4])
            ))))
        }
        "end" => {
            let _ = pfs
                .manager
                .end_session(
                    handle,
                    pfs.parent_id,
                    peer_key,
                    true,
                    &default_chat_options(),
                )
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("end pfs session failed: {error:?}"))
                })?;
            let _ = drain_events(handle, runtime, events, pfs).await?;
            Ok(UserInputOutcome::Continue(Some(format!(
                "ended pfs with {}",
                hex_encode(&peer_key.0[..4])
            ))))
        }
        "status" => {
            if let Some((local_id, peer_ephemeral)) = pfs.active_route(handle, peer_key)? {
                Ok(UserInputOutcome::Continue(Some(format!(
                    "pfs active: local slot {} -> {}",
                    local_id.0,
                    hex_encode(&peer_ephemeral.0[..4])
                ))))
            } else {
                Ok(UserInputOutcome::Continue(Some(String::from(
                    "pfs inactive",
                ))))
            }
        }
        minutes => {
            let duration_minutes: u16 = minutes.parse()?;
            pfs.manager
                .request_session(
                    handle,
                    pfs.parent_id,
                    peer_key,
                    duration_minutes,
                    &default_chat_options(),
                )
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("pfs request failed: {error:?}"))
                })?;
            Ok(UserInputOutcome::Continue(Some(format!(
                "requested pfs with {} for {duration_minutes} minutes",
                hex_encode(&peer_key.0[..4])
            ))))
        }
    }
}

async fn send_payload<'a, R: Radio>(
    handle: &ChatHandle<'a, R>,
    node: &LocalNode<ChatHandle<'a, R>>,
    pfs: &ExamplePfs<'a, R>,
    peer_key: &PublicKey,
    payload: &[u8],
    options: &SendOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some((local_id, peer_ephemeral)) = pfs.active_route(handle, peer_key)? {
        handle
            .send_unicast(local_id, &peer_ephemeral, payload, options)
            .await
            .map_err(|error| std::io::Error::other(format!("send failed: {error:?}")))?;
        return Ok(());
    }

    node.send(peer_key, payload, options)
        .await
        .map_err(|error| std::io::Error::other(format!("send failed: {error:?}")))?;
    Ok(())
}

async fn drain_events<'a, R: Radio>(
    handle: &ChatHandle<'a, R>,
    runtime: &NodeRuntime<ChatHandle<'a, R>>,
    events: &Rc<RefCell<Vec<NodeEvent>>>,
    pfs: &mut ExamplePfs<'a, R>,
) -> Result<Vec<NodeEvent>, Box<dyn std::error::Error>> {
    let drained: Vec<NodeEvent> = events.borrow_mut().drain(..).collect();
    let mut remaining = Vec::with_capacity(drained.len());
    for event in drained {
        match &event {
            NodeEvent::MacCommandReceived { from, command } => {
                if let Some(message) = pfs
                    .handle_command(handle, runtime, events, *from, command)
                    .await?
                {
                    println!("{message}");
                } else {
                    remaining.push(event);
                }
            }
            _ => remaining.push(event),
        }
    }
    let now_ms = handle
        .now_ms()
        .map_err(|_| std::io::Error::other("clock lookup failed"))?;
    for peer in pfs
        .manager
        .expire_sessions(handle, now_ms)
        .map_err(|error| std::io::Error::other(format!("expire pfs sessions failed: {error:?}")))?
    {
        println!("pfs expired with {}", hex_encode(&peer.0[..4]));
    }
    pfs.sync_active_nodes(runtime, events);
    Ok(remaining)
}

fn default_chat_options() -> SendOptions {
    SendOptions::default()
        .with_ack_requested(true)
        .with_flood_hops(5)
}

fn encode_text_payload(text: &str) -> Vec<u8> {
    use umsh::app::{PayloadType, text_message};
    use umsh::node::OwnedTextMessage;

    let message = OwnedTextMessage {
        message_type: umsh::app::MessageType::Basic,
        sender_handle: None,
        sequence: None,
        sequence_reset: false,
        regarding: None,
        editing: None,
        bg_color: None,
        text_color: None,
        body: String::from(text),
    };
    let mut body = [0u8; 512];
    let len = text_message::encode(&message.as_borrowed(), &mut body).unwrap();
    let mut payload = Vec::with_capacity(len + 1);
    payload.push(PayloadType::TextMessage as u8);
    payload.extend_from_slice(&body[..len]);
    payload
}

async fn run_mac_event<R>(
    mac: &RefCell<ChatMac<R>>,
    runtime: &NodeRuntime<ChatHandle<'_, R>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Radio,
    R::Error: core::fmt::Debug,
{
    mac.borrow_mut()
        .next_event(|identity_id, event| {
            runtime.dispatch(identity_id, &event);
        })
        .await
        .map_err(|error| format!("mac error: {error:?}"))?;
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

fn format_event(event: &NodeEvent) -> String {
    match event {
        NodeEvent::TextReceived { from, body } => {
            format!("[{}] {}", hex_encode(&from.0[..4]), body)
        }
        NodeEvent::ChannelTextReceived {
            from,
            channel_id,
            body,
            ..
        } => format!(
            "[{} @ {}] {}",
            hex_encode(&from.0[..4]),
            hex_encode(&channel_id.0),
            body
        ),
        NodeEvent::AckReceived { peer, .. } => {
            format!("ack received from {}", hex_encode(&peer.0[..4]))
        }
        NodeEvent::AckTimeout { peer, .. } => {
            format!("ack timeout waiting for {}", hex_encode(&peer.0[..4]))
        }
        NodeEvent::BeaconReceived { from_hint, .. } => {
            format!("beacon from {}", hex_encode(&from_hint.0))
        }
        NodeEvent::NodeDiscovered { key, .. } => {
            format!("node discovered {}", hex_encode(&key.0[..4]))
        }
        NodeEvent::MacCommandReceived { from, command } => {
            format!(
                "mac command {:?} from {}",
                command,
                hex_encode(&from.0[..4])
            )
        }
        NodeEvent::PfsSessionEstablished { peer } => {
            format!("pfs established with {}", hex_encode(&peer.0[..4]))
        }
        NodeEvent::PfsSessionEnded { peer } => {
            format!("pfs ended with {}", hex_encode(&peer.0[..4]))
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
