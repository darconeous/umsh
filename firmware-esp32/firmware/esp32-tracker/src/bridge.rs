//! Autonomous, node-only bridge client. All control stays independent of ULCP attach.
use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Context, Poll},
};
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_net::{
    IpAddress, Ipv4Address, Stack,
    dns::DnsQueryType,
    tcp::{TcpReader, TcpSocket, TcpWriter},
};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
    waitqueue::WakerRegistration,
};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::{ErrorType, Read, Write};
use embedded_tls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext};
use rand_core::{RngCore, SeedableRng};
use umsh_bridge_client::{
    ALPN, IDLE_MS, KEEPALIVE_MS, MAX_AGE_MS, MAX_BODY,
    tls::{IdentityProvider, failure_reason},
    tunnel::{Frame, Queue},
};
use umsh_radio_loraphy::MAX_PAYLOAD;
use umsh_ulcp::{
    bridge::{Link, Reason, State},
    hdlc,
};
use umsh_ulcp_device::bridge::BridgeConfig;
use umsh_ulcp_runtime::{driver::PublishEvent, radio_mux::BridgePort};

// Only byte buffers and plain queue data live in PSRAM.
pub struct Buffers {
    tcp_rx: [u8; 4096],
    tcp_tx: [u8; 4096],
    tls_rx: [u8; 18 * 1024],
    tls_tx: [u8; 4096],
    encoded: [u8; hdlc::max_encoded_len(MAX_BODY)],
}

pub struct Queues {
    to_node: Queue,
    to_server: Queue,
}
impl Queues {
    pub const fn new() -> Self {
        Self {
            to_node: Queue::new(),
            to_server: Queue::new(),
        }
    }
}

struct PortState {
    queues: Option<&'static mut Queues>,
    active: bool,
    node_waker: WakerRegistration,
    server_waker: WakerRegistration,
    malformed: u32,
}

pub struct Port(Mutex<CriticalSectionRawMutex, RefCell<PortState>>);
pub static PORT: Port = Port(Mutex::new(RefCell::new(PortState {
    queues: None,
    active: false,
    node_waker: WakerRegistration::new(),
    server_waker: WakerRegistration::new(),
    malformed: 0,
})));

impl Port {
    pub fn init(&self, queues: &'static mut Queues) {
        self.0.lock(|cell| cell.borrow_mut().queues = Some(queues));
    }

    fn activate(&self, active: bool) {
        self.0.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.active = active;
            if let Some(queues) = state.queues.as_mut() {
                queues.to_node.clear();
                queues.to_server.clear();
            }
            state.node_waker.wake();
            state.server_waker.wake();
        });
    }

    fn diagnostics(&self) {
        let counts = self.0.lock(|cell| {
            let state = cell.borrow();
            state.queues.as_ref().map(|q| {
                (
                    state.malformed,
                    q.to_node.overflow,
                    q.to_server.overflow,
                    q.to_node.stale,
                    q.to_server.stale,
                )
            })
        });
        if let Some((malformed, rx_overflow, tx_overflow, rx_stale, tx_stale)) = counts {
            super::debug_log(format_args!(
                "bridge drops: malformed={} overflow={}/{} stale={}/{}",
                malformed, rx_overflow, tx_overflow, rx_stale, tx_stale
            ));
        }
        super::debug_log(format_args!(
            "bridge memory: internal heap={} psram={} buffers={} queues={}",
            esp_alloc::HEAP.used(),
            super::external::used(),
            core::mem::size_of::<Buffers>(),
            core::mem::size_of::<Queues>()
        ));
    }

    fn received(&self, body: &[u8]) {
        self.0.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.active {
                return;
            }
            match Frame::parse(body, Instant::now().as_millis(), MAX_PAYLOAD) {
                Some(frame) => {
                    state.queues.as_mut().unwrap().to_node.push(frame);
                    state.node_waker.wake();
                }
                None => state.malformed = state.malformed.saturating_add(1),
            }
        });
    }

    fn malformed(&self) {
        self.0.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.malformed = state.malformed.saturating_add(1);
        });
    }

    async fn outgoing(&self) -> Frame {
        poll_fn(|cx| {
            self.0.lock(|cell| {
                let mut state = cell.borrow_mut();
                state.server_waker.register(cx.waker());
                if !state.active {
                    return Poll::Pending;
                }
                state
                    .queues
                    .as_mut()
                    .and_then(|q| q.to_server.pop(Instant::now().as_millis()))
                    .map_or(Poll::Pending, Poll::Ready)
            })
        })
        .await
    }
}

impl BridgePort for Port {
    fn poll_receive(&self, cx: &mut Context<'_>) -> Poll<heapless::Vec<u8, MAX_PAYLOAD>> {
        self.0.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.node_waker.register(cx.waker());
            if !state.active {
                return Poll::Pending;
            }
            state
                .queues
                .as_mut()
                .and_then(|q| q.to_node.pop(Instant::now().as_millis()))
                .map_or(Poll::Pending, |frame| {
                    Poll::Ready(heapless::Vec::from_slice(frame.data()).unwrap())
                })
        })
    }

    fn transmitted(&self, data: &[u8]) {
        self.0.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.active {
                return;
            }
            if let Some(frame) = Frame::transmitted(data, Instant::now().as_millis()) {
                state.queues.as_mut().unwrap().to_server.push(frame);
                state.server_waker.wake();
            }
        });
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Settings {
    config: BridgeConfig,
    identity: Option<[u8; 32]>,
    generation: u32,
}
static SETTINGS: Mutex<CriticalSectionRawMutex, RefCell<Option<Settings>>> =
    Mutex::new(RefCell::new(None));
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static LINK: Mutex<CriticalSectionRawMutex, RefCell<Link>> =
    Mutex::new(RefCell::new(Link::new(State::Disabled, Reason::None)));
static EVENTS: Signal<CriticalSectionRawMutex, Link> = Signal::new();

pub fn apply(config: &BridgeConfig, identity: Option<[u8; 32]>) {
    let changed = SETTINGS.lock(|cell| {
        let mut held = cell.borrow_mut();
        if held
            .as_ref()
            .is_some_and(|old| &old.config == config && old.identity == identity)
        {
            return false;
        }
        let generation = held
            .as_ref()
            .map_or(0, |old| old.generation.wrapping_add(1));
        *held = Some(Settings {
            config: config.clone(),
            identity,
            generation,
        });
        true
    });
    if changed {
        PORT.activate(false);
        CHANGED.signal(());
    }
}

pub async fn event() -> PublishEvent {
    PublishEvent::BridgeLink(EVENTS.wait().await)
}

fn publish(state: State, reason: Reason) {
    let link = Link::new(state, reason);
    LINK.lock(|cell| {
        let mut old = cell.borrow_mut();
        if *old != link {
            *old = link;
            EVENTS.signal(link);
            super::debug_log(format_args!("bridge: {:?} {:?}", state, reason));
        }
    });
}

fn settings() -> Option<Settings> {
    SETTINGS.lock(|cell| cell.borrow().clone())
}
fn ready(stack: Stack<'_>) -> bool {
    stack.is_link_up() && stack.is_config_up()
}
async fn disconnected(stack: Stack<'_>) {
    let config = stack.config_v4();
    while ready(stack) && stack.config_v4() == config {
        Timer::after_millis(100).await;
    }
}

#[embassy_executor::task]
pub async fn task(
    stack: Stack<'static>,
    seed: Option<[u8; 32]>,
    rng_seed: [u8; 32],
    buffers: &'static mut Buffers,
) -> ! {
    let mut rng = super::IdentityRng::from_seed(rng_seed);
    use umsh_crypto::NodeIdentity as _;
    let public = seed.as_ref().map(|seed| {
        umsh_crypto::software::SoftwareIdentity::from_secret_bytes(seed)
            .public_key()
            .0
    });
    let mut backoff = 1u64;
    loop {
        CHANGED.reset();
        let Some(wanted) = settings() else {
            CHANGED.wait().await;
            continue;
        };
        let inactive = if !wanted.config.enabled {
            Some((State::Disabled, Reason::None))
        } else if !wanted.config.configured() {
            Some((State::Unconfigured, Reason::None))
        } else if public.is_none() || wanted.identity != public {
            Some((State::Retrying, Reason::IdentityUnavailable))
        } else {
            None
        };
        if let Some((state, reason)) = inactive {
            publish(state, reason);
            backoff = 1;
            CHANGED.wait().await;
            continue;
        }
        if !ready(stack) {
            publish(State::WaitingForNetwork, Reason::None);
            select(CHANGED.wait(), Timer::after_millis(250)).await;
            backoff = 1;
            continue;
        }
        publish(State::Connecting, Reason::None);
        let start = Instant::now();
        let result = select3(
            CHANGED.wait(),
            disconnected(stack),
            connect(stack, &wanted, seed.as_ref().unwrap(), &mut rng, buffers),
        )
        .await;
        PORT.activate(false);
        PORT.diagnostics();
        let reason = match result {
            Either3::First(()) => {
                backoff = 1;
                continue;
            }
            Either3::Second(()) => continue,
            Either3::Third(reason) => reason,
        };
        publish(State::Retrying, reason);
        if start.elapsed() >= Duration::from_secs(60) {
            backoff = 1;
        }
        let delay_ms =
            (backoff * 750 + u64::from(rng.next_u32()) % (backoff * 500 + 1)).clamp(1000, 60_000);
        select3(
            CHANGED.wait(),
            disconnected(stack),
            Timer::after_millis(delay_ms),
        )
        .await;
        backoff = (backoff * 2).min(60);
    }
}

// embedded-tls splits by cloning its I/O delegate. Each clone shares separate
// TCP reader/writer halves; no borrow spans both directions, so a blocked read
// cannot hold the writer. These futures run on one executor and are !Send.
#[derive(Clone, Copy)]
struct Socket<'a, 's> {
    reader: &'a RefCell<TcpReader<'s>>,
    writer: &'a RefCell<TcpWriter<'s>>,
}
impl ErrorType for Socket<'_, '_> {
    type Error = embassy_net::tcp::Error;
}
impl Read for Socket<'_, '_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.reader.borrow_mut().read(buf).await
    }
}
impl Write for Socket<'_, '_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.writer.borrow_mut().write(buf).await
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.writer.borrow_mut().flush().await
    }
}

async fn connect(
    stack: Stack<'static>,
    wanted: &Settings,
    seed: &[u8; 32],
    rng: &mut super::IdentityRng,
    buffers: &mut Buffers,
) -> Reason {
    let mut addresses = heapless::Vec::<IpAddress, 4>::new();
    if let Ok(ip) = wanted.config.host.parse::<core::net::Ipv4Addr>() {
        addresses
            .push(IpAddress::Ipv4(Ipv4Address::from(ip.octets())))
            .unwrap();
    } else if wanted.config.host.contains(':') {
        return Reason::Dns;
    } else {
        match with_timeout(
            Duration::from_secs(10),
            stack.dns_query(&wanted.config.host, DnsQueryType::A),
        )
        .await
        {
            Ok(Ok(found)) => {
                for address in found {
                    let _ = addresses.push(address);
                }
            }
            _ => return Reason::Dns,
        }
    }
    if addresses.is_empty() {
        return Reason::Dns;
    }
    let mut socket = TcpSocket::new(stack, &mut buffers.tcp_rx, &mut buffers.tcp_tx);
    socket.set_timeout(Some(Duration::from_secs(30)));
    let mut connected = false;
    for address in addresses {
        if matches!(
            with_timeout(
                Duration::from_secs(10),
                socket.connect((address, wanted.config.port))
            )
            .await,
            Ok(Ok(()))
        ) {
            connected = true;
            break;
        }
        socket.abort();
    }
    if !connected {
        return Reason::Tcp;
    }
    let (reader, writer) = socket.split();
    let reader = RefCell::new(reader);
    let writer = RefCell::new(writer);
    let io = Socket {
        reader: &reader,
        writer: &writer,
    };
    let mut tls =
        TlsConnection::<_, Aes128GcmSha256>::new(io, &mut buffers.tls_rx, &mut buffers.tls_tx);
    let mut provider = match IdentityProvider::new(seed, &wanted.config.server_key.unwrap(), rng) {
        Ok(provider) => provider,
        Err(_) => return Reason::Authentication,
    };
    let mut config = TlsConfig::new().with_alpn(&[ALPN]);
    if wanted.config.host.parse::<core::net::Ipv4Addr>().is_err() {
        config = config.with_server_name(&wanted.config.host);
    }
    match with_timeout(
        Duration::from_secs(20),
        tls.open(TlsContext::new(&config, &mut provider)),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            super::debug_log(format_args!("bridge TLS: {:?}", error));
            return if provider.authentication_failed() {
                Reason::Authentication
            } else {
                failure_reason(&error)
            };
        }
        Err(_) => return Reason::Tls,
    }
    if !provider.authenticated() {
        return Reason::Authentication;
    }
    if settings().is_none_or(|s| s.generation != wanted.generation) {
        return Reason::IdentityUnavailable;
    }
    PORT.activate(true);
    publish(State::Connected, Reason::None);
    let (mut reader, mut writer) = tls.split();
    match select(
        receive(&mut reader),
        send(&mut writer, &mut buffers.encoded),
    )
    .await
    {
        Either::First(reason) | Either::Second(reason) => reason,
    }
}

async fn receive(reader: &mut impl Read<Error = embedded_tls::TlsError>) -> Reason {
    let mut decoder = hdlc::Decoder::<{ MAX_BODY + 2 }>::new();
    let mut bytes = [0; 512];
    loop {
        let count =
            match with_timeout(Duration::from_millis(IDLE_MS), reader.read(&mut bytes)).await {
                Ok(Ok(0)) => return Reason::Tcp,
                Ok(Err(error)) => return failure_reason(&error),
                Err(_) => return Reason::IdleTimeout,
                Ok(Ok(count)) => count,
            };
        for &byte in &bytes[..count] {
            if let Some(result) = decoder.push(byte) {
                match result {
                    Ok(body) if !body.is_empty() => PORT.received(body),
                    Ok(_) => {}
                    Err(_) => PORT.malformed(),
                }
            }
        }
    }
}

async fn send(
    writer: &mut impl Write<Error = embedded_tls::TlsError>,
    encoded: &mut [u8],
) -> Reason {
    let mut last = Instant::now();
    loop {
        let frame = match select(
            PORT.outgoing(),
            Timer::at(last + Duration::from_millis(KEEPALIVE_MS)),
        )
        .await
        {
            Either::First(frame) => Some(frame),
            Either::Second(()) => None,
        };
        let bytes = if let Some(frame) = &frame {
            if frame.stale(Instant::now().as_millis()) {
                continue;
            }
            let Ok(len) = hdlc::encode_frame(&frame.body, encoded) else {
                PORT.malformed();
                continue;
            };
            &encoded[..len]
        } else {
            &[0x7e]
        };
        let write = async {
            writer.write_all(bytes).await?;
            writer.flush().await
        };
        let remaining_ms = frame.as_ref().map_or(MAX_AGE_MS, |frame| {
            MAX_AGE_MS.saturating_sub(Instant::now().as_millis().saturating_sub(frame.queued_ms))
        });
        match with_timeout(Duration::from_millis(remaining_ms), write).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return failure_reason(&error),
            Err(_) => return Reason::Tcp,
        }
        last = Instant::now();
    }
}
