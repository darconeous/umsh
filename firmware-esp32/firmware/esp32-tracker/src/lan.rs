//! The LAN bearer: the device node's frames over IP multicast on the
//! station's network, and the DNS-SD record that describes them.
//!
//! One task owns the group membership and two sockets. While the bearer
//! is switched on and the station has an IPv4 address, it joins the
//! group, offers every datagram from it to [`PORT`] (which validates,
//! rate-limits, and queues it for the node), sends the group every frame
//! the radio transmits, as [`PORT`] collects them, and answers mDNS
//! queries for the `_umsh._udp` record. When any of that stops
//! holding—the bearer switched off or regrouped, the address lost or
//! replaced across a Wi-Fi reconnect—the port stops collecting, the task
//! leaves both groups, and it starts over. A join reports membership once, so starting over
//! is also what gets a reconnected station back into a snooping access
//! point's or switch's forwarding table.
//!
//! Spec: `docs/protocol/src/lan-bearer.md`.

use core::cell::RefCell;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::sync::atomic::{AtomicBool, Ordering};

use super::ip::{Network, NetworkReceiver};
use edge_mdns::domain::base::Ttl;
use edge_mdns::host::{Host, Service, ServiceAnswers};
use edge_mdns::{HostAnswersMdnsHandler, MdnsHandler, MdnsRequest, MdnsResponse};
use embassy_futures::join::join;
use embassy_futures::select::{Either, select, select4};
use embassy_net::udp::{PacketMetadata, RecvError, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Stack};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use umsh_lan_bearer::MAX_FRAME;
use umsh_lan_bearer::txt::{Advertisement, LoraSettings};
use umsh_ulcp::lan::State;
use umsh_ulcp_device::lan_bearer::LanBearerConfig;
use umsh_ulcp_runtime::driver::{LanBearerSettings, PublishEvent};
use umsh_ulcp_runtime::lan_bearer::LanPort;

/// The bearer's port into the radio multiplexer.
pub static PORT: LanPort<CriticalSectionRawMutex> = LanPort::new(Some(&super::STATS));

/// The mDNS group and port (RFC 6762).
const MDNS_GROUP: Ipv4Address = Ipv4Address::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
/// RFC 6762 §11: mDNS is sent with an IP TTL of 255.
const MDNS_HOP_LIMIT: u8 = 255;
/// How long a resolver may cache the record.
const MDNS_TTL_S: u32 = 120;
/// A query larger than this, such as one carrying a long known-answer
/// list, does not fit the receive buffer and goes unanswered; the
/// querier asks again.
const MDNS_QUERY: usize = 1024;
/// The whole record in one response: names, the TXT keys, and an address.
const MDNS_REPLY: usize = 512;

/// A DNS label's limit, which bounds the instance and host names.
const LABEL_MAX: usize = 63;

// ─── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq)]
struct Settings {
    config: LanBearerConfig,
    /// The DNS-SD instance name.
    name: heapless::String<LABEL_MAX>,
    node_key: Option<[u8; 32]>,
    lora: Option<LoraSettings>,
    meshcore: bool,
}

static SETTINGS: Mutex<CriticalSectionRawMutex, RefCell<Option<Settings>>> =
    Mutex::new(RefCell::new(None));
/// The bearer's own configuration moved, so the group is rejoined.
static CONFIG_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Something the DNS-SD record says moved, so it is announced again.
static RECORD_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Whether the internet bridge's link is up, which the record's `ib` key
/// reports.
static BRIDGE_UP: AtomicBool = AtomicBool::new(false);

/// Take the session's LAN bearer settings. Idempotent: the driver calls
/// this with every device-domain change.
pub fn apply(settings: LanBearerSettings<'_>) {
    let next = Settings {
        config: settings.config,
        name: label(settings.name),
        node_key: settings.node_key,
        lora: settings.lora.map(|radio| LoraSettings {
            freq_hz: radio.freq_khz.saturating_mul(1000),
            bw_hz: radio.bw_hz,
            sf: radio.sf,
            cr: radio.cr_denom,
            repeater: settings.repeater,
        }),
        meshcore: settings.meshcore,
    };
    let (config_changed, changed) = SETTINGS.lock(|cell| {
        let mut held = cell.borrow_mut();
        let config_changed = held.as_ref().is_none_or(|old| old.config != next.config);
        let changed = held.as_ref() != Some(&next);
        *held = Some(next);
        (config_changed, changed)
    });
    if config_changed {
        CONFIG_CHANGED.signal(());
    }
    if changed {
        RECORD_CHANGED.signal(());
    }
}

/// The internet bridge's link came up or went down.
#[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
pub fn set_bridge_up(up: bool) {
    if BRIDGE_UP.swap(up, Ordering::Relaxed) != up {
        RECORD_CHANGED.signal(());
    }
}

/// `text` cut to one DNS label, on a character boundary.
fn label(text: &str) -> heapless::String<LABEL_MAX> {
    let mut out = heapless::String::new();
    for c in text.chars() {
        if out.push(c).is_err() {
            break;
        }
    }
    out
}

fn config() -> Option<LanBearerConfig> {
    SETTINGS.lock(|cell| cell.borrow().as_ref().map(|settings| settings.config))
}

// ─── The bearer ─────────────────────────────────────────────────────────────

/// Socket storage and scratch, outside the task's future: in PSRAM where
/// the board has it, an internal static otherwise.
pub struct Buffers {
    rx_meta: [PacketMetadata; 4],
    rx: [u8; 4 * MAX_FRAME],
    tx_meta: [PacketMetadata; 2],
    tx: [u8; 2 * MAX_FRAME],
    /// One octet over the limit, so an oversized datagram arrives as
    /// one and is counted as malformed.
    datagram: [u8; MAX_FRAME + 1],
    mdns_rx_meta: [PacketMetadata; 2],
    mdns_rx: [u8; MDNS_QUERY],
    /// One reply at a time: the next waits for this one to go out.
    mdns_tx_meta: [PacketMetadata; 1],
    mdns_tx: [u8; MDNS_REPLY],
    reply: [u8; MDNS_REPLY],
}

impl Buffers {
    pub const fn new() -> Self {
        Self {
            rx_meta: [PacketMetadata::EMPTY; 4],
            rx: [0; 4 * MAX_FRAME],
            tx_meta: [PacketMetadata::EMPTY; 2],
            tx: [0; 2 * MAX_FRAME],
            datagram: [0; MAX_FRAME + 1],
            mdns_rx_meta: [PacketMetadata::EMPTY; 2],
            mdns_rx: [0; MDNS_QUERY],
            mdns_tx_meta: [PacketMetadata::EMPTY; 1],
            mdns_tx: [0; MDNS_REPLY],
            reply: [0; MDNS_REPLY],
        }
    }
}

#[cfg(feature = "psram")]
fn storage() -> &'static mut Buffers {
    super::external::lan_buffers()
}
#[cfg(not(feature = "psram"))]
fn storage() -> &'static mut Buffers {
    use static_cell::ConstStaticCell;
    static BUFFERS: ConstStaticCell<Buffers> = ConstStaticCell::new(Buffers::new());
    BUFFERS.take()
}

fn now_ms() -> u64 {
    Instant::now().as_millis()
}

/// The station's IPv4 address, while it has a link and one.
fn address(network: &Network) -> Option<Ipv4Address> {
    network.as_ref().map(|config| config.address.address())
}

/// Return once the station has an address.
async fn network_up(network: &mut NetworkReceiver) {
    network.get_and(|now| now.is_some()).await;
}

/// Return once `address` is no longer the station's, with the link, the
/// lease, or a lease renewed onto a different address.
async fn network_down(network: &mut NetworkReceiver, address: Ipv4Address) {
    network
        .get_and(|now| self::address(now) != Some(address))
        .await;
}

/// Publish `state` if it differs from what was last published.
async fn report(published: &mut Option<State>, state: State) {
    if *published != Some(state) {
        *published = Some(state);
        super::debug_log(format_args!("lan: {:?}", state));
        super::wifi::publish(PublishEvent::LanBearerState(state)).await;
    }
}

/// Stop the port carrying anything either way.
fn stop() {
    PORT.configure(false, 0, now_ms());
}

/// Run the bearer for the life of the device. Spawned with the device
/// node, which it reaches through [`PORT`].
pub async fn run(stack: Stack<'static>) -> ! {
    let buffers = storage();
    let mut network = super::ip::network();
    let mut published = None;
    // The port starts off, and every pass that switches it on ends by
    // switching it off, so the idle states below need not.
    loop {
        // Changes from here on are seen: the configuration is read after.
        CONFIG_CHANGED.reset();
        let Some(config) = config().filter(|config| config.enabled) else {
            report(&mut published, State::Disabled).await;
            CONFIG_CHANGED.wait().await;
            continue;
        };
        let group = Ipv4Address::from(config.group().address);
        let Some(address) = network.try_get().and_then(|now| address(&now)) else {
            report(&mut published, State::NoNetwork).await;
            select(CONFIG_CHANGED.wait(), network_up(&mut network)).await;
            continue;
        };

        // Leaving first makes every join a fresh membership report.
        let _ = stack.leave_multicast_group(group);
        let _ = stack.leave_multicast_group(MDNS_GROUP);
        let mut socket = UdpSocket::new(
            stack,
            &mut buffers.rx_meta,
            &mut buffers.rx,
            &mut buffers.tx_meta,
            &mut buffers.tx,
        );
        // Where the group reaches is the network's routing decision. A
        // unicast address in its place is a peer, and nothing is joined.
        socket.set_hop_limit(Some(umsh_lan_bearer::MULTICAST_TTL as u8));
        let multicast = config.group().is_multicast();
        if (multicast && stack.join_multicast_group(group).is_err())
            || socket.bind(config.group().port).is_err()
        {
            super::debug_log(format_args!("lan: could not join {}", group));
            drop(socket);
            let _ = stack.leave_multicast_group(group);
            report(&mut published, State::NoNetwork).await;
            select(CONFIG_CHANGED.wait(), network_down(&mut network, address)).await;
            continue;
        }
        // The record is a courtesy to browsers; the bearer runs without it.
        let mut mdns = UdpSocket::new(
            stack,
            &mut buffers.mdns_rx_meta,
            &mut buffers.mdns_rx,
            &mut buffers.mdns_tx_meta,
            &mut buffers.mdns_tx,
        );
        mdns.set_hop_limit(Some(MDNS_HOP_LIMIT));
        let mdns_ready =
            stack.join_multicast_group(MDNS_GROUP).is_ok() && mdns.bind(MDNS_PORT).is_ok();

        PORT.configure(true, config.ingress_limit(), now_ms());
        report(&mut published, State::Active).await;
        let own = IpEndpoint::new(IpAddress::Ipv4(address), config.group().port);
        let destination = IpEndpoint::new(IpAddress::Ipv4(group), config.group().port);
        select4(
            CONFIG_CHANGED.wait(),
            network_down(&mut network, address),
            join(
                receive(
                    &socket,
                    own,
                    (!multicast).then_some(destination),
                    &mut buffers.datagram,
                ),
                export(&socket, destination),
            ),
            advertise(&mut mdns, mdns_ready, address, &mut buffers.reply),
        )
        .await;

        stop();
        drop(socket);
        drop(mdns);
        let _ = stack.leave_multicast_group(group);
        let _ = stack.leave_multicast_group(MDNS_GROUP);
    }
}

/// Offer every datagram from the group to the node; on a point-to-point
/// link, only those from `peer`.
async fn receive(
    socket: &UdpSocket<'_>,
    own: IpEndpoint,
    peer: Option<IpEndpoint>,
    datagram: &mut [u8; MAX_FRAME + 1],
) {
    loop {
        match socket.recv_from(datagram).await {
            // An access point repeats a station's multicast to every
            // station, the sender included.
            Ok((_, meta)) if meta.endpoint == own => {}
            Ok((_, meta)) if peer.is_some_and(|peer| meta.endpoint != peer) => {}
            Ok((len, _)) => {
                PORT.offer(&datagram[..len], now_ms());
            }
            // Larger than the buffer, which is larger than any frame.
            Err(RecvError::Truncated) => {
                PORT.offer(datagram, now_ms());
            }
        }
    }
}

/// Send the group every frame the radio transmits.
async fn export(socket: &UdpSocket<'_>, destination: IpEndpoint) {
    loop {
        let frame = PORT.outgoing().await;
        // A send that fails is lost the way a collided transmission is.
        if let Err(error) = socket.send_to(&frame, destination).await {
            super::debug_log(format_args!("lan: send failed: {:?}", error));
        }
    }
}

// ─── DNS-SD ─────────────────────────────────────────────────────────────────

/// What this radio advertises, at one moment.
#[derive(Clone, PartialEq)]
struct Record {
    instance: heapless::String<LABEL_MAX>,
    hostname: heapless::String<LABEL_MAX>,
    address: Ipv4Address,
    port: u16,
    advertisement: Advertisement,
}

impl Record {
    /// The record as things stand, or `None` with no node key to name.
    fn current(address: Ipv4Address) -> Option<Self> {
        let settings = SETTINGS.lock(|cell| cell.borrow().clone())?;
        Some(Self {
            instance: settings.name,
            hostname: label(&super::wifi::hostname()?),
            address,
            port: settings.config.group().port,
            advertisement: Advertisement {
                group: settings.config.group().address,
                node_key: settings.node_key?,
                lora: settings.lora,
                meshcore: settings.meshcore,
                internet_bridge: BRIDGE_UP.load(Ordering::Relaxed),
            },
        })
    }

    /// Answer `request` into `out` with records that live `ttl_s`
    /// seconds; zero is a goodbye. `None` when there is nothing to send.
    fn answer(&self, request: MdnsRequest<'_>, ttl_s: u32, out: &mut [u8]) -> Option<usize> {
        // The longest value is the 44-digit key.
        let mut values = heapless::Vec::<(&'static str, heapless::String<48>), 10>::new();
        self.advertisement.for_each_property(|key, value| {
            let mut owned = heapless::String::new();
            let _ = owned.push_str(value);
            let _ = values.push((key, owned));
        });
        let txt: heapless::Vec<(&str, &str), 10> = values
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let (service, protocol) = umsh_lan_bearer::SERVICE_TYPE
            .split_once('.')
            .expect("a service type is two labels");
        let host = Host {
            hostname: &self.hostname,
            ipv4: Ipv4Addr::from(self.address.octets()),
            ipv6: Ipv6Addr::UNSPECIFIED,
            ttl: Ttl::from_secs(ttl_s),
        };
        let service = Service {
            name: &self.instance,
            priority: 0,
            weight: 0,
            service,
            protocol,
            port: self.port,
            service_subtypes: &[],
            txt_kvs: &txt,
        };
        let mut handler = HostAnswersMdnsHandler::new(ServiceAnswers::new(&host, &service));
        match handler.handle(request, out) {
            Ok(MdnsResponse::Reply { data, .. }) => Some(data.len()),
            Ok(MdnsResponse::None) => None,
            Err(error) => {
                super::debug_log(format_args!("lan: mDNS: {:?}", error));
                None
            }
        }
    }

    /// Send the whole record to the mDNS group, unsolicited.
    async fn announce(&self, socket: &UdpSocket<'_>, ttl_s: u32, reply: &mut [u8]) {
        if let Some(len) = self.answer(MdnsRequest::None, ttl_s, reply) {
            let _ = socket
                .send_to(&reply[..len], IpEndpoint::new(MDNS_GROUP.into(), MDNS_PORT))
                .await;
        }
    }

    /// Announce, then answer queries, until cancelled.
    async fn serve(&self, socket: &mut UdpSocket<'_>, reply: &mut [u8; MDNS_REPLY]) {
        // RFC 6762 §8.3: at least two announcements, a second apart.
        let mut announcements = 2;
        let mut next = Instant::now();
        loop {
            if announcements > 0 && Instant::now() >= next {
                self.announce(socket, MDNS_TTL_S, reply).await;
                announcements -= 1;
                next += Duration::from_secs(1);
            }
            let deadline = async {
                if announcements > 0 {
                    Timer::at(next).await
                } else {
                    core::future::pending().await
                }
            };
            let query = socket.recv_from_with(|query, meta| {
                // A query from a port other than 5353 is a one-shot
                // legacy query, answered to the asker alone.
                let legacy = meta.endpoint.port != MDNS_PORT;
                let request = MdnsRequest::Request {
                    legacy,
                    multicast: true,
                    data: query,
                };
                let destination = if legacy {
                    meta.endpoint
                } else {
                    IpEndpoint::new(MDNS_GROUP.into(), MDNS_PORT)
                };
                self.answer(request, MDNS_TTL_S, reply)
                    .map(|len| (len, destination))
            });
            if let Either::Second(Some((len, destination))) = select(deadline, query).await {
                let _ = socket.send_to(&reply[..len], destination).await;
            }
        }
    }
}

/// Keep the record announced and answered while the bearer runs.
async fn advertise(
    socket: &mut UdpSocket<'_>,
    ready: bool,
    address: Ipv4Address,
    reply: &mut [u8; MDNS_REPLY],
) {
    if !ready {
        super::debug_log(format_args!("lan: mDNS unavailable"));
        return core::future::pending().await;
    }
    let mut previous: Option<Record> = None;
    loop {
        RECORD_CHANGED.reset();
        let Some(record) = Record::current(address) else {
            RECORD_CHANGED.wait().await;
            continue;
        };
        // A record under another name replaces nothing: the old one is
        // withdrawn, or browsers list both until it expires.
        if let Some(old) = previous
            .as_ref()
            .filter(|old| old.instance != record.instance || old.hostname != record.hostname)
        {
            old.announce(socket, 0, reply).await;
        }
        previous = Some(record.clone());
        select(RECORD_CHANGED.wait(), record.serve(socket, reply)).await;
    }
}
