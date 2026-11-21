//! The air around the staged mesh, below an ordinary radio driver.
//!
//! The staged radio is a soft device, the companion's own ULCP session,
//! that the phone reaches through a [`MobileRadioDriver`] like any radio.
//! What it transmits reaches the staged peers, real mesh sessions under
//! the scenario's fixed keys, and what they transmit reaches it. A message
//! sent in staging is encrypted, framed, transmitted, decrypted, and
//! acknowledged by the code that does it over RF. Only the medium is
//! fabricated: frames move through memory, and airtime is free.
//!
//! The topology is a star: everything the radio transmits reaches every
//! peer, and everything a peer transmits reaches only the radio. Peers
//! never hear each other, which keeps a mesh of chat nodes that do not
//! forward from needing a channel-access model.
//!
//! Each peer keeps its chat in an in-memory store of its own, as the app
//! keeps the phone's: that is where it answers a request to send something
//! again from, and where it finds what the phone last said.
//!
//! The radio and the peers run on one thread of the air's own for as long
//! as the air lives.

use std::fmt;
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use umsh_core::{Fcf, FloodHops, PublicKey};
use umsh_node::location::NodeLocation;
use umsh_ulcp::battery::{BatteryChargeState, BatteryStatus};
use umsh_ulcp::gnss::{FixKind, GnssSnapshot};
use umsh_ulcp::{hdlc, profiles};
use umsh_ulcp_device::{Effect, TxOutcome};
use umsh_ulcp_simdev::driven::{self, HOST_EVENT_DEPTH, Heard, HostEvent, Medium, WireSink};
use umsh_ulcp_simdev::soft::{DeviceSession, SoftDevice, SoftPlatform};
use umsh_ulcp_simdev::{
    BatteryFields, DutyLedger, GnssConfig, RadioRxInfo, RadioSettings, SessionConfig, TimeConfig,
};

use super::{CHANNEL_NAME, NODES, Node, PRIVATE_CHANNEL_KEY, Role};
use crate::mobile_chat::MobileChatRegardingRef;
use crate::mobile_mesh::{
    MobileChannelRegistrationRecord, MobileChatSendRequest, MobileMeshRxRecord,
    MobileMeshWakeListener, MobilePeerRegistrationRecord,
};
use crate::radio_driver::{
    MobileRadioDriver, MobileRadioTransportPhase, MobileRadioTransportStateRecord, RadioLink,
};
use crate::{
    MobileAppStore, MobileChatDirection, MobileCounterStore, MobileIdentity, MobileMeetExchange,
    MobileMeetStateRecord, MobileMeshSession, channel_conversation_address, public_identity_record,
};

/// What the staged radio reports itself as.
const DEV_VERSION: &str = concat!("umsh-mobile-staging/", env!("CARGO_PKG_VERSION"));

/// What the staged radio is called until the phone renames it.
const RADIO_NAME: &str = "T-Echo";

/// The staged radio's identity secret: fixed, so its key reads the same
/// every run.
const RADIO_SECRET: [u8; 32] = [0x88; 32];

/// Where the staged radio's receiver says it is, in units of 1e-7 degrees:
/// the middle of the staged mesh.
const RADIO_LATITUDE_E7: i32 = 388_985_000;
const RADIO_LONGITUDE_E7: i32 = -1_201_020_000;

/// The identity each staged peer's store keeps its chat under.
const PEER_OWNER: &str = "staged-peer";

/// The model the speaking peer opens Add Peer as: a T-LoRa Pager.
const MEET_MODEL: u16 = 9;

/// How long a control waits for the speaking peer to transmit what it was
/// told to say.
const FLUSH_WAIT: Duration = Duration::from_secs(5);

/// How the radio hears a repeater's echo of its own flood.
const ECHO_RSSI_DBM: i16 = -96;
const ECHO_SNR_CB: i16 = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileStagingAirError {
    /// The air's state directory could not be created.
    StateUnavailable,
    /// The air's worker could not be started.
    WorkerUnavailable,
    /// The air has stopped.
    Stopped,
    /// No staged peer could be stood up.
    PeerUnavailable,
    /// The phone has not tethered the staged radio, so no peer knows it.
    NoPhone,
    /// The phone has said nothing to the speaking peer to answer.
    NothingToAnswer,
    /// The speaking peer's session refused.
    Refused,
    /// The speaking peer took what it was told to say and did not transmit
    /// it in time.
    NotTransmitted,
}

impl fmt::Display for MobileStagingAirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StateUnavailable => "the staging air's state directory is unavailable",
            Self::WorkerUnavailable => "the staging air's worker could not start",
            Self::Stopped => "the staging air has stopped",
            Self::PeerUnavailable => "no staged peer is standing",
            Self::NoPhone => "the phone has not tethered the staged radio",
            Self::NothingToAnswer => "the phone has said nothing to the staged peer",
            Self::Refused => "the staged peer's session refused",
            Self::NotTransmitted => "the staged peer did not transmit in time",
        })
    }
}

impl std::error::Error for MobileStagingAirError {}

/// The staged mesh: a radio for the phone, and the peers around it.
///
/// The staging controls are its methods, and each acts through the first
/// staged peer, the one that speaks. Dropping the air, or calling
/// [`Self::stop`], ends the radio and the peers.
#[derive(uniffi::Object)]
pub struct MobileStagingAir {
    radio: Arc<MobileRadioDriver>,
    link: Arc<AirLink>,
    controls: mpsc::UnboundedSender<Control>,
    failing: Arc<AtomicBool>,
    /// Dropped to stop the air.
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

impl Drop for MobileStagingAir {
    fn drop(&mut self) {
        self.stop();
    }
}

#[uniffi::export]
impl MobileStagingAir {
    /// Start the staged mesh, keeping each peer's frame counters under
    /// `state_dir`. The radio waits detached until [`Self::connect`].
    #[uniffi::constructor]
    pub fn start(state_dir: String) -> Result<Arc<Self>, MobileStagingAirError> {
        let dir = PathBuf::from(state_dir);
        std::fs::create_dir_all(&dir).map_err(|_| MobileStagingAirError::StateUnavailable)?;

        let (events, host_events) = mpsc::channel(HOST_EVENT_DEPTH);
        let link = Arc::new(AirLink {
            events,
            driver: OnceLock::new(),
            stopped: AtomicBool::new(false),
        });
        let radio = MobileRadioDriver::new(link.clone())
            .map_err(|_| MobileStagingAirError::WorkerUnavailable)?;
        let _ = link.driver.set(Arc::downgrade(&radio));

        let (controls, control_queue) = mpsc::unbounded_channel();
        let failing = Arc::new(AtomicBool::new(false));
        let medium_failing = failing.clone();
        let stop = driven::spawn("umsh-staging-air", move || {
            let (air_events, air_queue) = mpsc::unbounded_channel();
            let (heard, heard_queue) = mpsc::unbounded_channel();
            let medium = AirMedium {
                air: air_events,
                heard: heard_queue,
                failing: medium_failing,
                host_key: None,
            };
            let device = SoftDevice::new(radio_config(), StagedRadio::default());
            Ok::<_, std::convert::Infallible>(async move {
                let radio = driven::run(device, medium, host_events, |_| {});
                let air = Air::new(dir, heard).run(air_queue, control_queue);
                tokio::select! {
                    () = radio => {}
                    () = air => {}
                }
            })
        })
        .map_err(|_| MobileStagingAirError::WorkerUnavailable)?;
        Ok(Arc::new(Self {
            radio,
            link,
            controls,
            failing,
            stop: Mutex::new(Some(stop)),
        }))
    }

    /// The staged radio's driver, for the app to use as its radio.
    pub fn radio(&self) -> Arc<MobileRadioDriver> {
        self.radio.clone()
    }

    /// Bring the staged radio's link up, as a transport connecting to it.
    pub fn connect(&self) {
        self.link.connect();
    }

    /// Take the staged radio's link down. The radio carries on detached.
    pub fn disconnect(&self) {
        self.link.disconnect();
    }

    /// While `failing`, every transmission the staged radio makes fails.
    pub fn set_transmissions_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::Relaxed);
    }

    /// The speaking peer says `body` to the phone, or with `on_channel` to
    /// the staged named channel. Returns once it has transmitted.
    pub async fn peer_says(
        &self,
        body: String,
        on_channel: bool,
    ) -> Result<(), MobileStagingAirError> {
        self.control(Order::Say { body, on_channel }).await
    }

    /// The speaking peer says three things on the staged named channel, the
    /// second of which the phone never hears. The third opens a gap for
    /// it, which a resend request from the phone fills; the first lets the
    /// phone know where the peer's messages stand.
    pub async fn peer_says_losing_one(
        &self,
        first: String,
        lost: String,
        last: String,
    ) -> Result<(), MobileStagingAirError> {
        self.control(Order::SayLosingOne {
            bodies: [first, lost, last],
        })
        .await
    }

    /// The speaking peer reacts to the last thing the phone said to it.
    pub async fn peer_reacts(&self, body: String) -> Result<(), MobileStagingAirError> {
        self.control(Order::React { body }).await
    }

    /// The speaking peer replies to the last thing the phone said to it.
    pub async fn peer_replies(&self, body: String) -> Result<(), MobileStagingAirError> {
        self.control(Order::Reply { body }).await
    }

    /// The speaking peer opens Add Peer as a T-LoRa Pager would, so it
    /// shows on the phone's Nearby. `asking`, it asks the phone to exchange
    /// once it lists it. It agrees when asked, presses Same a moment after
    /// the code shows, and closes Add Peer once the attempt is over.
    pub async fn peer_opens_add_peer(&self, asking: bool) -> Result<(), MobileStagingAirError> {
        self.control(Order::OpenAddPeer { asking }).await
    }

    /// Stand the peers up afresh, with no frame counters: for a phone whose
    /// identity is starting over.
    pub async fn reset(&self) -> Result<(), MobileStagingAirError> {
        self.control(Order::Reset).await
    }

    /// Stop the air. The radio's link goes down, and the radio and the
    /// peers end. It cannot be started again; make another.
    pub fn stop(&self) {
        let stop = self
            .stop
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if stop.is_some() {
            self.link.stopped.store(true, Ordering::Relaxed);
            self.link.disconnect();
        }
    }
}

impl MobileStagingAir {
    async fn control(&self, order: Order) -> Result<(), MobileStagingAirError> {
        let (reply, answer) = oneshot::channel();
        self.controls
            .send(Control { order, reply })
            .map_err(|_| MobileStagingAirError::Stopped)?;
        answer.await.map_err(|_| MobileStagingAirError::Stopped)?
    }
}

// --- The staged radio ---

/// What stands where the staged radio's hardware and storage would: RAM,
/// a fixed identity, the system clock, and canned peripherals.
struct StagedRadio {
    snapshot: Option<Vec<u8>>,
    identity: Option<[u8; 32]>,
}

impl Default for StagedRadio {
    fn default() -> Self {
        Self {
            snapshot: None,
            identity: Some(RADIO_SECRET),
        }
    }
}

impl StagedRadio {
    /// A fix in the middle of the staged mesh, while the receiver is on.
    fn gnss(session: &DeviceSession) -> GnssSnapshot {
        let mut snapshot = GnssSnapshot::SEARCHING;
        if !session.gnss_enabled() {
            return snapshot;
        }
        snapshot.fix = FixKind::ThreeD;
        snapshot.altitude_m = Some(2_164);
        snapshot.accuracy_dm = Some(48);
        snapshot.sats_used = 11;
        snapshot.sats_in_view = Some(17);
        // At the cell size the scenario's nodes disclose.
        snapshot.set_location(
            NodeLocation::from_e7(
                RADIO_LATITUDE_E7,
                RADIO_LONGITUDE_E7,
                super::LOCATION_PRECISION,
            )
            .as_bytes(),
        );
        snapshot
    }
}

impl SoftPlatform for StagedRadio {
    fn load_snapshot(&mut self) -> Option<Vec<u8>> {
        self.snapshot.clone()
    }

    fn store_snapshot(&mut self, snapshot: Option<&[u8]>) -> Result<(), ()> {
        self.snapshot = snapshot.map(<[u8]>::to_vec);
        Ok(())
    }

    fn load_identity(&mut self) -> Option<[u8; 32]> {
        self.identity
    }

    fn store_identity(&mut self, secret: Option<&[u8; 32]>) -> Result<(), ()> {
        self.identity = secret.copied();
        Ok(())
    }

    fn generate_secret(&mut self) -> [u8; 32] {
        rand::random()
    }

    fn generates_identity_at_boot(&self) -> bool {
        true
    }

    fn wall_clock(&mut self) -> Option<u32> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        u32::try_from(seconds).ok()
    }

    fn peripheral(
        &mut self,
        effect: Effect,
        session: &mut DeviceSession,
        mut emit: &mut dyn FnMut(&[u8]),
    ) {
        match effect {
            Effect::SampleRssi { tid } => session.respond_rssi(tid, Ok(-77), &mut emit),
            Effect::SampleBattery { tid } => session.respond_battery(
                tid,
                Ok(BatteryStatus {
                    voltage_mv: Some(3_780),
                    level_percent: Some(76),
                    charge_state: Some(BatteryChargeState::Discharging),
                }),
                &mut emit,
            ),
            Effect::SampleGnss { tid, key } => {
                let fix = Self::gnss(session);
                session.respond_gnss(tid, key, Ok(fix), &mut emit);
            }
            // The configuration offers nothing else a platform serves.
            _ => {}
        }
    }
}

/// A tracker's capability surface: a battery, a clock, and a receiver
/// that runs unless switched off.
fn radio_config() -> SessionConfig {
    SessionConfig {
        dev_version: DEV_VERSION,
        dev_model: None,
        default_device_name: RADIO_NAME,
        mtu: 255,
        tx_preamble_symbols: 32,
        sync_word: profiles::DEFAULT.sync_word,
        min_tx_power_dbm: -9,
        max_tx_power_dbm: 22,
        freq_khz_min: 150_000,
        freq_khz_max: 960_000,
        defaults: RadioSettings {
            enabled: false,
            freq_khz: profiles::DEFAULT.freq_khz,
            bw_hz: profiles::DEFAULT.bw_hz,
            sf: profiles::DEFAULT.sf,
            cr_denom: profiles::DEFAULT.cr_denom,
            tx_power_dbm: profiles::DEFAULT_TX_POWER_DBM,
        },
        default_duty_limit: 0xFFFF,
        // One ledger per air, for as long as the process runs.
        duty: Box::leak(Box::new(DutyLedger::new())),
        battery_diagnostics: Default::default(),
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: true,
        }),
        alert: None,
        time: Some(TimeConfig),
        gnss: Some(GnssConfig::ALWAYS_ON),
        display_motion_wake: false,
        display: None,
        keyboard: false,
        sound: false,
        host_custody: false,
        illuminance: false,
        temperatures: false,
        ble: false,
        ble_pairing: false,
        ble_pin: false,
        // The device is a task of the air's; there is nothing for
        // `CMD_REBOOT` to restart.
        reboot: false,
        dev_identity: true,
        messaging: false,
        stats: None,
        mac_node: false,
        meshcore_forwarder: false,
        lan_bearer: umsh_ulcp_device::LanBearerRole::None,
        wifi: None,
        ip: None,
        bridge_client: false,
        i2c_buses: &[],
        i2c_devices: &[],
    }
}

// --- The link between the driver and the staged radio ---

/// The staged radio's link: whole frames from the driver, HDLC-Lite to
/// the device, and back.
struct AirLink {
    events: mpsc::Sender<HostEvent>,
    driver: OnceLock<Weak<MobileRadioDriver>>,
    /// The air has stopped, and there is no device to connect to.
    stopped: AtomicBool,
}

impl AirLink {
    fn driver(&self) -> Option<Arc<MobileRadioDriver>> {
        self.driver.get().and_then(Weak::upgrade)
    }

    /// Hand the device a host event without waiting: these are called on
    /// the driver's thread and the platform's. An event dropped because the
    /// device fell [`HOST_EVENT_DEPTH`] behind costs what it carried; the
    /// driver's own retries cover lost bytes.
    fn post(&self, event: HostEvent) {
        if let Err(mpsc::error::TrySendError::Full(event)) = self.events.try_send(event) {
            log::warn!(event = event.kind(); "the staged radio fell behind and dropped a host event");
        }
    }

    fn connect(&self) {
        let Some(driver) = self.driver() else {
            return;
        };
        if self.stopped.load(Ordering::Relaxed) || self.events.is_closed() {
            driver.transport_changed(transport(MobileRadioTransportPhase::Idle));
            return;
        }
        driver.transport_changed(transport(MobileRadioTransportPhase::Connecting));
        self.post(HostEvent::Attach(sink(Arc::downgrade(&driver))));
        driver.link_ready(true);
    }

    fn disconnect(&self) {
        self.post(HostEvent::Detach);
        if let Some(driver) = self.driver() {
            driver.transport_changed(transport(MobileRadioTransportPhase::Idle));
        }
    }
}

fn transport(phase: MobileRadioTransportPhase) -> MobileRadioTransportStateRecord {
    MobileRadioTransportStateRecord {
        phase,
        name: Some(RADIO_NAME.to_owned()),
        link_id: Some("staging".to_owned()),
        problem: None,
    }
}

/// Where one attach's replies go: decoded, and handed to the driver.
fn sink(driver: Weak<MobileRadioDriver>) -> WireSink {
    // The largest frame and its two-octet FCS.
    let mut decoder = Box::new(hdlc::Decoder::<{ umsh_ulcp::gatt::MAX_FRAME + 2 }>::new());
    Box::new(move |wire| {
        let Some(driver) = driver.upgrade() else {
            return;
        };
        for byte in wire {
            match decoder.push(byte) {
                Some(Ok(frame)) => driver.link_received(frame.to_vec()),
                // A bad frame costs that frame; the decoder resynchronizes
                // on the next flag.
                Some(Err(error)) => {
                    log::warn!(error:? = error; "the staged radio sent a frame the link could not decode");
                }
                None => {}
            }
        }
    })
}

impl RadioLink for AirLink {
    fn send(&self, frame: Vec<u8>, _raw_transaction_id: Option<u8>) {
        let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
        if let Ok(length) = hdlc::encode_frame(&frame, &mut wire) {
            wire.truncate(length);
            self.post(HostEvent::Bytes(wire));
        }
    }

    /// Frames cross whole, and each attach brings a fresh decoder, so
    /// nothing is ever partly framed.
    fn reset_framing(&self) {}

    fn invalidate(&self, retry: bool) {
        match retry {
            true => self.connect(),
            false => self.disconnect(),
        }
    }

    fn did_attach(&self) {}

    fn did_report_name(&self, _name: String) {}

    fn abandon_binding(&self) {}

    fn did_enter_dfu(&self) {}
}

// --- The medium ---

/// What the staged radio's medium tells the air.
enum AirEvent {
    /// The radio's host key changed: the phone that tethers it.
    Host(Option<[u8; 32]>),
    /// The radio transmitted a frame.
    Transmitted(Vec<u8>),
}

/// The staged radio's side of the air.
struct AirMedium {
    air: mpsc::UnboundedSender<AirEvent>,
    heard: mpsc::UnboundedReceiver<Heard>,
    failing: Arc<AtomicBool>,
    host_key: Option<[u8; 32]>,
}

impl Medium for AirMedium {
    fn follow<P: SoftPlatform>(&mut self, device: &mut SoftDevice<P>) {
        let host_key = device.session().host_key().copied();
        if host_key != self.host_key {
            self.host_key = host_key;
            let _ = self.air.send(AirEvent::Host(host_key));
        }
    }

    async fn transmit(&mut self, frame: &[u8]) -> TxOutcome {
        if self.failing.load(Ordering::Relaxed) {
            return TxOutcome::Failed;
        }
        let _ = self.air.send(AirEvent::Transmitted(frame.to_vec()));
        TxOutcome::Sent
    }

    async fn hear(&mut self) -> Option<Heard> {
        match self.heard.recv().await {
            Some(heard) => Some(heard),
            // The air has ended; the radio hears nothing more.
            None => std::future::pending().await,
        }
    }
}

// --- The peers ---

struct Peer {
    name: &'static str,
    session: Arc<MobileMeshSession>,
    store: Arc<MobileAppStore>,
    /// How the radio hears this peer, and how this peer hears the radio.
    /// Fixed per peer, so a staged conversation reads the same every run.
    rssi_dbm: i16,
    snr_cb: i16,
    lqi: u8,
}

/// Tells the air that a peer's session has an update.
struct PeerWake {
    index: usize,
    wakes: mpsc::UnboundedSender<usize>,
}

impl MobileMeshWakeListener for PeerWake {
    fn on_update_pending(&self) {
        let _ = self.wakes.send(self.index);
    }
}

struct Control {
    order: Order,
    reply: oneshot::Sender<Result<(), MobileStagingAirError>>,
}

enum Order {
    Say { body: String, on_channel: bool },
    SayLosingOne { bodies: [String; 3] },
    React { body: String },
    Reply { body: String },
    OpenAddPeer { asking: bool },
    Reset,
}

/// The peers, and what the air knows of the phone.
struct Air {
    /// Where the peers keep their frame counters: a numbered generation
    /// directory, then one per peer.
    dir: PathBuf,
    /// The generation the standing peers keep their counters in.
    generation: u32,
    peers: Vec<Peer>,
    /// The phone's address, once it tethers the radio.
    phone: Option<String>,
    /// To the radio's receiver.
    heard: mpsc::UnboundedSender<Heard>,
    wakes: mpsc::UnboundedSender<usize>,
    wake_queue: mpsc::UnboundedReceiver<usize>,
    /// The speaking peer asks the first device Add Peer lists.
    asks_when_listed: bool,
    /// The speaking peer has pressed Same on the code now showing.
    pressed_same: bool,
    /// The speaking peer's next transmissions never reach the radio.
    losing: bool,
}

impl Air {
    fn new(dir: PathBuf, heard: mpsc::UnboundedSender<Heard>) -> Self {
        let (wakes, wake_queue) = mpsc::unbounded_channel();
        let generation = generations(&dir).max().unwrap_or(0);
        Self {
            dir,
            generation,
            peers: Vec::new(),
            phone: None,
            heard,
            wakes,
            wake_queue,
            asks_when_listed: false,
            pressed_same: false,
            losing: false,
        }
    }

    async fn run(
        mut self,
        mut air: mpsc::UnboundedReceiver<AirEvent>,
        mut controls: mpsc::UnboundedReceiver<Control>,
    ) {
        self.retire_generations();
        self.stand_up().await;
        loop {
            tokio::select! {
                event = air.recv() => match event {
                    Some(event) => self.on_air(event).await,
                    None => break,
                },
                Some(index) = self.wake_queue.recv() => {
                    self.pump(index);
                }
                control = controls.recv() => match control {
                    Some(Control { order, reply }) => {
                        let _ = reply.send(self.obey(order).await);
                    }
                    None => break,
                },
            }
        }
    }

    /// Stand up a session for every staged node that carries chat. The
    /// repeaters stay out: a phone-role session does not forward.
    async fn stand_up(&mut self) {
        for node in NODES
            .iter()
            .filter(|node| !matches!(node.role, Role::Repeater))
        {
            match self.stand_up_peer(node).await {
                Ok(peer) => self.peers.push(peer),
                // A peer that cannot stand up is a node the staged mesh
                // never hears from; everything else keeps working.
                Err(error) => log::warn!("staged peer {} did not stand up: {error}", node.name),
            }
        }
    }

    async fn stand_up_peer(&self, node: &'static Node) -> Result<Peer, Box<dyn std::error::Error>> {
        let index = self.peers.len();
        let identity = MobileIdentity::unlock(vec![node.seed; 32])?;
        let counters = MobileCounterStore::new(self.counter_dir(node).display().to_string())?;
        let session = MobileMeshSession::start(identity.clone(), counters).await?;
        let store = MobileAppStore::open(":memory:".to_owned())?;
        store.upsert_identity(
            PEER_OWNER.to_owned(),
            identity.public_identity().canonical_address,
            0,
        )?;
        session
            .clone()
            .attach_chat_store(store.clone(), PEER_OWNER.to_owned(), None)?;
        session.set_chat_display_name(node.name.to_owned()).await?;
        session
            .register_channels(
                channel_keys()
                    .into_iter()
                    .map(|key| MobileChannelRegistrationRecord {
                        key,
                        max_flood_hops: None,
                    })
                    .collect(),
            )
            .await?;
        if let Some(phone) = &self.phone {
            session.register_peers(vec![phone_record(phone)]).await?;
        }
        session.set_wake_listener(Arc::new(PeerWake {
            index,
            wakes: self.wakes.clone(),
        }));
        let step = i16::try_from(index).unwrap_or(i16::MAX);
        Ok(Peer {
            name: node.name,
            session,
            store,
            rssi_dbm: (-52i16).saturating_sub(step.saturating_mul(6)),
            snr_cb: 74i16.saturating_sub(step.saturating_mul(9)),
            lqi: 214u8.saturating_sub(u8::try_from(index).unwrap_or(u8::MAX).saturating_mul(13)),
        })
    }

    /// Frame counters must survive relaunches for replay protection to
    /// hold between a peer and the phone, so each peer keeps its own.
    fn counter_dir(&self, node: &Node) -> PathBuf {
        self.dir
            .join(self.generation.to_string())
            .join(format!("{:02x}", node.seed))
    }

    /// Remove every counter generation but the current one. A session shut
    /// down only lately may still write to its own afterward; the next
    /// retirement removes what it wrote.
    fn retire_generations(&self) {
        let retired: Vec<u32> = generations(&self.dir)
            .filter(|&old| old != self.generation)
            .collect();
        for generation in retired {
            let _ = std::fs::remove_dir_all(self.dir.join(generation.to_string()));
        }
    }

    async fn on_air(&mut self, event: AirEvent) {
        match event {
            AirEvent::Host(Some(key)) => {
                let phone = public_identity_record(&PublicKey(key)).canonical_address;
                if self.phone.as_ref() == Some(&phone) {
                    return;
                }
                for peer in &self.peers {
                    if let Err(error) = peer
                        .session
                        .register_peers(vec![phone_record(&phone)])
                        .await
                    {
                        log::warn!("staged peer {} did not learn the phone: {error}", peer.name);
                    }
                }
                self.phone = Some(phone);
            }
            // A radio that lets its host go keeps what its peers know.
            AirEvent::Host(None) => {}
            AirEvent::Transmitted(frame) => {
                for index in 0..self.peers.len() {
                    let peer = &self.peers[index];
                    let _ = peer.session.receive(MobileMeshRxRecord {
                        data: frame.clone(),
                        rssi_dbm: Some(peer.rssi_dbm),
                        lqi: Some(peer.lqi),
                        snr_cb: Some(peer.snr_cb),
                        was_buffered: false,
                        was_acknowledged: false,
                        age_seconds: 0,
                    });
                    self.pump(index);
                }
                self.echo(&frame);
            }
        }
    }

    /// Let the radio hear its flood carried onward, as a real mesh would
    /// answer it. The staged repeaters do not forward, so each one's copy
    /// is fabricated: a moment apart, one flood hop spent, and no trace to
    /// say whose it is.
    fn echo(&self, frame: &[u8]) {
        let Some(echo) = forwarded(frame) else {
            return;
        };
        let repeaters = NODES
            .iter()
            .filter(|node| matches!(node.role, Role::Repeater));
        for (index, _) in repeaters.enumerate() {
            let heard = self.heard.clone();
            let frame = echo.clone();
            let delay = Duration::from_millis(400 + 600 * index as u64);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = heard.send(Heard {
                    frame,
                    info: RadioRxInfo::measured(ECHO_RSSI_DBM, ECHO_SNR_CB, None),
                });
            });
        }
    }

    /// Drain one peer: complete its transmissions and put them on the
    /// air. Its chat keeps itself, in the peer's own store. Answers how
    /// many frames it transmitted.
    fn pump(&mut self, index: usize) -> usize {
        let Some(peer) = self.peers.get(index) else {
            return 0;
        };
        let update = peer.session.poll_update();
        for frame in &update.outbound_frames {
            let _ = peer.session.complete_outbound_frame(frame.id, true);
        }
        let info = RadioRxInfo::measured(peer.rssi_dbm, peer.snr_cb, NonZeroU8::new(peer.lqi));
        let session = peer.session.clone();
        if index == 0
            && let Some(meet) = update.meet
        {
            self.follow_meet(meet, session);
        }
        let transmitted = update.outbound_frames.len();
        if index == 0 && self.losing && transmitted > 0 {
            self.losing = false;
            return transmitted;
        }
        for frame in update.outbound_frames {
            let _ = self.heard.send(Heard {
                frame: frame.data,
                info,
            });
        }
        transmitted
    }

    /// Pump until the speaking peer transmits, or [`FLUSH_WAIT`] passes.
    async fn flush(&mut self) -> Result<(), MobileStagingAirError> {
        let deadline = Instant::now() + FLUSH_WAIT;
        while self.pump(0) == 0 {
            match tokio::time::timeout_at(deadline, self.wake_queue.recv()).await {
                Ok(Some(0)) => {}
                Ok(Some(other)) => {
                    self.pump(other);
                }
                Ok(None) | Err(_) => return Err(MobileStagingAirError::NotTransmitted),
            }
        }
        Ok(())
    }

    async fn obey(&mut self, order: Order) -> Result<(), MobileStagingAirError> {
        match order {
            Order::Say { body, on_channel } => self.say(body, on_channel).await,
            Order::SayLosingOne {
                bodies: [first, lost, last],
            } => {
                self.say(first, true).await?;
                // Only what the lost message produces is lost: anything
                // the peer already has queued goes out first.
                self.pump(0);
                self.losing = true;
                let said = self.say(lost, true).await;
                self.losing = false;
                said?;
                self.say(last, true).await
            }
            Order::React { body } => {
                let target = self.last_heard()?;
                let phone = self.phone()?;
                self.speak(phone, MobileChatSendRequest::Reaction { target, body })
                    .await
            }
            Order::Reply { body } => {
                let target = self.last_heard()?;
                let phone = self.phone()?;
                self.speak(
                    phone,
                    MobileChatSendRequest::Reply {
                        target,
                        body,
                        forward_secret: None,
                    },
                )
                .await
            }
            Order::OpenAddPeer { asking } => {
                let session = self.speaker()?.session.clone();
                self.pressed_same = false;
                self.asks_when_listed = asking;
                session.open_meet(MEET_MODEL).await.map_err(refused)?;
                self.pump(0);
                Ok(())
            }
            Order::Reset => {
                self.reset().await;
                Ok(())
            }
        }
    }

    async fn say(&mut self, body: String, on_channel: bool) -> Result<(), MobileStagingAirError> {
        let address = match on_channel {
            true => channel_address(),
            false => self.phone()?,
        };
        self.speak(address, MobileChatSendRequest::Text { body })
            .await
    }

    /// Have the speaking peer send `request` to `address`, and wait for it
    /// to go out.
    async fn speak(
        &mut self,
        address: String,
        request: MobileChatSendRequest,
    ) -> Result<(), MobileStagingAirError> {
        let session = self.speaker()?.session.clone();
        session.send_chat(address, request).await.map_err(refused)?;
        self.flush().await
    }

    fn speaker(&self) -> Result<&Peer, MobileStagingAirError> {
        self.peers
            .first()
            .ok_or(MobileStagingAirError::PeerUnavailable)
    }

    fn phone(&self) -> Result<String, MobileStagingAirError> {
        self.phone.clone().ok_or(MobileStagingAirError::NoPhone)
    }

    /// The newest message the speaking peer has from the phone, as its own
    /// store names it.
    fn last_heard(&self) -> Result<MobileChatRegardingRef, MobileStagingAirError> {
        let phone = self.phone()?;
        let page = self
            .speaker()?
            .store
            .chat_message_page_newest(PEER_OWNER.to_owned(), phone, 50)
            .map_err(|_| MobileStagingAirError::NothingToAnswer)?;
        let message = page
            .messages
            .into_iter()
            .rev()
            .find(|message| !message.outbound)
            .ok_or(MobileStagingAirError::NothingToAnswer)?;
        Ok(MobileChatRegardingRef {
            session_id: message.reference.session_id.parse().unwrap_or(0),
            handle: message.reference.handle,
            wire_id: message.wire_id,
            direction: Some(MobileChatDirection::Inbound),
            sender_hint: message.sender_hint,
            epoch: message.epoch,
        })
    }

    /// Play the speaking peer's part in an exchange it opened.
    fn follow_meet(&mut self, meet: MobileMeetStateRecord, session: Arc<MobileMeshSession>) {
        match meet.exchange {
            MobileMeetExchange::Idle => {
                if !self.asks_when_listed {
                    return;
                }
                let Some(device) = meet.devices.first().map(|device| device.id) else {
                    return;
                };
                self.asks_when_listed = false;
                // As long as a holder takes to pick a row, which is time
                // enough for the phone to hear this peer's answering Hello
                // and list it by model.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let _ = session.ask_to_exchange(device).await;
                });
            }
            MobileMeetExchange::Asked { .. } => {
                tokio::spawn(async move {
                    let _ = session.answer_exchange(true).await;
                });
            }
            MobileMeetExchange::Comparing { sent: false, .. } if !self.pressed_same => {
                self.pressed_same = true;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = session.confirm_code(true).await;
                });
            }
            MobileMeetExchange::Exchanged { .. } | MobileMeetExchange::Ended { .. } => {
                tokio::spawn(async move {
                    let _ = session.close_meet().await;
                });
            }
            _ => {}
        }
    }

    /// Shut the peers down and stand them up afresh, with counters in a
    /// generation of their own: the old sessions may still be writing to
    /// theirs as they end.
    async fn reset(&mut self) {
        self.peers.clear();
        self.asks_when_listed = false;
        self.pressed_same = false;
        self.losing = false;
        self.generation = self.generation.wrapping_add(1);
        self.retire_generations();
        self.stand_up().await;
    }
}

/// The counter generations kept under `dir`.
fn generations(dir: &std::path::Path) -> impl Iterator<Item = u32> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
}

fn refused(error: impl fmt::Display) -> MobileStagingAirError {
    log::warn!("a staged peer refused: {error}");
    MobileStagingAirError::Refused
}

/// The phone, as a peer registers it: its identity always advertises
/// itself as mobile.
fn phone_record(address: &str) -> MobilePeerRegistrationRecord {
    MobilePeerRegistrationRecord {
        address: address.to_owned(),
        mobile: true,
    }
}

/// Both staged channels' keys, so every peer can read and speak on both.
fn channel_keys() -> Vec<Vec<u8>> {
    let named =
        umsh_node::Channel::named(CHANNEL_NAME).expect("the staged channel name derives a key");
    vec![PRIVATE_CHANNEL_KEY.to_vec(), named.key().0.to_vec()]
}

/// The named staged channel's conversation address.
fn channel_address() -> String {
    let named =
        umsh_node::Channel::named(CHANNEL_NAME).expect("the staged channel name derives a key");
    channel_conversation_address(named.key().0.to_vec())
        .expect("a channel key names a conversation")
}

/// `frame` as a flood repeater sends it on, or `None` when it may not
/// travel further.
fn forwarded(frame: &[u8]) -> Option<Vec<u8>> {
    // The flood-hops byte follows the frame control field.
    let (&fcf, rest) = frame.split_first()?;
    if !Fcf(fcf).flood_hops_present() {
        return None;
    }
    let hops = FloodHops(*rest.first()?);
    // A count that cannot move on is a flood that has gone as far as it
    // may.
    let next = hops.decremented();
    if next == hops {
        return None;
    }
    let mut bytes = frame.to_vec();
    bytes[1] = next.0;
    Some(bytes)
}

#[cfg(test)]
mod tests;
