//! The air around the staged mesh, below an ordinary radio driver.
//!
//! The staged radio is a soft device, the companion's own ULCP session,
//! that the phone reaches through a [`MobileRadioDriver`] like any radio.
//! Every staged node is a real mesh session under the scenario's fixed
//! key, and what one station transmits reaches the stations in range of
//! it ([`LINKS`]). A message sent in staging is encrypted, framed,
//! transmitted, forwarded, decrypted, and acknowledged by the code that
//! does it over RF. Only the medium is fabricated: frames move through
//! memory, and airtime is free.
//!
//! The two repeaters forward, and answer pings and Peer Repeaters
//! Requests. One of them is also the managed remote device: a soft device
//! under the repeater's identity, served through the responder the
//! firmware uses.
//!
//! Beside the phone stand two devices it can set up or change over a link
//! of their own, as it would one on the bench: one that forwards and one
//! that does not. Each is a fresh soft device behind an administrative
//! driver, on no air.
//!
//! Each chat peer keeps its chat in an in-memory store of its own, as the
//! app keeps the phone's: that is where it answers a request to send
//! something again from, and where it finds what the phone last said.
//!
//! The radio and the nodes run on one thread of the air's own for as long
//! as the air lives.

use std::fmt;
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use umsh_core::{PayloadType, PublicKey};
use umsh_node::location::NodeLocation;
use umsh_node_mgmt::{Admission, Admitted, Answer, Responder, admit, authorize};
use umsh_ulcp::battery::{BatteryChargeState, BatteryStatus};
use umsh_ulcp::frame as ulcp_frame;
use umsh_ulcp::gnss::{FixKind, GnssSnapshot};
use umsh_ulcp::ids::prop;
use umsh_ulcp::{hdlc, profiles};
use umsh_ulcp_device::{Effect, MULTI_MAX, TxOutcome};
use umsh_ulcp_simdev::driven::{self, HOST_EVENT_DEPTH, Heard, HostEvent, Medium, WireSink};
use umsh_ulcp_simdev::soft::{DeviceSession, SoftDevice, SoftPlatform};
use umsh_ulcp_simdev::{
    BatteryFields, DutyLedger, GnssConfig, RadioRxInfo, RadioSettings, SessionConfig,
    SimulatedPlatform, TimeConfig, WifiConfig,
};

use super::{CHANNEL_NAME, NODES, Node, PRIVATE_CHANNEL_KEY, Role};
use crate::mobile_chat::MobileChatRegardingRef;
use crate::mobile_mesh::{
    MobileChannelRegistrationRecord, MobileChatSendRequest, MobileMeshRxRecord,
    MobileMeshSharedLocationRecord, MobileMeshWakeListener, MobilePeerRegistrationRecord, NodeKind,
    NodeOptions, ReceiveTap,
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

/// The staged radio's link identifier, fixed so the app remembers it like
/// any other radio.
const RADIO_LINK_ID: &str = "3F6C2A9E-1B47-4D85-8E21-7A0C5D9B4E10";

/// The staged radio's identity secret fills all 32 bytes with this, as a
/// staged node's does with its seed: fixed, so its key reads the same
/// every run. It names the radio in [`LINKS`].
const RADIO_SEED: u8 = 0x88;

/// A staged device the phone sets up or changes over a link of its own,
/// as it would one on the bench beside it. It is on no air: what it
/// transmits goes nowhere, and it hears nothing.
struct Administered {
    /// Fills the device's identity secret, as a staged node's seed does.
    seed: u8,
    name: &'static str,
    model: &'static str,
    /// The link identifier its driver's state reports it under.
    link_id: &'static str,
    /// Whether it forwards, so the repeater goal takes it.
    forwards: bool,
}

/// The administered devices, the one that forwards first: the repeater
/// goal takes it and refuses the other.
const ADMINISTERED: [Administered; 2] = [
    Administered {
        seed: 0x99,
        name: "Ralston Peak",
        model: "SenseCAP Solar P1",
        link_id: "5B0E7C31-9A2D-4F68-B3C4-1D8E6A2F7059",
        forwards: true,
    },
    Administered {
        seed: 0xAA,
        name: "Fallen Leaf",
        model: "T1000-E",
        link_id: "C7A41E58-2F93-4B0D-9E6C-83D5B1A0F42E",
        forwards: false,
    },
];

/// A staged device beside the phone, as device setup lists it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStagedDeviceRecord {
    /// The link identifier its driver's state reports it under.
    pub link_id: String,
    /// What it is called until the phone renames it.
    pub name: String,
}

/// The speaking peer, by its place in [`NODES`]: a chat node in range of
/// the radio.
const SPEAKER: usize = 0;
const _: () = assert!(matches!(NODES[SPEAKER].role, Role::Chat));

/// The staged repeater the phone manages across the mesh: Tallac Ridge.
const MANAGED_SEED: u8 = 0x22;
const MANAGED: usize = place(MANAGED_SEED);
const _: () = assert!(matches!(NODES[MANAGED].role, Role::Repeater));

/// The place in [`NODES`] of the node with `seed`. A seed no node has
/// fails the build.
const fn place(seed: u8) -> usize {
    let mut index = 0;
    while index < NODES.len() {
        if NODES[index].seed == seed {
            return index;
        }
        index += 1;
    }
    panic!("no staged node has this seed");
}

/// The Node Management payload the managed repeater answers within: the
/// least a device may have.
const MANAGED_PAYLOAD: usize = umsh_node_mgmt::PAYLOAD_MAX;

/// Room for the replies the managed repeater retains, as the harnesses
/// size it.
const MANAGED_POOL: usize = 2 * MULTI_MAX;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileStagingAirError {
    /// The air's state directory could not be created.
    StateUnavailable,
    /// The air's worker could not be started.
    WorkerUnavailable,
    /// The air has stopped.
    Stopped,
    /// The speaking peer did not stand up.
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
    /// No staged device has this link identifier.
    NoSuchDevice,
    /// The host key is not one.
    InvalidHostKey,
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
            Self::NoSuchDevice => "no staged device has this link identifier",
            Self::InvalidHostKey => "the host key is malformed",
        })
    }
}

impl std::error::Error for MobileStagingAirError {}

/// The staged mesh: a radio for the phone, and the nodes around it.
///
/// The staging controls are its methods. Those that speak act through the
/// first staged peer. Dropping the air, or calling [`Self::stop`], ends the
/// radio and the nodes.
#[derive(uniffi::Object)]
pub struct MobileStagingAir {
    radio: Arc<MobileRadioDriver>,
    link: Arc<AirLink>,
    controls: mpsc::UnboundedSender<Control>,
    failing: Arc<AtomicBool>,
    remote_reachable: Arc<AtomicBool>,
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
    /// Start the staged mesh, keeping each node's frame counters under
    /// `state_dir`. The radio waits detached until [`Self::connect`].
    /// `wifi_scan_only` gives the managed repeater a receiver that scans
    /// and never joins.
    #[uniffi::constructor]
    pub fn start(
        state_dir: String,
        wifi_scan_only: bool,
    ) -> Result<Arc<Self>, MobileStagingAirError> {
        let dir = PathBuf::from(state_dir);
        std::fs::create_dir_all(&dir).map_err(|_| MobileStagingAirError::StateUnavailable)?;

        let (events, host_events) = mpsc::channel(HOST_EVENT_DEPTH);
        let link = Arc::new(AirLink {
            events,
            driver: OnceLock::new(),
            stopped: AtomicBool::new(false),
            name: RADIO_NAME,
            link_id: RADIO_LINK_ID,
            _device: None,
        });
        let radio = MobileRadioDriver::new(link.clone())
            .map_err(|_| MobileStagingAirError::WorkerUnavailable)?;
        let _ = link.driver.set(Arc::downgrade(&radio));

        let (controls, control_queue) = mpsc::unbounded_channel();
        let failing = Arc::new(AtomicBool::new(false));
        let medium_failing = failing.clone();
        let remote_reachable = Arc::new(AtomicBool::new(true));
        let air_reachable = remote_reachable.clone();
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
                let air = Air::new(dir, air_queue, heard, air_reachable, wifi_scan_only)
                    .run(control_queue);
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
            remote_reachable,
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

    /// While not `reachable`, the managed repeater neither hears nor is
    /// heard, so whatever asks it across the mesh meets silence.
    pub fn set_remote_device_reachable(&self, reachable: bool) {
        self.remote_reachable.store(reachable, Ordering::Relaxed);
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

    /// The staged radio's link identifier, which its snapshot reports.
    pub fn radio_link_id(&self) -> String {
        RADIO_LINK_ID.to_owned()
    }

    /// What the staged radio is called until the phone renames it.
    pub fn radio_name(&self) -> String {
        RADIO_NAME.to_owned()
    }

    /// The staged devices beside the phone that
    /// [`administered_device`](Self::administered_device) attaches to, the
    /// one that forwards first.
    pub fn administered_devices(&self) -> Vec<MobileStagedDeviceRecord> {
        ADMINISTERED
            .iter()
            .map(|staged| MobileStagedDeviceRecord {
                link_id: staged.link_id.to_owned(),
                name: staged.name.to_owned(),
            })
            .collect()
    }

    /// An administrative driver for a fresh copy of the staged device
    /// `link_id` names, attaching as it returns. It holds `host_key`
    /// before the link comes up, as a driver over Bluetooth does.
    /// `lazy_inspection` attaches without reading the device whole
    /// ([`MobileRadioDriver::administrative`]). The device runs for as
    /// long as the driver does, and starts afresh each call.
    pub fn administered_device(
        &self,
        link_id: String,
        host_key: Option<Vec<u8>>,
        lazy_inspection: bool,
    ) -> Result<Arc<MobileRadioDriver>, MobileStagingAirError> {
        if self.link.stopped.load(Ordering::Relaxed) {
            return Err(MobileStagingAirError::Stopped);
        }
        let staged = ADMINISTERED
            .iter()
            .find(|staged| staged.link_id == link_id)
            .ok_or(MobileStagingAirError::NoSuchDevice)?;
        let (events, host_events) = mpsc::channel(HOST_EVENT_DEPTH);
        let stop = driven::spawn("umsh-staging-administered", move || {
            let device = SoftDevice::new(
                administered_config(staged),
                SimulatedPlatform::with_identity([staged.seed; 32]),
            );
            Ok::<_, std::convert::Infallible>(driven::run(device, BenchMedium, host_events, |_| {}))
        })
        .map_err(|_| MobileStagingAirError::WorkerUnavailable)?;
        let link = Arc::new(AirLink {
            events,
            driver: OnceLock::new(),
            stopped: AtomicBool::new(false),
            name: staged.name,
            link_id: staged.link_id,
            _device: Some(stop),
        });
        let driver = MobileRadioDriver::administrative(link.clone(), lazy_inspection)
            .map_err(|_| MobileStagingAirError::WorkerUnavailable)?;
        let _ = link.driver.set(Arc::downgrade(&driver));
        if driver.set_host_key(host_key).is_err() {
            driver.stop();
            return Err(MobileStagingAirError::InvalidHostKey);
        }
        link.connect();
        Ok(driver)
    }

    /// Stop the air. The radio's link goes down, and the radio and the
    /// nodes end. It cannot be started again; make another.
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

    /// Stand every staged node up afresh, as another identity taking the
    /// radio does.
    #[cfg(test)]
    async fn reset(&self) -> Result<(), MobileStagingAirError> {
        self.control(Order::Reset).await
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
            identity: Some([RADIO_SEED; 32]),
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
        host_custody: false,
        illuminance: false,
        temperatures: false,
        ble: false,
        ble_pairing: false,
        ble_pin: false,
        uart_links: Default::default(),
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
        node_msg: None,
    }
}

/// An administered device's capability surface: everything a device can
/// offer, forwarding only when it `forwards`.
fn administered_config(staged: &'static Administered) -> SessionConfig {
    // One ledger per device, for as long as the process runs: a fresh
    // device must not inherit the last one's duty limit.
    let mut config = umsh_ulcp_simdev::full_config(Box::leak(Box::new(DutyLedger::new())), None);
    config.dev_version = DEV_VERSION;
    config.dev_model = Some(staged.model);
    config.default_device_name = staged.name;
    config.mac_node = staged.forwards;
    config
}

/// The medium of a device on the bench: on no air.
struct BenchMedium;

impl Medium for BenchMedium {
    fn follow<P: SoftPlatform>(&mut self, _device: &mut SoftDevice<P>) {}

    async fn transmit(&mut self, _frame: &[u8]) -> TxOutcome {
        TxOutcome::Sent
    }

    async fn hear(&mut self) -> Option<Heard> {
        std::future::pending().await
    }
}

// --- The link between the driver and a staged device ---

/// A staged device's link: whole frames from the driver, HDLC-Lite to
/// the device, and back.
struct AirLink {
    events: mpsc::Sender<HostEvent>,
    driver: OnceLock<Weak<MobileRadioDriver>>,
    /// The air has stopped, and there is no device to connect to.
    stopped: AtomicBool,
    /// What the link reports the device as, and under which identifier.
    name: &'static str,
    link_id: &'static str,
    /// The thread of a device that runs on one of its own, an administered
    /// device's: it ends when the link is let go of.
    _device: Option<oneshot::Sender<()>>,
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
            driver.transport_changed(self.transport(MobileRadioTransportPhase::Idle));
            return;
        }
        driver.transport_changed(self.transport(MobileRadioTransportPhase::Connecting));
        self.post(HostEvent::Attach(sink(Arc::downgrade(&driver))));
        driver.link_ready(true);
    }

    fn disconnect(&self) {
        self.post(HostEvent::Detach);
        if let Some(driver) = self.driver() {
            driver.transport_changed(self.transport(MobileRadioTransportPhase::Idle));
        }
    }

    fn transport(&self, phase: MobileRadioTransportPhase) -> MobileRadioTransportStateRecord {
        MobileRadioTransportStateRecord {
            phase,
            name: Some(self.name.to_owned()),
            link_id: Some(self.link_id.to_owned()),
            problem: None,
        }
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

// --- The air between stations ---

/// Two stations in range of each other, by seed, and how each hears the
/// other.
struct Link {
    a: u8,
    b: u8,
    rssi_dbm: i16,
    snr_cb: i16,
    lqi: u8,
}

impl Link {
    /// The station across this link from `seed`, if the link touches it.
    fn across(&self, seed: u8) -> Option<u8> {
        match seed {
            _ if self.a == seed => Some(self.b),
            _ if self.b == seed => Some(self.a),
            _ => None,
        }
    }
}

/// Who hears whom. Links are symmetric and fixed, so a staged conversation
/// reads the same every run.
///
/// Each node that does not forward hears one station, which keeps it from
/// needing a channel-access model: the chat peers hear the radio, and Sam
/// Ihara, out of the radio's range, hears only Glen Alpine Relay. The
/// repeaters hear the radio and each other.
const LINKS: &[Link] = &[
    Link {
        a: RADIO_SEED,
        b: 0x11,
        rssi_dbm: -52,
        snr_cb: 74,
        lqi: 214,
    },
    Link {
        a: RADIO_SEED,
        b: MANAGED_SEED,
        rssi_dbm: -61,
        snr_cb: 60,
        lqi: 190,
    },
    Link {
        a: RADIO_SEED,
        b: 0x33,
        rssi_dbm: -58,
        snr_cb: 65,
        lqi: 201,
    },
    Link {
        a: RADIO_SEED,
        b: 0x44,
        rssi_dbm: -64,
        snr_cb: 56,
        lqi: 188,
    },
    Link {
        a: RADIO_SEED,
        b: 0x55,
        rssi_dbm: -70,
        snr_cb: 47,
        lqi: 175,
    },
    Link {
        a: RADIO_SEED,
        b: 0x77,
        rssi_dbm: -88,
        snr_cb: 22,
        lqi: 120,
    },
    Link {
        a: MANAGED_SEED,
        b: 0x77,
        rssi_dbm: -95,
        snr_cb: 12,
        lqi: 96,
    },
    Link {
        a: 0x77,
        b: 0x66,
        rssi_dbm: -84,
        snr_cb: 30,
        lqi: 140,
    },
];

// Every link joins the radio or a staged node to a staged node.
const _: () = {
    let mut index = 0;
    while index < LINKS.len() {
        let link = &LINKS[index];
        if link.a != RADIO_SEED {
            place(link.a);
        }
        place(link.b);
        index += 1;
    }
};

// --- The staged nodes ---

/// A staged node standing on the air: a mesh session under the node's
/// fixed key.
struct Station {
    node: &'static Node,
    session: Arc<MobileMeshSession>,
    /// Where a chat peer keeps its chat. A repeater carries none.
    store: Option<Arc<MobileAppStore>>,
}

/// Tells the air that a station's session has an update.
struct StationWake {
    index: usize,
    wakes: mpsc::UnboundedSender<usize>,
}

impl MobileMeshWakeListener for StationWake {
    fn on_update_pending(&self) {
        let _ = self.wakes.send(self.index);
    }
}

// --- The managed repeater ---

/// The managed repeater's device: the companion's own ULCP session over a
/// simulated platform, under the repeater's identity, so the device key
/// the phone reads is the address it manages.
///
/// A write changes the device's properties, not the repeater's behavior:
/// the firmware mirrors its device domain into its MAC, and the air does
/// not. Staging needs the screens, not the behavior.
struct Managed {
    device: SoftDevice<SimulatedPlatform>,
    responder: Responder<MANAGED_PAYLOAD, MANAGED_POOL>,
    /// What the repeater's receive tap admits against.
    admins: Arc<Mutex<Vec<[u8; 32]>>>,
}

/// What reaches the managed repeater's responder.
enum Management {
    /// A request the receive tap admitted.
    Request {
        admitted: Admitted,
        payload: Vec<u8>,
    },
    /// The response to a request never went out.
    Unsent { from: [u8; 32], payload: Vec<u8> },
}

impl Managed {
    fn new(duty: &'static DutyLedger, wifi_scan_only: bool) -> Self {
        let mut config = umsh_ulcp_simdev::full_config(duty, None);
        config.dev_version = DEV_VERSION;
        config.default_device_name = NODES[MANAGED].name;
        config.dev_model = Some("SenseCAP Solar P1");
        // A repeater on a ridge: no light sensor.
        config.illuminance = false;
        config.mac_node = true;
        if wifi_scan_only {
            config.wifi = Some(WifiConfig::SCAN_ONLY);
        }
        Self {
            device: SoftDevice::new(config, SimulatedPlatform::with_identity([MANAGED_SEED; 32])),
            responder: Responder::new(rand::random()),
            admins: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The repeater's receive tap: admit Node Management Requests against
    /// the device's administrators, as the firmware's responder does, and
    /// hand them to the air. It claims nothing, so every other observer
    /// still sees the packet. The repeater is never tethered, so it has no
    /// host to hear beside its administrators.
    fn tap(&self, requests: mpsc::UnboundedSender<Management>) -> ReceiveTap {
        let admins = self.admins.clone();
        Box::new(move |packet| {
            let admission = admit(
                packet,
                |from| {
                    let admins = admins.lock().unwrap_or_else(PoisonError::into_inner);
                    authorize(from, &admins, None)
                },
                MANAGED_PAYLOAD,
            );
            match admission {
                Admission::Ignored => {}
                Admission::Refused(refusal) => {
                    log::debug!(refusal:? = refusal; "the managed repeater refused a request");
                }
                Admission::Admitted(admitted) => {
                    let _ = requests.send(Management::Request {
                        admitted,
                        payload: packet.payload().to_vec(),
                    });
                }
            }
            false
        })
    }

    /// Keep the tap's administrators in step with the device's.
    fn mirror(&self) {
        *self.admins.lock().unwrap_or_else(PoisonError::into_inner) =
            self.device.session().dev_admins().collect();
    }

    /// List `phone` as an administrator and save, as the repeater's owner
    /// would over USB before going up the ridge.
    fn administer(&mut self, phone: [u8; 32], now_ms: u64) {
        if self.device.session().dev_admins().any(|key| key == phone) {
            return;
        }
        self.device.attach();
        let mut frame = [0u8; 64];
        let inserted = ulcp_frame::prop_insert(&mut frame, 1, prop::DEV_ADMINS, &phone);
        self.ingest(inserted.map(|len| &frame[..len]), now_ms);
        let mut frame = [0u8; 8];
        let saved = ulcp_frame::save(&mut frame, 2);
        self.ingest(saved.map(|len| &frame[..len]), now_ms);
        while self.device.take_outbound().is_some() {}
        self.device.detach();
        self.mirror();
    }

    fn ingest(&mut self, frame: Result<&[u8], ulcp_frame::WriteError>, now_ms: u64) {
        let Ok(frame) = frame else {
            log::warn!("the managed repeater's provisioning frame did not encode");
            return;
        };
        let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
        let Ok(length) = hdlc::encode_frame(frame, &mut wire) else {
            return;
        };
        if let Err(error) = self.device.ingest(&wire[..length], now_ms) {
            log::warn!("the managed repeater did not take its provisioning: {error}");
        }
    }

    /// Answer one admitted request. Returns the response payload, its
    /// payload-type octet first, when one goes back.
    fn answer(&mut self, admitted: &Admitted, payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        let mut out = [0u8; MANAGED_PAYLOAD];
        let device = &mut self.device;
        let answer =
            self.responder
                .exchange(&admitted.from, payload, now_ms, &mut out, |dispatch| {
                    // One frame answers an exchange.
                    device
                        .admin_request(dispatch.frame, dispatch.budget, now_ms)
                        .pop()
                        .unwrap_or_default()
                });
        self.mirror();
        let len = match answer {
            Answer::Respond(len) => len?,
            Answer::Dropped(reason) => {
                log::debug!(reason:? = reason; "the managed repeater dropped a request");
                return None;
            }
            Answer::Unanswerable(error) => {
                log::warn!(error:? = error; "the managed repeater could not carry its reply");
                return None;
            }
        };
        let mut response = Vec::with_capacity(len + 1);
        response.push(PayloadType::NodeManagementResponse as u8);
        response.extend_from_slice(&out[..len]);
        Some(response)
    }
}

// --- The air ---

struct Control {
    order: Order,
    reply: oneshot::Sender<Result<(), MobileStagingAirError>>,
}

enum Order {
    Say {
        body: String,
        on_channel: bool,
    },
    SayLosingOne {
        bodies: [String; 3],
    },
    React {
        body: String,
    },
    Reply {
        body: String,
    },
    OpenAddPeer {
        asking: bool,
    },
    #[cfg(test)]
    Reset,
}

/// The staged nodes, and what the air knows of the phone.
struct Air {
    /// Where the nodes keep their frame counters: a numbered generation
    /// directory, then one per node.
    dir: PathBuf,
    /// The generation the standing nodes keep their counters in.
    generation: u32,
    /// One per staged node, in [`NODES`] order; `None` for a node that did
    /// not stand up.
    stations: Vec<Option<Station>>,
    managed: Option<Managed>,
    management: mpsc::UnboundedSender<Management>,
    management_queue: mpsc::UnboundedReceiver<Management>,
    /// The duty ledger of the managed repeater's device, one per air.
    duty: &'static DutyLedger,
    started: Instant,
    /// The phone's key, once it tethers the radio.
    phone: Option<[u8; 32]>,
    /// From the radio's medium: what the radio transmitted, and its host.
    air_events: mpsc::UnboundedReceiver<AirEvent>,
    /// To the radio's receiver.
    heard: mpsc::UnboundedSender<Heard>,
    wakes: mpsc::UnboundedSender<usize>,
    wake_queue: mpsc::UnboundedReceiver<usize>,
    /// While false, the managed repeater neither hears nor is heard.
    remote_reachable: Arc<AtomicBool>,
    /// The managed repeater's Wi-Fi scans and never joins.
    wifi_scan_only: bool,
    /// The speaking peer asks the first device Add Peer lists.
    asks_when_listed: bool,
    /// The speaking peer has pressed Same on the code now showing.
    pressed_same: bool,
    /// The next frame the speaking peer originates never reaches the
    /// radio. Its immediate acknowledgments still do.
    losing: bool,
}

impl Air {
    fn new(
        dir: PathBuf,
        air_events: mpsc::UnboundedReceiver<AirEvent>,
        heard: mpsc::UnboundedSender<Heard>,
        remote_reachable: Arc<AtomicBool>,
        wifi_scan_only: bool,
    ) -> Self {
        let (wakes, wake_queue) = mpsc::unbounded_channel();
        let (management, management_queue) = mpsc::unbounded_channel();
        let generation = generations(&dir).max().unwrap_or(0);
        Self {
            dir,
            generation,
            stations: Vec::new(),
            managed: None,
            management,
            management_queue,
            // One ledger per air, for as long as the process runs.
            duty: Box::leak(Box::new(DutyLedger::new())),
            started: Instant::now(),
            phone: None,
            air_events,
            heard,
            wakes,
            wake_queue,
            remote_reachable,
            wifi_scan_only,
            asks_when_listed: false,
            pressed_same: false,
            losing: false,
        }
    }

    async fn run(mut self, mut controls: mpsc::UnboundedReceiver<Control>) {
        self.retire_generations();
        self.stand_up().await;
        loop {
            tokio::select! {
                event = self.air_events.recv() => match event {
                    Some(event) => self.on_air(event).await,
                    None => break,
                },
                Some(index) = self.wake_queue.recv() => {
                    self.pump(index);
                }
                Some(management) = self.management_queue.recv() => {
                    self.manage(management);
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

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Stand up a session for every staged node, then let the repeaters
    /// introduce themselves, so each one's neighborhood lists the other.
    async fn stand_up(&mut self) {
        let managed = Managed::new(self.duty, self.wifi_scan_only);
        self.stations = Vec::with_capacity(NODES.len());
        for (index, node) in NODES.iter().enumerate() {
            let tap = (node.seed == MANAGED_SEED).then(|| managed.tap(self.management.clone()));
            match self.stand_up_node(index, node, tap).await {
                Ok(station) => self.stations.push(Some(station)),
                // A node that cannot stand up is one the staged mesh never
                // hears from; everything else keeps working.
                Err(error) => {
                    log::warn!("staged node {} did not stand up: {error}", node.name);
                    self.stations.push(None);
                }
            }
        }
        self.managed = Some(managed);
        if let Some(phone) = self.phone {
            self.administer(phone);
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|now| u32::try_from(now.as_secs()).ok());
        // Each on a task of its own: a transmission completes only as the
        // air pumps it, and the air is busy here until this returns.
        for station in self.stations.iter().flatten() {
            if !matches!(station.node.role, Role::Repeater) {
                continue;
            }
            let session = station.session.clone();
            let name = station.node.name;
            tokio::spawn(async move {
                if let Err(error) = session
                    .advertise_identity(Some(name.to_owned()), timestamp)
                    .await
                {
                    log::warn!("staged repeater {name} did not advertise: {error}");
                }
            });
        }
    }

    async fn stand_up_node(
        &self,
        index: usize,
        node: &'static Node,
        tap: Option<ReceiveTap>,
    ) -> Result<Station, Box<dyn std::error::Error>> {
        let identity = MobileIdentity::unlock(vec![node.seed; 32])?;
        let counters = MobileCounterStore::new(self.counter_dir(node).display().to_string())?;
        let repeater = matches!(node.role, Role::Repeater);
        let options = NodeOptions {
            kind: NodeKind {
                role: node.role.node_role(),
                capabilities: node.capabilities,
            },
            repeater,
            tap,
        };
        let session = MobileMeshSession::start_node(options, identity.clone(), counters).await?;
        let store = match repeater {
            true => {
                session
                    .set_discoverable(true, Some(node.name.to_owned()))
                    .await?;
                session
                    .set_advertised_location(Some(MobileMeshSharedLocationRecord {
                        latitude_degrees: node.latitude,
                        longitude_degrees: node.longitude,
                        precision_bytes: super::LOCATION_PRECISION,
                    }))
                    .await?;
                None
            }
            false => {
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
                Some(store)
            }
        };
        if let Some(phone) = self.phone {
            session.register_peers(vec![phone_record(&phone)]).await?;
        }
        session.set_wake_listener(Arc::new(StationWake {
            index,
            wakes: self.wakes.clone(),
        }));
        Ok(Station {
            node,
            session,
            store,
        })
    }

    /// Frame counters must survive relaunches for replay protection to
    /// hold between a node and the phone, so each node keeps its own.
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

    fn administer(&mut self, phone: [u8; 32]) {
        let now_ms = self.now_ms();
        if let Some(managed) = self.managed.as_mut() {
            managed.administer(phone, now_ms);
        }
    }

    async fn on_air(&mut self, event: AirEvent) {
        match event {
            AirEvent::Host(Some(key)) => match self.phone.replace(key) {
                Some(phone) if phone == key => {}
                // Another identity on the radio is a phone starting over,
                // and the staged mesh starts over with it: nothing keeps
                // the old key as a peer or an administrator.
                Some(_) => self.reset().await,
                None => self.learn_phone(key).await,
            },
            // A radio that lets its host go keeps what its peers know.
            AirEvent::Host(None) => {}
            AirEvent::Transmitted(frame) => self.transmit(RADIO_SEED, &frame),
        }
    }

    /// Introduce the phone to every station standing, and list it as the
    /// managed repeater's administrator.
    async fn learn_phone(&mut self, key: [u8; 32]) {
        for station in self.stations.iter().flatten() {
            if let Err(error) = station
                .session
                .register_peers(vec![phone_record(&key)])
                .await
            {
                log::warn!(
                    "staged node {} did not learn the phone: {error}",
                    station.node.name
                );
            }
        }
        self.administer(key);
    }

    /// Whether the station with `seed` is on the air at all.
    fn in_reach(&self, seed: u8) -> bool {
        seed != MANAGED_SEED || self.remote_reachable.load(Ordering::Relaxed)
    }

    /// Put `frame` from the station with `seed` on the air, to every
    /// station in range of it.
    fn transmit(&self, seed: u8, frame: &[u8]) {
        if !self.in_reach(seed) {
            return;
        }
        for link in LINKS {
            let Some(to) = link.across(seed).filter(|&to| self.in_reach(to)) else {
                continue;
            };
            if to == RADIO_SEED {
                let _ = self.heard.send(Heard {
                    frame: frame.to_vec(),
                    info: RadioRxInfo::measured(
                        link.rssi_dbm,
                        link.snr_cb,
                        NonZeroU8::new(link.lqi),
                    ),
                });
                continue;
            }
            let Some(station) = self.station_by_seed(to) else {
                continue;
            };
            // A full queue is a frame lost, as it would be over the air.
            let _ = station.session.receive(MobileMeshRxRecord {
                data: frame.to_vec(),
                rssi_dbm: Some(link.rssi_dbm),
                lqi: Some(link.lqi),
                snr_cb: Some(link.snr_cb),
                was_buffered: false,
                was_acknowledged: false,
                age_seconds: 0,
            });
        }
    }

    fn station_by_seed(&self, seed: u8) -> Option<&Station> {
        self.stations
            .iter()
            .flatten()
            .find(|station| station.node.seed == seed)
    }

    /// Drain one station: complete its transmissions and put them on the
    /// air. A peer's chat keeps itself, in its own store. Answers how many
    /// frames it originated: an immediate acknowledgment, the only frame a
    /// station sends without listening first, answers what it heard and is
    /// not counted.
    fn pump(&mut self, index: usize) -> usize {
        let Some(Some(station)) = self.stations.get(index) else {
            return 0;
        };
        let update = station.session.poll_update();
        for frame in &update.outbound_frames {
            let _ = station.session.complete_outbound_frame(frame.id, true);
        }
        let seed = station.node.seed;
        let session = station.session.clone();
        if index == SPEAKER
            && let Some(meet) = update.meet
        {
            self.follow_meet(meet, session);
        }
        let mut originated = 0;
        for frame in update.outbound_frames {
            if !frame.nocca {
                originated += 1;
                if index == SPEAKER && self.losing {
                    self.losing = false;
                    continue;
                }
            }
            self.transmit(seed, &frame.data);
        }
        originated
    }

    /// Answer the managed repeater's admitted requests through its session.
    fn manage(&mut self, management: Management) {
        let now_ms = self.now_ms();
        let Some(managed) = self.managed.as_mut() else {
            return;
        };
        let (admitted, payload) = match management {
            Management::Unsent { from, payload } => {
                managed.responder.unsent(&from, &payload);
                return;
            }
            Management::Request { admitted, payload } => (admitted, payload),
        };
        let Some(response) = managed.answer(&admitted, &payload, now_ms) else {
            return;
        };
        let Some(station) = self.station_by_seed(MANAGED_SEED) else {
            return;
        };
        // Sent on a task of its own: the session transmits only as the air
        // pumps it.
        let session = station.session.clone();
        let unsent = self.management.clone();
        tokio::spawn(async move {
            let sent = session
                .send_response(
                    PublicKey(admitted.from),
                    admitted.channel,
                    admitted.ack_mic,
                    response,
                )
                .await;
            if let Err(error) = sent {
                log::warn!("the managed repeater's response did not go out: {error}");
                let _ = unsent.send(Management::Unsent {
                    from: admitted.from,
                    payload,
                });
            }
        });
    }

    /// Pump until the speaking peer originates a frame, or [`FLUSH_WAIT`]
    /// passes.
    ///
    /// The radio's side of the air carries on meanwhile: what the speaker
    /// waits for may be the phone's acknowledgment of what it said last,
    /// once it has as many awaiting one as it may.
    async fn flush(&mut self) -> Result<(), MobileStagingAirError> {
        let deadline = Instant::now() + FLUSH_WAIT;
        while self.pump(SPEAKER) == 0 {
            tokio::select! {
                wake = self.wake_queue.recv() => match wake {
                    Some(SPEAKER) => {}
                    Some(other) => {
                        self.pump(other);
                    }
                    None => return Err(MobileStagingAirError::NotTransmitted),
                },
                event = self.air_events.recv() => match event {
                    // Boxed: a new host restands every node, whose future
                    // is too large to nest in every control's.
                    Some(event) => Box::pin(self.on_air(event)).await,
                    None => return Err(MobileStagingAirError::Stopped),
                },
                () = tokio::time::sleep_until(deadline) => {
                    return Err(MobileStagingAirError::NotTransmitted);
                }
            }
        }
        Ok(())
    }

    async fn obey(&mut self, order: Order) -> Result<(), MobileStagingAirError> {
        match order {
            Order::Say { body, on_channel } => self.say(body, on_channel, false).await,
            Order::SayLosingOne {
                bodies: [first, lost, last],
            } => {
                self.say(first, true, false).await?;
                self.say(lost, true, true).await?;
                self.say(last, true, false).await
            }
            Order::React { body } => {
                let target = self.last_heard()?;
                let phone = self.phone()?;
                self.speak(
                    phone,
                    MobileChatSendRequest::Reaction { target, body },
                    false,
                )
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
                    false,
                )
                .await
            }
            Order::OpenAddPeer { asking } => {
                let session = self.speaker()?.session.clone();
                self.pressed_same = false;
                self.asks_when_listed = asking;
                session.open_meet(MEET_MODEL).await.map_err(refused)?;
                self.pump(SPEAKER);
                Ok(())
            }
            #[cfg(test)]
            Order::Reset => {
                self.reset().await;
                Ok(())
            }
        }
    }

    async fn say(
        &mut self,
        body: String,
        on_channel: bool,
        lose: bool,
    ) -> Result<(), MobileStagingAirError> {
        let address = match on_channel {
            true => channel_address(),
            false => self.phone()?,
        };
        self.speak(address, MobileChatSendRequest::Text { body }, lose)
            .await
    }

    /// Have the speaking peer send `request` to `address`, and wait for it
    /// to go out. With `lose`, it never reaches the radio.
    async fn speak(
        &mut self,
        address: String,
        request: MobileChatSendRequest,
        lose: bool,
    ) -> Result<(), MobileStagingAirError> {
        let session = self.speaker()?.session.clone();
        // Anything the peer already has queued goes out first, and is not
        // taken for this send.
        self.pump(SPEAKER);
        session.send_chat(address, request).await.map_err(refused)?;
        self.losing = lose;
        let flushed = self.flush().await;
        self.losing = false;
        flushed
    }

    fn speaker(&self) -> Result<&Station, MobileStagingAirError> {
        self.stations
            .get(SPEAKER)
            .and_then(Option::as_ref)
            .ok_or(MobileStagingAirError::PeerUnavailable)
    }

    fn phone(&self) -> Result<String, MobileStagingAirError> {
        self.phone
            .map(|key| public_identity_record(&PublicKey(key)).canonical_address)
            .ok_or(MobileStagingAirError::NoPhone)
    }

    /// The newest message the speaking peer has from the phone, as its own
    /// store names it.
    fn last_heard(&self) -> Result<MobileChatRegardingRef, MobileStagingAirError> {
        let phone = self.phone()?;
        let page = self
            .speaker()?
            .store
            .as_ref()
            .ok_or(MobileStagingAirError::PeerUnavailable)?
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

    /// Shut every node down and stand them up afresh, the managed
    /// repeater's device too, with counters in a generation of their own:
    /// the old sessions may still be writing to theirs as they end.
    async fn reset(&mut self) {
        self.stations.clear();
        self.managed = None;
        // What the old repeater's tap queued is for a responder that is gone.
        while self.management_queue.try_recv().is_ok() {}
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

/// The phone, as a node registers it: its identity always advertises
/// itself as mobile.
fn phone_record(key: &[u8; 32]) -> MobilePeerRegistrationRecord {
    MobilePeerRegistrationRecord {
        address: public_identity_record(&PublicKey(*key)).canonical_address,
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

#[cfg(test)]
mod tests;
