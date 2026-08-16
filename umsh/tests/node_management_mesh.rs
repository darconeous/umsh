//! The Node Management binding carried by a real MAC.
//!
//! `umsh-node-mgmt`'s own integration test puts the two engines face to
//! face with the transport reduced to a function call, which is where the
//! binding's semantics are pinned down. This one puts a whole mesh between
//! them: two nodes on a simulated link, each with its own identity, secure
//! unicast doing the sealing, and the administrator half being the async
//! `NodeManager` that `umshctl manage` drives.
//!
//! What that adds is everything the engines deliberately know nothing
//! about — that a request reaches the device sealed and comes back
//! authenticated, that a response is attributed to the peer that sent it,
//! and that the administrator's loop terminates.

#![cfg(feature = "tokio-support")]

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::rng;

use umsh::core::{PayloadType, PublicKey};
use umsh::crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh::crypto::{CryptoEngine, NodeIdentity};
use umsh::hal::Radio;
use umsh::mac::test_support::{SimulatedNetwork, SimulatedRadio};
use umsh::mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh::node::{Host, LocalNode, PeerConnection, ReceivedPacketRef, Subscription};
use umsh::node_mgmt::device::{DeviceEngine, Dispatch, Ingress};
use umsh::node_mgmt::fragment::{continuable, produce};
use umsh::node_mgmt::{NodeManager, Outcome, Progress};
use umsh::tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform};
use umsh::ulcp_wire::ids::prop;
use umsh::ulcp_wire::{Cmd, Frame, MultiEntries, Status, frame, pui};
use umsh_sync::AsyncRefCell;
use umsh_ulcp_device::{
    AlertConfig, BatteryFields, DutyLedger, Effect, GnssConfig, MULTI_MAX, RadioSettings, Session,
    SessionConfig, TimeConfig,
};

/// What one Node Management payload carries, matching the ceiling the nRF
/// responder derives from its radio.
const PAYLOAD: usize = 180;

const IDENTITIES: usize = 1;
const PEERS: usize = 4;
const CHANNELS: usize = 1;
const ACKS: usize = 8;
const TX: usize = 8;
const FRAME: usize = 256;
const DUP: usize = 32;

type SimPlatform<R> = TokioPlatform<R, TokioFileCounterStore, TokioFileKeyValueStore>;
type SimMac<R> = Mac<SimPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type SimHandle<'a, R> =
    MacHandle<'a, SimPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

/// A test that stops making progress should fail rather than hang.
const PATIENCE: Duration = Duration::from_secs(30);

// ─── The device half ─────────────────────────────────────────────────────

/// The device as the mesh sees it: an authorization list, the binding's
/// device engine, and a real ULCP session behind them — the same three, in
/// the same order, as the firmware's responder.
struct DeviceSide {
    session: Session<SoftwareAes, SoftwareSha256>,
    engine: DeviceEngine<PAYLOAD, 2>,
    admins: Vec<[u8; 32]>,
    executed: u32,
    unauthorized: u32,
}

impl DeviceSide {
    fn new() -> Self {
        let config = SessionConfig {
            dev_version: "sim-dev/0.1",
            dev_model: Some("Simulated Board"),
            default_device_name: "Simulated Device",
            mtu: 255,
            sync_word: 0x1424,
            min_tx_power_dbm: -9,
            max_tx_power_dbm: 22,
            freq_khz_min: 150_000,
            freq_khz_max: 960_000,
            defaults: RadioSettings {
                enabled: false,
                freq_khz: 910_525,
                bw_hz: 62_500,
                sf: 7,
                cr_denom: 5,
                tx_power_dbm: 14,
            },
            default_duty_limit: 0xFFFF,
            duty: Box::leak(Box::new(DutyLedger::new())),
            battery: Some(BatteryFields {
                voltage: true,
                level: false,
                charge_state: true,
            }),
            alert: Some(AlertConfig::DEFAULT),
            time: Some(TimeConfig),
            gnss: Some(GnssConfig::DEFAULT),
            illuminance: true,
            // The simulated board is reachable over Bluetooth, so
            // `PROP_BLE_ENABLED` is one more property an administrator
            // can find over the mesh.
            ble: true,
        };
        let mut session = Session::new(
            config,
            Status::RESET_POWER_ON,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        // No host is attached: an administrator does not need one.
        session.attach(false);
        Self {
            session,
            engine: DeviceEngine::new(0x5AA5),
            admins: Vec::new(),
            executed: 0,
            unauthorized: 0,
        }
    }

    /// Provision an administrator over a secure local link, and mirror the
    /// resulting list the way the device-domain sync does.
    fn provision_admin(&mut self, key: &PublicKey) {
        let mut buf = [0u8; 64];
        let len = frame::prop_insert(&mut buf, 5, prop::DEV_ADMINS, &key.0).unwrap();
        let mut emitted = Vec::new();
        self.session.attach(true);
        self.session
            .handle_frame(&buf[..len], 0, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        self.session.attach(false);
        assert_eq!(
            Frame::parse(&emitted[0]).unwrap().command(),
            Some(Cmd::PropInserted),
            "the administrator was not accepted"
        );
        self.admins = vec![key.0];
    }

    /// Add a peer over the local link, to give the device state worth
    /// reading remotely.
    fn provision_peer(&mut self, key: &[u8; 32]) {
        let mut buf = [0u8; 64];
        let len = frame::prop_insert(&mut buf, 5, prop::DEV_PEERS, key).unwrap();
        self.session.attach(true);
        self.session
            .handle_frame(&buf[..len], 0, &mut |_bytes: &[u8]| {});
        self.session.attach(false);
    }

    /// Answer one Node Management Request payload, or say nothing at all.
    fn answer(&mut self, from: &PublicKey, payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        if !self.admins.iter().any(|listed| listed == &from.0) {
            self.unauthorized += 1;
            return None;
        }
        let generation = self.session.dev_domain_version() as u16;
        let mut out = [0u8; PAYLOAD];
        let mut cut = [0u8; PAYLOAD];
        let len = match self
            .engine
            .begin(&from.0, payload, generation, now_ms, &mut out)
        {
            Ingress::Drop(_) => return None,
            Ingress::Respond { len } => Some(len),
            Ingress::Dispatch(dispatch) => {
                self.executed += 1;
                let reply = self.serve(&dispatch, now_ms);
                let produced = produce(&reply, &dispatch, &mut cut);
                self.engine.complete(produced, &mut out).expect("complete")
            }
        };
        len.map(|len| out[..len].to_vec())
    }

    /// Run one frame through the session, serving the deferred platform
    /// round trips the way the driver's event loop does.
    fn serve(&mut self, dispatch: &Dispatch<'_>, now_ms: u64) -> Vec<u8> {
        let reply_budget = match dispatch.command() {
            Some(cmd) if continuable(cmd) => MULTI_MAX,
            _ => dispatch.budget,
        };
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut pending = self.session.handle_admin_frame(
            dispatch.frame,
            now_ms,
            reply_budget,
            &mut |bytes: &[u8]| emitted.push(bytes.to_vec()),
        );
        while let Some(effect) = pending.take() {
            if let Effect::SaveSnapshot { tid } = effect {
                self.session.respond_save(tid, Ok(()), &mut |bytes: &[u8]| {
                    emitted.push(bytes.to_vec())
                });
            }
            pending = self
                .session
                .resume_multi(now_ms, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        }
        self.session.end_admin_exchange();
        assert!(
            emitted.len() <= 1,
            "an administrative exchange answers with at most one frame"
        );
        emitted.pop().unwrap_or_default()
    }

    /// Read a property over the local binding, for checking what a remote
    /// write actually did.
    fn local_get(&mut self, key: u32) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 6, key).unwrap();
        let mut emitted = Vec::new();
        self.session
            .handle_frame(&buf[..len], 0, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        value_of(&emitted[0])
    }
}

// ─── The mesh ────────────────────────────────────────────────────────────

/// Requests the device took in, each with the administrator that sent it.
type Arrivals = Rc<RefCell<Vec<(PublicKey, Vec<u8>)>>>;

/// Both nodes, wired to a simulated link and ready to be driven.
///
/// The hosts are pumped by hand rather than spawned: the node layer is
/// `!Send`, and a test that owns its own scheduling cannot race itself.
struct Mesh<'a, R: Radio> {
    admin_host: Host<SimHandle<'a, R>>,
    device_host: Host<SimHandle<'a, R>>,
    manager: NodeManager<SimHandle<'a, R>>,
    device_peer: PeerConnection<LocalNode<SimHandle<'a, R>>>,
    device: Rc<RefCell<DeviceSide>>,
    /// Requests the device's receive callback took in, waiting for a turn
    /// where a response can be sent: a callback runs inside the
    /// coordinator's borrow and cannot await.
    arrivals: Arrivals,
    _subscription: Subscription,
    started: Instant,
}

impl<R: Radio> Mesh<'_, R>
where
    R::Error: core::fmt::Debug,
{
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Carry one operation to its end.
    async fn run(&mut self, request: &[u8]) -> Outcome {
        self.manager
            .begin(request, self.now_ms())
            .expect("nothing else is outstanding");
        let deadline = Instant::now() + PATIENCE;
        loop {
            assert!(Instant::now() < deadline, "the exchange never finished");
            match self
                .manager
                .service(self.now_ms())
                .await
                .expect("the administrator can send")
            {
                Progress::Done(outcome) => return outcome,
                Progress::Waiting { .. } => self.turn().await,
            }
        }
    }

    /// One turn of both hosts, plus whatever the device owes an answer to.
    async fn turn(&mut self) {
        tokio::select! {
            result = self.admin_host.pump_once() => result.expect("administrator host"),
            result = self.device_host.pump_once() => result.expect("device host"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        let arrivals: Vec<_> = self.arrivals.borrow_mut().drain(..).collect();
        for (from, payload) in arrivals {
            let now_ms = self.now_ms();
            let answer = self.device.borrow_mut().answer(&from, &payload, now_ms);
            let Some(answer) = answer else { continue };
            let mut response = Vec::with_capacity(1 + answer.len());
            response.push(PayloadType::NodeManagementResponse as u8);
            response.extend_from_slice(&answer);
            // The device asks for no acknowledgment: the administrator's
            // token retry is the reliability layer.
            self.device_peer
                .send(&response, &SendOptions::default())
                .await
                .expect("the device can answer");
        }
    }

    /// Reply frames only: a test that asked a question expects an answer.
    async fn reply(&mut self, request: &[u8]) -> Vec<u8> {
        match self.run(request).await {
            Outcome::Replied { .. } => self.manager.reply().to_vec(),
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    /// Drive the mesh for a while without insisting on an answer.
    async fn settle(&mut self, turns: usize) {
        for _ in 0..turns {
            let _ = self.manager.service(self.now_ms()).await;
            self.turn().await;
        }
    }
}

// ─── Frame readers ───────────────────────────────────────────────────────

fn value_of(frame: &[u8]) -> Vec<u8> {
    let parsed = Frame::parse(frame).unwrap();
    assert_eq!(parsed.command(), Some(Cmd::PropIs));
    let (_, consumed) = pui::decode(parsed.payload).unwrap();
    parsed.payload[consumed..].to_vec()
}

fn entries_of(frame: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let parsed = Frame::parse(frame).unwrap();
    assert_eq!(parsed.command(), Some(Cmd::PropAre));
    MultiEntries::new(parsed.payload)
        .map(|entry| entry.unwrap())
        .map(|entry| (entry.key, entry.value.to_vec()))
        .collect()
}

// ─── Bring-up ────────────────────────────────────────────────────────────

/// A temporary directory for one test's frame counters, removed with it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        Self(std::env::temp_dir().join(format!("umsh-node-mgmt-{name}-{unique}")))
    }

    fn join(&self, leaf: &str) -> PathBuf {
        self.0.join(leaf)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn build_mac<R: Radio>(radio: R, counters: PathBuf) -> SimMac<R> {
    Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rng(),
        TokioFileCounterStore::new(counters).expect("counter store"),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn link() -> (SimulatedRadio, SimulatedRadio) {
    let network = SimulatedNetwork::new();
    // A frame large enough for a full Node Management payload; the
    // simulated default is smaller than any real LoRa radio's.
    let admin = network.add_radio_with_config(255, 20);
    let device = network.add_radio_with_config(255, 20);
    network.connect_bidirectional(admin.id(), device.id());
    (admin, device)
}

/// Stand both nodes up around coordinators the caller owns.
///
/// The coordinators have to outlive the handles that borrow them, which is
/// why they are the caller's and not this function's.
async fn stand_up<'a, R: Radio>(
    admin_mac: &'a AsyncRefCell<SimMac<R>>,
    device_mac: &'a AsyncRefCell<SimMac<R>>,
) -> Mesh<'a, R> {
    let admin_identity = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
    let device_identity = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);
    let admin_key = *admin_identity.public_key();
    let device_key = *device_identity.public_key();

    let admin_handle = MacHandle::new(admin_mac);
    let device_handle = MacHandle::new(device_mac);
    let admin_id = admin_handle
        .add_identity(admin_identity)
        .await
        .expect("the administrator identity fits");
    let device_id = device_handle
        .add_identity(device_identity)
        .await
        .expect("the device identity fits");

    let mut admin_host = Host::new(admin_handle);
    let mut device_host = Host::new(device_handle);
    let admin_node = admin_host.add_node(admin_id);
    let device_node = device_host.add_node(device_id);
    let target = admin_node.peer(device_key).await.expect("peer");
    // Registering the administrator is what the device-domain sync does
    // for every key in `PROP_DEV_ADMINS`: without it the device can
    // neither unseal the request nor seal the answer.
    let device_peer = device_node.peer(admin_key).await.expect("peer");

    let mut side = DeviceSide::new();
    side.provision_admin(&admin_key);
    let device = Rc::new(RefCell::new(side));

    let arrivals = Rc::new(RefCell::new(Vec::new()));
    let subscription = {
        let arrivals = arrivals.clone();
        device_node.on_receive(move |packet: &ReceivedPacketRef<'_>| {
            if packet.payload_type() != PayloadType::NodeManagementRequest {
                return false;
            }
            let Some(from) = packet.from_key().filter(|_| packet.source_authenticated()) else {
                return false;
            };
            arrivals
                .borrow_mut()
                .push((from, packet.payload().to_vec()));
            true
        })
    };

    Mesh {
        admin_host,
        device_host,
        manager: NodeManager::new(target, 0x2A),
        device_peer,
        device,
        arrivals,
        _subscription: subscription,
        started: Instant::now(),
    }
}

/// `mesh!(name, binding)` — two nodes on a link, bound to `binding`.
macro_rules! mesh {
    ($name:literal, $mesh:ident) => {
        let scratch = Scratch::new($name);
        let (admin_radio, device_radio) = link();
        let admin_mac = AsyncRefCell::new(build_mac(admin_radio, scratch.join("admin")));
        let device_mac = AsyncRefCell::new(build_mac(device_radio, scratch.join("device")));
        #[allow(unused_mut)]
        let mut $mesh = stand_up(&admin_mac, &device_mac).await;
    };
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn an_administrator_reads_a_property_across_the_mesh() {
    mesh!("read", mesh);
    let mut buf = [0u8; 16];
    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    assert_eq!(value_of(&reply), b"Simulated Device");
    assert_eq!(mesh.device.borrow().executed, 1);
    assert_eq!(mesh.manager.stray(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_takes_effect_and_is_echoed_back() {
    mesh!("write", mesh);
    let mut buf = [0u8; 64];
    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Ridgeline").unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    assert_eq!(value_of(&reply), b"Ridgeline");
    assert_eq!(
        mesh.device.borrow_mut().local_get(prop::DEV_NAME),
        b"Ridgeline"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn several_properties_travel_in_one_exchange() {
    mesh!("multi", mesh);
    let keys = [prop::PROTOCOL_VERSION, prop::DEV_VERSION, prop::DEV_NAME];
    let mut buf = [0u8; 32];
    let len = frame::prop_multi_get(&mut buf, 0, &keys).unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    let entries = entries_of(&reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys.to_vec()
    );
    assert_eq!(entries[2].1, b"Simulated Device");
    assert_eq!(mesh.device.borrow().executed, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_read_larger_than_one_payload_is_continued_across_exchanges() {
    mesh!("cursor", mesh);
    // Enough state that the answer cannot fit one payload: each peer is
    // 32 octets of entry, and the whole table is read at once.
    for index in 0..6u8 {
        let mut key = [0x70u8; 32];
        key[31] = index;
        mesh.device.borrow_mut().provision_peer(&key);
    }

    let keys = [
        prop::DEV_PEERS,
        prop::DEV_ADMINS,
        prop::DEV_NAME,
        prop::CAPS,
    ];
    let mut buf = [0u8; 32];
    let len = frame::prop_multi_get(&mut buf, 0, &keys).unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    let entries = entries_of(&reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys.to_vec(),
        "the reassembled entry list covers every slot"
    );
    assert_eq!(entries[0].1.len(), 6 * 32);
    assert!(
        mesh.device.borrow().executed > 1,
        "a continued read takes several exchanges"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_reset_is_answered_by_the_acknowledgment_and_nothing_else() {
    mesh!("reset", mesh);
    let mut buf = [0u8; 8];
    let len = frame::reset(&mut buf, 0).unwrap();
    assert_eq!(mesh.run(&buf[..len]).await, Outcome::NoResponse);
    assert_eq!(mesh.device.borrow().executed, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn an_unlisted_administrator_is_answered_by_silence() {
    mesh!("unlisted", mesh);
    // The device forgets who may manage it, without telling anyone.
    mesh.device.borrow_mut().admins.clear();
    let mut buf = [0u8; 16];
    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    mesh.manager.begin(&buf[..len], mesh.now_ms()).unwrap();
    // Waiting out the whole attempt budget would take half a minute and
    // prove nothing further: what matters is that the request arrived,
    // was refused, and drew no answer.
    mesh.settle(8).await;
    assert!(mesh.manager.is_busy(), "still waiting on an answer");
    assert!(mesh.device.borrow().unauthorized > 0);
    assert_eq!(mesh.device.borrow().executed, 0);
}
