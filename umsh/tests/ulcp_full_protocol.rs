//! Adapter-free full-protocol integration tests: the host-side
//! [`UlcpDevice`] workflow driven end-to-end against the **real**
//! ULCP session engine (`umsh_ulcp_device::Session`) — the same state
//! machine both firmware targets run — with persistence, the radio,
//! and time simulated in RAM. No fake device re-implementation sits in
//! between, so a behavior proven here can only diverge on hardware at
//! the framing, storage, or radio boundary, and the per-command trace
//! places a failure at whichever boundary broke.
//!
//! The flagship test executes the increment-9 hardware script
//! in-process: provision → save → power-cycle → autonomous detached
//! operation with delegated acknowledgement → reattach → ownership
//! verification → drain.

#![cfg(feature = "tokio-support")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use umsh::hal::Radio as _;
use umsh::ulcp::{
    FrameLink, HostOwnership, HostProvisioning, SavedSnapshot, UlcpDevice, UlcpDeviceConfig,
    UlcpError, describe_frame,
};
use umsh_core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PacketType};
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_crypto::{CryptoEngine, NodeIdentity as _, PairwiseKeys};
use umsh_ulcp::Status;
use umsh_ulcp::ids::cap;
use umsh_ulcp::items::{Filter, PeerKeyEntry};
use umsh_ulcp::meta::{BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED};
use umsh_ulcp_device::{
    Effect, IdentitySource, RadioRxInfo, RadioSettings, SNAPSHOT_MAX, SessionConfig, TxOutcome,
};

type Session = umsh_ulcp_device::Session<SoftwareAes, SoftwareSha256>;

const HOST_KEY: [u8; 32] = [0xC4; 32];
const PEER_PUB: [u8; 32] = [0x0A; 32];

fn engine() -> CryptoEngine<SoftwareAes, SoftwareSha256> {
    CryptoEngine::new(SoftwareAes, SoftwareSha256)
}

fn session_config() -> SessionConfig {
    SessionConfig {
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
        // One leaked ledger per simulated device: sessions in parallel
        // tests must not share duty state.
        duty: Box::leak(Box::new(umsh_ulcp_device::DutyLedger::new())),
        // The simulator reports all three battery measurements.
        battery: Some(umsh_ulcp_device::BatteryFields {
            voltage: true,
            level: true,
            charge_state: true,
        }),
        // A simulated device has nothing to flash or beep with, so it
        // does not advertise CAP_ALERT.
        alert: None,
        // It does keep a clock and a synthetic receiver, so the host
        // wrappers for both are exercised against the real session
        // rather than only against a firmware nobody can run in CI.
        time: Some(umsh_ulcp_device::TimeConfig),
        gnss: Some(umsh_ulcp_device::GnssConfig::DEFAULT),
        // And a synthetic light sensor, so the host wrapper is exercised
        // against the real session too.
        illuminance: true,
        ble: true,
        ble_pairing: true,
        reboot: true,
        stats: None,
        mac_node: true,
    }
}

/// The simulated device: the real session engine plus RAM stand-ins for
/// everything the firmware supplies — the snapshot and identity
/// journals, the radio, the entropy source, and the clock.
struct SimDevice {
    session: Session,
    /// Frames the device emitted toward the host.
    out: VecDeque<Vec<u8>>,
    /// Frames the device transmitted on the (simulated) air.
    air: Vec<Vec<u8>>,
    /// Durable snapshot journal.
    snapshot: Option<Vec<u8>>,
    /// Durable identity journal: (secret, public).
    identity: Option<([u8; 32], [u8; 32])>,
    /// Deterministic stand-in for the hardware TRNG.
    identity_seed: u8,
    now_ms: u64,
    /// The simulated wall clock, unset until something sets it.
    epoch: Option<u32>,
    /// Per-command capture, both directions.
    log: Vec<String>,
}

impl SimDevice {
    /// Bonds this simulated transport pretends to be holding, so a wipe
    /// has something to remove.
    const BONDS: u8 = 2;

    fn new() -> Arc<Mutex<Self>> {
        let mut session = Session::new(session_config(), Status::RESET_POWER_ON, engine());
        session.set_ble_bond_count(Self::BONDS, &mut |_| {});
        Arc::new(Mutex::new(Self {
            session,
            out: VecDeque::new(),
            air: Vec::new(),
            snapshot: None,
            identity: None,
            identity_seed: 0,
            now_ms: 0,
            epoch: None,
            log: Vec::new(),
        }))
    }

    /// Come up from the durable journals the way the firmware does:
    /// identity installed and the saved snapshot restored, before any
    /// host command is served.
    fn boot(&mut self) {
        // Bonds live in a journal of their own, so a reboot finds exactly
        // the ones it left — including none, after a wipe.
        let bonds = self.session.ble_bond_count();
        self.session = Session::new(session_config(), Status::RESET_POWER_ON, engine());
        self.session.set_ble_bond_count(bonds, &mut |_| {});
        if let Some((_, public)) = self.identity {
            self.session.set_boot_identity(public);
        }
        if let Some(snapshot) = self.snapshot.clone() {
            let restored = self.session.restore_at_boot(&snapshot);
            assert!(restored.is_ok(), "saved snapshot must restore at boot");
        }
    }

    /// The synthetic receiver's view: a three-dimensional fix while the
    /// receiver is enabled, and the searching state while it is not.
    fn gnss_sample(&self) -> umsh_ulcp::gnss::GnssSnapshot {
        if !self.session.gnss_enabled() {
            return umsh_ulcp::gnss::GnssSnapshot::SEARCHING;
        }
        let mut snapshot = umsh_ulcp::gnss::GnssSnapshot::SEARCHING;
        snapshot.fix = umsh_ulcp::gnss::FixKind::ThreeD;
        snapshot.altitude_m = Some(31);
        snapshot.accuracy_dm = Some(60);
        snapshot.sats_used = 9;
        snapshot.sats_in_view = Some(13);
        snapshot.set_location(&[0x8a, 0x1f, 0x4c, 0x00, 0xd3]);
        snapshot
    }

    /// Execute one session effect the way the firmware's effect arms
    /// do, collecting any frames the completion emits.
    fn execute(&mut self, effect: Option<Effect>, emitted: &mut Vec<Vec<u8>>) {
        let mut emit = |frame: &[u8]| emitted.push(frame.to_vec());
        match effect {
            None
            | Some(Effect::ApplyRadio(_))
            | Some(Effect::DeviceNameChanged)
            | Some(Effect::ApplyAlert(_)) => {}
            // The simulator has no platform to wipe and reboot; a
            // factory reset is exercised against real firmware.
            Some(Effect::FactoryReset) => panic!("simulator does not implement CMD_FACTORY_RESET"),
            // A power cycle and nothing else: the journals survive, the
            // session comes back announcing its power-on reset, and the
            // saved snapshot is replayed the way a board replays it on
            // the way up. Nothing is emitted — on hardware the reboot
            // drops the link before anything could be.
            Some(Effect::Reboot) => self.boot(),
            Some(Effect::StartTransmit) => {
                self.air.push(self.session.tx_data().to_vec());
                self.session
                    .on_tx_result(TxOutcome::Sent, self.now_ms, &mut emit);
            }
            Some(Effect::SampleRssi { tid }) => {
                self.session.respond_rssi(tid, Ok(-77), &mut emit);
            }
            Some(Effect::SampleBattery { tid }) => {
                // Stable simulated measurement matching the simulator's
                // configured field set (all three fields).
                self.session.respond_battery(
                    tid,
                    Ok(umsh_ulcp::battery::BatteryStatus {
                        voltage_mv: Some(4111),
                        level_percent: Some(87),
                        charge_state: Some(umsh_ulcp::battery::BatteryChargeState::Charging),
                    }),
                    &mut emit,
                );
            }
            Some(Effect::SampleIlluminance { tid }) => {
                // A stable simulated reading: ordinary office lighting.
                self.session
                    .respond_illuminance(tid, Some(320_000), &mut emit);
            }
            Some(Effect::SetPairingPin { tid, .. }) => {
                self.session.respond_pin_set(tid, Ok(()), &mut emit);
            }
            Some(Effect::ClearBleBonds { tid }) => {
                self.session.set_ble_bond_count(0, &mut emit);
                self.session.respond_ble_bond_count(tid, Ok(()), &mut emit);
            }
            Some(Effect::SetBlePairing { tid, open }) => {
                self.session.respond_ble_pairing(tid, Ok(open), &mut emit);
            }
            Some(Effect::ReadTime { tid }) => {
                self.session.respond_time(tid, self.epoch, &mut emit);
            }
            Some(Effect::ApplyTime { epoch }) => self.epoch = epoch,
            Some(Effect::SampleGnss { tid, key }) => {
                let sample = self.gnss_sample();
                self.session.respond_gnss(tid, key, Ok(sample), &mut emit);
            }
            Some(Effect::DrainQueue) => while self.session.drain_step(self.now_ms, &mut emit) {},
            Some(Effect::SaveSnapshot { tid }) => {
                let mut buf = [0u8; SNAPSHOT_MAX];
                let result = match self.session.encode_snapshot(&mut buf) {
                    Some(len) => {
                        self.snapshot = Some(buf[..len].to_vec());
                        Ok(())
                    }
                    None => Err(()),
                };
                self.session.respond_save(tid, result, &mut emit);
            }
            Some(Effect::ClearSaved { tid }) => {
                self.snapshot = None;
                self.identity = None;
                self.session.respond_clear(tid, Ok(()), &mut emit);
            }
            // No test reads PROP_IDENT yet; the simulator mirrors a
            // platform without a signer until the shared identity
            // responder lands.
            Some(Effect::SignIdentity { tid }) => {
                self.session.respond_identity_blob(tid, Err(()), &mut emit);
            }
            Some(Effect::ProvisionIdentity { tid }) => {
                let result = match self.session.identity_request() {
                    Some(source) => {
                        let secret = match source {
                            IdentitySource::Install(secret) => secret,
                            IdentitySource::Generate => {
                                self.identity_seed += 1;
                                [self.identity_seed; 32]
                            }
                        };
                        let public = SoftwareIdentity::from_secret_bytes(&secret).public_key().0;
                        self.identity = Some((secret, public));
                        Ok(public)
                    }
                    None => Err(()),
                };
                self.session.respond_identity(tid, result, &mut emit);
            }
        }
    }

    /// Log and queue everything the session emitted toward the host.
    fn finish(&mut self, emitted: Vec<Vec<u8>>) {
        for frame in emitted {
            self.log
                .push(format!("device→host {}", describe_frame(&frame)));
            self.out.push_back(frame);
        }
    }
}

/// [`FrameLink`] straight into the simulated device: frames are handled
/// synchronously by the real session, so responses are ready before
/// `send_frame` returns.
struct SessionLink {
    sim: Arc<Mutex<SimDevice>>,
}

impl FrameLink for SessionLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        let mut sim = self.sim.lock().unwrap();
        sim.log
            .push(format!("host→device {}", describe_frame(frame)));
        let now_ms = sim.now_ms;
        let mut emitted = Vec::new();
        let mut pending = sim
            .session
            .handle_frame(frame, now_ms, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        // As in the firmware driver: a multi-property command comes back
        // here once per deferred value, and `resume_multi` carries it to
        // the next entry until the reply is emitted.
        while pending.is_some() {
            sim.execute(pending.take(), &mut emitted);
            pending = sim
                .session
                .resume_multi(now_ms, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        }
        sim.finish(emitted);
        Ok(())
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        let mut sim = self.sim.lock().unwrap();
        match sim.out.pop_front() {
            Some(frame) => core::task::Poll::Ready(Ok(frame)),
            None => {
                // Frames only appear synchronously from our own
                // send_frame; self-wake so timeouts still resolve.
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }
    }
}

fn attach(sim: &Arc<Mutex<SimDevice>>, link_secure: bool) {
    sim.lock().unwrap().session.attach(link_secure);
}

fn detach(sim: &Arc<Mutex<SimDevice>>) {
    sim.lock().unwrap().session.detach();
}

/// Simulate a power cycle: a fresh session boots from the durable
/// journals exactly as the firmware does — identity installed and the
/// snapshot restored before any host command.
fn power_cycle(sim: &Arc<Mutex<SimDevice>>) {
    let mut sim = sim.lock().unwrap();
    sim.session = Session::new(session_config(), Status::RESET_POWER_ON, engine());
    if let Some((_, public)) = sim.identity {
        sim.session.set_boot_identity(public);
    }
    if let Some(snapshot) = sim.snapshot.clone() {
        let restored = sim.session.restore_at_boot(&snapshot);
        assert!(restored.is_ok(), "saved snapshot must restore at boot");
    }
    sim.now_ms += 60_000;
    sim.log.push("(power cycle)".to_owned());
}

/// Deliver one frame from the (simulated) air while the session is in
/// whatever attach state the test arranged.
fn inject_radio_rx(sim: &Arc<Mutex<SimDevice>>, frame: &[u8]) {
    let mut sim = sim.lock().unwrap();
    let now_ms = sim.now_ms;
    let mut emitted = Vec::new();
    let effect = sim.session.on_radio_rx(
        frame,
        &RadioRxInfo::measured(-80, 40, None),
        now_ms,
        &mut |bytes: &[u8]| emitted.push(bytes.to_vec()),
    );
    sim.execute(effect, &mut emitted);
    sim.finish(emitted);
}

async fn attached_host(sim: &Arc<Mutex<SimDevice>>) -> UlcpDevice<SessionLink> {
    attach(sim, true);
    UlcpDevice::attach_existing(SessionLink { sim: sim.clone() }, host_config())
        .await
        .expect("attach handshake")
}

fn host_config() -> UlcpDeviceConfig {
    let mut config = UlcpDeviceConfig::new(906_875, 250_000, 9, 5);
    config.tx_power_dbm = 10;
    config.response_timeout = std::time::Duration::from_millis(500);
    config
}

fn test_pairwise() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [0xE0; 32],
        k_mic: [0x50; 32],
    }
}

fn desired_provisioning() -> HostProvisioning {
    HostProvisioning {
        host_key: HOST_KEY,
        filters: vec![Filter::PktType(PacketType::Multicast as u8)],
        channel_keys: vec![[0x42; 32]],
        peer_keys: vec![PeerKeyEntry {
            public_key: PEER_PUB,
            k_enc: test_pairwise().k_enc,
            k_mic: test_pairwise().k_mic,
        }],
        auto_ack: true,
    }
}

/// A sealed, acknowledgement-requesting unicast frame from the
/// provisioned peer to the host, as it would arrive over the air.
fn sealed_unicast(counter: u32) -> Vec<u8> {
    let mut buf = [0u8; 96];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(NodeHint([0xC4, 0xC4, 0xC4]))
        .source_hint(NodeHint([0x0A, 0x0A, 0x0A]))
        .frame_counter(counter)
        .ack_requested()
        .mic_size(MicSize::Mic8)
        .payload(&[3, 1, 2])
        .build()
        .unwrap();
    engine().seal_packet(&mut packet, &test_pairwise()).unwrap();
    packet.as_bytes().to_vec()
}

async fn configure_and_enable_phy(radio: &mut UlcpDevice<SessionLink>) {
    let config = host_config();
    radio
        .set_prop(
            umsh::ulcp_wire::ids::prop::PHY_FREQ,
            &config.freq_khz.to_le_bytes(),
        )
        .await
        .unwrap();
    radio
        .set_prop(
            umsh::ulcp_wire::ids::prop::PHY_LORA_BW,
            &config.bandwidth_hz.to_le_bytes(),
        )
        .await
        .unwrap();
    radio
        .set_prop(umsh::ulcp_wire::ids::prop::PHY_ENABLED, &[1])
        .await
        .unwrap();
}

/// The full increment-9 hardware script, in-process: provision the
/// host domain and device identity, save, power-cycle with no host,
/// operate autonomously (queue + delegated ack), reattach, verify
/// ownership, reconcile (a no-op — no secret crosses the link again),
/// and drain the acknowledged frame.
#[tokio::test]
async fn full_lifecycle_provision_save_power_cycle_autonomy_reattach_drain() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    // Capture the host-side trace alongside the harness log.
    let trace: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = trace.clone();
    radio.set_frame_trace(Some(Box::new(move |direction, line| {
        sink.lock().unwrap().push(format!("{direction} {line}"));
    })));

    // Fresh device: full capability set, unclaimed, nothing saved.
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert!(sync.reset_since_last_contact);
    assert_eq!(sync.last_status, Status::RESET_POWER_ON);
    assert_eq!(sync.ownership, HostOwnership::Unclaimed);
    for capability in [
        cap::HOST_FILTER,
        cap::HOST_RX_QUEUE,
        cap::HOST_KEYS,
        cap::HOST_AUTO_ACK,
        cap::SAVE,
        cap::DEV_IDENTITY,
    ] {
        assert!(sync.has_capability(capability), "missing cap {capability}");
    }
    assert_eq!(sync.saved, Some(SavedSnapshot::None));
    assert_eq!(sync.queue_count, Some(0));
    assert!(!sync.phy_enabled);
    assert_eq!(sync.dev_key, None);
    assert_eq!(sync.device_name, "Simulated Device");

    // Device identity: generated on-device once, then stable.
    let dev_key = radio.ensure_device_identity().await.unwrap();
    assert_eq!(radio.ensure_device_identity().await.unwrap(), dev_key);
    assert_eq!(
        sim.lock().unwrap().identity_seed,
        1,
        "exactly one generation"
    );

    // Provision the host domain, configure the PHY, and persist.
    let report = radio.provision(&desired_provisioning()).await.unwrap();
    assert!(report.host_replaced);
    assert!(report.filters_replaced);
    assert_eq!(report.channels_inserted, 1);
    assert_eq!(report.peers_inserted, 1);
    assert!(report.auto_ack_changed);
    configure_and_enable_phy(&mut radio).await;
    radio.save().await.unwrap();

    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.ownership, HostOwnership::Ours);
    assert_eq!(sync.saved, Some(SavedSnapshot::Current));
    assert!(sync.phy_enabled);
    assert_eq!(sync.dev_key, Some(dev_key));

    // Autonomous detached operation while still powered: the host
    // domain outlives the disconnect, so the peer's frame is accepted,
    // queued, and acknowledged on the host's behalf.
    drop(radio);
    detach(&sim);
    inject_radio_rx(&sim, &sealed_unicast(5));
    {
        let sim = sim.lock().unwrap();
        assert_eq!(sim.air.len(), 1, "delegated ack must transmit");
        let header = PacketHeader::parse(&sim.air[0]).unwrap();
        assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    }

    // A power cycle is where it ends. The device domain comes back from
    // the snapshot — PHY configured and enabled, identity intact — and
    // the host domain does not, taking the queue with it.
    power_cycle(&sim);
    let mut radio = attached_host(&sim).await;
    let sink = trace.clone();
    radio.set_frame_trace(Some(Box::new(move |direction, line| {
        sink.lock().unwrap().push(format!("{direction} {line}"));
    })));
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert!(sync.reset_since_last_contact);
    assert_eq!(sync.ownership, HostOwnership::Unclaimed);
    assert_eq!(sync.saved, Some(SavedSnapshot::Current));
    assert_eq!(sync.queue_count, Some(0));
    assert_eq!(sync.auto_ack, Some(false));
    assert_eq!(
        sync.dev_key,
        Some(dev_key),
        "identity survives the power cycle"
    );
    assert!(sync.phy_enabled, "snapshot re-enabled the PHY at boot");
    assert_eq!(sync.freq_khz, host_config().freq_khz);

    // Re-provisioning is unconditional and complete: every table is
    // written again whether or not the device already agreed.
    let report = radio.provision(&desired_provisioning()).await.unwrap();
    assert!(report.host_replaced);
    assert_eq!(report.peers_inserted, 1);
    assert_eq!(report.channels_inserted, 1);

    // ...and doing it a second time, against a device that now holds
    // exactly this domain, still writes everything.
    let report = radio.provision(&desired_provisioning()).await.unwrap();
    assert!(!report.host_replaced, "the key already matches");
    assert_eq!(report.peers_inserted, 1, "key material is re-asserted");
    assert_eq!(report.peers_removed, 0);

    // Detached queueing works again on the re-provisioned domain.
    drop(radio);
    detach(&sim);
    inject_radio_rx(&sim, &sealed_unicast(6));
    let mut radio = attached_host(&sim).await;
    let sink = trace.clone();
    radio.set_frame_trace(Some(Box::new(move |direction, line| {
        sink.lock().unwrap().push(format!("{direction} {line}"));
    })));
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.queue_count, Some(1));

    // Drain when ready: the buffered frame carries its acknowledged
    // flag so the host knows not to re-ack it.
    let mut drained: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    radio
        .queue_drain_with(|data, meta| drained.push((data.to_vec(), meta.to_vec())))
        .await
        .unwrap();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].0, sealed_unicast(6));
    let meta = BufferedRxMeta::decode(&drained[0].1).unwrap();
    assert_eq!(
        meta.flags & (RX_FLAG_BUFFERED | RX_FLAG_ACKED),
        RX_FLAG_BUFFERED | RX_FLAG_ACKED
    );

    // The same frame surfaces through the ordinary receive path wearing
    // its buffered-delivery metadata, so a MAC fed from this handle can
    // suppress the duplicate ack and backdate the reception.
    let mut rx_buf = [0u8; 256];
    let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut rx_buf))
        .await
        .unwrap();
    assert_eq!(&rx_buf[..info.len], sealed_unicast(6).as_slice());
    let buffered = info.buffered.expect("a drained frame reports as buffered");
    assert!(buffered.acked);

    // The capture places every full-protocol command on the record.
    let trace = trace.lock().unwrap();
    for needle in [
        "PROP_CAPS",
        "PROP_HOST_KEY",
        "PROP_DEV_KEY",
        "QueueDrain",
        "StrRecv",
    ] {
        assert!(
            trace.iter().any(|line| line.contains(needle)),
            "trace missing {needle}: {trace:#?}"
        );
    }
    let log = &sim.lock().unwrap().log;
    assert!(log.iter().any(|line| line.contains("Save tid=")));
}

/// A returning host discovers another identity owns the radio; taking
/// it over durably wipes the previous host's provisioning, so not even
/// a power cycle resurrects it.
#[tokio::test]
async fn other_host_detection_and_takeover_wipes_durably() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;
    radio.provision(&desired_provisioning()).await.unwrap();
    radio.save().await.unwrap();

    // A different host attaches and checks ownership first.
    let other_key = [0xBB; 32];
    let sync = radio.sync(Some(&other_key)).await.unwrap();
    assert_eq!(sync.ownership, HostOwnership::OtherHost(HOST_KEY));

    // Taking over replaces the host domain; the previous host's tables
    // are gone.
    let mut takeover = desired_provisioning();
    takeover.host_key = other_key;
    takeover.channel_keys = vec![[0x77; 32]];
    takeover.peer_keys = Vec::new();
    let report = radio.provision(&takeover).await.unwrap();
    assert!(report.host_replaced);
    let sync = radio.sync(Some(&other_key)).await.unwrap();
    assert_eq!(sync.ownership, HostOwnership::Ours);
    assert_eq!(sync.host_peer_keys.as_deref(), Some(&[][..]));

    // The replacement's durable wipe outlives a power cycle: the new
    // host never saved, so the radio boots with the old snapshot's
    // device domain and a defaulted host domain.
    drop(radio);
    detach(&sim);
    power_cycle(&sim);
    let mut radio = attached_host(&sim).await;
    let sync = radio.sync(Some(&other_key)).await.unwrap();
    assert_eq!(
        sync.ownership,
        HostOwnership::Unclaimed,
        "a power cycle must not resurrect any host's provisioning"
    );
}

/// Channel reconciliation: keys the device is missing are inserted
/// individually, but an identifier the host holds no key for forces an
/// atomic whole-table replacement (its remove selector is the key).
#[tokio::test]
async fn channel_reconciliation_inserts_or_replaces() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;
    let mut desired = desired_provisioning();
    desired.channel_keys = vec![[0x41; 32], [0x42; 32]];
    radio.provision(&desired).await.unwrap();

    // Growing the set only inserts the new key.
    desired.channel_keys.push([0x43; 32]);
    let report = radio.provision(&desired).await.unwrap();
    assert!(!report.host_replaced && !report.channels_replaced);
    assert_eq!(report.channels_inserted, 1);

    // Dropping a key the device still holds forces the whole-table form.
    desired.channel_keys = vec![[0x41; 32], [0x43; 32]];
    let report = radio.provision(&desired).await.unwrap();
    assert!(report.channels_replaced);
    assert_eq!(report.channels_inserted, 0);
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.host_channel_ids.map(|ids| ids.len()), Some(2));
}

/// A full 16-frame device queue drains losslessly through the drain
/// callback even though it is larger than the host driver's bounded
/// receive buffer — the exact failure the T-1000E hardware pass
/// caught: the callback used to miss every frame the bounded buffer
/// evicted mid-drain.
#[tokio::test]
async fn full_queue_drains_losslessly_through_the_callback() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;
    radio.provision(&desired_provisioning()).await.unwrap();
    configure_and_enable_phy(&mut radio).await;
    drop(radio);
    detach(&sim);

    // 19 distinct frames into a 16-slot queue: 3 evictions.
    for counter in 1..=19u32 {
        inject_radio_rx(&sim, &sealed_unicast(counter));
    }

    let mut radio = attached_host(&sim).await;
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.queue_count, Some(16));
    assert_eq!(sync.queue_dropped, Some(3));
    let mut drained = Vec::new();
    radio
        .queue_drain_with(|data, _meta| drained.push(data.to_vec()))
        .await
        .unwrap();
    assert_eq!(drained.len(), 16, "every queued frame reaches the callback");
    assert_eq!(
        drained[0],
        sealed_unicast(4),
        "oldest surviving frame first"
    );
    assert_eq!(drained[15], sealed_unicast(19));
}

/// Over a transport that does not meet its provisioning-security
/// binding the device refuses key material, and the host surfaces the
/// status; non-secret provisioning still works.
#[tokio::test]
async fn insecure_link_refuses_key_provisioning() {
    let sim = SimDevice::new();
    attach(&sim, false);
    let mut radio = UlcpDevice::attach_existing(SessionLink { sim: sim.clone() }, host_config())
        .await
        .unwrap();

    match radio.ensure_device_identity().await {
        Err(UlcpError::Status(status)) => {
            assert_eq!(status, Status::INVALID_STATE)
        }
        other => panic!("expected INVALID_STATE, got {other:?}"),
    }
    match radio.provision(&desired_provisioning()).await {
        Err(UlcpError::Status(status)) => {
            assert_eq!(status, Status::INVALID_STATE)
        }
        other => panic!("expected INVALID_STATE, got {other:?}"),
    }
    // The ungated pieces (host key, filters) were accepted before the
    // gate refused the channel key; ownership is already established.
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.ownership, HostOwnership::Ours);
}

#[tokio::test]
async fn battery_status_samples_through_the_typed_accessor() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    // The capability is advertised and each read round-trips a sampled
    // snapshot through Effect::SampleBattery; battery is deliberately
    // not part of sync.
    let status = radio
        .battery_status()
        .await
        .unwrap()
        .expect("simulator advertises CAP_BATTERY");
    assert_eq!(status.voltage_mv, Some(4111));
    assert_eq!(status.level_percent, Some(87));
    assert_eq!(
        status.charge_state,
        Some(umsh::ulcp_wire::battery::BatteryChargeState::Charging)
    );
}

/// The clock a device does not have is reported as not having one, which
/// is the state a device with a screen must show nothing for.
#[tokio::test]
async fn the_wall_clock_starts_unset_and_survives_a_round_trip() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    let time = radio
        .time()
        .await
        .unwrap()
        .expect("simulator advertises CAP_TIME");
    assert_eq!(time.epoch, None, "a device starts not knowing the time");
    assert_eq!(time.tz_offset_min, 0);

    assert_eq!(
        radio.set_time(Some(1_780_000_000)).await.unwrap(),
        Some(1_780_000_000)
    );
    assert_eq!(radio.set_tz_offset(-480).await.unwrap(), -480);
    let time = radio.time().await.unwrap().unwrap();
    assert_eq!(time.epoch, Some(1_780_000_000));
    assert_eq!(time.tz_offset_min, -480);

    // Clearing is a legitimate operation, not an error: it returns the
    // device to not knowing.
    assert_eq!(radio.set_time(None).await.unwrap(), None);
    assert_eq!(radio.time().await.unwrap().unwrap().epoch, None);
    // The zone is configuration and is unaffected by the clock.
    assert_eq!(radio.time().await.unwrap().unwrap().tz_offset_min, -480);
}

/// The two announcement schedules are independent knobs, and both are
/// device-domain settings a power cycle restores.
#[tokio::test]
async fn advertisement_policy_is_two_independent_schedules_that_persist() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    let policy = radio
        .advert_policy()
        .await
        .unwrap()
        .expect("simulator advertises CAP_ADVERT");
    assert_eq!(policy.advert_interval_s, 4 * 60 * 60);
    assert_eq!(policy.beacon_interval_s, 60 * 60);
    assert!(policy.startup_beacon);

    // Each moves without disturbing the other, and zero is the off
    // switch rather than a rejected value.
    assert_eq!(radio.set_advert_interval(0).await.unwrap(), 0);
    assert_eq!(radio.set_beacon_interval(1800).await.unwrap(), 1800);
    assert!(!radio.set_startup_beacon(false).await.unwrap());
    let policy = radio.advert_policy().await.unwrap().unwrap();
    assert_eq!(policy.advert_interval_s, 0);
    assert_eq!(policy.beacon_interval_s, 1800);
    assert!(!policy.startup_beacon);

    // Outside the bounds at either end is a mistake, not a schedule.
    assert!(radio.set_beacon_interval(30).await.is_err());
    assert!(radio.set_beacon_interval(48 * 60 * 60).await.is_err());

    radio.save().await.unwrap();
    drop(radio);
    detach(&sim);
    power_cycle(&sim);
    let mut radio = attached_host(&sim).await;
    let policy = radio.advert_policy().await.unwrap().unwrap();
    assert_eq!(policy.advert_interval_s, 0);
    assert_eq!(policy.beacon_interval_s, 1800);
    assert!(!policy.startup_beacon);
}

/// Every positioning property folds back into one snapshot, and a
/// receiver that is off reports being off rather than failing.
#[tokio::test]
async fn positioning_reports_the_receiver_state_and_the_fix() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    let status = radio
        .gnss_status()
        .await
        .unwrap()
        .expect("simulator advertises CAP_GNSS");
    assert!(!status.enabled, "the receiver starts off");
    assert_eq!(status.fix.fix, umsh::ulcp_wire::gnss::FixKind::None);
    assert_eq!(status.fix.sats_used, 0);
    assert_eq!(status.fix.location(), &[] as &[u8]);
    assert_eq!(status.fix.altitude_m, None);
    assert_eq!(status.fix.accuracy_dm, None);
    assert!(status.time_trust, "time trust is on by default");
    assert!(!status.ident_update);
    assert_eq!(status.ident_precision, 5);

    assert!(radio.set_gnss_enabled(true).await.unwrap());
    let status = radio.gnss_status().await.unwrap().unwrap();
    assert!(status.enabled);
    assert_eq!(status.fix.fix, umsh::ulcp_wire::gnss::FixKind::ThreeD);
    assert_eq!(status.fix.location(), &[0x8a, 0x1f, 0x4c, 0x00, 0xd3]);
    assert_eq!(status.fix.altitude_m, Some(31));
    assert_eq!(status.fix.accuracy_dm, Some(60));
    assert_eq!(status.fix.sats_used, 9);
    assert_eq!(status.fix.sats_in_view, Some(13));

    // The policy is independent of the switch.
    assert!(radio.set_gnss_ident_update(true).await.unwrap());
    assert_eq!(radio.set_gnss_ident_precision(3).await.unwrap(), 3);
    assert!(!radio.set_gnss_time_trust(false).await.unwrap());
    let status = radio.gnss_status().await.unwrap().unwrap();
    assert!(status.ident_update);
    assert_eq!(status.ident_precision, 3);
    assert!(!status.time_trust);
}

/// Several properties in one exchange, against the real session: values
/// the session holds, values it has to sample from the platform, and a
/// property that does not exist all come back in request order.
#[tokio::test]
async fn several_properties_travel_in_one_exchange() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    let keys = [
        umsh_ulcp::ids::prop::PHY_TX_POWER,
        umsh_ulcp::ids::prop::TIME,
        60_000,
        umsh_ulcp::ids::prop::PHY_LORA_SF,
    ];
    let answers = radio.get_props(&keys).await.unwrap();

    assert_eq!(answers.len(), keys.len());
    assert_eq!(
        answers[0].as_ref().unwrap(),
        &(umsh_ulcp::ids::prop::PHY_TX_POWER, vec![14])
    );
    // The clock is deferred to the platform and still lands in its slot;
    // the simulator boots without one set, so the value is empty.
    assert_eq!(
        answers[1].as_ref().unwrap(),
        &(umsh_ulcp::ids::prop::TIME, Vec::new())
    );
    assert_eq!(answers[2], Err(Status::PROP_NOT_FOUND));
    assert_eq!(
        answers[3].as_ref().unwrap(),
        &(umsh_ulcp::ids::prop::PHY_LORA_SF, vec![7])
    );

    // Writes apply in order and echo the authoritative value.
    let applied = radio
        .set_props(&[
            (umsh_ulcp::ids::prop::PHY_TX_POWER, vec![20]),
            (umsh_ulcp::ids::prop::PHY_LORA_SF, vec![9]),
        ])
        .await
        .unwrap();
    assert_eq!(applied.len(), 2);
    assert_eq!(
        applied[0].as_ref().unwrap(),
        &(umsh_ulcp::ids::prop::PHY_TX_POWER, vec![20])
    );
    assert_eq!(
        radio
            .get_prop(umsh_ulcp::ids::prop::PHY_LORA_SF)
            .await
            .unwrap(),
        vec![9]
    );
}

/// A write sequence stops where it fails, and nothing after it runs.
#[tokio::test]
async fn an_ordered_write_sequence_stops_at_its_first_failure() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    let applied = radio
        .set_props(&[
            (umsh_ulcp::ids::prop::PHY_TX_POWER, vec![20]),
            (umsh_ulcp::ids::prop::PHY_LORA_SF, vec![99]),
            (umsh_ulcp::ids::prop::PHY_LORA_CR, vec![8]),
        ])
        .await
        .unwrap();

    assert_eq!(applied.len(), 2);
    assert_eq!(
        applied[0].as_ref().unwrap(),
        &(umsh_ulcp::ids::prop::PHY_TX_POWER, vec![20])
    );
    assert_eq!(applied[1], Err(Status::INVALID_ARGUMENT));
    assert_eq!(
        radio
            .get_prop(umsh_ulcp::ids::prop::PHY_LORA_CR)
            .await
            .unwrap(),
        vec![5]
    );
}

/// Bond management is two property writes, and each answers with the
/// value the device settled on. Unlike a reset there is no silence to
/// interpret: what the device did is what it says.
#[tokio::test]
async fn bonds_are_cleared_and_the_count_follows() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    assert_eq!(
        radio
            .get_prop(umsh_ulcp::ids::prop::BLE_BOND_COUNT)
            .await
            .unwrap(),
        vec![2],
        "the simulator starts with hosts to forget"
    );

    assert_eq!(
        radio.set_ble_pairing(true).await.unwrap(),
        Some(true),
        "the simulator advertises CAP_BLE, and the window opens as a toggle"
    );

    // The simulator's host is attached over its simulated serial link,
    // not over Bluetooth, so the link property answers truthfully that
    // nobody is on the transport it describes.
    assert_eq!(
        radio
            .get_prop(umsh_ulcp::ids::prop::BLE_LINK)
            .await
            .unwrap(),
        vec![umsh_ulcp::ble::BleLinkState::None.code()]
    );

    assert_eq!(
        radio.clear_ble_bonds().await.unwrap(),
        Some(0),
        "the write is answered with the count the device now holds"
    );
    assert_eq!(
        radio
            .get_prop(umsh_ulcp::ids::prop::BLE_BOND_COUNT)
            .await
            .unwrap(),
        vec![0],
        "the count is what proves the wipe ran"
    );

    // Bonds are transport state, not protocol state: a reset does not
    // bring back hosts the device was told to forget.
    radio.reset().await.unwrap();
    assert_eq!(
        radio
            .get_prop(umsh_ulcp::ids::prop::BLE_BOND_COUNT)
            .await
            .unwrap(),
        vec![0]
    );
}

/// `CMD_REBOOT` is the one reset that puts nothing back: the device
/// power-cycles, comes up announcing `STATUS_RESET_POWER_ON`, and finds
/// its saved snapshot exactly where it left it.
///
/// The command answers nothing at all, so what proves it ran is the state
/// on the far side of it — which is also why a device that *cannot*
/// restart has to say so out loud rather than stay quiet.
#[tokio::test]
async fn a_reboot_restarts_the_device_and_keeps_what_was_saved() {
    let sim = SimDevice::new();
    let mut radio = attached_host(&sim).await;

    configure_and_enable_phy(&mut radio).await;
    radio
        .set_device_name("named before the reboot")
        .await
        .unwrap();
    radio.save().await.unwrap();

    assert!(
        radio.reboot().await.unwrap(),
        "the simulator advertises CAP_REBOOT"
    );
    // Nothing came back, and the session on the other side is a new one:
    // the handle the host is holding belongs to a device that no longer
    // exists.
    drop(radio);

    let mut radio = attached_host(&sim).await;
    let sync = radio.sync(None).await.unwrap();
    assert!(sync.reset_since_last_contact);
    assert_eq!(sync.last_status, Status::RESET_POWER_ON);
    assert_eq!(sync.saved, Some(SavedSnapshot::Current));
    assert_eq!(sync.device_name, "named before the reboot");
    assert!(sync.phy_enabled, "the snapshot re-enabled the PHY at boot");
    assert_eq!(sync.freq_khz, host_config().freq_khz);
}
