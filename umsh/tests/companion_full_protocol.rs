//! Adapter-free full-protocol integration tests: the host-side
//! [`CompanionRadio`] workflow driven end-to-end against the **real**
//! NCP session engine (`umsh_companion_ncp::Session`) — the same state
//! machine both firmware targets run — with persistence, the radio,
//! and time simulated in RAM. No fake NCP re-implementation sits in
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

use umsh::companion_radio::{
    CompanionRadio, CompanionRadioConfig, CompanionRadioError, FrameLink, HostOwnership,
    HostProvisioning, describe_frame,
};
use umsh_companion::Status;
use umsh_companion::ids::cap;
use umsh_companion::items::{Filter, PeerKeyEntry};
use umsh_companion::meta::{BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED};
use umsh_companion_ncp::{
    Effect, IdentitySource, RadioSettings, SNAPSHOT_MAX, SessionConfig,
};
use umsh_core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PacketType};
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_crypto::{CryptoEngine, NodeIdentity as _, PairwiseKeys};

type Session = umsh_companion_ncp::Session<SoftwareAes, SoftwareSha256>;

const HOST_KEY: [u8; 32] = [0xC4; 32];
const PEER_PUB: [u8; 32] = [0x0A; 32];

fn engine() -> CryptoEngine<SoftwareAes, SoftwareSha256> {
    CryptoEngine::new(SoftwareAes, SoftwareSha256)
}

fn session_config() -> SessionConfig {
    SessionConfig {
        ncp_version: "sim-ncp/0.1",
        default_device_name: "Simulated NCP",
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
    }
}

/// The simulated NCP: the real session engine plus RAM stand-ins for
/// everything the firmware supplies — the snapshot and identity
/// journals, the radio, the entropy source, and the clock.
struct SimNcp {
    session: Session,
    /// Frames the NCP emitted toward the host.
    out: VecDeque<Vec<u8>>,
    /// Frames the NCP transmitted on the (simulated) air.
    air: Vec<Vec<u8>>,
    /// Durable snapshot journal.
    snapshot: Option<Vec<u8>>,
    /// Durable identity journal: (secret, public).
    identity: Option<([u8; 32], [u8; 32])>,
    /// Deterministic stand-in for the hardware TRNG.
    identity_seed: u8,
    now_ms: u64,
    /// Per-command capture, both directions.
    log: Vec<String>,
}

impl SimNcp {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            session: Session::new(session_config(), Status::RESET_POWER_ON, engine()),
            out: VecDeque::new(),
            air: Vec::new(),
            snapshot: None,
            identity: None,
            identity_seed: 0,
            now_ms: 0,
            log: Vec::new(),
        }))
    }

    /// Execute one session effect the way the firmware's effect arms
    /// do, collecting any frames the completion emits.
    fn execute(&mut self, effect: Option<Effect>, emitted: &mut Vec<Vec<u8>>) {
        let mut emit = |frame: &[u8]| emitted.push(frame.to_vec());
        match effect {
            None
            | Some(Effect::ApplyRadio(_))
            | Some(Effect::DeviceNameChanged) => {}
            Some(Effect::StartTransmit) => {
                self.air.push(self.session.tx_data().to_vec());
                self.session.on_tx_result(true, self.now_ms, &mut emit);
            }
            Some(Effect::SampleRssi { tid }) => {
                self.session.respond_rssi(tid, Ok(-77), &mut emit);
            }
            Some(Effect::SetPairingPin { tid, .. }) => {
                self.session.respond_pin_set(tid, Ok(()), &mut emit);
            }
            Some(Effect::WipeHostDomain { tid }) => {
                let mut buf = [0u8; SNAPSHOT_MAX];
                if let Some(len) = self.session.encode_wiped_snapshot(&mut buf) {
                    self.snapshot = Some(buf[..len].to_vec());
                }
                self.session.respond_host_wipe(tid, Ok(()), &mut emit);
            }
            Some(Effect::DrainQueue) => {
                while self.session.drain_step(self.now_ms, &mut emit) {}
            }
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
                        let public = SoftwareIdentity::from_secret_bytes(&secret)
                            .public_key()
                            .0;
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
            self.log.push(format!("ncp→host {}", describe_frame(&frame)));
            self.out.push_back(frame);
        }
    }
}

/// [`FrameLink`] straight into the simulated NCP: frames are handled
/// synchronously by the real session, so responses are ready before
/// `send_frame` returns.
struct SessionLink {
    sim: Arc<Mutex<SimNcp>>,
}

impl FrameLink for SessionLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), CompanionRadioError> {
        let mut sim = self.sim.lock().unwrap();
        sim.log.push(format!("host→ncp {}", describe_frame(frame)));
        let now_ms = sim.now_ms;
        let mut emitted = Vec::new();
        let effect = sim
            .session
            .handle_frame(frame, now_ms, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        sim.execute(effect, &mut emitted);
        sim.finish(emitted);
        Ok(())
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, CompanionRadioError>> {
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

fn attach(sim: &Arc<Mutex<SimNcp>>, link_secure: bool) {
    sim.lock().unwrap().session.attach(link_secure);
}

fn detach(sim: &Arc<Mutex<SimNcp>>) {
    sim.lock().unwrap().session.detach();
}

/// Simulate a power cycle: a fresh session boots from the durable
/// journals exactly as the firmware does — identity installed and the
/// snapshot restored before any host command.
fn power_cycle(sim: &Arc<Mutex<SimNcp>>) {
    let mut sim = sim.lock().unwrap();
    sim.session = Session::new(session_config(), Status::RESET_POWER_ON, engine());
    if let Some((_, public)) = sim.identity {
        sim.session.set_boot_identity(public);
    }
    if let Some(snapshot) = sim.snapshot.clone() {
        let restored = sim.session.restore_at_boot(&snapshot);
        assert!(restored.is_some(), "saved snapshot must restore at boot");
    }
    sim.now_ms += 60_000;
    sim.log.push("(power cycle)".to_owned());
}

/// Deliver one frame from the (simulated) air while the session is in
/// whatever attach state the test arranged.
fn inject_radio_rx(sim: &Arc<Mutex<SimNcp>>, frame: &[u8]) {
    let mut sim = sim.lock().unwrap();
    let now_ms = sim.now_ms;
    let mut emitted = Vec::new();
    let effect = sim
        .session
        .on_radio_rx(frame, -80, 40, None, now_ms, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
    sim.execute(effect, &mut emitted);
    sim.finish(emitted);
}

async fn attached_host(
    sim: &Arc<Mutex<SimNcp>>,
) -> CompanionRadio<SessionLink> {
    attach(sim, true);
    CompanionRadio::attach_existing(SessionLink { sim: sim.clone() }, host_config())
        .await
        .expect("attach handshake")
}

fn host_config() -> CompanionRadioConfig {
    let mut config = CompanionRadioConfig::new(906_875, 250_000, 9, 5);
    config.tx_power_dbm = 10;
    config.response_timeout = std::time::Duration::from_millis(500);
    config
}

fn test_pairwise() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [0xE0; 16],
        k_mic: [0x50; 16],
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

async fn configure_and_enable_phy(radio: &mut CompanionRadio<SessionLink>) {
    let config = host_config();
    radio
        .set_prop(umsh::companion::ids::prop::PHY_FREQ, &config.freq_khz.to_le_bytes())
        .await
        .unwrap();
    radio
        .set_prop(
            umsh::companion::ids::prop::PHY_LORA_BW,
            &config.bandwidth_hz.to_le_bytes(),
        )
        .await
        .unwrap();
    radio
        .set_prop(umsh::companion::ids::prop::PHY_ENABLED, &[1])
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
    let sim = SimNcp::new();
    let mut radio = attached_host(&sim).await;

    // Capture the host-side trace alongside the harness log.
    let trace: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = trace.clone();
    radio.set_frame_trace(Some(Box::new(move |direction, line| {
        sink.lock().unwrap().push(format!("{direction} {line}"));
    })));

    // Fresh NCP: full capability set, unclaimed, nothing saved.
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
    assert_eq!(sync.saved, Some(false));
    assert_eq!(sync.queue_count, Some(0));
    assert!(!sync.phy_enabled);
    assert_eq!(sync.dev_key, None);
    assert_eq!(sync.device_name, "Simulated NCP");

    // Device identity: generated on-device once, then stable.
    let dev_key = radio.ensure_device_identity().await.unwrap();
    assert_eq!(radio.ensure_device_identity().await.unwrap(), dev_key);
    assert_eq!(sim.lock().unwrap().identity_seed, 1, "exactly one generation");

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
    assert_eq!(sync.saved, Some(true));
    assert!(sync.phy_enabled);
    assert_eq!(sync.dev_key, Some(dev_key));

    // The host leaves; the radio keeps operating from its saved
    // provisioning across a power cycle.
    drop(radio);
    detach(&sim);
    power_cycle(&sim);

    // Autonomous detached operation: the peer's frame is accepted,
    // queued, and acknowledged on the host's behalf.
    inject_radio_rx(&sim, &sealed_unicast(5));
    {
        let sim = sim.lock().unwrap();
        assert_eq!(sim.air.len(), 1, "delegated ack must transmit");
        let header = PacketHeader::parse(&sim.air[0]).unwrap();
        assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    }

    // The host returns: reset detected, ownership verified, saved
    // provisioning intact, one frame waiting.
    let mut radio = attached_host(&sim).await;
    let sink = trace.clone();
    radio.set_frame_trace(Some(Box::new(move |direction, line| {
        sink.lock().unwrap().push(format!("{direction} {line}"));
    })));
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert!(sync.reset_since_last_contact);
    assert_eq!(sync.ownership, HostOwnership::Ours);
    assert_eq!(sync.saved, Some(true));
    assert_eq!(sync.queue_count, Some(1));
    assert_eq!(sync.auto_ack, Some(true));
    assert_eq!(sync.dev_key, Some(dev_key), "identity survives the power cycle");
    assert!(sync.phy_enabled, "snapshot re-enabled the PHY at boot");
    assert_eq!(sync.freq_khz, host_config().freq_khz);

    // Reconciliation is a no-op: everything matches the digests, so
    // no key material crosses the link a second time.
    let report = radio.provision(&desired_provisioning()).await.unwrap();
    assert!(!report.changed(), "reattach reconcile must be a no-op: {report:?}");

    // Drain when ready: the buffered frame carries its acknowledged
    // flag so the host knows not to re-ack it.
    let mut drained: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    radio
        .queue_drain_with(|data, meta| drained.push((data.to_vec(), meta.to_vec())))
        .await
        .unwrap();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].0, sealed_unicast(5));
    let meta = BufferedRxMeta::decode(&drained[0].1).unwrap();
    assert_eq!(meta.flags & (RX_FLAG_BUFFERED | RX_FLAG_ACKED), RX_FLAG_BUFFERED | RX_FLAG_ACKED);

    // The capture places every full-protocol command on the record.
    let trace = trace.lock().unwrap();
    for needle in ["PROP_CAPS", "PROP_HOST_KEY", "PROP_DEV_KEY", "QueueDrain", "StrRecv"] {
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
    let sim = SimNcp::new();
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

/// Channel reconciliation: keys the NCP is missing are inserted
/// individually, but an identifier the host holds no key for forces an
/// atomic whole-table replacement (its remove selector is the key).
#[tokio::test]
async fn channel_reconciliation_inserts_or_replaces() {
    let sim = SimNcp::new();
    let mut radio = attached_host(&sim).await;
    let mut desired = desired_provisioning();
    desired.channel_keys = vec![[0x41; 32], [0x42; 32]];
    radio.provision(&desired).await.unwrap();

    // Growing the set only inserts the new key.
    desired.channel_keys.push([0x43; 32]);
    let report = radio.provision(&desired).await.unwrap();
    assert!(!report.host_replaced && !report.channels_replaced);
    assert_eq!(report.channels_inserted, 1);

    // Dropping a key the NCP still holds forces the whole-table form.
    desired.channel_keys = vec![[0x41; 32], [0x43; 32]];
    let report = radio.provision(&desired).await.unwrap();
    assert!(report.channels_replaced);
    assert_eq!(report.channels_inserted, 0);
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.host_channel_ids.map(|ids| ids.len()), Some(2));
}

/// A full 16-frame NCP queue drains losslessly through the drain
/// callback even though it is larger than the host driver's bounded
/// receive buffer — the exact failure the T-1000E hardware pass
/// caught: the callback used to miss every frame the bounded buffer
/// evicted mid-drain.
#[tokio::test]
async fn full_queue_drains_losslessly_through_the_callback() {
    let sim = SimNcp::new();
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
    assert_eq!(drained[0], sealed_unicast(4), "oldest surviving frame first");
    assert_eq!(drained[15], sealed_unicast(19));
}

/// Over a transport that does not meet its provisioning-security
/// binding the NCP refuses key material, and the host surfaces the
/// status; non-secret provisioning still works.
#[tokio::test]
async fn insecure_link_refuses_key_provisioning() {
    let sim = SimNcp::new();
    attach(&sim, false);
    let mut radio =
        CompanionRadio::attach_existing(SessionLink { sim: sim.clone() }, host_config())
            .await
            .unwrap();

    match radio.ensure_device_identity().await {
        Err(CompanionRadioError::Status(status)) => {
            assert_eq!(status, Status::INVALID_STATE)
        }
        other => panic!("expected INVALID_STATE, got {other:?}"),
    }
    match radio.provision(&desired_provisioning()).await {
        Err(CompanionRadioError::Status(status)) => {
            assert_eq!(status, Status::INVALID_STATE)
        }
        other => panic!("expected INVALID_STATE, got {other:?}"),
    }
    // The ungated pieces (host key, filters) were accepted before the
    // gate refused the channel key; ownership is already established.
    let sync = radio.sync(Some(&HOST_KEY)).await.unwrap();
    assert_eq!(sync.ownership, HostOwnership::Ours);
}
