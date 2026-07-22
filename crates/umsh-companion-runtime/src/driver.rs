//! The board-agnostic companion-NCP session driver (Phase 5, increment C).
//!
//! This is the extraction of the nRF NCP's `ncp_task` select loop, its
//! `apply_effect` radio-effect dispatcher, and the `Emitter` frame stager —
//! the one copy of the session-driving logic shared by every companion
//! firmware (T-Echo, T-1000E, Heltec V3). The board personalities that used
//! to be `cfg(feature = "t1000e")` forks inside the loop are expressed as
//! [`NcpEnv`] hooks with no-op defaults, so a new board supplies exactly the
//! couplings it has and nothing else.
//!
//! The split of responsibilities:
//!
//! - **This module** owns the protocol loop: transport arbitration, frame
//!   handling, radio RX/TX-completion processing, every deferred `Effect`
//!   arm (save/clear/wipe/provision/PIN/RSSI/battery/drain), and the
//!   device-domain mirror.
//! - **The board** owns the edges: transport tasks feeding [`InEvent`]s and
//!   draining [`TransportChannels`], the radio runner + mux serving the
//!   session's virtual [`Channels`] bundle, and an [`NcpEnv`] implementation
//!   wiring persistence, entropy, pairing, and indicators to its hardware.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Channel;
use embassy_time::Instant;

use umsh_companion_ncp::{
    Effect, IdentitySource, MAX_CHANNEL_KEYS, MAX_DEV_PEERS, SNAPSHOT_MAX, Session, TxPower,
};
use umsh_crypto::software::SoftwareIdentity;
use umsh_crypto::{AesProvider, NodeIdentity as _, Sha256Provider};
use umsh_journal_store::proto;
use umsh_radio_loraphy::{
    Channels, MAX_PAYLOAD, NcpControl, NcpSettings, RxFrame, TxRequest, bandwidth_from_hz,
    coding_rate_from_denom, spreading_factor_from_u8,
};

use crate::transport_policy::{SessionArbitration, Transport};

/// Largest raw companion frame accepted from a transport.
pub const FRAME_IN_MAX: usize = 300;
/// Largest companion frame the session emits (CMD_STR_RECV around a
/// full-MTU payload).
pub const FRAME_OUT_MAX: usize = 300;

/// One raw companion frame moving through the driver.
pub type FrameBuf = heapless::Vec<u8, FRAME_IN_MAX>;

/// Framing-free receive path and connection edges into the driver.
pub enum InEvent {
    Attached(Transport),
    Detached(Transport),
    Frame(Transport, FrameBuf),
}

/// The inbound event channel every transport task feeds.
pub type InputChannel<M> = Channel<M, InEvent, 8>;

/// One raw companion frame in a transport output queue, stamped with the
/// session generation that produced it so a displaced session's frames
/// are dropped at the transport edge (`transport_policy::generation_checked`).
pub struct OutFrame {
    pub generation: u32,
    pub frame: FrameBuf,
}

/// The per-transport outbound frame queues, drained by the board's
/// transport output tasks. `wired` is the physical-possession transport
/// (USB-CDC or UART), `ble` the bonded GATT transport — the same pairing
/// `transport_policy::Transport` names.
pub struct TransportChannels<M: RawMutex> {
    pub wired: Channel<M, OutFrame, 4>,
    pub ble: Channel<M, OutFrame, 4>,
}

impl<M: RawMutex> TransportChannels<M> {
    pub const fn new() -> Self {
        Self {
            wired: Channel::new(),
            ble: Channel::new(),
        }
    }

    fn for_transport(&self, transport: Transport) -> &Channel<M, OutFrame, 4> {
        match transport {
            Transport::Usb => &self.wired,
            Transport::Ble => &self.ble,
        }
    }
}

/// The session's device-domain tables, mirrored to the board's device
/// node whenever their generation moves (device-node plan increment 3).
pub struct DevDomainSnapshot {
    pub channel_keys: heapless::Vec<[u8; 32], MAX_CHANNEL_KEYS>,
    pub peers: heapless::Vec<[u8; 32], MAX_DEV_PEERS>,
    pub identity_present: bool,
}

/// Board couplings of the session driver. Everything the loop needs from
/// the platform, expressed as one trait so the driver itself stays free
/// of HAL types and `cfg` board forks. Hooks a board doesn't have keep
/// their no-op defaults (e.g. only the T-1000E implements the attention
/// indicator and transmit-load hooks today).
// Single-executor embedded consumers; `Send` futures are irrelevant here,
// same as the embassy ecosystem's own async traits.
#[allow(async_fn_in_trait)]
pub trait NcpEnv {
    /// Durably persist the encoded protocol snapshot (CMD_SAVE / host wipe).
    async fn persist_snapshot(&mut self, bytes: &[u8]) -> Result<(), ()>;
    /// Tombstone the snapshot journal (CMD_CLEAR).
    async fn clear_snapshot(&mut self) -> Result<(), ()>;
    /// Durably persist the encoded device identity.
    async fn persist_identity(&mut self, bytes: &[u8]) -> Result<(), ()>;
    /// Tombstone the identity journal (CMD_CLEAR).
    async fn clear_identity(&mut self) -> Result<(), ()>;
    /// Drop persisted frame-counter boundaries after a successful
    /// identity clear. Boards without a device node keep the default.
    async fn clear_counters(&mut self) {}
    /// Fill `secret` from the platform's cryptographic RNG. Fails closed:
    /// an error refuses identity generation rather than degrading.
    fn fill_secret(&mut self, secret: &mut [u8; 32]) -> Result<(), ()>;
    /// One fresh battery measurement (`Effect::SampleBattery`). Only
    /// emitted when the board's `SessionConfig::battery` advertises
    /// fields, so the default refuses.
    async fn sample_battery(&mut self) -> Result<umsh_companion::battery::BatteryStatus, ()> {
        Err(())
    }
    /// Apply a `PROP_BLE_PAIRING_PIN` write against the bond journal and
    /// the live BLE stack; `true` when it took effect.
    async fn apply_pairing_pin(&mut self, pin: Option<u32>) -> bool;
    /// `CMD_FACTORY_RESET`: erase EVERY piece of persistent state the
    /// platform owns — saved snapshot, device identity, frame-counter
    /// boundaries, BLE bonds, pairing PIN, and any other journal — then
    /// reboot. Never returns: the reset discards in-RAM state and the
    /// board comes back factory-fresh. There is no separate "clear bonds"
    /// hook because a reboot reloads bonds from the (now-erased) journal,
    /// so the live BLE stack never has to be touched.
    async fn factory_reset(&mut self) -> !;
    /// Publish the transport-arbitration advertising policy (a wired
    /// attach suppresses BLE advertising). Diagnostic builds may
    /// deliberately ignore `allowed`.
    fn set_advertising_allowed(&mut self, allowed: bool);
    /// Publish the session's device name to the board's consumers
    /// (advertising data, device node, UI).
    async fn publish_device_name(&mut self, name: &str);
    /// Deliver a device-domain mirror to the board's device node.
    fn publish_dev_domain(&mut self, snapshot: DevDomainSnapshot);
    /// A covered frame was queued for an attached-or-future host
    /// (T-1000E: request the attention LED).
    fn request_attention(&mut self) {}
    /// The host-facing queue drained to empty (T-1000E: clear it).
    fn clear_attention(&mut self) {}
    /// A transmit is about to start; boards with a battery-level
    /// estimator mark the load spike.
    fn note_transmit_load(&mut self) {}
    /// Diagnostic trace line (routed to the board's debug channel; the
    /// default discards).
    fn trace(&mut self, args: core::fmt::Arguments<'_>) {
        let _ = args;
    }
}

/// The driver's `'static` wiring: the channels and control blocks the
/// loop shares with the board's transport and radio tasks.
pub struct NcpRuntime<M: RawMutex + 'static, const RX: usize, const TX: usize> {
    /// Inbound frames and connection edges from every transport task.
    pub input: &'static InputChannel<M>,
    /// The session's radio endpoint — its private virtual `Channels`
    /// bundle served by the board's radio mux (never the real radio
    /// bundle directly).
    pub radio: &'static Channels<M, RX, TX>,
    /// Runtime radio settings / RSSI sampling into the radio runner.
    pub ctl: &'static NcpControl<M>,
    /// Outbound frame queues drained by the transport output tasks.
    pub out: &'static TransportChannels<M>,
    /// Published session epoch, checked by each transport at framing
    /// edges (`transport_policy::generation_checked`).
    pub session_gen: &'static AtomicU32,
}

/// Collects frames emitted synchronously by the session, then flushes
/// them to the active transport's output queue asynchronously. The
/// session emits at most one frame per call; two slots give headroom.
struct Emitter {
    bufs: [[u8; FRAME_OUT_MAX]; 2],
    lens: [usize; 2],
    count: usize,
}

impl Emitter {
    const fn new() -> Self {
        Self {
            bufs: [[0; FRAME_OUT_MAX]; 2],
            lens: [0; 2],
            count: 0,
        }
    }

    /// Copy one raw companion frame into the next slot.
    ///
    /// The session is expected to emit at most `bufs.len()` frames per call
    /// and every frame is expected to fit `FRAME_OUT_MAX`. Both invariants are
    /// asserted in debug builds so a future session change that violates
    /// them is caught rather than silently dropping a response.
    fn push(&mut self, frame: &[u8]) {
        if self.count >= self.bufs.len() {
            debug_assert!(
                false,
                "Emitter overflow: session emitted more frames per call than staging slots"
            );
            return;
        }
        if frame.len() <= FRAME_OUT_MAX {
            self.bufs[self.count][..frame.len()].copy_from_slice(frame);
            self.lens[self.count] = frame.len();
            self.count += 1;
        } else {
            debug_assert!(false, "Emitter: companion frame exceeds FRAME_OUT_MAX");
        }
    }

    /// Queue all staged frames for the active transport output task.
    async fn flush<M: RawMutex>(
        &mut self,
        destination: Option<(Transport, u32)>,
        out: &TransportChannels<M>,
    ) {
        if let Some((transport, generation)) = destination {
            for index in 0..self.count {
                let mut frame: FrameBuf = heapless::Vec::new();
                if frame
                    .extend_from_slice(&self.bufs[index][..self.lens[index]])
                    .is_err()
                {
                    // FRAME_OUT_MAX == FrameBuf capacity, so this cannot
                    // happen; assert in debug rather than silently drop.
                    debug_assert!(false, "Emitter frame copy exceeded FrameBuf capacity");
                    continue;
                }
                out.for_transport(transport)
                    .send(OutFrame { generation, frame })
                    .await;
            }
        }
        self.count = 0;
    }
}

/// Execute a radio side effect requested by the session.
async fn apply_effect<A, S, const TXQ: usize, M, const RX: usize, const TX: usize, E>(
    session: &Session<A, S, TXQ>,
    effect: Option<Effect>,
    rt: &NcpRuntime<M, RX, TX>,
    env: &mut E,
) where
    A: AesProvider,
    S: Sha256Provider,
    M: RawMutex,
    E: NcpEnv,
{
    match effect {
        Some(Effect::ApplyRadio(settings)) => {
            env.publish_device_name(session.device_name()).await;
            // The session validates values against the same discrete
            // sets these converters accept, so None here is
            // unreachable; bail out defensively rather than panic.
            let (Some(sf), Some(bw), Some(cr)) = (
                spreading_factor_from_u8(settings.sf),
                bandwidth_from_hz(settings.bw_hz),
                coding_rate_from_denom(settings.cr_denom),
            ) else {
                return;
            };
            rt.ctl.apply(NcpSettings {
                enabled: settings.enabled,
                freq_hz: settings.freq_khz.saturating_mul(1_000),
                sf,
                bw,
                cr,
                power_dbm: i32::from(settings.tx_power_dbm),
            });
        }
        Some(Effect::StartTransmit) => {
            let mut data: heapless::Vec<u8, MAX_PAYLOAD> = heapless::Vec::new();
            if data.extend_from_slice(session.tx_data()).is_err() {
                env.trace(format_args!(
                    "radio tx staging=FAILED len={}",
                    session.tx_data().len()
                ));
                return;
            }
            let power_dbm = match session.tx_power() {
                TxPower::Default => None,
                TxPower::Max => Some(i32::from(session.max_tx_power_dbm())),
                TxPower::Dbm(dbm) => Some(i32::from(dbm)),
            };
            // Mark the load for the board's battery level estimator (the
            // radio runner transmits within milliseconds of this).
            env.note_transmit_load();
            rt.radio.tx.send(TxRequest { data, power_dbm }).await;
        }
        Some(Effect::DeviceNameChanged) => {
            env.publish_device_name(session.device_name()).await;
        }
        // Deferred effects needing `&mut Session` + the emitter are
        // handled inline in the run loop rather than here.
        Some(Effect::SampleRssi { .. })
        | Some(Effect::SampleBattery { .. })
        | Some(Effect::SetPairingPin { .. })
        | Some(Effect::WipeHostDomain { .. })
        | Some(Effect::DrainQueue)
        | Some(Effect::SaveSnapshot { .. })
        | Some(Effect::ClearSaved { .. })
        | Some(Effect::ProvisionIdentity { .. })
        | Some(Effect::FactoryReset)
        | None => {}
    }
}

/// Mirror the session's device-domain node tables to the device node
/// when their generation moved (device-node plan increment 3).
/// `synced_version` is the caller's cache of the last published
/// generation. Cheap when nothing changed — one u32 compare — so the
/// loop runs it after every session interaction.
fn sync_dev_domain<A, S, const TXQ: usize, E>(
    session: &Session<A, S, TXQ>,
    synced_version: &mut u32,
    env: &mut E,
) where
    A: AesProvider,
    S: Sha256Provider,
    E: NcpEnv,
{
    if session.dev_domain_version() == *synced_version {
        return;
    }
    *synced_version = session.dev_domain_version();
    let mut snapshot = DevDomainSnapshot {
        channel_keys: heapless::Vec::new(),
        peers: heapless::Vec::new(),
        identity_present: session.dev_key().is_some(),
    };
    for key in session.dev_channel_keys() {
        let _ = snapshot.channel_keys.push(key);
    }
    for public_key in session.dev_peers() {
        let _ = snapshot.peers.push(public_key);
    }
    env.publish_dev_domain(snapshot);
}

/// Drive the companion session forever: restore persisted state, then
/// select over host frames, radio receptions, and transmit completions,
/// executing every session effect through the board's [`NcpEnv`].
///
/// The caller constructs the [`Session`] with its board profile
/// (`SessionConfig`) and boot status, mounts its journals, and hands the
/// stored payloads in; the driver owns everything after that.
pub async fn run<A, S, const TXQ: usize, M, const RX: usize, const TX: usize, E>(
    mut session: Session<A, S, TXQ>,
    boot_snapshot: Option<&[u8]>,
    boot_identity: Option<[u8; 32]>,
    rt: NcpRuntime<M, RX, TX>,
    mut env: E,
) -> !
where
    A: AesProvider,
    S: Sha256Provider,
    M: RawMutex,
    E: NcpEnv,
{
    let mut emitter = Emitter::new();
    let mut arbitration = SessionArbitration::new(rt.session_gen.load(Ordering::Acquire));
    // Last device-domain generation mirrored to the device node.
    // Matches the session's initial value; the first mutation (or a
    // boot restore) publishes the first snapshot.
    let mut dev_domain_synced: u32 = session.dev_domain_version();
    // Shared staging buffer for the durable-write effect arms
    // (save/wipe). Held across their persist awaits, so as a
    // loop-lifetime local it costs one future slot instead of one
    // per arm.
    let mut snapshot_buf = [0u8; SNAPSHOT_MAX];

    // The device identity is persisted independently of snapshots;
    // its post-reset value is whatever the identity journal holds.
    if let Some(public_key) = boot_identity {
        session.set_boot_identity(public_key);
    }

    // Restore a stored snapshot before processing any host command:
    // the saved configuration is applied, the PHY re-enabled if it
    // was enabled when saved, and detached operation begins
    // immediately. A snapshot that fails to decode is ignored.
    if let Some(payload) = boot_snapshot {
        let effect = session.restore_at_boot(payload);
        env.trace(format_args!(
            "proto-store boot-restore={}",
            if effect.is_some() { "ok" } else { "IGNORED" }
        ));
        apply_effect(&session, effect, &rt, &mut env).await;
        // Replay the restored device-domain tables into the device
        // node before any host interaction: detached multicast
        // processing must not wait for an attach.
        sync_dev_domain(&session, &mut dev_domain_synced, &mut env);
    }

    loop {
        // Only wait for a TX completion while one is outstanding,
        // so a spurious tx_done can never be consumed early.
        let tx_done = async {
            if session.has_pending_tx() {
                rt.radio.tx_done.wait().await
            } else {
                core::future::pending().await
            }
        };

        match select3(rt.input.receive(), rt.radio.rx.receive(), tx_done).await {
            Either3::First(InEvent::Attached(transport)) => {
                // Fresh session state for the new host session; the
                // device domain (PHY configuration and enable state,
                // device name, duty accounting) is deliberately
                // untouched and nothing is emitted (full-protocol
                // attach semantics).
                arbitration.attach(transport);
                rt.session_gen
                    .store(arbitration.generation(), Ordering::Release);
                env.set_advertising_allowed(arbitration.advertising_allowed());
                // Both transports meet their provisioning-security
                // binding here: the wired transport by physical
                // possession, BLE because the companion GATT service
                // refuses any access outside an encrypted LESC-bonded
                // link.
                session.attach(true);
            }
            Either3::First(InEvent::Detached(transport)) => {
                // Only the active transport's detach ends the
                // session; a displaced transport's stale detach
                // must not clear the successor's session state.
                if arbitration.detach(transport) {
                    env.set_advertising_allowed(true);
                    session.detach();
                }
            }
            Either3::First(InEvent::Frame(transport, frame_bytes)) => {
                if arbitration.accepts_frame(transport) {
                    let now_ms = Instant::now().as_millis();
                    let effect = session.handle_frame(&frame_bytes, now_ms, &mut |frame: &[u8]| {
                        emitter.push(frame)
                    });
                    emitter.flush(arbitration.destination(), rt.out).await;
                    match effect {
                        Some(Effect::SampleRssi { tid }) => {
                            // Round-trip to the radio runner for an
                            // instantaneous RSSI sample, then answer the
                            // deferred PROP_PHY_RSSI get.
                            rt.ctl.request_rssi();
                            let sample = rt.ctl.wait_rssi().await;
                            session.respond_rssi(tid, sample, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::SampleBattery { tid }) => {
                            // Round-trip to the platform battery
                            // source for a fresh measurement, then
                            // answer the deferred PROP_BATTERY get.
                            let sample = env.sample_battery().await;
                            session.respond_battery(tid, sample, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::DrainQueue) => {
                            // Deliver the covered frames one per
                            // step, flushing between steps so the
                            // two-slot emitter never overflows and
                            // the transport applies backpressure.
                            loop {
                                let more = session.drain_step(
                                    Instant::now().as_millis(),
                                    &mut |frame: &[u8]| emitter.push(frame),
                                );
                                emitter.flush(arbitration.destination(), rt.out).await;
                                if !more {
                                    break;
                                }
                            }
                            env.clear_attention();
                        }
                        Some(Effect::WipeHostDomain { tid }) => {
                            // Durably wipe the host-domain portion of
                            // any saved snapshot before the new host
                            // key takes effect; with nothing saved the
                            // wipe is trivially satisfied.
                            let result = match session.encode_wiped_snapshot(&mut snapshot_buf) {
                                Some(len) => env.persist_snapshot(&snapshot_buf[..len]).await,
                                None => Ok(()),
                            };
                            session.respond_host_wipe(tid, result, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::SaveSnapshot { tid }) => {
                            let result = match session.encode_snapshot(&mut snapshot_buf) {
                                Some(len) => env.persist_snapshot(&snapshot_buf[..len]).await,
                                None => Err(()),
                            };
                            session.respond_save(tid, result, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::ClearSaved { tid }) => {
                            // CMD_CLEAR covers all persisted
                            // provisioning: the snapshot and the
                            // independently persisted device
                            // identity. Each journal's tombstone is
                            // individually atomic; an interruption
                            // between them reports failure and the
                            // host's retry completes the erase.
                            let result = match env.clear_snapshot().await {
                                Ok(()) => env.clear_identity().await,
                                Err(()) => Err(()),
                            };
                            // With the identity durably gone, its
                            // counter boundaries are dead weight;
                            // drop them with it. (Kept if the
                            // identity clear failed — the identity
                            // then survives the reboot and still
                            // needs its TX boundary.)
                            if result.is_ok() {
                                env.clear_counters().await;
                            }
                            session.respond_clear(tid, result, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::ProvisionIdentity { tid }) => {
                            // Build the keypair (drawing a fresh
                            // secret from the platform RNG for
                            // on-device generation), persist it, and
                            // only then report the public key.
                            let result = match session.identity_request() {
                                Some(source) => {
                                    let secret = match source {
                                        IdentitySource::Install(secret) => Ok(secret),
                                        IdentitySource::Generate => {
                                            let mut secret = [0u8; 32];
                                            env.fill_secret(&mut secret).map(|()| secret)
                                        }
                                    };
                                    match secret {
                                        Ok(secret) => {
                                            let identity =
                                                SoftwareIdentity::from_secret_bytes(&secret);
                                            let public_key = identity.public_key().0;
                                            let payload =
                                                proto::encode_identity(&secret, &public_key);
                                            env.persist_identity(&payload)
                                                .await
                                                .map(|()| public_key)
                                        }
                                        Err(()) => Err(()),
                                    }
                                }
                                None => Err(()),
                            };
                            session.respond_identity(tid, result, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::SetPairingPin { tid, pin }) => {
                            let applied = env.apply_pairing_pin(pin).await;
                            session.respond_pin_set(
                                tid,
                                applied.then_some(()).ok_or(()),
                                &mut |frame: &[u8]| emitter.push(frame),
                            );
                            emitter.flush(arbitration.destination(), rt.out).await;
                        }
                        Some(Effect::FactoryReset) => {
                            // Hand off to the platform, which erases every
                            // persistent journal and reboots. This never
                            // returns; no acknowledgement is sent because the
                            // reset drops the link. Any frames the session
                            // already staged were flushed above.
                            env.trace(format_args!("CMD_FACTORY_RESET: wiping all state + reboot"));
                            env.factory_reset().await
                        }
                        other => apply_effect(&session, other, &rt, &mut env).await,
                    }
                    if session.queued_frame_count() == 0 {
                        env.clear_attention();
                    }
                }
            }
            Either3::Second(RxFrame { data, info }) => {
                // While detached this may stage a delegated MAC
                // acknowledgement (Effect::StartTransmit).
                let queued_before = session.queued_frame_count();
                let effect = session.on_radio_rx(
                    &data,
                    info.rssi,
                    info.snr.as_centibels(),
                    info.lqi,
                    Instant::now().as_millis(),
                    &mut |frame: &[u8]| emitter.push(frame),
                );
                if session.queued_frame_count() > queued_before {
                    env.request_attention();
                }
                emitter.flush(arbitration.destination(), rt.out).await;
                apply_effect(&session, effect, &rt, &mut env).await;
            }
            Either3::Third(result) => {
                let now_ms = Instant::now().as_millis();
                let effect = session.on_tx_result(result.is_ok(), now_ms, &mut |frame: &[u8]| {
                    emitter.push(frame)
                });
                emitter.flush(arbitration.destination(), rt.out).await;
                apply_effect(&session, effect, &rt, &mut env).await;
            }
        }
        // Any of the arms may have moved the device-domain tables
        // (property mutation, CMD_RST, CMD_RESTORE); one u32
        // compare when they did not.
        sync_dev_domain(&session, &mut dev_domain_synced, &mut env);
    }
}
