//! The board-agnostic ULCP session driver (Phase 5, increment C).
//!
//! This is the extraction of the nRF firmware's `device_task` select loop, its
//! `apply_effect` radio-effect dispatcher, and the `Emitter` frame stager —
//! the one copy of the session-driving logic shared by every device
//! firmware (T-Echo, T-1000E, Heltec V3). The board personalities that used
//! to be `cfg(feature = "t1000e")` forks inside the loop are expressed as
//! [`DeviceEnv`] hooks with no-op defaults, so a new board supplies exactly the
//! couplings it has and nothing else.
//!
//! The split of responsibilities:
//!
//! - **This module** owns the protocol loop: transport arbitration, frame
//!   handling, radio RX/TX-completion processing, every deferred `Effect`
//!   arm (save/clear/wipe/provision/PIN/RSSI/battery/drain), asynchronous
//!   property publication ([`DeviceEnv::battery_event`]), and the
//!   device-domain mirror.
//! - **The board** owns the edges: transport tasks feeding [`InEvent`]s and
//!   draining [`TransportChannels`], the radio runner + mux serving the
//!   session's virtual [`Channels`] bundle, and an [`DeviceEnv`] implementation
//!   wiring persistence, entropy, pairing, and indicators to its hardware.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::select::{Either, Either4, select, select4};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Instant, Timer};

use umsh_crypto::software::SoftwareIdentity;
use umsh_crypto::{AesProvider, NodeIdentity as _, Sha256Provider};
use umsh_hal::RxOrigin;
use umsh_journal_store::proto;
use umsh_radio_loraphy::{
    CadPolicy, Channels, DeviceControl, DeviceSettings, MAX_PAYLOAD, RxFrame, TxRequest,
    bandwidth_from_hz, coding_rate_from_denom, spreading_factor_from_u8,
};
use umsh_ulcp_device::{
    Effect, IdentitySource, MAX_CHANNEL_KEYS, MAX_DEV_ADMINS, MAX_DEV_PEERS, MAX_REPEATER_REGIONS,
    RadioRxInfo, SNAPSHOT_MAX, SavedStatus, Session, TxOutcome, TxPower,
};

/// The session sizes its snapshots and the journal sizes its records
/// independently. This is the only place both are visible, so it is
/// where a snapshot growing past what a record can carry is caught.
const _: () = assert!(
    SNAPSHOT_MAX <= proto::MAX_PAYLOAD,
    "SNAPSHOT_MAX outgrew what a journal record can carry"
);

use crate::transport_policy::{SessionArbitration, Transport};

/// Derive a device identity's public key and its persisted record from a
/// raw Ed25519 secret.
///
/// Shared by first-boot generation and `Effect::ProvisionIdentity` so the
/// two can never disagree about the derivation or the record layout.
///
/// The caller supplies `secret` and owns the question this function
/// cannot answer: it **MUST** come from a cryptographic RNG with real
/// entropy behind it. On the nRF boards that is the hardware TRNG with
/// bias correction enabled; on Espressif it is `EspCryptoRng`, which
/// refuses to exist unless the RF noise source is live.
pub fn device_identity_record(secret: &[u8; 32]) -> ([u8; 32], [u8; proto::IDENTITY_PAYLOAD_LEN]) {
    let public_key = SoftwareIdentity::from_secret_bytes(secret).public_key().0;
    (public_key, proto::encode_identity(secret, &public_key))
}

/// How many older snapshot generations boot will try after the newest
/// one is rejected.
///
/// Bounded deliberately. Corruption is expected to affect one record, so
/// a handful of generations covers it; a payload that is *systematically*
/// undecodable is a firmware bug, and walking the whole journal for it on
/// every boot would only delay booting bare and reporting the fact.
pub const SNAPSHOT_FALLBACK_LIMIT: usize = 4;

/// Buffer the driver hands `DeviceEnv::sign_identity`: a node-identity
/// payload plus its 64-octet detached signature, with room for the
/// descriptive options.
pub const IDENTITY_BLOB_MAX: usize = 320;

/// Largest raw ULCP frame accepted from a transport.
pub const FRAME_IN_MAX: usize = 300;
/// Largest ULCP frame the session emits (CMD_STR_RECV around a
/// full-MTU payload).
pub const FRAME_OUT_MAX: usize = 300;

/// One raw ULCP frame moving through the driver.
pub type FrameBuf = heapless::Vec<u8, FRAME_IN_MAX>;

/// A Node Management Request's ULCP frame on its way into the session,
/// and the response frame on its way back out.
///
/// The exchange crosses the driver's event loop rather than borrowing the
/// session, because the session is exclusively owned by [`run`] and an
/// exchange can await several platform round trips before it is finished.
pub type AdminFrame = FrameBuf;

/// One-slot return path for [`InEvent::Admin`].
///
/// A single static rather than a channel per request: there is one
/// session driver per device, it serves one event at a time, and the
/// responder that feeds it holds one exchange open at a time. An empty
/// response — which is what a reset-class command produces — is
/// distinguished by its length, so the responder always receives exactly
/// one message per request and never has to time the loop out.
pub static ADMIN_REPLY: Channel<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    AdminFrame,
    1,
> = Channel::new();

/// Framing-free receive path and connection edges into the driver.
pub enum InEvent {
    Attached(Transport),
    Detached(Transport),
    Frame(Transport, FrameBuf),
    /// One ULCP frame from a mesh administrator, whose response must fit
    /// `reply_budget` octets. The driver answers on [`ADMIN_REPLY`].
    ///
    /// Authorization has already happened: the responder checked that the
    /// packet arrived by unicast or blind unicast, that its source is
    /// authenticated, and that the source key is listed in
    /// `PROP_DEV_ADMINS`. Nothing that fails those checks reaches here.
    Admin {
        frame: AdminFrame,
        reply_budget: usize,
    },
    /// Someone cancelled a running locate alert at the device — the
    /// button press of whoever found the radio. Ignored when no alert is
    /// running, so a board may report the press unconditionally.
    CancelAlert,
    /// A switch was flipped at the device, on a board that offers the
    /// setting as a user-facing control. Ignored when the device lacks
    /// the capability behind it, so a board may report the press
    /// unconditionally.
    Toggle(Setting),
}

/// A device-domain switch a board may offer as a control the operator
/// can reach — a menu entry, a button, a gesture.
///
/// Each names a property rather than a piece of hardware: what the
/// device does with it is the platform's business, and a board that
/// cannot perform one simply never sends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// `PROP_BLE_ENABLED`: whether the device is reachable over
    /// Bluetooth.
    Bluetooth,
    /// `PROP_GNSS_ENABLED`: whether the receiver is powered.
    Gnss,
    /// `PROP_GNSS_IDENT_UPDATE`: whether position goes out in what the
    /// device advertises.
    ShareLocation,
    /// `PROP_MAC_REPEATER_ENABLED`: whether the node forwards other
    /// nodes' frames.
    Forwarding,
}

/// The inbound event channel the board's tasks feed: every transport
/// task, and whatever owns the buttons on a board with `CAP_ALERT`.
pub type InputChannel<M> = Channel<M, InEvent, 8>;

/// One raw ULCP frame in a transport output queue, stamped with the
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
    /// The session's device-domain generation when this snapshot was
    /// taken. Every mutation moves it, which is what a Node Management
    /// cursor encodes so that a position taken before a change is
    /// detected rather than served wrong.
    pub version: u32,
    pub channel_keys: heapless::Vec<[u8; 32], MAX_CHANNEL_KEYS>,
    pub peers: heapless::Vec<[u8; 32], MAX_DEV_PEERS>,
    /// `PROP_DEV_ADMINS`: the nodes allowed to manage this device over
    /// the mesh. Mirrored here because authorization is checked against
    /// the arriving frame's source key before anything reaches the
    /// session, and the responder holds no session borrow.
    pub admins: heapless::Vec<[u8; 32], MAX_DEV_ADMINS>,
    /// The session's live `PROP_DEV_KEY`.
    ///
    /// The device node compares this against the key its MAC was built
    /// with rather than merely checking that *some* identity exists. The
    /// two can disagree — a newly installed `PROP_DEV_PRIVATE_KEY` takes
    /// effect at the next boot, and `CMD_CLEAR` + `CMD_RST` erases the
    /// stored one — and in every such case the running node is no longer
    /// the identity the session describes and must stop originating
    /// traffic under it.
    pub dev_key: Option<[u8; 32]>,
    /// `PROP_MAC_REPEATER_ENABLED`: whether the device node should
    /// forward overheard routable frames. Advertised as the `REP`
    /// capability bit — a fact about what the node does, not a choice
    /// about what it calls itself.
    pub repeater_enabled: bool,
    /// `PROP_MAC_REPEATER_REGIONS`: the flood-forwarding region filter,
    /// as concatenated 2-octet codes. Empty imposes no restriction.
    ///
    /// Carried in wire order so the device node can both configure the
    /// MAC's region filter and hand the same bytes to the Supported
    /// Regions identity option without reshaping either.
    pub repeater_regions: heapless::Vec<u8, { MAX_REPEATER_REGIONS * 2 }>,
    /// `PROP_MAC_REPEATER_DEFAULT_REGION`: the code the node inserts
    /// into an untagged flood packet, or `None` to never tag.
    pub repeater_default_region: Option<[u8; 2]>,
    /// `PROP_MAC_REPEATER_MIN_RSSI`: minimum RSSI in dBm to
    /// flood-forward, or `None` for no threshold.
    pub repeater_min_rssi: Option<i16>,
    /// `PROP_MAC_REPEATER_MIN_SNR`: minimum SNR in whole dB to
    /// flood-forward, or `None` for no threshold.
    pub repeater_min_snr: Option<i8>,
    /// `PROP_IDENT_ROLE`: the advertised `ROLE` byte, or `None` to
    /// derive it from the forwarding state.
    pub ident_role: Option<u8>,
    /// `PROP_IDENT_MOBILE`: whether to advertise the `MOB` capability
    /// bit.
    pub ident_mobile: bool,
    /// `PROP_DEV_DISCOVERABLE`: whether the device identity answers
    /// Identity Requests.
    pub discoverable: bool,
    /// `PROP_ADVERT_INTERVAL`: seconds between unsolicited
    /// advertisements, 0 for none.
    pub advert_interval_s: u32,
    /// `PROP_BEACON_INTERVAL`: seconds between unsolicited beacons, 0 for
    /// none.
    pub beacon_interval_s: u32,
    /// `PROP_STARTUP_BEACON`: whether one beacon goes out at bring-up.
    pub startup_beacon: bool,
    /// `PROP_TZ_OFFSET`: minutes east of UTC, for whatever renders a
    /// local time.
    pub tz_offset_min: i16,
    /// `PROP_GNSS_ENABLED`: whether the receiver should be powered.
    /// Always false on a board without `CAP_GNSS`.
    ///
    /// Carried here rather than as an effect of its own so that a host
    /// write, a boot restore, and a `CMD_RST` all reach the receiver by
    /// the same path — the mirror is published whenever the device domain
    /// moves, which is exactly the set of moments this can change.
    pub gnss_enabled: bool,
    /// `PROP_GNSS_IDENT_UPDATE`: whether fixes refresh the advertised
    /// node identity's location.
    pub gnss_ident_update: bool,
    /// `PROP_GNSS_IDENT_PRECISION`: how far the advertised location is
    /// clamped down from the fix.
    pub gnss_ident_precision: u8,
    /// `PROP_GNSS_TIME_TRUST`: whether receiver-derived time may set the
    /// wall clock.
    pub gnss_time_trust: bool,
    /// `PROP_BLE_ENABLED`: whether the device is reachable over
    /// Bluetooth. Always false on a board without `CAP_BLE`.
    ///
    /// Carried here for the same reason the receiver switch is: the
    /// mirror is published whenever the device domain moves, which is
    /// exactly the set of moments this can change, so the transport
    /// hears about a host write, a boot restore, a `CMD_RST` and a menu
    /// entry by one path instead of four.
    pub ble_enabled: bool,
}

/// A device-initiated property publication, yielded by
/// [`DeviceEnv::publish_event`].
///
/// The driver has exactly one select arm for everything the board pushes
/// unasked, because a hook per property would need one `&mut self` borrow
/// per arm and no two of those can coexist. One arm, one enum, and the
/// board decides internally which of its sources woke it.
pub enum PublishEvent {
    /// An unsolicited `PROP_BATTERY`.
    Battery(umsh_ulcp::battery::BatteryStatus),
    /// An unsolicited `PROP_TIME`; `None` is a clock that has gone back
    /// to not knowing what time it is.
    Time(Option<u32>),
    /// An unsolicited positioning property, named by its key, encoded
    /// from the accompanying snapshot.
    Gnss(u32, umsh_ulcp::gnss::GnssSnapshot),
}

/// Board couplings of the session driver. Everything the loop needs from
/// the platform, expressed as one trait so the driver itself stays free
/// of HAL types and `cfg` board forks. Hooks a board doesn't have keep
/// their no-op defaults (e.g. only the T-1000E implements the attention
/// indicator and transmit-load hooks today).
// Single-executor embedded consumers; `Send` futures are irrelevant here,
// same as the embassy ecosystem's own async traits.
#[allow(async_fn_in_trait)]
pub trait DeviceEnv {
    /// Durably persist the encoded protocol snapshot (CMD_SAVE / host wipe).
    async fn persist_snapshot(&mut self, bytes: &[u8]) -> Result<(), ()>;
    /// Tombstone the snapshot journal (CMD_CLEAR).
    async fn clear_snapshot(&mut self) -> Result<(), ()>;
    /// Copy the newest committed snapshot generation strictly older than
    /// the one last handed to the driver into `out`, returning its
    /// length.
    ///
    /// Called only after a payload is rejected, so the cost is paid on a
    /// boot that is already going wrong. Implementations re-scan the
    /// journal rather than retaining a runner-up, keeping the mount
    /// path's "never buffers a second copy" discipline. The default
    /// refuses, which makes rejection terminal for boards whose journal
    /// cannot walk back.
    async fn older_snapshot(&mut self, out: &mut [u8]) -> Option<usize> {
        let _ = out;
        None
    }
    /// A stored snapshot was rejected at boot. Boards with an indicator
    /// surface it locally: the host-visible report reaches nobody on an
    /// unattended repeater, which is exactly the deployment this
    /// matters for.
    fn report_snapshot_rejected(&mut self, fell_back: bool) {
        let _ = fell_back;
    }
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
    async fn sample_battery(&mut self) -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
        Err(())
    }
    /// One fresh ambient light measurement in millilux
    /// (`Effect::SampleIlluminance`). Only emitted on a board whose
    /// `SessionConfig::illuminance` is set, so the default reports nothing.
    ///
    /// `None` is a legitimate answer — the sensor exists but could not be
    /// read — and reaches the host as the empty value rather than an error.
    async fn sample_illuminance(&mut self) -> Option<u32> {
        None
    }
    /// Wait for a battery measurement the board considers worth
    /// announcing, for publication as an unsolicited `PROP_BATTERY`
    /// (`Session::publish_battery`).
    ///
    /// The board owns the whole policy: the sampling cadence, the
    /// charge-state edges, and which changes matter. It is the only layer
    /// that sees every sample, so filtering there keeps the session free
    /// of cached readings and keeps this hook's contract simple — every
    /// value it yields is published.
    ///
    /// Cancellation-safe: the driver drops and re-creates this future on
    /// every other loop iteration, so an implementation must not lose an
    /// update it was cancelled on (an `embassy_sync::watch::Watch`
    /// receiver behaves correctly here; a bare `Signal` does not).
    ///
    /// The default never completes, so boards without battery push add
    /// nothing to the select.
    async fn battery_event(&mut self) -> umsh_ulcp::battery::BatteryStatus {
        core::future::pending().await
    }
    /// Wait for anything the board wants to publish unasked, across every
    /// property it pushes.
    ///
    /// This is the driver's single select arm for device-initiated
    /// publication. The default delegates to
    /// [`battery_event`](Self::battery_event), so a board that pushes only
    /// battery measurements implements that and nothing else. A board that
    /// also pushes time or position overrides this instead and selects
    /// over its own sources — which it can do without fighting the
    /// borrow checker, since those are its own fields rather than three
    /// `&mut self` calls.
    ///
    /// Cancellation-safe on the same terms as
    /// [`battery_event`](Self::battery_event).
    async fn publish_event(&mut self) -> PublishEvent {
        PublishEvent::Battery(self.battery_event().await)
    }
    /// Read the platform wall clock (`Effect::ReadTime`): Unix seconds,
    /// or `None` when the device does not know what time it is.
    ///
    /// Not knowing is the honest answer for a board that has never had a
    /// fix and was never told, and it is what stops a display from
    /// showing a clock. The default is exactly that, so a board without
    /// `CAP_TIME` never has to implement it.
    async fn read_time(&mut self) -> Option<u32> {
        None
    }
    /// Apply a `PROP_TIME` write (`Effect::ApplyTime`): set the wall
    /// clock, or return it to not knowing.
    ///
    /// A manual set outranks every receiver-derived one, so this applies
    /// regardless of `PROP_GNSS_TIME_TRUST`.
    async fn apply_time(&mut self, epoch: Option<u32>) {
        let _ = epoch;
    }
    /// Sample the receiver's current view of position and constellation
    /// (`Effect::SampleGnss`). Only emitted on a board whose
    /// `SessionConfig::gnss` advertises the capability, so the default
    /// refuses.
    async fn sample_gnss(&mut self) -> Result<umsh_ulcp::gnss::GnssSnapshot, ()> {
        Err(())
    }
    /// Build and sign the device identity's node-identity blob into
    /// `out` (`Effect::SignIdentity`), returning its length.
    ///
    /// The board owns both halves the session does not: the signing key,
    /// and the advertised profile the Identity Request responder uses.
    /// Boards without a device node keep the default, which refuses.
    async fn sign_identity(&mut self, out: &mut [u8]) -> Option<usize> {
        let _ = out;
        None
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
    /// Start or stop the board's locate indication (`PROP_ALERT`).
    ///
    /// Carries the authoritative state and is called for every
    /// transition — host write, local cancellation, and deadline — so an
    /// implementation can treat it as idempotent and needs no notion of
    /// *why* the alert ended. `AlertState::Locate` must override a local
    /// silence setting without clearing it (spec §PROP_ALERT); boards
    /// without `CAP_ALERT` never see this and keep the default.
    fn set_alert(&mut self, state: umsh_ulcp::alert::AlertState) {
        let _ = state;
    }
    /// The receiver switch was flipped at the device, and is now
    /// `enabled`.
    ///
    /// Only for the local gesture: a host write already knows what it
    /// asked for, and a board that indicated one would announce the
    /// phone's own settings screen back at it. Carries the resulting
    /// state rather than the fact of a press, because "on" and "off"
    /// are what the operator needs told apart.
    fn gnss_switched(&mut self, enabled: bool) {
        let _ = enabled;
    }
    /// Make the Bluetooth transport reachable, or stop it being so.
    ///
    /// Called from the device-domain mirror rather than from any one
    /// gesture, so it arrives for a host write, a boot restore, a
    /// `CMD_RST` and a menu entry alike — and arrives again whenever
    /// anything else in the domain moves. Implementations must therefore
    /// be idempotent, and boards without `CAP_BLE` never see anything
    /// but the default.
    ///
    /// Disabled means unreachable, not powered down: dropping the
    /// attached host and stopping advertising is what a user turns this
    /// off for, and a stack that cannot be torn down at runtime is no
    /// reason to refuse them that.
    fn set_ble_enabled(&mut self, enabled: bool) {
        let _ = enabled;
    }
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
pub struct DeviceRuntime<M: RawMutex + 'static, const RX: usize, const TX: usize> {
    /// Inbound frames and connection edges from every transport task.
    pub input: &'static InputChannel<M>,
    /// The session's radio endpoint — its private virtual `Channels`
    /// bundle served by the board's radio mux (never the real radio
    /// bundle directly).
    pub radio: &'static Channels<M, RX, TX>,
    /// Runtime radio settings / RSSI sampling into the radio runner.
    pub ctl: &'static DeviceControl<M>,
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

    /// Copy one raw ULCP frame into the next slot.
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
            debug_assert!(false, "Emitter: ULCP frame exceeds FRAME_OUT_MAX");
        }
    }

    /// Hand all staged frames to whoever is being answered.
    async fn flush<M: RawMutex>(&mut self, sink: &mut ReplySink<'_, M>) {
        for index in 0..self.count {
            let frame = &self.bufs[index][..self.lens[index]];
            match sink {
                ReplySink::Transport {
                    destination: Some((transport, generation)),
                    out,
                } => {
                    let mut copy: FrameBuf = heapless::Vec::new();
                    if copy.extend_from_slice(frame).is_err() {
                        // FRAME_OUT_MAX == FrameBuf capacity, so this
                        // cannot happen; assert in debug rather than
                        // silently drop.
                        debug_assert!(false, "Emitter frame copy exceeded FrameBuf capacity");
                        continue;
                    }
                    out.for_transport(*transport)
                        .send(OutFrame {
                            generation: *generation,
                            frame: copy,
                        })
                        .await;
                }
                // Nobody attached: the response has nowhere to go.
                ReplySink::Transport {
                    destination: None, ..
                } => {}
                ReplySink::Admin { reply } => {
                    // An exchange is one request and one response. A
                    // second frame would mean the session emitted
                    // something unsolicited, which this binding does not
                    // carry, so keep the first and account for the rest.
                    if reply.is_empty() {
                        let _ = reply.extend_from_slice(frame);
                    } else {
                        debug_assert!(false, "admin exchange emitted more than one frame");
                    }
                }
            }
        }
        self.count = 0;
    }
}

/// Where the frames a session emits while serving one command are
/// delivered.
///
/// The command paths do not know which they are feeding — that is the
/// point. A deferred property read makes the same `respond_*` call
/// whether the value is going to an attached host over USB or back to an
/// administrator across the mesh.
enum ReplySink<'a, M: RawMutex> {
    /// The attached host's output queue, or nowhere when none is
    /// attached.
    Transport {
        destination: Option<(Transport, u32)>,
        out: &'a TransportChannels<M>,
    },
    /// The response frame of a Node Management exchange, staged for the
    /// responder that will envelope and transmit it. Empty when the
    /// command produced no response, which is what a reset does.
    Admin { reply: &'a mut AdminFrame },
}

/// Execute a radio side effect requested by the session.
async fn apply_effect<A, S, const TXQ: usize, M, const RX: usize, const TX: usize, E>(
    session: &Session<A, S, TXQ>,
    effect: Option<Effect>,
    rt: &DeviceRuntime<M, RX, TX>,
    env: &mut E,
) where
    A: AesProvider,
    S: Sha256Provider,
    M: RawMutex,
    E: DeviceEnv,
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
            rt.ctl.apply(DeviceSettings {
                enabled: settings.enabled,
                freq_hz: settings.freq_khz.saturating_mul(1_000),
                sf,
                bw,
                cr,
                power_dbm: i32::from(settings.tx_power_dbm),
            });
            // Published for anything that wants to show what the radio is
            // actually set to — a board's stats page, in particular —
            // without having to hold the session to ask. The statics live
            // with the device node, which not every driver consumer
            // builds.
            #[cfg(feature = "device-node")]
            crate::device_node::set_tx_power_dbm(settings.tx_power_dbm);
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
            let cad = if session.tx_nocca() {
                CadPolicy::Skip
            } else {
                CadPolicy::Gate
            };
            rt.radio
                .tx
                .send(TxRequest {
                    data,
                    power_dbm,
                    cad,
                })
                .await;
        }
        Some(Effect::DeviceNameChanged) => {
            env.publish_device_name(session.device_name()).await;
        }
        Some(Effect::ApplyAlert(state)) => {
            env.set_alert(state);
        }
        Some(Effect::ApplyTime { epoch }) => {
            env.apply_time(epoch).await;
        }
        Some(Effect::ApplyBackhaul { enabled }) => {
            crate::radio_mux::MUX_MODE.set_backhaul(enabled);
        }
        // Deferred effects needing `&mut Session` + the emitter are
        // handled inline in the run loop rather than here.
        Some(Effect::SampleRssi { .. })
        | Some(Effect::SignIdentity { .. })
        | Some(Effect::SampleBattery { .. })
        | Some(Effect::SampleIlluminance { .. })
        | Some(Effect::ReadTime { .. })
        | Some(Effect::SampleGnss { .. })
        | Some(Effect::SetPairingPin { .. })
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
/// Generate, persist, and install a fresh device identity.
///
/// The counterpart to first-boot generation, for the one runtime path
/// that can leave the session without one: `CMD_CLEAR` followed by the
/// `CMD_RST` that completes a factory reset. A device identity is not a
/// commissioning step, so there is no state in which the operator has to
/// supply one.
///
/// A failure to draw entropy or to persist leaves the session
/// identityless, which is a worse outcome than either but not one this
/// layer can repair: it is reported and the next boot regenerates.
async fn regenerate_device_identity<A, S, const TXQ: usize, E>(
    session: &mut Session<A, S, TXQ>,
    env: &mut E,
) where
    A: AesProvider,
    S: Sha256Provider,
    E: DeviceEnv,
{
    let mut secret = [0u8; 32];
    if env.fill_secret(&mut secret).is_err() {
        env.trace(format_args!("device identity regenerate: entropy FAILED"));
        return;
    }
    let (public_key, payload) = device_identity_record(&secret);
    match env.persist_identity(&payload).await {
        Ok(()) => {
            session.set_boot_identity(public_key);
            env.trace(format_args!(
                "device identity regenerated after clear+reset"
            ));
        }
        Err(()) => env.trace(format_args!(
            "device identity regenerate: persist FAILED — none in effect"
        )),
    }
}

fn sync_dev_domain<A, S, const TXQ: usize, E>(
    session: &Session<A, S, TXQ>,
    synced_version: &mut u32,
    env: &mut E,
) where
    A: AesProvider,
    S: Sha256Provider,
    E: DeviceEnv,
{
    if session.dev_domain_version() == *synced_version {
        return;
    }
    *synced_version = session.dev_domain_version();
    let mut snapshot = DevDomainSnapshot {
        version: *synced_version,
        channel_keys: heapless::Vec::new(),
        peers: heapless::Vec::new(),
        admins: heapless::Vec::new(),
        dev_key: session.dev_key().copied(),
        repeater_enabled: session.repeater_enabled(),
        repeater_regions: heapless::Vec::from_slice(session.repeater_regions()).unwrap_or_default(),
        repeater_default_region: session.repeater_default_region(),
        repeater_min_rssi: session.repeater_min_rssi(),
        repeater_min_snr: session.repeater_min_snr(),
        ident_role: session.ident_role(),
        ident_mobile: session.ident_mobile(),
        discoverable: session.dev_discoverable(),
        advert_interval_s: session.advert_interval_s(),
        beacon_interval_s: session.beacon_interval_s(),
        startup_beacon: session.startup_beacon(),
        tz_offset_min: session.tz_offset_min(),
        gnss_enabled: session.gnss_enabled(),
        gnss_ident_update: session.gnss_ident_update(),
        gnss_ident_precision: session.gnss_ident_precision(),
        gnss_time_trust: session.gnss_time_trust(),
        ble_enabled: session.ble_enabled(),
    };
    for key in session.dev_channel_keys() {
        let _ = snapshot.channel_keys.push(key);
    }
    for public_key in session.dev_peers() {
        let _ = snapshot.peers.push(public_key);
    }
    for public_key in session.dev_admins() {
        let _ = snapshot.admins.push(public_key);
    }
    // Ahead of the mirror: the mirror is consumed by the device node,
    // and Bluetooth reachability is the transport's business rather than
    // the node's.
    env.set_ble_enabled(snapshot.ble_enabled);
    env.publish_dev_domain(snapshot);
}

/// One ULCP frame to serve, and what its binding needs to know.
enum Exchange<'a> {
    /// A frame from the attached host. The reply is bounded by the
    /// transport frame, which is what the session assumes by default.
    Local(&'a [u8]),
    /// A frame from a mesh administrator, whose reply must fit
    /// `reply_budget` octets of Node Management payload.
    Admin {
        frame: &'a [u8],
        reply_budget: usize,
    },
}

/// Serve one ULCP frame to completion, deferred platform round trips
/// included, delivering everything the session emits to `sink`.
///
/// This is the whole of the driver's command path, and it is deliberately
/// one function for both bindings. A multi-property command is served
/// entry by entry: each deferred value returns here for its platform
/// round trip, and `resume_multi` hands back the next one until the reply
/// is emitted. For every other command `resume_multi` answers `None` and
/// the loop runs exactly once. None of that changes because the answer is
/// going to the mesh instead of to a cable — the only thing that changes
/// is where the frames go, which is `sink`'s business.
async fn serve_frame<A, S, const TXQ: usize, M, const RX: usize, const TX: usize, E>(
    session: &mut Session<A, S, TXQ>,
    exchange: Exchange<'_>,
    emitter: &mut Emitter,
    sink: &mut ReplySink<'_, M>,
    snapshot_buf: &mut [u8; SNAPSHOT_MAX],
    rt: &DeviceRuntime<M, RX, TX>,
    env: &mut E,
) where
    A: AesProvider,
    S: Sha256Provider,
    M: RawMutex,
    E: DeviceEnv,
{
    let now_ms = Instant::now().as_millis();
    let mut pending = match exchange {
        Exchange::Local(bytes) => {
            session.handle_frame(bytes, now_ms, &mut |frame: &[u8]| emitter.push(frame))
        }
        Exchange::Admin {
            frame,
            reply_budget,
        } => session.handle_admin_frame(frame, now_ms, reply_budget, &mut |frame: &[u8]| {
            emitter.push(frame)
        }),
    };
    emitter.flush(sink).await;
    while pending.is_some() {
        match pending.take() {
            Some(Effect::SampleRssi { tid }) => {
                // Round-trip to the radio runner for an
                // instantaneous RSSI sample, then answer the
                // deferred PROP_PHY_RSSI get.
                rt.ctl.request_rssi();
                let sample = rt.ctl.wait_rssi().await;
                session.respond_rssi(tid, sample, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
            }
            Some(Effect::SignIdentity { tid }) => {
                // The session holds no signing key, so the
                // platform builds the canonical node-identity
                // payload from the same profile the Identity
                // Request responder advertises and signs it
                // with the device identity.
                let mut blob = [0u8; IDENTITY_BLOB_MAX];
                let signed = env.sign_identity(&mut blob).await;
                session.respond_identity_blob(
                    tid,
                    signed.map(|len| &blob[..len]).ok_or(()),
                    &mut |frame: &[u8]| emitter.push(frame),
                );
                emitter.flush(sink).await;
            }
            Some(Effect::SampleBattery { tid }) => {
                // Round-trip to the platform battery
                // source for a fresh measurement, then
                // answer the deferred PROP_BATTERY get.
                let sample = env.sample_battery().await;
                session.respond_battery(tid, sample, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
            }
            Some(Effect::SampleIlluminance { tid }) => {
                let millilux = env.sample_illuminance().await;
                session.respond_illuminance(tid, millilux, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
            }
            Some(Effect::ReadTime { tid }) => {
                let epoch = env.read_time().await;
                session.respond_time(tid, epoch, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
            }
            Some(Effect::SampleGnss { tid, key }) => {
                let sample = env.sample_gnss().await;
                session.respond_gnss(tid, key, sample, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
            }
            Some(Effect::DrainQueue) => {
                // Deliver the covered frames one per
                // step, flushing between steps so the
                // two-slot emitter never overflows and
                // the transport applies backpressure.
                loop {
                    let more = session
                        .drain_step(Instant::now().as_millis(), &mut |frame: &[u8]| {
                            emitter.push(frame)
                        });
                    emitter.flush(sink).await;
                    if !more {
                        break;
                    }
                }
                env.clear_attention();
            }
            Some(Effect::SaveSnapshot { tid }) => {
                let result = match session.encode_snapshot(snapshot_buf) {
                    Some(len) => env.persist_snapshot(&snapshot_buf[..len]).await,
                    None => Err(()),
                };
                session.respond_save(tid, result, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
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
                session.respond_clear(tid, result, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
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
                                let (public_key, payload) = device_identity_record(&secret);
                                env.persist_identity(&payload).await.map(|()| public_key)
                            }
                            Err(()) => Err(()),
                        }
                    }
                    None => Err(()),
                };
                session.respond_identity(tid, result, &mut |frame: &[u8]| emitter.push(frame));
                emitter.flush(sink).await;
            }
            Some(Effect::SetPairingPin { tid, pin }) => {
                let applied = env.apply_pairing_pin(pin).await;
                session.respond_pin_set(
                    tid,
                    applied.then_some(()).ok_or(()),
                    &mut |frame: &[u8]| emitter.push(frame),
                );
                emitter.flush(sink).await;
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
            other => apply_effect(session, other, rt, env).await,
        }
        pending = session.resume_multi(Instant::now().as_millis(), &mut |frame: &[u8]| {
            emitter.push(frame)
        });
        emitter.flush(sink).await;
    }
    // Whatever this exchange was, the next frame is served on its own
    // terms. Restoring the local binding here rather than at the next
    // frame's arrival keeps every other emitting path — a publication, a
    // transmit completion, an alert deadline — reading the binding it
    // expects.
    session.end_admin_exchange();
    // A device identity always exists. `CMD_CLEAR` erases the stored one
    // without touching live state, and the `CMD_RST` that completes a
    // factory reset is where the live copy catches up — leaving the device
    // with none, which is the one state the invariant forbids. Regenerate
    // here, exactly as first boot would, so the only way to reach an
    // identityless device is to physically remove it from existence.
    //
    // The running device node keeps the *previous* key in its MAC until
    // the next boot (identity is fixed at bring-up), and stops
    // originating traffic because the dev-domain sync gate compares keys
    // rather than counting them.
    if session.dev_key().is_none() {
        regenerate_device_identity(session, env).await;
    }
    if session.queued_frame_count() == 0 {
        env.clear_attention();
    }
}

/// Drive the ULCP session forever: restore persisted state, then
/// select over host frames, radio receptions, and transmit completions,
/// executing every session effect through the board's [`DeviceEnv`].
///
/// The caller constructs the [`Session`] with its board profile
/// (`SessionConfig`) and boot status, mounts its journals, and hands the
/// stored payloads in; the driver owns everything after that.
pub async fn run<A, S, const TXQ: usize, M, const RX: usize, const TX: usize, E>(
    mut session: Session<A, S, TXQ>,
    boot_snapshot: Option<&[u8]>,
    boot_identity: Option<[u8; 32]>,
    rt: DeviceRuntime<M, RX, TX>,
    mut env: E,
) -> !
where
    A: AesProvider,
    S: Sha256Provider,
    M: RawMutex,
    E: DeviceEnv,
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
    // immediately.
    //
    // A payload that does not decode is not the end of it. The journal
    // is multi-record and newest-generation-wins, so an older readable
    // generation usually sits behind the rejected one — and for an
    // unattended repeater, falling back to it is the only outcome that
    // keeps the device forwarding. Walk back a bounded number of
    // generations: a systematically undecodable payload is a firmware
    // bug rather than corruption, and re-walking the whole journal on
    // every boot would just be slower about it.
    if let Some(payload) = boot_snapshot {
        let mut generation = 0usize;
        let mut restored = session.restore_at_boot(payload);
        while let Err(error) = restored {
            env.trace(format_args!(
                "proto-store boot-restore generation=-{generation} REJECTED error={error:?}"
            ));
            session.note_snapshot_rejected();
            generation += 1;
            if generation > SNAPSHOT_FALLBACK_LIMIT {
                env.trace(format_args!(
                    "proto-store boot-restore fallback=EXHAUSTED limit={SNAPSHOT_FALLBACK_LIMIT}"
                ));
                break;
            }
            let Some(len) = env.older_snapshot(&mut snapshot_buf).await else {
                env.trace(format_args!("proto-store boot-restore fallback=NONE"));
                break;
            };
            restored = session.restore_at_boot(&snapshot_buf[..len]);
        }
        match restored {
            Ok(effect) => {
                if generation > 0 {
                    env.trace(format_args!(
                        "proto-store boot-restore=FALLBACK generation=-{generation}"
                    ));
                    env.report_snapshot_rejected(true);
                } else {
                    env.trace(format_args!("proto-store boot-restore=ok"));
                }
                apply_effect(&session, Some(effect), &rt, &mut env).await;
            }
            Err(_) => {
                env.trace(format_args!("proto-store boot-restore=BARE"));
                env.report_snapshot_rejected(false);
            }
        }
    }

    // Publish the device domain once before any host interaction, on every
    // boot path rather than only after a successful restore.
    //
    // Two things depend on it. Detached multicast processing needs the
    // restored tables without waiting for an attach — the original reason.
    // And anything that waits for the domain to be published before acting
    // needs that publication to happen on a device that has never been
    // configured, where the answer is "the post-reset defaults" rather than
    // silence: the boot-time GNSS clock read waits on exactly this, and on
    // a bare device it would otherwise wait for a host that may never come.
    sync_dev_domain(&session, &mut dev_domain_synced, &mut env);

    loop {
        // Resolve the next event in its own statement so the select's
        // futures — one of which mutably borrows `env` — are dropped
        // before the arms below use `env` again. A `match select4(..)`
        // scrutinee would hold them for the whole match.
        let event = {
            // Only wait for a TX completion while one is outstanding,
            // so a spurious tx_done can never be consumed early.
            let tx_done = async {
                if session.has_pending_tx() {
                    rt.radio.tx_done.wait().await
                } else {
                    core::future::pending().await
                }
            };
            // The locate alert's deadline. Enforced here rather than by
            // each board so that "a device MUST bound how long it will
            // remain in ALERT_LOCATE" holds for every board that
            // advertises CAP_ALERT, including ones whose UX layer has no
            // timer of its own. Idle (never completes) while no alert is
            // running. It borrows `session` immutably, alongside
            // `tx_done` — only `publish_event` touches `env`.
            let alert_deadline = async {
                match session.alert_deadline_ms() {
                    Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                    None => core::future::pending().await,
                }
            };
            select4(
                rt.input.receive(),
                rt.radio.rx.receive(),
                tx_done,
                select(env.publish_event(), alert_deadline),
            )
            .await
        };

        match event {
            Either4::First(InEvent::Attached(transport)) => {
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
                // possession, BLE because the ULCP GATT service
                // refuses any access outside an encrypted LESC-bonded
                // link.
                session.attach(true);
                // PROP_MAC_BACKHAUL is session-scoped but its routing
                // lives in the mux, which the session-state reset above
                // cannot reach. A displaced session attaches without any
                // detach in between, so this is the reset that keeps a
                // predecessor's backhaul mode from leaving the new
                // session deaf to the air while its property reads 0.
                crate::radio_mux::MUX_MODE.set_backhaul(false);
            }
            Either4::First(InEvent::Detached(transport)) => {
                // Only the active transport's detach ends the
                // session; a displaced transport's stale detach
                // must not clear the successor's session state.
                if arbitration.detach(transport) {
                    env.set_advertising_allowed(true);
                    session.detach();
                    // The session that enabled backhaul is gone; without
                    // this, detached operation would keep the mux routing
                    // for a host that no longer exists and the device
                    // would stop queueing what it hears off the air.
                    crate::radio_mux::MUX_MODE.set_backhaul(false);
                }
            }
            Either4::First(InEvent::CancelAlert) => {
                // Whoever found the radio silenced it. Publishing the
                // transition is not conditional on a host being
                // attached — `cancel_alert` handles that — and a press
                // with no alert running is simply nothing.
                let effect = session.cancel_alert(&mut |frame: &[u8]| emitter.push(frame));
                emitter
                    .flush(&mut ReplySink::Transport {
                        destination: arbitration.destination(),
                        out: rt.out,
                    })
                    .await;
                apply_effect(&session, effect, &rt, &mut env).await;
            }
            Either4::First(InEvent::Toggle(setting)) => {
                // The switch itself reaches the platform through the
                // device-domain mirror at the bottom of this loop, like
                // every other write to it.
                let flipped = match setting {
                    Setting::Bluetooth => {
                        session.toggle_ble(&mut |frame: &[u8]| emitter.push(frame))
                    }
                    Setting::Gnss => session.toggle_gnss(&mut |frame: &[u8]| emitter.push(frame)),
                    Setting::ShareLocation => {
                        session.toggle_gnss_ident_update(&mut |frame: &[u8]| emitter.push(frame))
                    }
                    Setting::Forwarding => {
                        session.toggle_repeater(&mut |frame: &[u8]| emitter.push(frame))
                    }
                };
                if let Some(enabled) = flipped {
                    emitter
                        .flush(&mut ReplySink::Transport {
                            destination: arbitration.destination(),
                            out: rt.out,
                        })
                        .await;
                    if setting == Setting::Gnss {
                        env.gnss_switched(enabled);
                    }
                    // Keep an existing snapshot in step, so a switch the
                    // operator flipped is still flipped after a reboot.
                    // A device with nothing saved gets nothing saved:
                    // manufacturing a snapshot from a button press would
                    // persist every other live-only value with it.
                    if session.saved_status() != SavedStatus::None
                        && let Some(len) = session.encode_snapshot(&mut snapshot_buf)
                        && env.persist_snapshot(&snapshot_buf[..len]).await.is_ok()
                    {
                        session.note_snapshot_saved();
                    }
                    crate::log::debug_log(format_args!(
                        "ulcp: {:?} {} at the device",
                        setting,
                        if enabled { "ON" } else { "off" }
                    ));
                }
            }
            Either4::First(InEvent::Frame(transport, frame_bytes)) => {
                if arbitration.accepts_frame(transport) {
                    let mut sink = ReplySink::Transport {
                        destination: arbitration.destination(),
                        out: rt.out,
                    };
                    serve_frame(
                        &mut session,
                        Exchange::Local(&frame_bytes),
                        &mut emitter,
                        &mut sink,
                        &mut snapshot_buf,
                        &rt,
                        &mut env,
                    )
                    .await;
                }
            }
            Either4::First(InEvent::Admin {
                frame,
                reply_budget,
            }) => {
                // The responder is blocked on the reply channel, so this
                // arm must always answer. An empty reply is the answer
                // for a reset-class command, and for anything the session
                // declined to respond to at all.
                let mut reply = AdminFrame::new();
                {
                    let mut sink = ReplySink::Admin { reply: &mut reply };
                    serve_frame(
                        &mut session,
                        Exchange::Admin {
                            frame: &frame,
                            reply_budget,
                        },
                        &mut emitter,
                        &mut sink,
                        &mut snapshot_buf,
                        &rt,
                        &mut env,
                    )
                    .await;
                }
                ADMIN_REPLY.send(reply).await;
            }
            Either4::Second(RxFrame { data, info }) => {
                // While detached this may stage a delegated MAC
                // acknowledgement (Effect::StartTransmit).
                let queued_before = session.queued_frame_count();
                let rx_info = match info.origin {
                    RxOrigin::Air => {
                        RadioRxInfo::measured(info.rssi, info.snr.as_centibels(), info.lqi)
                    }
                    // Backhaul frames travel host-to-node, so the session
                    // never sees one arriving.
                    RxOrigin::LocalTx | RxOrigin::Backhaul => RadioRxInfo::self_transmitted(),
                };
                let effect = session.on_radio_rx(
                    &data,
                    &rx_info,
                    Instant::now().as_millis(),
                    &mut |frame: &[u8]| emitter.push(frame),
                );
                if session.queued_frame_count() > queued_before {
                    env.request_attention();
                }
                emitter
                    .flush(&mut ReplySink::Transport {
                        destination: arbitration.destination(),
                        out: rt.out,
                    })
                    .await;
                apply_effect(&session, effect, &rt, &mut env).await;
            }
            Either4::Third(result) => {
                let now_ms = Instant::now().as_millis();
                let outcome = match result {
                    Ok(()) => TxOutcome::Sent,
                    Err(umsh_hal::TxError::CadTimeout) => TxOutcome::ChannelBusy,
                    Err(umsh_hal::TxError::Io(_)) => TxOutcome::Failed,
                };
                let effect =
                    session.on_tx_result(outcome, now_ms, &mut |frame: &[u8]| emitter.push(frame));
                emitter
                    .flush(&mut ReplySink::Transport {
                        destination: arbitration.destination(),
                        out: rt.out,
                    })
                    .await;
                apply_effect(&session, effect, &rt, &mut env).await;
            }
            Either4::Fourth(Either::First(event)) => {
                // The board decided this is worth announcing; publish it
                // unsolicited. Dropped silently while no host is
                // attached, and no effect can result — a publication is
                // not an operation.
                let emit = &mut |frame: &[u8]| emitter.push(frame);
                match event {
                    PublishEvent::Battery(sample) => {
                        session.publish_battery(sample, emit);
                    }
                    PublishEvent::Time(epoch) => {
                        session.publish_time(epoch, emit);
                    }
                    PublishEvent::Gnss(key, snapshot) => {
                        session.publish_gnss(key, &snapshot, emit);
                    }
                }
                emitter
                    .flush(&mut ReplySink::Transport {
                        destination: arbitration.destination(),
                        out: rt.out,
                    })
                    .await;
            }
            Either4::Fourth(Either::Second(())) => {
                // The alert outlived its deadline: stop the indication
                // and publish the transition the host did not command.
                let effect = session
                    .poll_alert(Instant::now().as_millis(), &mut |frame: &[u8]| {
                        emitter.push(frame)
                    });
                emitter
                    .flush(&mut ReplySink::Transport {
                        destination: arbitration.destination(),
                        out: rt.out,
                    })
                    .await;
                apply_effect(&session, effect, &rt, &mut env).await;
            }
        }
        // Any of the arms may have moved the device-domain tables
        // (property mutation, CMD_RST, CMD_RESTORE); one u32
        // compare when they did not.
        sync_dev_domain(&session, &mut dev_domain_synced, &mut env);
    }
}
