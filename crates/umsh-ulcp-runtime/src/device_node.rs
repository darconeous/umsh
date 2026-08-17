//! The device node: a full `umsh-mac`/`umsh-node` stack running on the
//! device itself, alongside the ULCP session.
//!
//! The device identity "exists even when no phone is attached" (ULCP spec
//! §Identities); this module is what makes that true. It is an ordinary
//! MAC + `Host` pump with the device's constraints baked into
//! [`DeviceNodePlatform`]:
//!
//! - **Radio** is a `LoraphyRadio` over the node's virtual mux bundle
//!   ([`NODE_CH`], mux client B) behind the shared duty-ledger gate: the
//!   session and the node share one physical radio through `radio_mux`
//!   and draw from one combined `PROP_PHY_DUTY_LIMIT` budget. A refused
//!   transmit is shed via the MAC's CAD-backoff path rather than killing
//!   the pump.
//! - **Rng** is a ChaCha20 CSPRNG seeded from the board's hardware TRNG
//!   at boot ([`NodeRng`]): project policy forbids non-crypto RNGs, and
//!   under BLE builds the RNG peripheral is not ours to read at runtime.
//! - **The counter store** is the board's — the `CS` parameter — so TX
//!   reservation boundaries for the device identity and per-peer RX
//!   replay boundaries survive power cycles, flushed from inside the MAC
//!   pump one whole-map record per persist block.
//!
//! The node **always exists**: a device identity is generated and
//! persisted at first boot, so bring-up is unconditional and the only
//! question is whether the node is *transmitting*. That is configuration
//! — the PHY enable state and the forwarding switch — plus the
//! `NODE_ACTIVE` gate, which closes while a factory reset is in flight
//! (the identity has been erased from storage but the running MAC still
//! holds it until the reboot that completes the wipe).
//!
//! Beacon requests arrive through [`BEACON_TRIGGER`] rather than from any
//! specific button handler: the trigger is an input, so a button press,
//! bring-up, and the advertisement-policy timers in [`advert_loop`] all
//! reach the radio by one path.
//!
//! # Board seam
//!
//! Embassy task functions cannot be generic, so the spawnable tasks stay
//! in each firmware as thin shims around the `*_loop` functions here, and
//! the board owns the two statics whose types depend on `CS`: the MAC
//! cell and its counter store. Everything else — every static whose type
//! is fixed, and every line of logic — is here once.

extern crate alloc;

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use embassy_time::{Duration, Instant, Timer};
use static_cell::StaticCell;

use umsh_core::{ChannelKey, PublicKey};
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_hal::{CounterStore, EmbassyClock, NoKeyValueStore};
use umsh_mac::{MacCounters, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::{
    Host, LocalNode, NodeCapabilities, NodeIdentityProfile, NodeRole, default_respond_policy,
    never_respond_policy,
};
use umsh_sync::AsyncRefCell;
use umsh_ulcp_device::{MAX_CHANNEL_KEYS, MAX_DEV_ADMINS, MAX_DEV_PEERS, MAX_DEVICE_NAME_LEN};

use crate::driver::DevDomainSnapshot;
use crate::duty_gate::DutyGatedRadio;
use crate::log::debug_log;

/// The mutex kind guarding the node's statics.
///
/// The nRF images run a single thread-mode executor, where
/// `ThreadModeRawMutex` is a no-op lock — worth keeping, because these
/// statics sit in the radio RX/TX path on boards whose BLE controller
/// (MPSL/SDC) has hard real-time deadlines that a critical section would
/// intrude on. Boards without that constraint take the portable default.
///
/// `embassy_sync` only defines `ThreadModeRawMutex` for bare-metal targets,
/// so the host build takes the portable default regardless of the feature.
/// Nothing on the host runs the device node — it builds there for tests and
/// rustdoc — and the portable lock is the correct choice under a hosted OS
/// anyway.
#[cfg(all(feature = "node-thread-mode-mutex", target_os = "none"))]
pub type NodeMutex = embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
#[cfg(not(all(feature = "node-thread-mode-mutex", target_os = "none")))]
pub type NodeMutex = CriticalSectionRawMutex;

// ─── Platform ────────────────────────────────────────────────────────────────

/// ChaCha20 CSPRNG adapter implementing the `rand 0.10` traits the MAC
/// requires (`Platform::Rng: rand::CryptoRng`). Seeded once at boot from
/// the board's hardware TRNG, exactly like the session's `IdentityRng`,
/// while that source is still ours to read.
pub struct NodeRng(rand_chacha::ChaCha20Rng);

impl NodeRng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(<rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed(seed))
    }
}

impl rand::TryRng for NodeRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand_core::RngCore::next_u32(&mut self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand_core::RngCore::next_u64(&mut self.0))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::RngCore::fill_bytes(&mut self.0, dest);
        Ok(())
    }
}

// ChaCha20 is a cryptographically secure generator; the seed comes from
// the board's hardware TRNG.
impl rand::TryCryptoRng for NodeRng {}

/// `umsh_mac::Platform` bundle for the device node, generic only over the
/// board's counter store — the one piece of the platform that is
/// genuinely per-board, because it is backed by that board's flash.
pub struct DeviceNodePlatform<CS>(core::marker::PhantomData<CS>);

/// The node's radio path: its virtual mux bundle behind the shared
/// duty-ledger admission gate.
pub type DeviceNodeRadio =
    DutyGatedRadio<umsh_radio_loraphy::LoraphyRadio<NodeMutex, 4, 2>, EmbassyClock>;

impl<CS: CounterStore + 'static> umsh_mac::Platform for DeviceNodePlatform<CS> {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = DeviceNodeRadio;
    type Delay = embassy_time::Delay;
    type Clock = EmbassyClock;
    type Rng = NodeRng;
    type CounterStore = CS;
    type KeyValueStore = NoKeyValueStore;
}

/// Every node the device domain names, which is what the MAC peer table
/// has to hold: a full peer list and a full administrator list can be
/// provisioned at once, and each needs a pairwise session.
pub const MAX_NODE_PEERS: usize = MAX_DEV_PEERS + MAX_DEV_ADMINS;

/// Device-node MAC sized to the session's device-domain tables, which are
/// the only provisioning source it has: 1 identity (the device identity;
/// no PFS ephemerals on the device node), `MAX_NODE_PEERS` peers,
/// `MAX_CHANNEL_KEYS` channels (a smaller MAC table would refuse channels
/// the property surface accepted), 4 pending ACKs, 4 TX slots (beacons
/// and future acks — no application traffic), 255-byte frames, 32-entry
/// dup cache. The per-channel replay maps are the RAM hot spot (~330
/// bytes per tracked sender): 4 full-key + 2 hint-only senders per
/// channel keeps the whole table ~2 KiB/channel; extra concurrent senders
/// on one channel fail closed (dropped, never accepted unchecked).
pub type DeviceNodeMac<CS> =
    umsh_mac::Mac<DeviceNodePlatform<CS>, 1, MAX_NODE_PEERS, MAX_CHANNEL_KEYS, 4, 4, 255, 32, 4, 2>;
pub type DeviceNodeHandle<CS> = MacHandle<
    'static,
    DeviceNodePlatform<CS>,
    1,
    MAX_NODE_PEERS,
    MAX_CHANNEL_KEYS,
    4,
    4,
    255,
    32,
    4,
    2,
>;
pub type DeviceNodeHost<CS> = Host<DeviceNodeHandle<CS>>;
pub type DeviceNode<CS> = LocalNode<DeviceNodeHandle<CS>>;

/// The `StaticCell` a board declares for its MAC. Board-side because its
/// type depends on `CS`, and a `static` cannot be generic.
pub type DeviceNodeMacCell<CS> = StaticCell<AsyncRefCell<DeviceNodeMac<CS>>>;

// ─── Statics ─────────────────────────────────────────────────────────────────

/// The node's virtual radio bundle (mux client B). Static regardless of
/// whether the node is running: the mux fans RX out to it either way, and
/// a full queue just drops frames per the mux's per-client policy.
pub static NODE_CH: umsh_radio_loraphy::Channels<NodeMutex, 4, 2> =
    umsh_radio_loraphy::Channels::new();

/// Latest-wins hand-off from the session driver to the sync loop. A
/// `Signal` rather than a queue: intermediate table states are
/// irrelevant, only convergence on the newest snapshot matters. On a boot
/// that skipped node bring-up (a crash-report boot) a pending snapshot
/// just sits here unconsumed.
pub static DEV_SYNC: Signal<NodeMutex, DevDomainSnapshot> = Signal::new();

/// Whether the device node may transmit. Cleared when a snapshot reports
/// the identity gone (factory reset); the MAC still holds the old
/// identity until reboot, but it must stop originating traffic.
static NODE_ACTIVE: AtomicBool = AtomicBool::new(true);

/// Whether the device node is acting as a repeater
/// (`PROP_MAC_REPEATER_ENABLED`).
static NODE_IS_REPEATER: AtomicBool = AtomicBool::new(false);

/// The public key the running MAC actually holds, published once at
/// bring-up.
///
/// The session has the same value in `PROP_DEV_KEY`, but a display
/// reading it there would be reading what the device is *configured*
/// with; this is what it is answering to on the air, which is the thing
/// someone comparing an address against a phone screen needs.
///
/// `None` until bring-up runs, and on a board that never brings a node
/// up at all — which is the honest answer for a screen that would
/// otherwise print a placeholder address.
static NODE_KEY: BlockingMutex<CriticalSectionRawMutex, RefCell<Option<[u8; 32]>>> =
    BlockingMutex::new(RefCell::new(None));

/// Whether the device node forwards other nodes' frames.
///
/// Reads the same state the session's `PROP_MAC_REPEATER_ENABLED` names,
/// published here so a display can glance at it without borrowing the
/// coordinator or racing `dev_sync_loop` for the mirror — which is a
/// single-consumer `Signal` and already has one.
pub fn repeater_enabled() -> bool {
    NODE_IS_REPEATER.load(Ordering::Relaxed)
}

/// The public key the running node answers to, or `None` before
/// bring-up.
pub fn node_key() -> Option<[u8; 32]> {
    NODE_KEY.lock(|key| *key.borrow())
}

/// Whether bring-up ran this boot. Without it nothing answers
/// [`IDENT_REQUEST`], and a `PROP_IDENT` read must fail rather than hang
/// the session waiting for a task that does not exist.
static NODE_UP: AtomicBool = AtomicBool::new(false);

/// The MAC's frame tallies, republished by [`pump_loop`] after each wake
/// cycle so a board's display can read them without borrowing the
/// coordinator.
///
/// Plain atomics rather than a mutex: the readers are display code
/// that wants a glance, not a consistent transaction, and a torn read
/// across two of these counters is invisible at the resolution anyone
/// looks at them. Publishing from inside the pump costs no extra wakeups —
/// it happens on a loop that was going to run anyway.
static MAC_TX_FRAMES: AtomicU32 = AtomicU32::new(0);
static MAC_TX_ABANDONED: AtomicU32 = AtomicU32::new(0);
static MAC_RX_FRAMES: AtomicU32 = AtomicU32::new(0);
static MAC_RX_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static MAC_FORWARDED: AtomicU32 = AtomicU32::new(0);
static MAC_FORWARD_CANCELLED: AtomicU32 = AtomicU32::new(0);

/// The most recently published MAC tallies.
///
/// All zero before the node's first wake cycle, which is
/// indistinguishable from a node that has done nothing — and is the same
/// thing as far as a reader is concerned.
pub fn mac_counters() -> MacCounters {
    MacCounters {
        tx_frames: MAC_TX_FRAMES.load(Ordering::Relaxed),
        tx_abandoned: MAC_TX_ABANDONED.load(Ordering::Relaxed),
        rx_frames: MAC_RX_FRAMES.load(Ordering::Relaxed),
        rx_accepted: MAC_RX_ACCEPTED.load(Ordering::Relaxed),
        forwarded: MAC_FORWARDED.load(Ordering::Relaxed),
        forward_cancelled: MAC_FORWARD_CANCELLED.load(Ordering::Relaxed),
    }
}

fn publish_mac_counters(counters: MacCounters) {
    MAC_TX_FRAMES.store(counters.tx_frames, Ordering::Relaxed);
    MAC_TX_ABANDONED.store(counters.tx_abandoned, Ordering::Relaxed);
    MAC_RX_FRAMES.store(counters.rx_frames, Ordering::Relaxed);
    MAC_RX_ACCEPTED.store(counters.rx_accepted, Ordering::Relaxed);
    MAC_FORWARDED.store(counters.forwarded, Ordering::Relaxed);
    MAC_FORWARD_CANCELLED.store(counters.forward_cancelled, Ordering::Relaxed);
}

/// The transmit power the radio was last configured with, in dBm, offset
/// by 128 so the sentinel for "not yet configured" is a value no real
/// setting occupies.
static TX_POWER_DBM: AtomicU16 = AtomicU16::new(u16::MAX);

/// The applied `PROP_PHY_TX_POWER`, or `None` before the first
/// `Effect::ApplyRadio`.
pub fn tx_power_dbm() -> Option<i8> {
    match TX_POWER_DBM.load(Ordering::Relaxed) {
        u16::MAX => None,
        raw => Some((raw as i16 - 128) as i8),
    }
}

/// Publish the transmit power the board just applied to the radio.
pub fn set_tx_power_dbm(dbm: i8) {
    TX_POWER_DBM.store((i16::from(dbm) + 128) as u16, Ordering::Relaxed);
}

/// The live device name, pushed by the board.
///
/// Pushed rather than pulled: the name lives behind a board-owned async
/// mutex, and the profile paths that need it are called from places that
/// cannot await one. The board writes it at boot and on every change,
/// which is the same edge it already had to handle.
static DEVICE_NAME: BlockingMutex<
    CriticalSectionRawMutex,
    RefCell<heapless::Vec<u8, MAX_DEVICE_NAME_LEN>>,
> = BlockingMutex::new(RefCell::new(heapless::Vec::new()));

/// Signalled internally by [`set_device_name`] so the Identity Request
/// responder's profile name stays current.
static NAME_CHANGED: Signal<NodeMutex, ()> = Signal::new();

/// Publish the live device name to the node. Call at boot and whenever
/// the session's device name changes.
pub fn set_device_name(name: &[u8]) {
    DEVICE_NAME.lock(|cell| {
        let mut current = cell.borrow_mut();
        current.clear();
        let _ = current.extend_from_slice(&name[..name.len().min(MAX_DEVICE_NAME_LEN)]);
    });
    NAME_CHANGED.signal(());
}

/// Snapshot the live device name as a spec-capped (≤24-byte) Node Name
/// identity option value, or `None` when unset/empty.
fn profile_name() -> Option<alloc::string::String> {
    DEVICE_NAME.lock(|cell| {
        let current = cell.borrow();
        core::str::from_utf8(&current)
            .ok()
            .map(|name| truncate_utf8(name, 24))
            .filter(|name| !name.is_empty())
            .map(alloc::string::String::from)
    })
}

/// Trim to at most `max` bytes without splitting a UTF-8 sequence.
fn truncate_utf8(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The advertised (role, capabilities) pair for the device identity.
///
/// Role and forwarding are separate dimensions, and this is where they
/// meet without being conflated. Capabilities are **facts**: `REP` is set
/// exactly when the node is actually forwarding, `MOB` exactly when the
/// operator has said the device moves. The role is what the device
/// *presents itself as*, which is configuration — an explicit
/// `PROP_IDENT_ROLE` is advertised verbatim, so a mobile repeater and a
/// fixed tracker are both expressible.
///
/// With no role configured the device derives one, which is what makes
/// the default sensible rather than a lie: a forwarding node is a
/// repeater, and anything else is a tracker.
fn advertised_identity(
    is_repeater: bool,
    is_mobile: bool,
    configured_role: Option<u8>,
) -> (NodeRole, NodeCapabilities) {
    let role = match configured_role {
        Some(byte) => NodeRole::from_byte(byte),
        None if is_repeater => NodeRole::Repeater,
        None => NodeRole::Tracker,
    };
    let mut capabilities = NodeCapabilities::empty();
    capabilities.set(NodeCapabilities::REPEATER, is_repeater);
    capabilities.set(NodeCapabilities::MOBILE, is_mobile);
    (role, capabilities)
}

/// The regions the node should advertise as supported, given a snapshot.
///
/// A device that is not forwarding makes no claim at all and omits the
/// option (node-identity.md §Supported Regions); a forwarding device with
/// an empty list forwards regardless of region, which is likewise not a
/// claim about any particular region. Only a forwarding device with a
/// configured list has something to say.
fn advertised_regions(
    snapshot: &DevDomainSnapshot,
) -> Option<alloc::vec::Vec<alloc::string::String>> {
    (snapshot.repeater_enabled && !snapshot.repeater_region_names.is_empty()).then(|| {
        snapshot
            .repeater_region_names
            .iter()
            // Validated as UTF-8 by the session that stored them.
            .filter_map(|name| core::str::from_utf8(name).ok())
            .map(alloc::string::String::from)
            .collect()
    })
}

// ─── Device-domain sync ──────────────────────────────────────────────────────

/// Reconciles the node's MAC against each [`DevDomainSnapshot`]: joins
/// newly provisioned channels, removes de-provisioned ones (dropping
/// their replay state), and registers peers. Peer *removal* is not
/// propagated — MAC registry entries carry no key material, so a stale
/// entry is inert, and the registry is rebuilt from the live table at the
/// next boot.
pub async fn dev_sync_loop<CS: CounterStore + 'static>(
    node: DeviceNode<CS>,
    mac: DeviceNodeHandle<CS>,
    node_key: [u8; 32],
) {
    // Channel keys currently applied to the MAC. Starts empty: the MAC is
    // built bare at bring-up and every channel arrives through here.
    let mut applied: heapless::Vec<[u8; 32], MAX_CHANNEL_KEYS> = heapless::Vec::new();
    loop {
        let snapshot = DEV_SYNC.wait().await;
        // Published first: the administrator list gates whether an
        // arriving request is heard at all, and its generation is what a
        // Node Management cursor is validated against. Neither should lag
        // a device-domain change by the length of a MAC reconciliation.
        crate::admin_responder::publish_dev_domain(&snapshot);
        // The gate is key equality, not mere presence. The session's live
        // identity and the one this MAC was built around can legitimately
        // differ — an installed `PROP_DEV_PRIVATE_KEY` takes effect at the
        // next boot, and `CMD_CLEAR` + `CMD_RST` erases the stored key —
        // and in every such case originating traffic would be signing as
        // an identity the device no longer claims.
        let matches_live = snapshot.dev_key == Some(node_key);
        NODE_ACTIVE.store(matches_live, Ordering::Relaxed);
        // Reconcile the forwarding switch, the forwarding policy, and the
        // advertised role/capabilities. All are idempotent; the profile is
        // refreshed unconditionally because the role and mobility
        // properties can move without the forwarding flag.
        mac.set_repeater_enabled(snapshot.repeater_enabled).await;
        let regions: heapless::Vec<[u8; 2], 8> =
            snapshot.repeater_region_codes.iter().copied().collect();
        let stored = mac
            .set_repeater_policy(
                &regions,
                snapshot.repeater_default_region,
                snapshot.repeater_min_rssi,
                snapshot.repeater_min_snr,
            )
            .await;
        if stored != regions.len() {
            debug_log(format_args!(
                "node dev-sync: repeater regions TRUNCATED {} of {}",
                stored,
                regions.len()
            ));
        }
        let (role, capabilities) = advertised_identity(
            snapshot.repeater_enabled,
            snapshot.ident_mobile,
            snapshot.ident_role,
        );
        let supported_regions = advertised_regions(&snapshot);
        // The profile is rebuilt from scratch on every snapshot rather than
        // patched, so the position has to be put back with everything else —
        // otherwise any device-domain write would quietly drop the advertised
        // location until the node next moved far enough to earn a new one.
        let mut profile = NodeIdentityProfile::new(PublicKey(node_key), role, capabilities);
        profile.name = profile_name();
        profile.supported_regions = supported_regions;
        // Identity option 3 dates each payload as it is built, so the
        // profile carries the clock rather than a reading. A device
        // that does not know the time omits the option, which is the
        // same answer the default gives.
        profile.clock = umsh_hal::wall_clock::now;
        #[cfg(feature = "gnss")]
        crate::gnss::stamp_identity(&mut profile);
        // `PROP_DEV_DISCOVERABLE` gates only the *responder*. The profile
        // stays installed either way because unsolicited advertisements are
        // built from it, and the spec keeps those governed by advertisement
        // policy rather than by discoverability.
        if snapshot.discoverable {
            node.enable_identity_responder(profile, default_respond_policy);
        } else {
            node.enable_identity_responder(profile, never_respond_policy);
        }
        // A repeater answers for its neighborhood; a node that forwards
        // nothing has no peer repeaters to describe and stays quiet. Gated
        // on forwarding rather than on discoverability, because the listing
        // is about the mesh around this node, not about this node.
        if snapshot.repeater_enabled {
            node.enable_peer_repeaters_responder();
        } else {
            node.disable_peer_repeaters_responder();
        }
        if NODE_IS_REPEATER.swap(snapshot.repeater_enabled, Ordering::Relaxed)
            != snapshot.repeater_enabled
        {
            debug_log(format_args!(
                "node dev-sync: repeater {}",
                if snapshot.repeater_enabled {
                    "ON"
                } else {
                    "off"
                }
            ));
        }
        let mut index = 0;
        while index < applied.len() {
            if snapshot.channel_keys.contains(&applied[index]) {
                index += 1;
                continue;
            }
            let key = applied.swap_remove(index);
            let _ = node
                .leave(&umsh_node::Channel::private(ChannelKey(key), ""))
                .await;
            debug_log(format_args!(
                "node dev-sync: channel {:02x}{:02x}.. removed",
                key[0], key[1]
            ));
        }
        for key in snapshot.channel_keys.iter() {
            if applied.contains(key) {
                continue;
            }
            match node
                .join(&umsh_node::Channel::private(ChannelKey(*key), ""))
                .await
            {
                Ok(_) => {
                    let _ = applied.push(*key);
                    debug_log(format_args!(
                        "node dev-sync: channel {:02x}{:02x}.. joined",
                        key[0], key[1]
                    ));
                }
                Err(_) => debug_log(format_args!(
                    "node dev-sync: channel {:02x}{:02x}.. join FAILED",
                    key[0], key[1]
                )),
            }
        }
        // Registration is add-or-refresh; repeats are harmless. An
        // administrator is registered alongside the peers: it is by
        // definition a node this device must be able to unseal a request
        // from and seal an answer to, and registering it is what lets
        // both travel under the ordinary source hint.
        for public_key in snapshot.peers.iter().chain(snapshot.admins.iter()) {
            if node.peer(PublicKey(*public_key)).await.is_err() {
                debug_log(format_args!(
                    "node dev-sync: peer {:02x}{:02x}.. register FAILED",
                    public_key[0], public_key[1]
                ));
            }
        }
        // Seed persisted RX replay boundaries for the registered peers (a
        // repeat only refreshes each peer's initial boundary; live replay
        // windows are untouched). Without this, a peer's replay floor
        // would restart at zero after every power cycle.
        if !snapshot.peers.is_empty() {
            let _ = mac.load_all_persisted_rx_counters().await;
        }
        // Published last, once the profile an advertisement is built from
        // is installed and `NODE_ACTIVE` reflects this snapshot. That
        // ordering is the whole reason `advert_loop` waits on this rather
        // than starting its own clock at bring-up.
        ADVERT_POLICY.sender().send(AdvertPolicy {
            advert_interval_s: snapshot.advert_interval_s,
            beacon_interval_s: snapshot.beacon_interval_s,
            startup_beacon: snapshot.startup_beacon,
        });
        debug_log(format_args!(
            "node dev-sync: {} channels, {} peers, identity-matches-live={}",
            snapshot.channel_keys.len(),
            snapshot.peers.len(),
            matches_live
        ));
    }
}

// ─── Beacon trigger input ────────────────────────────────────────────────────

/// Why a beacon was requested. Carried through [`BEACON_TRIGGER`] so the
/// send path never assumes a button.
#[derive(Clone, Copy)]
pub enum BeaconTrigger {
    /// The board's primary-action button slot. Boards without one carry
    /// the variant unused.
    Button,
    /// Emit a solicited advertisement — a broadcast carrying the signed
    /// node identity payload — echoing `nonce` when set. Currently
    /// unconstructed: the Identity Request responder that will drive it
    /// (with a targeted unicast reply) is a follow-up; the generator is
    /// kept for that pass.
    Advertise { nonce: Option<u32> },
    /// Emit an advertisement on the device's own schedule
    /// (`PROP_ADVERT_INTERVAL`) or at bring-up.
    ///
    /// Distinct from [`Button`](Self::Button) because it goes out with no
    /// flood budget: a scheduled advertisement is a standing statement
    /// rather than an introduction, so it reaches the neighbours that can
    /// hear the device and stops, and repeating it across the mesh every
    /// interval would cost far more airtime than it is worth.
    AutoAdvertise,
    /// Emit a beacon — a broadcast with no payload at all — which
    /// announces a path back to the device rather than who it is.
    Beacon,
}

/// Beacon requests into the node. On a boot that skipped node bring-up
/// the queue is never drained and requests are dropped at the `try_send`
/// in [`request_beacon`], leaving the slot inert rather than blocking the
/// caller.
pub static BEACON_TRIGGER: Channel<NodeMutex, BeaconTrigger, 2> = Channel::new();

/// Fire-and-forget beacon request. A full queue means a beacon (or
/// advertisement) is already pending, so dropping the extra request loses
/// nothing — bursts of Advertisement Requests coalesce here.
pub fn request_beacon(trigger: BeaconTrigger) {
    let _ = BEACON_TRIGGER.try_send(trigger);
}

/// Flood-hop budget on an unsolicited beacon.
///
/// A beacon exists to publish a path, so it has to travel far enough for
/// there to be a path worth publishing.
const BEACON_FLOOD_HOPS: u8 = 5;

/// What the device announces without being asked, mirrored from the
/// device domain's advertisement-policy properties.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdvertPolicy {
    /// `PROP_ADVERT_INTERVAL`, in seconds. 0 disables.
    pub advert_interval_s: u32,
    /// `PROP_BEACON_INTERVAL`, in seconds. 0 disables.
    pub beacon_interval_s: u32,
    /// `PROP_STARTUP_BEACON`.
    pub startup_beacon: bool,
}

/// The live advertisement policy.
///
/// A `Watch` for the same reasons [`crate::gnss`] uses one: [`advert_loop`]
/// arrives after the first device-domain sync and must still see it, and it
/// selects this against a timer, so the wait is dropped and rebuilt
/// constantly and must not lose an edge it was cancelled on.
///
/// Publishing it from [`dev_sync_loop`] rather than from each board is
/// what orders the startup beacon correctly: the first value can only
/// appear once the identity profile has been built and `NODE_ACTIVE`
/// settled, so nothing scheduled here can go out under a default profile.
static ADVERT_POLICY: Watch<NodeMutex, AdvertPolicy, 1> = Watch::new();

/// Board couplings the node cannot express itself.
#[derive(Clone, Copy)]
pub struct NodeHooks {
    /// Mark a completed node transmit for a board's battery-level
    /// estimator: voltage sampled near a transmission is sagged, not
    /// resting OCV. Boards with no estimator pass a no-op.
    pub note_external_load: fn(),
    /// Confirmation feedback for a button-triggered beacon, fired when
    /// the MAC *accepts* the send — a refusal (queue full, duty limiting)
    /// leaves the slot silent. Boards with no indicator pass a no-op.
    pub beacon_confirm: fn(),
}

impl Default for NodeHooks {
    fn default() -> Self {
        Self {
            note_external_load: || {},
            beacon_confirm: || {},
        }
    }
}

// ─── Loops ───────────────────────────────────────────────────────────────────

/// Drives the device node's MAC pump. Never returns while healthy; an
/// exit means the MAC hit an unrecoverable radio error, and rebooting
/// through the panic handler beats silently losing the device identity.
pub async fn pump_loop<CS: CounterStore + 'static>(
    mut host: DeviceNodeHost<CS>,
    mac: DeviceNodeHandle<CS>,
) -> ! {
    debug_log(format_args!("node pump: running"));
    // `Host::run` is this loop without the republish. Spelling it out here
    // is what lets the counters be refreshed on a schedule that already
    // exists: one wake cycle has just completed, the coordinator's borrow
    // is released, and nothing else had to be woken to notice.
    loop {
        if let Err(error) = host.pump_once().await {
            debug_log(format_args!("node pump: EXITED error={error:?}"));
            break;
        }
        publish_mac_counters(mac.counters().await);
    }
    panic!("device node host exited");
}

/// Turns beacon triggers into node sends on the device identity: a signed
/// advertisement either way — unsolicited for the button slot, echoing a
/// nonce for an Advertisement Request.
pub async fn beacon_loop<CS: CounterStore + 'static>(
    node: DeviceNode<CS>,
    identity: SoftwareIdentity,
    hooks: NodeHooks,
) {
    loop {
        let trigger = BEACON_TRIGGER.receive().await;
        // A factory-cleared identity leaves the slot inert, exactly like
        // an unprovisioned one.
        if !NODE_ACTIVE.load(Ordering::Relaxed) {
            continue;
        }
        match trigger {
            BeaconTrigger::Button => {
                // Currently a full signed identity rather than the empty
                // trace-route beacon: a listener that has never seen this
                // node learns nothing from a bare packet, and until the
                // node is reachable by discovery the button is the only
                // way to introduce it. Costs airtime a beacon does not.
                if send_advertisement(&node, &identity, None, AdvertReach::Mesh).await {
                    (hooks.beacon_confirm)();
                }
            }
            BeaconTrigger::Advertise { nonce } => {
                let accepted = send_advertisement(&node, &identity, nonce, AdvertReach::Mesh).await;
                debug_log(format_args!(
                    "node advert: nonce={nonce:?} accepted={accepted}"
                ));
            }
            BeaconTrigger::AutoAdvertise => {
                let accepted =
                    send_advertisement(&node, &identity, None, AdvertReach::Neighbours).await;
                debug_log(format_args!("node advert: scheduled accepted={accepted}"));
            }
            BeaconTrigger::Beacon => {
                let accepted = send_beacon(&node).await;
                debug_log(format_args!("node beacon: accepted={accepted}"));
            }
        }
    }
}

/// How far a scheduled or solicited advertisement is allowed to travel.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AdvertReach {
    /// Flood across the mesh under the default budget.
    Mesh,
    /// Direct neighbours only — no flood hops, no source route.
    Neighbours,
}

/// Broadcast an empty beacon: no payload, so nothing identifies the sender
/// beyond its source address, and the whole packet is the trace the
/// options collect on the way out.
async fn send_beacon<CS: CounterStore + 'static>(node: &DeviceNode<CS>) -> bool {
    use umsh_node::Transport as _;
    // Trace route to learn the path, trace signal to learn what that path
    // costs — the pair is what makes a beacon worth more than the fact
    // that the sender is alive.
    let options = SendOptions::default()
        .with_flood_hops(BEACON_FLOOD_HOPS)
        .with_trace_route()
        .with_trace_signal();
    node.send_all(&[], &options).await.is_ok()
}

/// Build, sign, and broadcast a solicited advertisement: the node
/// identity payload (role, live device name, echoed nonce) with the
/// standalone EdDSA signature the spec prefers for broadcasts, typed as a
/// NodeIdentity payload.
async fn send_advertisement<CS: CounterStore + 'static>(
    node: &DeviceNode<CS>,
    identity: &SoftwareIdentity,
    nonce: Option<u32>,
    reach: AdvertReach,
) -> bool {
    use umsh_crypto::NodeIdentity as _;
    use umsh_node::Transport as _;
    // The node's own profile is the canonical statement of what this node
    // is — kept current by `dev_sync_loop` and `identity_profile_loop` —
    // so build the payload from it rather than assembling a second,
    // drifting copy here.
    let Some(payload) = node.with_identity_profile(|profile| profile.to_payload(nonce)) else {
        return false;
    };
    // Payload-type byte + role/caps + name (≤26) + nonce (6) + 0xFF +
    // 64-byte signature, plus whatever the region list fits in what is
    // left. The signature's room is reserved up front rather than
    // discovered afterwards, so the encoder can drop trailing regions to
    // fit instead of framing a payload that then has nowhere to be signed.
    const SIGNATURE_LEN: usize = 64;
    let mut buf = [0u8; 192];
    buf[0] = umsh_core::PayloadType::NodeIdentity as u8;
    let signable = buf.len() - 1 - SIGNATURE_LEN;
    let Ok(body_len) = payload.encode_for_signing(&mut buf[1..1 + signable]) else {
        return false;
    };
    let mut len = 1 + body_len;
    // The signature covers ROLE through the 0xFF terminator — the
    // payload-type byte stays outside the signed range.
    let Ok(signature) = identity.sign(&buf[1..len]).await else {
        return false;
    };
    buf[len..len + SIGNATURE_LEN].copy_from_slice(&signature);
    len += SIGNATURE_LEN;
    // Full source, not a hint: the bundle's detached signature is only
    // checkable against the sender's public key, and a broadcast carries no
    // MIC to authenticate it otherwise. A hint-only advertisement is
    // unverifiable by anyone who does not already hold the key, which is
    // exactly the audience an advertisement is for.
    let options = SendOptions::default().with_full_source();
    let options = match reach {
        // Trace route for the same reason a beacon carries one, and trace
        // signal for the same reason again: the two are read as one list,
        // and a route with no signal beside it cannot be ranked against
        // the next one to arrive.
        AdvertReach::Mesh => options.with_trace_route().with_trace_signal(),
        // No flood budget and no trace: a scheduled advertisement is
        // already the largest packet this node originates, and the path
        // back to it is what the beacon interval is for.
        AdvertReach::Neighbours => options.no_flood(),
    };
    node.send_all(&buf[..len], &options).await.is_ok()
}

/// Emits the device's unsolicited announcements: one beacon at bring-up
/// under `PROP_STARTUP_BEACON`, then whatever `PROP_ADVERT_INTERVAL` and
/// `PROP_BEACON_INTERVAL` ask for.
///
/// The two intervals run independently rather than sharing a period. They
/// announce different things at very different costs — a beacon is a
/// path, an advertisement is a signed identity — so a mesh normally wants
/// the cheap one far more often than the expensive one, and one knob
/// could not express that.
///
/// Every period is scattered by up to [`ANNOUNCE_JITTER_SHIFT`] of the
/// interval. Two nodes configured alike and switched on together would
/// otherwise stay in step indefinitely, colliding on the air every period
/// and — worse — colliding again on each retry, since a shared schedule
/// makes them contend from the same starting instant every time. CAD and
/// backoff settle the individual collision; the scatter is what keeps the
/// mesh from having to.
///
/// The startup beacon itself is not delayed. Devices do not power on in
/// unison, so bring-up is already dispersed by whatever staggered them,
/// and a node that has just come up is the one whose neighbours most need
/// to hear from it.
pub async fn advert_loop<CS: CounterStore + 'static>(mac: DeviceNodeHandle<CS>) {
    let Some(mut policy_rx) = ADVERT_POLICY.receiver() else {
        debug_assert!(false, "node: advert_loop is single-caller");
        return;
    };
    // The first value doubles as the go-ahead: it cannot arrive until the
    // device domain has been synced, which is what makes the startup
    // beacon carry a real node rather than a half-built one.
    let mut policy = policy_rx.changed().await;
    if policy.startup_beacon {
        request_beacon(BeaconTrigger::Beacon);
    }

    let mut next_advert = schedule(&mac, policy.advert_interval_s).await;
    let mut next_beacon = schedule(&mac, policy.beacon_interval_s).await;
    loop {
        // A disabled interval has no deadline, so the arm is simply the
        // other one; with both off there is nothing to wait for but a
        // change of policy.
        let due = match (next_advert, next_beacon) {
            (Some(advert), Some(beacon)) => Some(advert.min(beacon)),
            (deadline, None) | (None, deadline) => deadline,
        };
        match due {
            Some(deadline) => {
                match select(Timer::at(deadline), policy_rx.changed()).await {
                    Either::First(()) => {
                        // Both fire when they fall due together: one
                        // announces the path, the other who is on it.
                        if next_advert == Some(deadline) {
                            request_beacon(BeaconTrigger::AutoAdvertise);
                            next_advert = schedule(&mac, policy.advert_interval_s).await;
                        }
                        if next_beacon == Some(deadline) {
                            request_beacon(BeaconTrigger::Beacon);
                            next_beacon = schedule(&mac, policy.beacon_interval_s).await;
                        }
                    }
                    Either::Second(updated) => {
                        // A rewritten interval restarts from now. Keeping
                        // the old deadline would make a host that shortens
                        // the period wait out the longer one first.
                        if updated.advert_interval_s != policy.advert_interval_s {
                            next_advert = schedule(&mac, updated.advert_interval_s).await;
                        }
                        if updated.beacon_interval_s != policy.beacon_interval_s {
                            next_beacon = schedule(&mac, updated.beacon_interval_s).await;
                        }
                        policy = updated;
                    }
                }
            }
            None => {
                let updated = policy_rx.changed().await;
                next_advert = schedule(&mac, updated.advert_interval_s).await;
                next_beacon = schedule(&mac, updated.beacon_interval_s).await;
                policy = updated;
            }
        }
    }
}

/// How far past its interval a period may be scattered, as a right shift
/// of the interval. Two is a quarter.
const ANNOUNCE_JITTER_SHIFT: u32 = 2;

/// When an interval next falls due, or `None` when it is switched off.
///
/// The wait is the whole interval plus a uniform draw between zero and a
/// quarter of it. The scatter only ever *delays*, which is what lets
/// `MIN_AUTO_ANNOUNCE_INTERVAL_S` be an absolute floor: no configuration
/// and no draw can put an unsolicited announcement on the air sooner than
/// the interval a host asked for.
///
/// The randomness is the MAC's ChaCha20 generator, seeded at boot from the
/// board's hardware TRNG. The node has one generator and this borrows it
/// rather than growing a second — a scheduling scatter does not need
/// unpredictability, but a node that keeps a weak generator around for the
/// undemanding cases eventually uses it for a demanding one.
async fn schedule<CS: CounterStore + 'static>(
    mac: &DeviceNodeHandle<CS>,
    interval_s: u32,
) -> Option<Instant> {
    if interval_s == 0 {
        return None;
    }
    let mut draw = [0u8; 4];
    mac.fill_random(&mut draw).await;
    let delay_s = jittered_delay_s(interval_s, u32::from_le_bytes(draw));
    Some(Instant::now() + Duration::from_secs(delay_s))
}

/// The seconds to wait for one period, given one random draw.
///
/// Split from [`schedule`] so the arithmetic can be checked without an
/// executor or a MAC: what matters about it is the bound it never
/// crosses, and that is a property of the numbers alone.
fn jittered_delay_s(interval_s: u32, draw: u32) -> u64 {
    // Fixed-point scaling rather than a modulus: it lands in `0..=spread`
    // for any spread, without a division or a rejection loop, and without
    // the modulo bias a `%` would leave at the top of the range.
    let spread = u64::from(interval_s >> ANNOUNCE_JITTER_SHIFT);
    let jitter = (u64::from(draw) * (spread + 1)) >> 32;
    u64::from(interval_s) + jitter
}

/// Keeps the Identity Request responder's profile name synced to the live
/// device name. The responder builds replies synchronously and cannot
/// await, so the current name is pushed in here on each change rather
/// than read at reply time.
pub async fn identity_profile_loop<CS: CounterStore + 'static>(node: DeviceNode<CS>) {
    loop {
        NAME_CHANGED.wait().await;
        let name = profile_name();
        node.update_identity_profile(move |profile| profile.name = name);
    }
}

/// Keeps the advertised identity's position synced to what the receiver
/// has settled on, under `PROP_GNSS_IDENT_UPDATE`.
///
/// Wakes on a change of the *advertised* cell rather than on each fix:
/// at the default precision a stationary node's fixes all land in the
/// same cell, and this would otherwise rewrite the profile every second
/// to say exactly what it already said.
///
/// Nothing here runs on a timer. The identity's freshness marker dates
/// each payload as it is built, so a stationary node has nothing to
/// restate — the position it is advertising is still the position it is
/// at, and rewriting it would change no byte.
#[cfg(feature = "gnss")]
pub async fn location_profile_loop<CS: CounterStore + 'static>(node: DeviceNode<CS>) {
    let Some(mut moved) = crate::gnss::identity_updates() else {
        debug_assert!(false, "node: location_profile_loop is single-caller");
        return;
    };
    loop {
        node.update_identity_profile(crate::gnss::stamp_identity);
        moved.changed().await;
    }
}

/// A `PROP_IDENT` read in flight.
///
/// A request/response signal pair rather than a shared handle: the node
/// is single-executor `Rc`/`RefCell` state and cannot live in a `static`
/// at all, and this is the same shape the pairing-PIN round trip already
/// uses.
static IDENT_REQUEST: Signal<NodeMutex, ()> = Signal::new();
static IDENT_RESPONSE: Signal<NodeMutex, Option<IdentityBlob>> = Signal::new();

/// A complete signed node-identity blob: the canonical unsigned encoding
/// followed by its 64-octet detached signature.
type IdentityBlob = heapless::Vec<u8, 320>;

/// Build and sign this node's identity blob into `out`, returning its
/// length.
///
/// This is the standalone framing of the same statement the Identity
/// Request responder makes — same profile, same builder — differing only
/// in that it carries no request nonce and is authenticated by the
/// signature rather than by an enclosing unicast.
pub async fn sign_identity_blob(out: &mut [u8]) -> Option<usize> {
    if !NODE_UP.load(Ordering::Relaxed) {
        return None;
    }
    IDENT_RESPONSE.reset();
    IDENT_REQUEST.signal(());
    let blob = IDENT_RESPONSE.wait().await?;
    if blob.len() > out.len() {
        return None;
    }
    out[..blob.len()].copy_from_slice(&blob);
    Some(blob.len())
}

/// Answers [`IDENT_REQUEST`] with the node's current signed identity.
pub async fn identity_blob_loop<CS: CounterStore + 'static>(
    node: DeviceNode<CS>,
    identity: SoftwareIdentity,
) {
    use umsh_crypto::NodeIdentity as _;
    loop {
        IDENT_REQUEST.wait().await;
        let mut blob = IdentityBlob::new();
        let _ = blob.resize_default(blob.capacity());
        // The node's own profile is the canonical statement of what this
        // node is; building from it is what keeps the local-control
        // framing and the over-the-air framing from drifting apart.
        let signed = async {
            let payload = node.with_identity_profile(|profile| profile.to_payload(None))?;
            let body = payload.encode_for_signing(&mut blob).ok()?;
            let signature = identity.sign(blob.get(..body)?).await.ok()?;
            blob.get_mut(body..body + 64)?.copy_from_slice(&signature);
            Some(body + 64)
        }
        .await;
        IDENT_RESPONSE.signal(signed.map(|len| {
            blob.truncate(len);
            blob
        }));
    }
}

// ─── Bring-up ────────────────────────────────────────────────────────────────

/// Everything bring-up produced, for the board to spawn its task shims
/// around. Embassy tasks cannot be generic, so the spawning itself stays
/// board-side.
pub struct DeviceNodeParts<CS: CounterStore + 'static> {
    pub host: DeviceNodeHost<CS>,
    pub node: DeviceNode<CS>,
    pub mac: DeviceNodeHandle<CS>,
    /// The public key the MAC was actually built around, for the
    /// device-domain sync gate.
    pub node_key: [u8; 32],
}

/// Construct the MAC around the device identity and wire up the node.
/// Call at most once. The identity is never absent — boot generates and
/// persists one when the journal is empty — so there is no
/// "unprovisioned" path here.
///
/// `t_frame_ms` is the worst-case airtime hint for the MAC scheduler.
/// The caller spawns the loops and must do so promptly: `NODE_UP` is set
/// here, so a `PROP_IDENT` read arriving between this returning and the
/// spawns would wait on the signal.
pub async fn bring_up<CS: CounterStore + 'static>(
    mac_cell: &'static DeviceNodeMacCell<CS>,
    identity_secret: &[u8; 32],
    node_seed: [u8; 32],
    t_frame_ms: u32,
    counters: CS,
    duty: &'static umsh_ulcp_device::DutyLedger,
    hooks: NodeHooks,
) -> DeviceNodeParts<CS> {
    // The Mac is ~37 KiB. `init_with` lets the compiler construct it in
    // place inside the static cell; building it as a stack local (what
    // `StaticCell::init` does) transits the stack once per move in the
    // chain — hardware-diagnosed on the nRF images as boot HardFaults
    // (INVSTATE jumps to 0) and a smashed allocator when the temporaries
    // blew through the stack budget. Keep the construction a single
    // in-place expression.
    let mac_cell: &'static AsyncRefCell<DeviceNodeMac<CS>> = mac_cell.init_with(|| {
        AsyncRefCell::new(DeviceNodeMac::new(
            DutyGatedRadio::with_load_hook(
                umsh_radio_loraphy::LoraphyRadio::new(&NODE_CH, t_frame_ms),
                duty,
                EmbassyClock,
                hooks.note_external_load,
            ),
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
            EmbassyClock,
            NodeRng::from_seed(node_seed),
            counters,
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        ))
    });
    debug_log(format_args!("node bring-up: mac cell ready"));
    let identity = SoftwareIdentity::from_secret_bytes(identity_secret);
    // Retained for the device-domain sync gate, which compares the
    // session's live PROP_DEV_KEY against the key this MAC actually holds.
    let node_key = umsh_crypto::NodeIdentity::public_key(&identity).0;
    NODE_KEY.lock(|key| key.replace(Some(node_key)));
    let identity_id = mac_cell
        .try_borrow_mut()
        .expect("mac cell is unshared during bring-up")
        .add_identity(identity)
        .unwrap_or_else(|_| panic!("device node identity"));
    // Seed the identity's TX frame counter from the persisted boundary so
    // secured sends can never reuse counter space from a previous boot.
    // With nothing persisted the random initial counter stands.
    match MacHandle::new(mac_cell)
        .load_persisted_counter(identity_id)
        .await
    {
        Ok(counter) => debug_log(format_args!("node bring-up: tx counter {counter}")),
        Err(_) => debug_log(format_args!("node bring-up: tx counter load FAILED")),
    }

    let mut host: DeviceNodeHost<CS> = Host::new(MacHandle::new(mac_cell));
    let node = host.add_node(identity_id);
    // Permanent observability tap: every packet the node processes is one
    // debug line. This is the device-domain acceptance instrument
    // (multicast on a provisioned device channel shows up here) and it
    // never consumes the packet. The subscription is leaked because the
    // node lives for the rest of the boot.
    core::mem::forget(node.on_receive(|packet| {
        let channel = packet
            .channel()
            .map(|info| u16::from_be_bytes(info.id().0))
            .unwrap_or(0);
        debug_log(format_args!(
            "node rx: {:?} ch={:04x} len={} auth={}",
            packet.packet_family(),
            channel,
            packet.payload().len(),
            packet.source_authenticated(),
        ));
        false
    }));
    // Node Management Requests. The tap only decides whether the sender
    // is entitled to be heard and queues what is; the exchange itself is
    // run by `admin_responder::responder_loop`, which the board spawns.
    // Never consumes: this is one more observer of every packet.
    core::mem::forget(node.on_receive(|packet| {
        crate::admin_responder::admit(packet);
        false
    }));
    // Identity Request observability tap. The actual reply is produced by
    // the built-in responder enabled below (a targeted unicast identity,
    // echoing any NONCE); this handler only logs, and never consumes.
    core::mem::forget(node.on_mac_command(|from, command| {
        if let umsh_node::OwnedMacCommand::IdentityRequest { options } = command {
            let nonce = umsh_node::mac_command::IdentityRequestFilters::new(options)
                .nonce()
                .ok()
                .flatten();
            debug_log(format_args!(
                "node identity-request: from {:02x}{:02x}.. nonce={:?}",
                from.0[0], from.0[1], nonce
            ));
        }
    }));
    // Enable the built-in Identity Request responder. Role and
    // capabilities start derived and are corrected by the first
    // device-domain sync; the name tracks the live device name via
    // `identity_profile_loop`. The default policy answers every request
    // whose filters select us, including our full source key when the
    // request wasn't authenticated to us. Replies are authenticated
    // unicast — never signed, never a broadcast fallback: a request whose
    // source can't be resolved to a key is dropped by the MAC before the
    // responder runs.
    {
        use umsh_crypto::NodeIdentity as _;
        let public_key = *SoftwareIdentity::from_secret_bytes(identity_secret).public_key();
        let mut profile =
            NodeIdentityProfile::new(public_key, NodeRole::Tracker, NodeCapabilities::empty());
        profile.name = profile_name();
        node.enable_identity_responder_default(profile);
    }
    // Let the node answer a brand-new requester that supplied its full
    // 32-byte source key: the MAC auto-registers it transiently
    // (LRU-evictable, never pinned) so the pairwise reply can be sealed.
    // Repeaters specifically must be able to respond this way.
    MacHandle::new(mac_cell)
        .set_auto_register_full_key_peers(true)
        .await;
    debug_log(format_args!("node bring-up: host ready"));
    NODE_UP.store(true, Ordering::Relaxed);
    DeviceNodeParts {
        host,
        node: node.clone(),
        mac: MacHandle::new(mac_cell),
        node_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::ids::{MAX_AUTO_ANNOUNCE_INTERVAL_S, MIN_AUTO_ANNOUNCE_INTERVAL_S};

    /// The property the whole scheme rests on: scatter delays a period and
    /// never brings it forward, so a configured interval is the shortest
    /// gap between two unsolicited announcements no matter what is drawn.
    /// Without this the protocol's floor would not be a floor.
    #[test]
    fn scatter_only_ever_delays_a_period() {
        for interval in [
            MIN_AUTO_ANNOUNCE_INTERVAL_S,
            3_600,
            14_400,
            MAX_AUTO_ANNOUNCE_INTERVAL_S,
        ] {
            for draw in [0, 1, u32::MAX / 3, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
                let delay = jittered_delay_s(interval, draw);
                assert!(
                    delay >= u64::from(interval),
                    "interval {interval} draw {draw} came early at {delay}"
                );
                assert!(
                    delay <= u64::from(interval) + u64::from(interval / 4),
                    "interval {interval} draw {draw} ran long at {delay}"
                );
            }
        }
    }

    /// Both ends of the draw are reachable, so the scatter actually
    /// spreads rather than clustering at one end of its range.
    #[test]
    fn the_scatter_spans_a_quarter_of_the_interval() {
        let interval = 14_400;
        assert_eq!(jittered_delay_s(interval, 0), u64::from(interval));
        assert_eq!(
            jittered_delay_s(interval, u32::MAX),
            u64::from(interval) + u64::from(interval / 4)
        );
        // Midway through the draw is midway through the scatter.
        assert_eq!(
            jittered_delay_s(interval, u32::MAX / 2),
            u64::from(interval) + u64::from(interval / 8)
        );
    }
}
