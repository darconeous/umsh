//! The companion radio's device node: a full `umsh-mac`/`umsh-node`
//! stack running on the radio itself, alongside the companion session
//! (increment 2 of `docs/companion-device-node-plan.md`).
//!
//! The device identity "exists even when no phone is attached"
//! (companion-radio spec §Identities); this module is what makes that
//! true. It is an ordinary MAC + `Host` pump — the same shape as the
//! `companion-cli-t1000e` firmware on identical hardware — with the NCP's
//! constraints baked into [`NcpNodePlatform`]:
//!
//! - **Radio** is a [`LoraphyRadio`] over the node's virtual mux bundle
//!   ([`NODE_CH`], mux client B): the session and the node share the one
//!   physical radio through `radio_mux`.
//! - **Rng** is a ChaCha20 CSPRNG seeded from the hardware TRNG at boot
//!   ([`NodeRng`]): under BLE builds MPSL owns the RNG peripheral, and
//!   project policy forbids non-crypto RNGs outright.
//! - **Radio** transmissions pass through the shared duty ledger
//!   (`duty_gate`): the node and the session draw from one combined
//!   `PROP_PHY_DUTY_LIMIT` budget, and a refused transmit is shed via
//!   the MAC's CAD-backoff path rather than killing the pump.
//! - **The counter store** is the `COUNTER_PAGE0` journal
//!   (`firmware::NodeCounterStore`): TX reservation boundaries for the
//!   device identity and per-peer RX replay boundaries survive power
//!   cycles, flushed from inside the MAC pump (`MacHandle::next_event`)
//!   one whole-map record per persist block.
//!
//! The node is **dormant unless a device identity exists** at boot (the
//! identity journal is empty until provisioned; the `no-ble` image has no
//! journal at all and fails closed). [`bring_up`] is simply not called —
//! nothing here runs, and beacon triggers fall into an undrained queue.
//!
//! Beacon requests arrive through [`BEACON_TRIGGER`] rather than from any
//! specific button handler: the trigger is an input, because wake- and
//! timer-driven advertisement policy (reserved device-domain properties
//! 69–95) will feed the same path later.

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use static_cell::StaticCell;

use umsh_bsp_nrf52840::EmbassyClock;
use umsh_companion_ncp::{MAX_CHANNEL_KEYS, MAX_DEV_PEERS};
use umsh_core::{ChannelKey, PublicKey};
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_hal::NoKeyValueStore;
use umsh_mac::{MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh_node::{Host, LocalNode};
use umsh_sync::AsyncRefCell;

// ─── Platform ────────────────────────────────────────────────────────────────

/// ChaCha20 CSPRNG adapter implementing the `rand 0.10` traits the MAC
/// requires (`Platform::Rng: rand::CryptoRng`). Seeded once at boot from
/// the hardware TRNG, exactly like the session's `IdentityRng`, while the
/// RNG peripheral is still ours to read.
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
// the nRF52840 TRNG with bias correction.
impl rand::TryCryptoRng for NodeRng {}

/// `umsh_mac::Platform` bundle for the device node inside the NCP
/// firmware. Board-independent: both the T-Echo and the T-1000E images
/// use software crypto, the embassy clock, and the mux-backed radio.
pub struct NcpNodePlatform;

/// The node's radio path: its virtual mux bundle behind the shared
/// duty-ledger admission gate.
type NcpNodeRadio = crate::duty_gate::DutyGatedRadio<
    umsh_radio_loraphy::LoraphyRadio<ThreadModeRawMutex, 4, 2>,
    EmbassyClock,
>;

impl umsh_mac::Platform for NcpNodePlatform {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = NcpNodeRadio;
    type Delay = embassy_time::Delay;
    type Clock = EmbassyClock;
    type Rng = NodeRng;
    type CounterStore = crate::firmware::NodeCounterStore;
    type KeyValueStore = NoKeyValueStore;
}

/// Device-node MAC sized to the session's device-domain tables, which
/// are the only provisioning source it has: 1 identity (the device
/// identity; no PFS ephemerals on the NCP node), `MAX_DEV_PEERS` peers,
/// `MAX_CHANNEL_KEYS` channels (a smaller MAC table would refuse
/// channels the property surface accepted), 4 pending ACKs, 4 TX slots
/// (beacons and future acks — no application traffic), 255-byte frames,
/// 32-entry dup cache. The per-channel replay maps are the RAM hot
/// spot (~330 bytes per tracked sender): 4 full-key + 2 hint-only
/// senders per channel keeps the whole table ~2 KiB/channel; extra
/// concurrent senders on one channel fail closed (dropped, never
/// accepted unchecked).
pub type NcpNodeMac =
    umsh_mac::Mac<NcpNodePlatform, 1, MAX_DEV_PEERS, MAX_CHANNEL_KEYS, 4, 4, 255, 32, 4, 2>;
type NcpNodeHandle =
    MacHandle<'static, NcpNodePlatform, 1, MAX_DEV_PEERS, MAX_CHANNEL_KEYS, 4, 4, 255, 32, 4, 2>;
type NcpNodeHost = Host<NcpNodeHandle>;
type NcpNode = LocalNode<NcpNodeHandle>;

// ─── Statics ─────────────────────────────────────────────────────────────────

/// The node's virtual radio bundle (mux client B). Static regardless of
/// whether the node is running: the mux fans RX out to it either way, and
/// a full queue just drops frames per the mux's per-client policy.
pub static NODE_CH: umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2> =
    umsh_radio_loraphy::Channels::new();

static NODE_MAC_CELL: StaticCell<AsyncRefCell<NcpNodeMac>> = StaticCell::new();

// ─── Device-domain sync input ────────────────────────────────────────────────

/// A point-in-time copy of the session's device-domain node tables
/// (`PROP_DEV_CHANNEL_KEYS`, `PROP_DEV_PEERS`) plus whether a device
/// identity is live. Built by `ncp_task` whenever the session's
/// `dev_domain_version` moves and handed to [`node_dev_sync_task`],
/// which reconciles the node's MAC against it. The session stays
/// authoritative for the property surface; the node only mirrors it.
pub struct DevDomainSnapshot {
    pub channel_keys: heapless::Vec<[u8; 32], MAX_CHANNEL_KEYS>,
    pub peers: heapless::Vec<[u8; 32], MAX_DEV_PEERS>,
    /// `PROP_DEV_KEY` is live. Goes false when a factory reset
    /// (`CMD_CLEAR` + `CMD_RST`) completes; the running node then goes
    /// dormant (beacons gated off, channels removed) until the reboot
    /// that finishes tearing it down.
    pub identity_present: bool,
}

/// Latest-wins hand-off from `ncp_task` to the sync task. A `Signal`
/// rather than a queue: intermediate table states are irrelevant, only
/// convergence on the newest snapshot matters. With the node dormant
/// (never brought up) a pending snapshot just sits here unconsumed.
pub static DEV_SYNC: Signal<ThreadModeRawMutex, DevDomainSnapshot> = Signal::new();

/// Whether the device node may transmit. Cleared when a snapshot
/// reports the identity gone (factory reset); the MAC still holds the
/// old identity until reboot, but it must stop originating traffic.
static NODE_ACTIVE: AtomicBool = AtomicBool::new(true);

/// Reconciles the node's MAC against each [`DevDomainSnapshot`]: joins
/// newly provisioned channels, removes de-provisioned ones (dropping
/// their replay state), and registers peers. Peer *removal* is not
/// propagated — MAC registry entries carry no key material, so a stale
/// entry is inert, and the registry is rebuilt from the live table at
/// the next boot.
#[embassy_executor::task]
async fn node_dev_sync_task(node: NcpNode, mac: NcpNodeHandle) {
    // Channel keys currently applied to the MAC. Starts empty: the MAC
    // is built bare at bring-up and every channel arrives through here.
    let mut applied: heapless::Vec<[u8; 32], MAX_CHANNEL_KEYS> = heapless::Vec::new();
    loop {
        let snapshot = DEV_SYNC.wait().await;
        NODE_ACTIVE.store(snapshot.identity_present, Ordering::Relaxed);
        let mut index = 0;
        while index < applied.len() {
            if snapshot.channel_keys.contains(&applied[index]) {
                index += 1;
                continue;
            }
            let key = applied.swap_remove(index);
            let _ = node.leave(&umsh_node::Channel::private(ChannelKey(key), ""));
            mac.remove_channel(&ChannelKey(key)).await;
            crate::firmware::debug_log(format_args!(
                "node dev-sync: channel {:02x}{:02x}.. removed",
                key[0], key[1]
            ));
        }
        for key in snapshot.channel_keys.iter() {
            if applied.contains(key) {
                continue;
            }
            match node.join(&umsh_node::Channel::private(ChannelKey(*key), "")).await {
                Ok(_) => {
                    let _ = applied.push(*key);
                    crate::firmware::debug_log(format_args!(
                        "node dev-sync: channel {:02x}{:02x}.. joined",
                        key[0], key[1]
                    ));
                }
                Err(_) => crate::firmware::debug_log(format_args!(
                    "node dev-sync: channel {:02x}{:02x}.. join FAILED",
                    key[0], key[1]
                )),
            }
        }
        // Registration is add-or-refresh; repeats are harmless.
        for public_key in snapshot.peers.iter() {
            if node.peer(PublicKey(*public_key)).await.is_err() {
                crate::firmware::debug_log(format_args!(
                    "node dev-sync: peer {:02x}{:02x}.. register FAILED",
                    public_key[0], public_key[1]
                ));
            }
        }
        // Seed persisted RX replay boundaries for the registered peers
        // (a repeat only refreshes each peer's initial boundary; live
        // replay windows are untouched). Without this, a peer's replay
        // floor would restart at zero after every power cycle.
        if !snapshot.peers.is_empty() {
            let _ = mac.load_all_persisted_rx_counters().await;
        }
        crate::firmware::debug_log(format_args!(
            "node dev-sync: {} channels, {} peers, identity={}",
            snapshot.channel_keys.len(),
            snapshot.peers.len(),
            snapshot.identity_present
        ));
    }
}

// ─── Beacon trigger input ────────────────────────────────────────────────────

/// Why a beacon was requested. Carried through [`BEACON_TRIGGER`] so the
/// send path never assumes a button: beacon-at-wake and periodic beacons
/// (device-domain advertisement policy) are planned triggers.
///
/// Only the T-1000E wires a trigger source today; the T-Echo image
/// carries the input surface unused.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "t1000e"), allow(dead_code))]
pub enum BeaconTrigger {
    /// The board's primary-action button slot.
    Button,
}

/// Beacon requests into the node. With the node dormant the queue is
/// never drained and requests are dropped at the `try_send` in
/// [`request_beacon`] — the slot is inert, exactly as the UX guidelines
/// require for an unprovisioned device.
pub static BEACON_TRIGGER: Channel<ThreadModeRawMutex, BeaconTrigger, 2> = Channel::new();

/// Fire-and-forget beacon request. A full queue means a beacon is
/// already pending, so dropping the extra request loses nothing.
#[cfg_attr(not(feature = "t1000e"), allow(dead_code))]
pub fn request_beacon(trigger: BeaconTrigger) {
    let _ = BEACON_TRIGGER.try_send(trigger);
}

// ─── Tasks ───────────────────────────────────────────────────────────────────

/// Drives the device node's MAC pump. Never returns while healthy; an
/// exit means the MAC hit an unrecoverable radio error, and rebooting
/// through the panic handler beats silently losing the device identity.
#[embassy_executor::task]
async fn node_pump_task(mut host: NcpNodeHost) {
    crate::firmware::debug_log(format_args!("node pump: running"));
    let result = host.run().await;
    crate::firmware::debug_log(format_args!("node pump: EXITED ok={}", result.is_ok()));
    panic!("device node host exited");
}

/// Turns beacon triggers into `send_all` calls on the device identity.
/// Confirmation feedback fires only when the MAC *accepts* the send —
/// a refusal (queue full, future duty limiting) leaves the slot silent.
#[embassy_executor::task]
async fn node_beacon_task(node: NcpNode) {
    use umsh_node::Transport as _;
    loop {
        let _trigger = BEACON_TRIGGER.receive().await;
        // A factory-cleared identity leaves the slot inert, exactly
        // like an unprovisioned one.
        if !NODE_ACTIVE.load(Ordering::Relaxed) {
            continue;
        }
        let accepted = node.send_all(&[], &SendOptions::default()).await.is_ok();
        #[cfg(feature = "t1000e")]
        if accepted {
            umsh_bsp_t1000e::indicator::LED_SEQUENCE_SIGNAL
                .signal(umsh_ux_tracker::led::LedSequence::ActionConfirm);
            umsh_bsp_t1000e::BUZZER_SIGNAL
                .signal(&umsh_ux_tracker::buzzer::melodies::BEACON_ACK);
        }
        #[cfg(not(feature = "t1000e"))]
        let _ = accepted;
    }
}

// ─── Bring-up ────────────────────────────────────────────────────────────────

/// Construct the MAC around the persisted device identity and spawn the
/// node tasks. Call at most once, and only when the identity journal
/// yielded a keypair; without one the node stays dormant.
///
/// `t_frame_ms` is the worst-case airtime hint for the MAC scheduler.
pub async fn bring_up(
    spawner: Spawner,
    identity_secret: &[u8; 32],
    node_seed: [u8; 32],
    t_frame_ms: u32,
    counters: &'static crate::firmware::NodeCountersMutex,
) {
    // The Mac is ~37 KiB. `init_with` lets the compiler construct it
    // in place inside the static cell; building it as a stack local
    // (what `StaticCell::init` does) transits the stack once per move
    // in the chain, and this image's statics leave only ~110 KiB of
    // stack — hardware-diagnosed as boot HardFaults (INVSTATE jumps to
    // 0) and a smashed allocator when the temporaries blew through it.
    // Keep the construction a single in-place expression.
    let mac_cell: &'static AsyncRefCell<NcpNodeMac> = NODE_MAC_CELL.init_with(|| {
        AsyncRefCell::new(NcpNodeMac::new(
            crate::duty_gate::DutyGatedRadio::new(
                umsh_radio_loraphy::LoraphyRadio::new(&NODE_CH, t_frame_ms),
                &crate::firmware::DUTY_LEDGER,
                EmbassyClock,
            ),
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
            EmbassyClock,
            NodeRng::from_seed(node_seed),
            crate::firmware::NodeCounterStore::new(counters),
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        ))
    });
    crate::firmware::debug_log(format_args!("node bring-up: mac cell ready"));
    let identity = SoftwareIdentity::from_secret_bytes(identity_secret);
    let identity_id = mac_cell
        .try_borrow_mut()
        .expect("mac cell is unshared during bring-up")
        .add_identity(identity)
        .unwrap_or_else(|_| panic!("device node identity"));
    // Seed the identity's TX frame counter from the persisted boundary
    // so secured sends can never reuse counter space from a previous
    // boot. With nothing persisted the random initial counter stands.
    match MacHandle::new(mac_cell).load_persisted_counter(identity_id).await {
        Ok(counter) => {
            crate::firmware::debug_log(format_args!("node bring-up: tx counter {counter}"))
        }
        Err(_) => crate::firmware::debug_log(format_args!("node bring-up: tx counter load FAILED")),
    }

    let mut host: NcpNodeHost = Host::new(MacHandle::new(mac_cell));
    let node = host.add_node(identity_id);
    // Permanent observability tap: every packet the node processes is
    // one debug line. This is the device-domain acceptance instrument
    // (multicast on a provisioned device channel shows up here) and it
    // never consumes the packet. The subscription is leaked because the
    // node lives for the rest of the boot.
    core::mem::forget(node.on_receive(|packet| {
        let channel = packet
            .channel()
            .map(|info| u16::from_be_bytes(info.id().0))
            .unwrap_or(0);
        crate::firmware::debug_log(format_args!(
            "node rx: {:?} ch={:04x} len={} auth={}",
            packet.packet_family(),
            channel,
            packet.payload().len(),
            packet.source_authenticated(),
        ));
        false
    }));
    crate::firmware::debug_log(format_args!("node bring-up: host ready"));
    spawner.spawn(node_pump_task(host).unwrap());
    spawner.spawn(node_dev_sync_task(node.clone(), MacHandle::new(mac_cell)).unwrap());
    spawner.spawn(node_beacon_task(node).unwrap());
}
