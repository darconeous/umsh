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
//! - **Counter/key-value stores** are no-ops for now: the node currently
//!   transmits nothing but unsecured broadcasts, for which no counter
//!   state exists. The durable counter journal is the device-node plan's
//!   increment 4 and must land before the node sends secured traffic.
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

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use static_cell::StaticCell;

use umsh_bsp_nrf52840::EmbassyClock;
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_hal::{NoCounterStore, NoKeyValueStore};
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

impl umsh_mac::Platform for NcpNodePlatform {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = umsh_radio_loraphy::LoraphyRadio<ThreadModeRawMutex, 4, 2>;
    type Delay = embassy_time::Delay;
    type Clock = EmbassyClock;
    type Rng = NodeRng;
    type CounterStore = NoCounterStore;
    type KeyValueStore = NoKeyValueStore;
}

/// Device-node MAC with the same capacities as the CLI firmware (which
/// proves the footprint on identical hardware): 2 identities, 8 peers,
/// 4 channels, 4 pending ACKs, 8 TX slots, 255-byte frames, 32-entry
/// dup cache.
pub type NcpNodeMac = umsh_mac::Mac<NcpNodePlatform, 2, 8, 4, 4, 8, 255, 32>;
type NcpNodeHandle = MacHandle<'static, NcpNodePlatform, 2, 8, 4, 4, 8, 255, 32>;
type NcpNodeHost = Host<NcpNodeHandle>;
type NcpNode = LocalNode<NcpNodeHandle>;

// ─── Statics ─────────────────────────────────────────────────────────────────

/// The node's virtual radio bundle (mux client B). Static regardless of
/// whether the node is running: the mux fans RX out to it either way, and
/// a full queue just drops frames per the mux's per-client policy.
pub static NODE_CH: umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2> =
    umsh_radio_loraphy::Channels::new();

static NODE_MAC_CELL: StaticCell<AsyncRefCell<NcpNodeMac>> = StaticCell::new();

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
    let _ = host.run().await;
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
pub fn bring_up(spawner: Spawner, identity_secret: &[u8; 32], node_seed: [u8; 32], t_frame_ms: u32) {
    let radio = umsh_radio_loraphy::LoraphyRadio::new(&NODE_CH, t_frame_ms);
    let mut mac = NcpNodeMac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        EmbassyClock,
        NodeRng::from_seed(node_seed),
        NoCounterStore,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    );
    let identity = SoftwareIdentity::from_secret_bytes(identity_secret);
    let identity_id = mac
        .add_identity(identity)
        .unwrap_or_else(|_| panic!("device node identity"));
    // No persisted-counter load: the store is a no-op until the counter
    // journal lands (device-node plan increment 4).
    let mac_cell = NODE_MAC_CELL.init(AsyncRefCell::new(mac));

    let mut host: NcpNodeHost = Host::new(MacHandle::new(mac_cell));
    let node = host.add_node(identity_id);
    spawner.spawn(node_pump_task(host).unwrap());
    spawner.spawn(node_beacon_task(node).unwrap());
}
