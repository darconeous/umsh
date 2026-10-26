//! This board's binding of the shared device node.
//!
//! The node itself—the MAC/`Host` pump, the device-domain sync, the
//! beacon and identity paths—lives in
//! [`umsh_ulcp_runtime::device_node`], shared with every other UMSH
//! device firmware. What stays here is what cannot be shared: the
//! counter-store type (backed by this board's flash), the board's UX
//! hooks, and the spawnable task shims, because embassy task functions
//! cannot be generic.

use embassy_executor::Spawner;

use umsh_crypto::software::SoftwareIdentity;
use umsh_ulcp_runtime::device_node as node;

// Re-exported for `main.rs`. The beacon trigger is only reached from a
// board with a primary-action button, so it is unused in some builds.
#[allow(unused_imports)]
pub use umsh_ulcp_runtime::device_node::{
    BeaconTrigger, NODE_CH, mac_counters, node_key, publish_snapshot, quiesce_for_reboot,
    radio_enabled, repeater_enabled, request_beacon, set_device_name, set_tx_power_dbm,
    sign_identity_blob, tx_power_dbm,
};

/// The node's platform binding: everything generic resolved against this
/// board's counter store.
type CounterStore = crate::NodeCounterStore;
pub(crate) type DeviceNode = node::DeviceNode<CounterStore>;
pub(crate) type DeviceNodeHandle = node::DeviceNodeHandle<CounterStore>;
type DeviceNodeHost = node::DeviceNodeHost<CounterStore>;

/// The driver's inbound event channel, which a Node Management exchange
/// crosses to reach the session.
type SessionInput = umsh_ulcp_runtime::driver::InputChannel<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
>;

// SAFETY of every `&mut` borrow below: `bring_up` runs at most once
// (its documented contract), before any reference to the arena exists.
//
// On the classic ESP32 the ~32 KiB Mac lives in `dram2_seg`—the DRAM
// past the ROM data and stack areas—because `dram_seg` shrinks to
// 128 KiB once esp-hal reserves the BT controller's 64 KiB and the Mac
// does not fit there alongside the rest of the image. `ram(reclaimed)`
// only admits `MaybeUninit` statics (the section is NOLOAD, so nothing
// zero-initialized may claim it), which is exactly what the arena is.
//
// Boards with PSRAM keep it there instead (`external::node_mac_arena`),
// which hands its ~33 KiB of internal RAM back to the main stack.
#[cfg(not(feature = "psram"))]
#[cfg_attr(feature = "chip-esp32", esp_hal::ram(reclaimed))]
static mut NODE_MAC_ARENA: node::DeviceNodeMacArena<CounterStore> =
    core::mem::MaybeUninit::uninit();

// ─── Task shims ──────────────────────────────────────────────────────────────

#[embassy_executor::task]
async fn node_pump_task(host: DeviceNodeHost, mac: DeviceNodeHandle) {
    node::pump_loop(host, mac, Some(&crate::STATS)).await
}

#[embassy_executor::task]
async fn node_dev_sync_task(node_handle: DeviceNode, mac: DeviceNodeHandle, node_key: [u8; 32]) {
    node::dev_sync_loop(node_handle, mac, node_key).await
}

#[embassy_executor::task]
async fn node_identity_profile_task(node_handle: DeviceNode) {
    node::identity_profile_loop(node_handle).await
}

#[embassy_executor::task]
async fn node_identity_blob_task(node_handle: DeviceNode, identity: SoftwareIdentity) {
    node::identity_blob_loop(node_handle, identity).await
}

#[embassy_executor::task]
async fn node_beacon_task(
    node_handle: DeviceNode,
    identity: SoftwareIdentity,
    hooks: node::NodeHooks,
) {
    node::beacon_loop(node_handle, identity, hooks).await
}

#[embassy_executor::task]
async fn node_advert_task(mac: DeviceNodeHandle) {
    node::advert_loop(mac).await
}

#[embassy_executor::task]
async fn node_reboot_quiesce_task(mac: DeviceNodeHandle) {
    node::reboot_quiesce_loop(mac).await
}

#[embassy_executor::task]
async fn node_admin_task(node_handle: DeviceNode, input: &'static SessionInput, nonce: u16) {
    umsh_ulcp_runtime::admin_responder::responder_loop(node_handle, input, nonce).await
}

#[cfg(feature = "lan-bearer")]
#[embassy_executor::task]
async fn lan_bearer_task(stack: embassy_net::Stack<'static>) {
    crate::lan::run(stack).await
}

#[cfg(feature = "meshcore-forwarder")]
#[embassy_executor::task]
async fn meshcore_forwarder_task(public_key: [u8; 32], seed: [u8; 32], t_frame_ms: u32) {
    umsh_ulcp_runtime::meshcore::forwarder_loop(
        meshcore_storage(public_key, seed),
        public_key,
        t_frame_ms,
        &crate::DUTY_LEDGER,
        Some(&crate::STATS),
        hooks().note_external_load,
    )
    .await
}

/// The forwarder's bulk state: external RAM where the board has it, an
/// internal static otherwise.
#[cfg(all(feature = "meshcore-forwarder", feature = "psram"))]
fn meshcore_storage(
    public_key: [u8; 32],
    seed: [u8; 32],
) -> &'static mut umsh_ulcp_runtime::meshcore::MeshCoreStorage {
    crate::external::meshcore_storage(public_key, seed)
}
#[cfg(all(feature = "meshcore-forwarder", not(feature = "psram")))]
fn meshcore_storage(
    public_key: [u8; 32],
    seed: [u8; 32],
) -> &'static mut umsh_ulcp_runtime::meshcore::MeshCoreStorage {
    static STORAGE: static_cell::StaticCell<umsh_ulcp_runtime::meshcore::MeshCoreStorage> =
        static_cell::StaticCell::new();
    STORAGE.init_with(|| umsh_ulcp_runtime::meshcore::MeshCoreStorage::new(public_key, seed))
}

// ─── Bring-up ────────────────────────────────────────────────────────────────

/// A board whose divider reads the rail marks each transmission for its
/// battery-level estimator. A board with a status LED flashes it when a
/// button check-in is accepted.
fn hooks() -> node::NodeHooks {
    node::NodeHooks {
        #[cfg(feature = "battery-adc-rail")]
        note_external_load: crate::note_external_load,
        #[cfg(feature = "status-led")]
        beacon_confirm: crate::status_led::confirm_action,
        ..node::NodeHooks::default()
    }
}

/// Construct the node around the device identity and spawn its tasks.
/// Call at most once.
///
/// A task rather than something `main` awaits, and deliberately so. The
/// MAC arena write below is ~32 KiB constructed in place, but the
/// temporaries around it are sized into whichever poll frame the body is
/// inlined into—and `main`'s poll frame is held for the whole boot, so
/// inlining it there leaves every other phase, and any interrupt that
/// lands during one, running on what little is left underneath. As a
/// task it gets a frame that exists only while bring-up runs. Nothing in
/// `main` needs bring-up to have finished; the loops are spawned here.
#[embassy_executor::task]
pub async fn bring_up(
    spawner: Spawner,
    identity_secret: [u8; 32],
    node_seed: [u8; 32],
    t_frame_ms: u32,
    counters: &'static crate::NodeCountersMutex,
    input: &'static SessionInput,
    admin_nonce: u16,
    #[cfg(feature = "communicator")] chats: &'static crate::communicator::Node,
    #[cfg(feature = "lan-bearer")] stack: embassy_net::Stack<'static>,
) {
    // Seed the node's copy of the device name before bring-up, so the
    // Identity Request responder's profile is correct from its first
    // reply rather than only from the first name change.
    let identity_secret = &identity_secret;
    set_device_name(&crate::device_name_snapshot().await);
    let hooks = hooks();
    #[cfg(feature = "psram")]
    let arena = crate::external::node_mac_arena();
    // SAFETY: sole borrow; `bring_up` is called at most once.
    #[cfg(not(feature = "psram"))]
    let arena = unsafe { &mut *&raw mut NODE_MAC_ARENA };
    let parts = node::bring_up(
        arena,
        identity_secret,
        node_seed,
        t_frame_ms,
        crate::NodeCounterStore::new(counters),
        &crate::DUTY_LEDGER,
        hooks,
    )
    .await;
    // The communicator's chats: what the node hears for them, copied out
    // for their task, which sends through the node too. The taps live as
    // long as the node.
    #[cfg(feature = "communicator")]
    {
        core::mem::forget(umsh_communicator::task::listen(
            &parts.node,
            &crate::communicator::INBOX,
            umsh_core::PublicKey(parts.node_key),
            umsh_communicator::WellKnownChannels::derive(),
        ));
        spawner.spawn(crate::communicator::chats(chats, parts.node.clone()).unwrap());
    }
    spawner.spawn(node_pump_task(parts.host, parts.mac).unwrap());
    spawner.spawn(
        node_identity_blob_task(
            parts.node.clone(),
            SoftwareIdentity::from_secret_bytes(identity_secret),
        )
        .unwrap(),
    );
    #[cfg(feature = "meshcore-forwarder")]
    spawner.spawn(
        meshcore_forwarder_task(
            parts.node_key,
            umsh_ulcp_runtime::meshcore::derive_seed(&node_seed),
            t_frame_ms,
        )
        .unwrap(),
    );
    spawner.spawn(node_dev_sync_task(parts.node.clone(), parts.mac, parts.node_key).unwrap());
    spawner.spawn(node_identity_profile_task(parts.node.clone()).unwrap());
    spawner.spawn(node_admin_task(parts.node.clone(), input, admin_nonce).unwrap());
    spawner.spawn(
        node_beacon_task(
            parts.node,
            SoftwareIdentity::from_secret_bytes(identity_secret),
            hooks,
        )
        .unwrap(),
    );
    spawner.spawn(node_advert_task(parts.mac).unwrap());
    #[cfg(feature = "lan-bearer")]
    spawner.spawn(lan_bearer_task(stack).unwrap());
    spawner.spawn(node_reboot_quiesce_task(parts.mac).unwrap());
}
