//! This board's binding of the shared device node.
//!
//! The node itself — the MAC/`Host` pump, the device-domain sync, the
//! beacon and identity paths — lives in
//! [`umsh_ulcp_runtime::device_node`], shared with every other UMSH
//! device firmware. What stays here is what cannot be shared: the
//! counter-store type (backed by this board's flash), the board's UX
//! hooks, and the spawnable task shims, because embassy task functions
//! cannot be generic.

use embassy_executor::Spawner;
use static_cell::StaticCell;

use umsh_crypto::software::SoftwareIdentity;
use umsh_ulcp_runtime::device_node as node;

// Re-exported for `main.rs`. The beacon trigger is only reached from a
// board with a primary-action button, so it is unused in some builds.
#[allow(unused_imports)]
pub use umsh_ulcp_runtime::device_node::{
    BeaconTrigger, DEV_SYNC, NODE_CH, mac_counters, request_beacon, set_device_name,
    set_tx_power_dbm, sign_identity_blob, tx_power_dbm,
};

/// The node's platform binding: everything generic resolved against this
/// board's counter store.
type CounterStore = crate::NodeCounterStore;
type DeviceNode = node::DeviceNode<CounterStore>;
type DeviceNodeHandle = node::DeviceNodeHandle<CounterStore>;
type DeviceNodeHost = node::DeviceNodeHost<CounterStore>;

static NODE_MAC_CELL: node::DeviceNodeMacCell<CounterStore> = StaticCell::new();

// ─── Task shims ──────────────────────────────────────────────────────────────

#[embassy_executor::task]
async fn node_pump_task(host: DeviceNodeHost, mac: DeviceNodeHandle) {
    node::pump_loop(host, mac).await
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

// ─── Bring-up ────────────────────────────────────────────────────────────────

/// This board has no battery-level estimator to feed and no indicator
/// to confirm a beacon on, so both hooks stay at their no-op defaults.
fn hooks() -> node::NodeHooks {
    node::NodeHooks::default()
}

/// Construct the node around the device identity and spawn its tasks.
/// Call at most once.
pub async fn bring_up(
    spawner: Spawner,
    identity_secret: &[u8; 32],
    node_seed: [u8; 32],
    t_frame_ms: u32,
    counters: &'static crate::NodeCountersMutex,
) {
    // Seed the node's copy of the device name before bring-up, so the
    // Identity Request responder's profile is correct from its first
    // reply rather than only from the first name change.
    set_device_name(&crate::device_name_snapshot().await);
    let hooks = hooks();
    let parts = node::bring_up(
        &NODE_MAC_CELL,
        identity_secret,
        node_seed,
        t_frame_ms,
        crate::NodeCounterStore::new(counters),
        &crate::DUTY_LEDGER,
        hooks,
    )
    .await;
    spawner.spawn(node_pump_task(parts.host, parts.mac).unwrap());
    spawner.spawn(
        node_identity_blob_task(
            parts.node.clone(),
            SoftwareIdentity::from_secret_bytes(identity_secret),
        )
        .unwrap(),
    );
    spawner.spawn(node_dev_sync_task(parts.node.clone(), parts.mac, parts.node_key).unwrap());
    spawner.spawn(node_identity_profile_task(parts.node.clone()).unwrap());
    spawner.spawn(
        node_beacon_task(
            parts.node,
            SoftwareIdentity::from_secret_bytes(identity_secret),
            hooks,
        )
        .unwrap(),
    );
}
