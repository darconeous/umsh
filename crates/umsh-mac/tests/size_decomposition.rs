//! Size decomposition of the MAC's fixed-capacity components. Run with
//! `--nocapture` to see the numbers.
//!
//! The receive windows dominate any Mac instantiation: one ~380-byte
//! window for every registered peer and every stranger kept. The
//! assertions guard the per-entry costs against accidental structural
//! growth; capacity choices stay visible at the instantiation site.

use umsh_mac::{
    ChannelState, ChannelTable, DuplicateCache, PeerCryptoMap, PeerRegistry, QueuedTx,
    ReplayWindow, RxWindow, RxWindows, TxQueue,
};

#[test]
fn component_sizes() {
    let replay = core::mem::size_of::<ReplayWindow>();
    let channel_state = core::mem::size_of::<ChannelState>();
    let channel_table_8 = core::mem::size_of::<ChannelTable<8>>();
    let peer_registry_8 = core::mem::size_of::<PeerRegistry<8>>();
    let dup_32 = core::mem::size_of::<DuplicateCache<32>>();
    let queued = core::mem::size_of::<QueuedTx<255>>();
    let tx_4 = core::mem::size_of::<TxQueue<4, 255>>();
    println!("ReplayWindow          = {replay}");
    println!("ChannelState          = {channel_state}");
    println!("ChannelTable<8>       = {channel_table_8}");
    println!("PeerRegistry<8>       = {peer_registry_8}");
    println!("DuplicateCache<32>    = {dup_32}");
    println!("QueuedTx<255>         = {queued}");
    println!("TxQueue<4,255>        = {tx_4}");

    // Includes one ACK enqueue offset per retained MIC, so the first eligible
    // copy can be ACKed independently of when its payload was accepted.
    assert!(replay <= 384, "ReplayWindow grew: {replay}");
    assert!(channel_state <= 256, "ChannelState grew: {channel_state}");
    // Channels keep no replay state; a table is its keys and nothing more.
    assert!(
        channel_table_8 <= 8 * channel_state + 16,
        "ChannelTable<8> grew: {channel_table_8}"
    );
    // A forward's confirmation state rides in the entry's padding: the
    // queue entry is the whole of it.
    assert!(queued <= 304, "QueuedTx grew: {queued}");
}

/// Receive windows: one per remote key, shared by every identity, beside
/// a per-identity map that now holds only pairwise keys. The device node
/// (`umsh-ulcp-runtime/src/device_node.rs`) keeps 24 peers and 8
/// strangers, 80 peers on a communicator.
#[test]
fn receive_windows_per_remote_key() {
    let rx_window = core::mem::size_of::<RxWindow>();
    let peer_crypto_16 = core::mem::size_of::<PeerCryptoMap<16>>();
    let rx_windows_16_8 = core::mem::size_of::<RxWindows<16, 8>>();
    let rx_windows_80_8 = core::mem::size_of::<RxWindows<80, 8>>();
    println!("RxWindow              = {rx_window}");
    println!("PeerCryptoMap<16>     = {peer_crypto_16}");
    println!("RxWindows<16,8>       = {rx_windows_16_8}");
    println!("RxWindows<80,8>       = {rx_windows_80_8}");
    assert!(rx_window <= 448, "RxWindow grew: {rx_window}");
}

/// Every `Mac` carries one signature-input scratch buffer, so a frame's
/// signature input is never assembled on the stack or in a send's future.
#[test]
fn signature_input_scratch() {
    let scratch = umsh_core::SIGNATURE_INPUT_MAX;
    println!("SIGNATURE_INPUT_MAX   = {scratch}");
    assert!(scratch <= 1088, "signature input scratch grew: {scratch}");
}
