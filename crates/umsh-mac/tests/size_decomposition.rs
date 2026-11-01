//! Size decomposition of the MAC's fixed-capacity components. Run with
//! `--nocapture` to see the numbers.
//!
//! The channel table dominates any Mac instantiation because every
//! tracked sender costs one ~330-byte replay window per channel
//! (`RN` full-key + `HN` hint-only senders, `Mac`'s two trailing const
//! generics). The assertions guard the per-entry costs against
//! accidental structural growth; capacity choices stay visible at the
//! instantiation site.

use umsh_mac::{
    ChannelState, ChannelTable, DuplicateCache, PeerCryptoMap, PeerRegistry, ReplayWindow,
    RxWindow, RxWindows, TxQueue,
};

#[test]
fn component_sizes() {
    let replay = core::mem::size_of::<ReplayWindow>();
    let channel_state_default = core::mem::size_of::<ChannelState<8, 8>>();
    let channel_table_default = core::mem::size_of::<ChannelTable<8>>();
    let peer_registry_8 = core::mem::size_of::<PeerRegistry<8>>();
    let dup_32 = core::mem::size_of::<DuplicateCache<32>>();
    let tx_4 = core::mem::size_of::<TxQueue<4, 255>>();
    println!("ReplayWindow          = {replay}");
    println!("ChannelState<8,8>     = {channel_state_default}");
    println!("ChannelTable<8>       = {channel_table_default}");
    println!("PeerRegistry<8>       = {peer_registry_8}");
    println!("DuplicateCache<32>    = {dup_32}");
    println!("TxQueue<4,255>        = {tx_4}");

    // Includes one ACK enqueue offset per retained MIC, so the first eligible
    // copy can be ACKed independently of when its payload was accepted.
    assert!(replay <= 384, "ReplayWindow grew: {replay}");
    assert!(
        channel_state_default <= 6 * 1024,
        "ChannelState<8,8> grew: {channel_state_default}"
    );
}

/// The ULCP device node's channel table
/// (`firmware/techo/src/device_node.rs`,
/// `DeviceNodeMac = Mac<_, 1, 8, 8, 4, 4, 255, 32, 4, 2>`).
/// With per-MIC ACK timing, the host layout is ChannelState<4,2> = 2,152
/// and the 8-channel table is 17,224 bytes. The 20 KiB ceiling is a growth
/// guard, not a hardware limit; raise it consciously, not by drift.
#[test]
fn device_node_channel_table_within_budget() {
    let channel_state = core::mem::size_of::<ChannelState<4, 2>>();
    let channel_table = core::mem::size_of::<ChannelTable<8, 4, 2>>();
    println!("ChannelState<4,2>     = {channel_state}");
    println!("ChannelTable<8,4,2>   = {channel_table}");
    assert!(
        channel_table <= 20 * 1024,
        "device node channel table grew past 20 KiB: {channel_table}"
    );
}

/// Receive windows: one per remote key, shared by every identity, beside
/// a per-identity map that now holds only pairwise keys. The device node
/// (`umsh-ulcp-runtime/src/device_node.rs`) keeps 16 peers and 8
/// strangers, 32 peers on a communicator.
#[test]
fn receive_windows_per_remote_key() {
    let rx_window = core::mem::size_of::<RxWindow>();
    let peer_crypto_16 = core::mem::size_of::<PeerCryptoMap<16>>();
    let rx_windows_16_8 = core::mem::size_of::<RxWindows<16, 8>>();
    let rx_windows_32_8 = core::mem::size_of::<RxWindows<32, 8>>();
    println!("RxWindow              = {rx_window}");
    println!("PeerCryptoMap<16>     = {peer_crypto_16}");
    println!("RxWindows<16,8>       = {rx_windows_16_8}");
    println!("RxWindows<32,8>       = {rx_windows_32_8}");
    assert!(rx_window <= 448, "RxWindow grew: {rx_window}");
}
