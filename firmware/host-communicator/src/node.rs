//! The communicator's node behind the window, as the Pager runs it: its
//! settings served by the device's own ULCP session, and its chats kept in
//! a flash partition that is a file in the instance's directory.

use umsh_communicator::{Clock, CommunicatorNode, FlashMapStore};
use umsh_ulcp::profiles;
use umsh_ulcp_device::{DisplayConfig, LanBearerRole, RadioSettings, SessionConfig, TimeConfig};
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::model::{
    ClockSource, DEFAULT_AUTO_LOCK_S, Node as _, State, brightness_at,
};

use crate::board::{DUTY, Port, STATS};
use crate::flash::FileFlash;

pub type Node = CommunicatorNode<Port, FlashMapStore<FileFlash>>;

/// The device's clocks, as the node reads them: the board's, and the wall
/// clock the session keeps.
pub struct Clocks;

impl Clock for Clocks {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }

    fn wall(&self) -> Option<u32> {
        umsh_hal::wall_clock::now()
    }

    fn source(&self) -> Option<(ClockSource, u64)> {
        use umsh_hal::wall_clock::TimeSource;
        let clock = umsh_hal::wall_clock::snapshot();
        let source = match clock.source()? {
            TimeSource::Manual => ClockSource::Manual,
            TimeSource::GnssFix | TimeSource::GnssRtc => ClockSource::Gnss,
            TimeSource::ExternalRtc => ClockSource::Rtc,
        };
        Some((source, clock.set_at()?))
    }
}

pub static CLOCK: Clocks = Clocks;

/// The device the window stands for: a communicator whose radio is an IP
/// multicast group, named `name` until it is given a name of its own.
///
/// The group is its PHY, so the PHY starts on. Its node can repeat, but a
/// node whose only medium is the group should not, so forwarding starts
/// off as it does on every board.
pub fn config(name: &'static str) -> SessionConfig {
    SessionConfig {
        dev_version: concat!("host-communicator/", env!("CARGO_PKG_VERSION")),
        dev_model: None,
        default_device_name: name,
        mtu: 255,
        tx_preamble_symbols: 32,
        sync_word: profiles::DEFAULT.sync_word,
        min_tx_power_dbm: -9,
        max_tx_power_dbm: 22,
        freq_khz_min: 150_000,
        freq_khz_max: 960_000,
        defaults: RadioSettings {
            enabled: true,
            freq_khz: profiles::DEFAULT.freq_khz,
            bw_hz: profiles::DEFAULT.bw_hz,
            sf: profiles::DEFAULT.sf,
            cr_denom: profiles::DEFAULT.cr_denom,
            tx_power_dbm: profiles::DEFAULT_TX_POWER_DBM,
        },
        default_duty_limit: 0xFFFF,
        duty: &DUTY,
        battery_diagnostics: Default::default(),
        battery: None,
        alert: None,
        time: Some(TimeConfig),
        gnss: None,
        display_motion_wake: false,
        display: Some(DisplayConfig {
            brightness: brightness_at(5),
            timeout_s: DEFAULT_AUTO_LOCK_S,
        }),
        keyboard: true,
        sound: true,
        illuminance: false,
        temperatures: false,
        ble: false,
        ble_pairing: false,
        ble_pin: false,
        // The process restarts in place.
        reboot: true,
        dev_identity: true,
        messaging: true,
        stats: Some(&STATS),
        mac_node: true,
        meshcore_forwarder: false,
        lan_bearer: LanBearerRole::Phy,
        wifi: None,
        ip: None,
        bridge_client: false,
        i2c_buses: &[],
        i2c_devices: &[],
    }
}

/// The interface's state over `node`: locked, as a device boots, over the
/// Chats screen of `board`.
pub fn state(node: &'static Node, board: &'static Board) -> State {
    let mut state = State::new(node, board);
    state.firmware = concat!("simulator ", env!("CARGO_PKG_VERSION"));
    state.status.device_name = node.device_name();
    state.set_wall_time(umsh_hal::wall_clock::now());
    state.reload();
    state.focus_list();
    state.lock();
    state
}
