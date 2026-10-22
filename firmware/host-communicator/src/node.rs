//! The communicator's node behind the window, as the Pager runs it: its
//! settings served by a soft device on this host, which keeps its saved
//! state and identity in a directory, and its chats kept in a flash
//! partition that is a file in the same directory.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use umsh_communicator::{
    ChannelCrypto, Clock, CommunicatorNode, FlashMap, FlashMapStore, Quota, Seeds,
};
use umsh_ulcp::profiles;
use umsh_ulcp_admin::{LocalPort, PortBusy, PortFrame};
use umsh_ulcp_simdev::host::HostPlatform;
use umsh_ulcp_simdev::soft::SoftDevice;
use umsh_ulcp_simdev::{
    DisplayConfig, DutyLedger, LanBearerRole, RadioSettings, SessionConfig, TimeConfig,
};
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::model::{DEFAULT_AUTO_LOCK_S, Node as _, State, brightness_at};

use crate::flash::{self, FileFlash};

/// A soft device's own interface, on the host's clock.
pub struct Port {
    device: Rc<RefCell<SoftDevice<HostPlatform>>>,
    start: Instant,
}

impl Port {
    /// The device behind it.
    pub fn device(&self) -> &Rc<RefCell<SoftDevice<HostPlatform>>> {
        &self.device
    }
}

impl LocalPort for Port {
    fn send(&mut self, frame: &[u8]) -> Result<(), PortBusy> {
        let now = self.start.elapsed().as_millis() as u64;
        self.device.borrow_mut().device_request(frame, now);
        Ok(())
    }

    fn receive(&mut self, out: &mut [u8]) -> Option<PortFrame> {
        let frame = self.device.borrow_mut().take_device_frame()?;
        out[..frame.len()].copy_from_slice(&frame);
        Some(PortFrame::Frame(frame.len()))
    }
}

pub type Node = CommunicatorNode<Port, FlashMapStore<FileFlash>>;

/// The host's clocks.
struct HostClock(Instant);

impl Clock for HostClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }

    fn wall(&self) -> Option<u32> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|since| since.as_secs() as u32)
    }
}

/// The device the window stands for: a communicator on the default
/// profile, with no LoRa radio.
fn config() -> SessionConfig {
    SessionConfig {
        dev_version: "host-communicator",
        dev_model: None,
        default_device_name: "Communicator",
        mtu: 255,
        tx_preamble_symbols: 32,
        sync_word: profiles::DEFAULT.sync_word,
        min_tx_power_dbm: -9,
        max_tx_power_dbm: 22,
        freq_khz_min: 150_000,
        freq_khz_max: 960_000,
        defaults: RadioSettings {
            enabled: false,
            freq_khz: profiles::DEFAULT.freq_khz,
            bw_hz: profiles::DEFAULT.bw_hz,
            sf: profiles::DEFAULT.sf,
            cr_denom: profiles::DEFAULT.cr_denom,
            tx_power_dbm: profiles::DEFAULT_TX_POWER_DBM,
        },
        default_duty_limit: 0xFFFF,
        duty: Box::leak(Box::new(DutyLedger::new())),
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
        illuminance: false,
        temperatures: false,
        ble: false,
        ble_pairing: false,
        ble_pin: false,
        // The device is part of this process; there is nothing for
        // `CMD_REBOOT` to restart.
        reboot: false,
        dev_identity: true,
        stats: None,
        // Its node does not forward, so there is no repeater to switch on.
        mac_node: false,
        meshcore_forwarder: false,
        lan_bearer: LanBearerRole::None,
        wifi: None,
        ip: None,
        bridge_client: false,
        i2c_buses: &[],
        i2c_devices: &[],
    }
}

/// A node over a soft device keeping its state under `dir`, with its
/// settings read and its chats mounted.
pub fn open(dir: &Path, start: Instant) -> std::io::Result<&'static Node> {
    let starting_keys = Box::leak(Box::new(ChannelCrypto::software().starting_keys()));
    let platform = HostPlatform::new(dir)?.holding_lists(starting_keys);
    let mut device = SoftDevice::new(config(), platform);
    device.open_device_interface();
    let flash = FileFlash::open(&dir.join("chats.flash"))?;
    let buffer = Box::leak(vec![0u8; 2048].into_boxed_slice());
    let store = FlashMapStore::mount(
        FlashMap::new(flash, 0..flash::SIZE as u32, buffer),
        Quota::DEFAULT,
    )
    .map_err(|error| std::io::Error::other(format!("the chats did not mount: {error:?}")))?;
    let node: &'static Node = Box::leak(Box::new(CommunicatorNode::new(
        Port {
            device: Rc::new(RefCell::new(device)),
            start,
        },
        store,
        ChannelCrypto::software(),
        &std::alloc::System,
        Box::leak(Box::new(HostClock(start))),
        Seeds {
            session_id: rand::random(),
            jitter_seed: rand::random(),
        },
    )));
    node.pump();
    while node.next_event().is_some() {}
    Ok(node)
}

/// The interface's state over `node`: locked, as a device boots, over the
/// Chats screen of `board`.
pub fn state(node: &'static Node, board: &'static Board) -> State {
    let mut state = State::new(node, board);
    state.status.device_name = node.device_name();
    state.set_wall_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|since| since.as_secs() as u32),
    );
    state.reload();
    state.focus_list();
    state.lock();
    state
}
