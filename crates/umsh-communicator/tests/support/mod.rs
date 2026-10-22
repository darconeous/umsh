//! What the communicator's tests share: a soft device, and the device's
//! own interface into it.

#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use umsh_communicator::{ChannelCrypto, RamFlash, RamFlashError};

use umsh_ulcp::frame;
use umsh_ulcp::hdlc;
use umsh_ulcp::ids::prop;
use umsh_ulcp_admin::{LocalPort, PortBusy, PortFrame};
use umsh_ulcp_simdev::{DisplayConfig, DutyLedger, RadioSettings, SessionConfig, SimulatedDevice};

pub fn config() -> SessionConfig {
    SessionConfig {
        dev_version: "umsh-communicator-test/0.1",
        dev_model: None,
        default_device_name: "Pocket",
        mtu: 255,
        tx_preamble_symbols: 32,
        sync_word: 0x1424,
        min_tx_power_dbm: -9,
        max_tx_power_dbm: 22,
        freq_khz_min: 150_000,
        freq_khz_max: 960_000,
        defaults: RadioSettings {
            enabled: false,
            freq_khz: 910_525,
            bw_hz: 62_500,
            sf: 7,
            cr_denom: 5,
            tx_power_dbm: 14,
        },
        default_duty_limit: 0xFFFF,
        duty: Box::leak(Box::new(DutyLedger::new())),
        battery_diagnostics: Default::default(),
        battery: None,
        alert: None,
        time: None,
        gnss: None,
        display_motion_wake: false,
        display: Some(DisplayConfig {
            brightness: 113,
            timeout_s: 30,
        }),
        keyboard: true,
        illuminance: false,
        temperatures: false,
        ble: true,
        ble_pairing: false,
        ble_pin: false,
        reboot: true,
        dev_identity: true,
        stats: None,
        mac_node: false,
        meshcore_forwarder: false,
        lan_bearer: umsh_ulcp_simdev::LanBearerRole::None,
        wifi: None,
        ip: None,
        bridge_client: false,
        i2c_buses: &[],
        i2c_devices: &[],
    }
}

/// The soft device's own interface. The test keeps a handle to the device
/// too, to act as a phone attached to it would.
#[derive(Clone)]
pub struct Port(pub Rc<RefCell<SimulatedDevice>>);

impl LocalPort for Port {
    fn send(&mut self, frame: &[u8]) -> Result<(), PortBusy> {
        self.0.borrow_mut().device_request(frame, 1_000);
        Ok(())
    }

    fn receive(&mut self, out: &mut [u8]) -> Option<PortFrame> {
        let frame = self.0.borrow_mut().take_device_frame()?;
        out[..frame.len()].copy_from_slice(&frame);
        Some(PortFrame::Frame(frame.len()))
    }
}

/// A soft device holding its lists as a communicator's store does.
pub fn device() -> Rc<RefCell<SimulatedDevice>> {
    let mut sim = SimulatedDevice::holding_lists(config(), starting_keys());
    sim.open_device_interface();
    Rc::new(RefCell::new(sim))
}

/// The channel keys a communicator's lists hold after a reset.
pub fn starting_keys() -> &'static [[u8; 32]] {
    Box::leak(Box::new(ChannelCrypto::software().starting_keys()))
}

/// Gives `sim` the identity `secret` makes, or one it makes itself, as
/// whoever holds the device may.
pub fn provision(sim: &Rc<RefCell<SimulatedDevice>>, secret: Option<&[u8; 32]>) {
    let mut request = [0u8; 48];
    let value: &[u8] = secret.map_or(&[], |secret| &secret[..]);
    let len = frame::prop_set(&mut request, 1, prop::DEV_PRIVATE_KEY, value).unwrap();
    sim.borrow_mut().device_request(&request[..len], 0);
    while sim.borrow_mut().take_device_frame().is_some() {}
}

/// A phone attached to `sim` inserts `item` into the table `key`.
pub fn phone_inserts(sim: &Rc<RefCell<SimulatedDevice>>, key: u32, item: &[u8]) {
    sim.borrow_mut().attach();
    while sim.borrow_mut().take_outbound().is_some() {}
    let mut request = [0u8; 64];
    let len = frame::prop_insert(&mut request, 2, key, item).unwrap();
    let mut encoded = vec![0u8; hdlc::max_encoded_len(len)];
    let len = hdlc::encode_frame(&request[..len], &mut encoded).unwrap();
    sim.borrow_mut().ingest(&encoded[..len], 0).unwrap();
}

/// One flash that a node started again finds as the last one left it.
#[derive(Clone)]
pub struct SharedFlash(pub Rc<RefCell<RamFlash>>);

impl SharedFlash {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(RamFlash::new(size))))
    }
}

impl ErrorType for SharedFlash {
    type Error = RamFlashError;
}

// The flash in memory finishes every call at once, so no borrow is held
// across a suspension.
#[allow(clippy::await_holding_refcell_ref)]
impl ReadNorFlash for SharedFlash {
    const READ_SIZE: usize = RamFlash::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.borrow_mut().read(offset, bytes).await
    }

    fn capacity(&self) -> usize {
        self.0.borrow().capacity()
    }
}

#[allow(clippy::await_holding_refcell_ref)]
impl NorFlash for SharedFlash {
    const WRITE_SIZE: usize = RamFlash::WRITE_SIZE;
    const ERASE_SIZE: usize = RamFlash::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.borrow_mut().erase(from, to).await
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.borrow_mut().write(offset, bytes).await
    }
}

impl MultiwriteNorFlash for SharedFlash {}
