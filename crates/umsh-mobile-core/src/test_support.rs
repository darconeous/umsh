//! Test benches several modules share.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use umsh_ulcp::hdlc;
use umsh_ulcp_simdev::soft::{SoftDevice, SoftPlatform};
use umsh_ulcp_simdev::{DutyLedger, SimulatedPlatform, full_config};

use crate::radio_driver::{
    MobileRadioDriver, MobileRadioPhase, MobileRadioTransportPhase,
    MobileRadioTransportStateRecord, RadioLink,
};

/// A radio link to a soft device: the companion firmware's device engine,
/// in process.
pub(crate) struct DeviceLink {
    pub(crate) device: Mutex<SoftDevice<SimulatedPlatform>>,
    decoder: Mutex<hdlc::Decoder<{ umsh_ulcp::gatt::MAX_FRAME }>>,
    pub(crate) driver: OnceLock<Weak<MobileRadioDriver>>,
    pub(crate) attached: Mutex<u32>,
    /// Whether the link swallows what the driver sends: a radio that
    /// has stopped answering.
    pub(crate) silent: AtomicBool,
}

impl DeviceLink {
    pub(crate) fn new() -> Arc<Self> {
        let duty = Box::leak(Box::new(DutyLedger::new()));
        let mut platform = SimulatedPlatform::new();
        platform.store_identity(Some(&[1; 32])).unwrap();
        Arc::new(Self {
            device: Mutex::new(SoftDevice::new(full_config(duty, None), platform)),
            decoder: Mutex::new(hdlc::Decoder::new()),
            driver: OnceLock::new(),
            attached: Mutex::new(0),
            silent: AtomicBool::new(false),
        })
    }

    /// Hand the driver whatever the device has said.
    pub(crate) fn deliver(&self) {
        let Some(driver) = self.driver.get().and_then(Weak::upgrade) else {
            return;
        };
        let mut frames = Vec::new();
        {
            let mut device = self.device.lock().unwrap();
            let mut decoder = self.decoder.lock().unwrap();
            while let Some(wire) = device.take_outbound() {
                for byte in wire {
                    if let Some(frame) = decoder.push(byte) {
                        frames.push(frame.unwrap().to_vec());
                    }
                }
            }
        }
        for frame in frames {
            driver.link_received(frame);
        }
    }
}

impl RadioLink for DeviceLink {
    fn send(&self, frame: Vec<u8>, _raw_transaction_id: Option<u8>) {
        if self.silent.load(Ordering::Relaxed) {
            return;
        }
        let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
        let length = hdlc::encode_frame(&frame, &mut wire).unwrap();
        self.device
            .lock()
            .unwrap()
            .ingest(&wire[..length], 0)
            .unwrap();
        self.deliver();
    }
    fn reset_framing(&self) {}
    fn invalidate(&self, _retry: bool) {}
    fn did_attach(&self) {
        *self.attached.lock().unwrap() += 1;
    }
    fn did_report_name(&self, _name: String) {}
    fn abandon_binding(&self) {}
    fn did_enter_dfu(&self) {}
}

/// Wait, in real time, for `done`.
pub(crate) fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A driver linked to a soft device of its own, with no host key yet: the
/// radio waits for one.
pub(crate) fn linked_driver() -> (Arc<DeviceLink>, Arc<MobileRadioDriver>) {
    let link = DeviceLink::new();
    let driver = MobileRadioDriver::new(link.clone()).unwrap();
    link.driver.set(Arc::downgrade(&driver)).unwrap();
    driver.transport_changed(MobileRadioTransportStateRecord {
        phase: MobileRadioTransportPhase::Connecting,
        name: Some("Device link".to_owned()),
        link_id: Some("device".to_owned()),
        problem: None,
    });
    link.device.lock().unwrap().attach();
    link.deliver();
    driver.link_ready(true);
    (link, driver)
}

/// A driver attached to a soft device of its own, as `host_key`'s radio.
pub(crate) fn attached_driver(host_key: &[u8; 32]) -> (Arc<DeviceLink>, Arc<MobileRadioDriver>) {
    let (link, driver) = linked_driver();
    driver.set_host_key(Some(host_key.to_vec())).unwrap();
    eventually("attached", || {
        driver.state().phase == MobileRadioPhase::Attached
            && driver
                .state()
                .provisioning
                .is_some_and(|provisioning| provisioning.phy_enabled)
    });
    (link, driver)
}
