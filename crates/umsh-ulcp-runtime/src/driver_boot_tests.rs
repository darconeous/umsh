use super::*;
use core::future::Future;
use core::task::{Context, Poll, Waker};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use std::cell::RefCell;
use std::rc::Rc;
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_ulcp_device::{DutyLedger, RadioSettings, SessionConfig};

type TestSession = Session<SoftwareAes, SoftwareSha256, 1>;

fn session(name: &'static str) -> TestSession {
    Session::new(
        SessionConfig {
            dev_version: "test",
            dev_model: None,
            default_device_name: name,
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
            default_duty_limit: 0xffff,
            duty: Box::leak(Box::new(DutyLedger::new())),
            battery: None,
            battery_diagnostics: Default::default(),
            stats: None,
            alert: None,
            time: None,
            gnss: None,
            display_motion_wake: false,
            illuminance: false,
            temperatures: false,
            ble: true,
            ble_pairing: true,
            reboot: false,
            mac_node: false,
            wifi: None,
            ip: None,
            bridge_client: false,
            i2c_buses: &[],
            i2c_devices: &[],
        },
        Status::RESET_POWER_ON,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    )
}

#[derive(Debug, PartialEq)]
enum Event {
    Name(std::string::String),
    BleEnabled(bool),
    Domain,
    Ready,
}

struct Env {
    events: Rc<RefCell<std::vec::Vec<Event>>>,
    older: Option<std::vec::Vec<u8>>,
    restore_gate: &'static Signal<NoopRawMutex, ()>,
    name_gate: Option<&'static Signal<NoopRawMutex, ()>>,
}

impl DeviceEnv for Env {
    async fn persist_snapshot(&mut self, _: &[u8]) -> Result<(), ()> {
        unreachable!()
    }
    async fn clear_snapshot(&mut self) -> Result<(), ()> {
        unreachable!()
    }
    async fn persist_identity(&mut self, _: &[u8]) -> Result<(), ()> {
        unreachable!()
    }
    async fn clear_identity(&mut self) -> Result<(), ()> {
        unreachable!()
    }
    fn fill_secret(&mut self, _: &mut [u8; 32]) -> Result<(), ()> {
        unreachable!()
    }
    async fn apply_pairing_pin(&mut self, _: Option<u32>) -> bool {
        unreachable!()
    }
    async fn factory_reset(&mut self) -> ! {
        unreachable!()
    }
    async fn reboot(&mut self) -> ! {
        unreachable!()
    }
    fn set_advertising_allowed(&mut self, _: bool) {
        unreachable!()
    }
    async fn older_snapshot(&mut self, out: &mut [u8]) -> Option<usize> {
        self.restore_gate.wait().await;
        let bytes = self.older.take()?;
        out[..bytes.len()].copy_from_slice(&bytes);
        Some(bytes.len())
    }
    async fn publish_device_name(&mut self, name: &str) {
        if let Some(gate) = self.name_gate.take() {
            gate.wait().await;
        }
        self.events.borrow_mut().push(Event::Name(name.into()));
    }
    fn set_ble_enabled(&mut self, enabled: bool) {
        self.events.borrow_mut().push(Event::BleEnabled(enabled));
    }
    fn publish_dev_domain(&mut self, _: DevDomainSnapshot) {
        self.events.borrow_mut().push(Event::Domain);
    }
    fn boot_settings_ready(&mut self) {
        self.events.borrow_mut().push(Event::Ready);
    }
}

#[test]
fn transport_readiness_follows_restore_name_and_settings_on_every_boot_path() {
    let mut saved_session = session("Saved radio");
    assert_eq!(saved_session.toggle_ble(&mut |_| {}), Some(false));
    let mut saved = [0; SNAPSHOT_MAX];
    let len = saved_session.encode_snapshot(&mut saved).unwrap();
    let saved = &saved[..len];
    let corrupt = &[0xff][..];
    for (boot, older, expected_name, expected_enabled) in [
        (Some(saved), None, "Saved radio", false),
        (Some(corrupt), Some(saved), "Saved radio", false),
        (None, None, "Default radio", true),
        (Some(corrupt), None, "Default radio", true),
    ] {
        let events = Rc::new(RefCell::new(std::vec::Vec::new()));
        let restore_gate = Box::leak(Box::new(Signal::new()));
        let name_gate = Box::leak(Box::new(Signal::new()));
        let env = Env {
            events: events.clone(),
            older: older.map(|bytes| bytes.to_vec()),
            restore_gate,
            name_gate: Some(name_gate),
        };
        let rt = DeviceRuntime {
            input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
            radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
            ctl: Box::leak(Box::new(DeviceControl::new())),
            out: Box::leak(Box::new(TransportChannels::new())),
            session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        };
        let mut session = session("Default radio");
        let mut storage = [0; SNAPSHOT_MAX];
        let mut run = core::pin::pin!(run_with_storage(
            &mut session,
            &mut storage,
            boot,
            None,
            rt,
            env
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(run.as_mut().poll(&mut cx), Poll::Pending));
        assert!(
            events.borrow().is_empty(),
            "Must wait for NVRAM and name publication"
        );
        restore_gate.signal(());
        assert!(matches!(run.as_mut().poll(&mut cx), Poll::Pending));
        assert!(
            events.borrow().is_empty(),
            "Name publication must finish before readiness"
        );
        name_gate.signal(());
        assert!(matches!(run.as_mut().poll(&mut cx), Poll::Pending));
        let events = events.borrow();
        assert_eq!(events.last(), Some(&Event::Ready));
        assert_eq!(events.iter().filter(|e| **e == Event::Ready).count(), 1);
        assert!(events.contains(&Event::Name(expected_name.into())));
        assert!(
            events
                .iter()
                .all(|e| !matches!(e, Event::Name(name) if name != expected_name))
        );
        assert!(events.ends_with(&[
            Event::BleEnabled(expected_enabled),
            Event::Domain,
            Event::Ready
        ]));
    }
}
