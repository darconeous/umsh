use super::*;
use core::future::Future;
use core::task::{Context, Poll, Waker};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use std::cell::RefCell;
use std::rc::Rc;
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_ulcp_device::{DutyLedger, RadioSettings, SavedStatus, SessionConfig};

type TestSession = Session<SoftwareAes, SoftwareSha256, 1>;

fn session(name: &'static str) -> TestSession {
    Session::new(
        config(name),
        Status::RESET_POWER_ON,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    )
}

fn config(name: &'static str) -> SessionConfig {
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
        display: None,
        keyboard: false,
        sound: false,
        host_custody: true,
        illuminance: false,
        temperatures: false,
        ble: true,
        ble_pairing: true,
        ble_pin: true,
        uart_links: Default::default(),
        reboot: true,
        dev_identity: true,
        messaging: false,
        mac_node: false,
        meshcore_forwarder: false,
        lan_bearer: umsh_ulcp_device::LanBearerRole::None,
        wifi: None,
        ip: None,
        bridge_client: false,
        i2c_buses: &[],
        i2c_devices: &[],
        node_msg: None,
    }
}

#[derive(Debug, PartialEq)]
enum Event {
    Name(std::string::String),
    BleEnabled(bool),
    Domain,
    Ready,
    Dfu(umsh_ulcp::DfuMode),
    SnapshotPersisted,
    ListsPersisted(Option<std::vec::Vec<u8>>),
}

struct Env {
    events: Rc<RefCell<std::vec::Vec<Event>>>,
    older: Option<std::vec::Vec<u8>>,
    restore_gate: &'static Signal<NoopRawMutex, ()>,
    name_gate: Option<&'static Signal<NoopRawMutex, ()>>,
    dfu_result: Result<umsh_ulcp::DfuMode, Status>,
}

impl DeviceEnv for Env {
    async fn prepare_dfu(&mut self, _: umsh_ulcp::DfuMode) -> Result<umsh_ulcp::DfuMode, Status> {
        self.dfu_result
    }
    fn enter_dfu(&mut self, mode: umsh_ulcp::DfuMode) -> ! {
        self.events.borrow_mut().push(Event::Dfu(mode));
        panic!("test bootloader handoff")
    }
    async fn persist_snapshot(&mut self, _: &[u8]) -> Result<(), ()> {
        self.events.borrow_mut().push(Event::SnapshotPersisted);
        Ok(())
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
    async fn persist_lists(&mut self, record: Option<&[u8]>) -> Result<(), ()> {
        self.events
            .borrow_mut()
            .push(Event::ListsPersisted(record.map(<[u8]>::to_vec)));
        Ok(())
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
    fn set_advertising_allowed(&mut self, _: bool) {}
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
            dfu_result: Err(Status::UNIMPLEMENTED),
        };
        let rt = DeviceRuntime {
            input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
            radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
            ctl: Box::leak(Box::new(DeviceControl::new())),
            out: Box::leak(Box::new(TransportChannels::new())),
            session_gen: Box::leak(Box::new(AtomicU32::new(0))),
            device: None,
            snapshot: Box::leak(Box::new(SnapshotControl::new())),
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

#[test]
fn dfu_preparation_and_matching_transmission_precede_handoff() {
    use embassy_futures::block_on;
    use umsh_ulcp::{DfuMode, Frame, PropPayload, frame};
    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(42))),
        device: None,
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let events = Rc::new(RefCell::new(std::vec::Vec::new()));
    let mut env = Env {
        events: events.clone(),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session = session("DFU test");
    session.set_boot_identity([0x55; 32]);
    let mut snapshot = [0; SNAPSHOT_MAX];
    let mut before = [0; SNAPSHOT_MAX];
    let before_len = session.encode_snapshot(&mut before).unwrap();
    let mut request = [0; 3];
    let len = frame::dfu(&mut request, 3, Some(DfuMode::Ble)).unwrap();
    let mut emitter = Emitter::new();
    let mut previous: Option<crate::reply_completion::ReplyCompletion> = None;
    for (prepared, sent) in [
        (Err(Status::UNIMPLEMENTED), false),
        (Err(Status::FAILURE), false),
        (Ok(DfuMode::Ble), false),
        (Ok(DfuMode::Ble), true),
    ] {
        env.dfu_result = prepared;
        let dfu = block_on(serve_frame(
            &mut session,
            Exchange::Local(&request[..len]),
            &mut emitter,
            &mut ReplySink::Transport {
                destination: Some((Transport::Usb, 42)),
                out: rt.out,
                device: None,
            },
            &mut snapshot,
            &rt,
            &mut env,
        ));
        let response = rt.out.wired.try_receive().unwrap();
        assert_eq!(response.generation, 42);
        let parsed = Frame::parse(&response.frame).unwrap();
        assert_eq!(parsed.header.tid(), 3);
        let prop = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!(prop.key, umsh_ulcp::ids::prop::LAST_STATUS);
        let expected = prepared.map(|_| Status::OK).unwrap_or_else(|error| error);
        assert_eq!(umsh_ulcp::pui::decode(prop.value).unwrap().0, expected.0);
        assert!(
            events
                .borrow()
                .iter()
                .all(|event| !matches!(event, Event::Dfu(_)))
        );
        let Some((_, completion)) = dfu else {
            assert!(
                response.completion.is_none(),
                "preparation failure must not authorize transmission completion"
            );
            continue;
        };
        let mut wait = core::pin::pin!(completion.wait());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            wait.as_mut().poll(&mut cx).is_pending(),
            "queue acceptance must not authorize a handoff"
        );
        if let Some(stale) = previous {
            stale.complete(true);
        }
        assert!(
            wait.as_mut().poll(&mut cx).is_pending(),
            "stale completion must not authorize a handoff"
        );
        // Wait was only polled, not consumed, so the driver can own it now.
        response.completion.unwrap().complete(sent);
        previous = Some(completion);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(finish_dfu(&mut env, dfu))
        }));
        assert_eq!(result.is_err(), sent, "only the final handoff diverges");
        let mut after = [0; SNAPSHOT_MAX];
        let after_len = session.encode_snapshot(&mut after).unwrap();
        assert_eq!(&after[..after_len], &before[..before_len]);
    }
    let expired = crate::reply_completion::ReplyCompletion::begin(Instant::now());
    assert!(
        !expired.complete(true),
        "late transmission cannot retain cached success"
    );
    assert!(!block_on(expired.wait()));
    let timed_out = crate::reply_completion::ReplyCompletion::begin(Instant::now());
    assert!(
        !block_on(timed_out.wait()),
        "a missing completion must expire"
    );
    assert!(
        !timed_out.complete(true),
        "retired tokens cannot authorize a later action"
    );
    assert_eq!(
        events
            .borrow()
            .iter()
            .filter(|event| matches!(event, Event::Dfu(DfuMode::Ble)))
            .count(),
        1
    );
}

#[test]
fn stored_identity_must_match_its_own_secret() {
    use umsh_journal_store::proto::StoredIdentity;
    let secret = [0x5a; 32];
    let (public, record) = device_identity_record(&secret);
    assert_eq!(
        stored_device_identity(Some(&record)),
        StoredIdentity::Keys { secret, public }
    );
    let mut damaged = record;
    damaged[40] ^= 1;
    assert_eq!(
        stored_device_identity(Some(&damaged)),
        StoredIdentity::Unparseable
    );
    assert_eq!(
        stored_device_identity(Some(&record[..32])),
        StoredIdentity::Unparseable
    );
    assert_eq!(stored_device_identity(None), StoredIdentity::Absent);
}

/// A change the device makes on its own is persisted only over a
/// snapshot that is current: never onto a device with nothing saved,
/// and never over a generation boot rejected, where the write would
/// bury the fault `PROP_SAVED` reports. Written once, it is owed no more.
#[test]
fn device_changes_persist_only_over_a_current_snapshot() {
    use embassy_futures::block_on;
    let mut saved = [0; SNAPSHOT_MAX];
    let len = session("Saved radio").encode_snapshot(&mut saved).unwrap();
    let saved = &saved[..len];
    for (restored, rejected, expected_status, persists) in [
        (false, false, SavedStatus::None, false),
        (true, false, SavedStatus::Current, true),
        (true, true, SavedStatus::Fallback, false),
        (false, true, SavedStatus::Unreadable, false),
    ] {
        let mut session = session("Device change");
        if rejected {
            session.note_snapshot_rejected();
        }
        if restored {
            session.restore_at_boot(saved).unwrap();
        }
        assert_eq!(session.saved_status(), expected_status);
        let events = Rc::new(RefCell::new(std::vec::Vec::new()));
        let mut env = Env {
            events: events.clone(),
            older: None,
            restore_gate: Box::leak(Box::new(Signal::new())),
            name_gate: None,
            dfu_result: Err(Status::UNIMPLEMENTED),
        };
        let mut snapshot = [0; SNAPSHOT_MAX];
        assert_eq!(session.toggle_ble(&mut |_| {}), Some(false));
        let mut due = None;
        note_device_change(&mut session, &mut due);
        assert_eq!(due.is_some(), persists, "{expected_status:?}");
        block_on(write_device_changes(&mut session, &mut snapshot, &mut env));
        assert_eq!(
            events.borrow().contains(&Event::SnapshotPersisted),
            persists,
            "{expected_status:?}"
        );
        assert_eq!(session.saved_status(), expected_status);
        events.borrow_mut().clear();
        block_on(write_device_changes(&mut session, &mut snapshot, &mut env));
        assert!(!events.borrow().contains(&Event::SnapshotPersisted));
    }
}

/// A change made through the device's own interface keeps a current
/// snapshot in step, as a switch flipped at the device does. A read, or a
/// write of something the snapshot does not hold, owes nothing. What is
/// owed is not written while the interface is answered, but later, or at
/// once when the board settles it on its way off.
#[test]
fn device_interface_writes_keep_a_current_snapshot_in_step() {
    use umsh_ulcp::{frame, ids::prop};
    let mut saved = [0; SNAPSHOT_MAX];
    let len = session("Saved radio").encode_snapshot(&mut saved).unwrap();
    let saved = &saved[..len];
    let link: &'static DeviceLink<NoopRawMutex> = Box::leak(Box::new(DeviceLink::new()));
    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        device: Some(link),
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let input = rt.input;
    let snapshot = rt.snapshot;
    let events = Rc::new(RefCell::new(std::vec::Vec::new()));
    let env = Env {
        events: events.clone(),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session = session("Device change");
    let mut storage = [0; SNAPSHOT_MAX];
    let mut run = core::pin::pin!(run_with_storage(
        &mut session,
        &mut storage,
        Some(saved),
        Some([0x55; 32]),
        rt,
        env
    ));
    let mut cx = Context::from_waker(Waker::noop());
    // Serves `frame` from the device's own interface, if there is one,
    // then, when `settled`, has what the snapshot is owed written as a
    // board on its way off would. Returns whether the snapshot was written.
    let mut step = |frame: Option<&[u8]>, settled: bool| {
        if let Some(frame) = frame {
            assert!(
                input
                    .try_send(InEvent::Device(FrameBuf::from_slice(frame).unwrap()))
                    .is_ok()
            );
            assert!(run.as_mut().poll(&mut cx).is_pending());
            while link.try_receive().is_some() {}
        }
        if settled {
            let mut settle = core::pin::pin!(snapshot.settle());
            assert!(settle.as_mut().poll(&mut cx).is_pending());
            assert!(run.as_mut().poll(&mut cx).is_pending());
            assert!(settle.as_mut().poll(&mut cx).is_ready());
        }
        let persisted = events.borrow().contains(&Event::SnapshotPersisted);
        events.borrow_mut().clear();
        persisted
    };
    let mut buf = [0u8; 64];
    let len = frame::prop_get(&mut buf, 1, prop::DEV_NAME).unwrap();
    assert!(!step(Some(&buf[..len]), true), "a read");
    let len = frame::prop_set(&mut buf, 2, prop::HOST_AUTO_ACK, &[1]).unwrap();
    assert!(
        !step(Some(&buf[..len]), true),
        "a write the snapshot does not hold"
    );
    let len = frame::prop_set(&mut buf, 3, prop::DEV_NAME, b"Pocket").unwrap();
    assert!(
        !step(Some(&buf[..len]), false),
        "a saved setting, as it is answered"
    );
    assert!(step(None, true), "a saved setting, settled");
    assert!(!step(None, true), "nothing more is owed");
}

/// On a device whose own store keeps the device lists, a change to one
/// reaches the store, and the snapshot is not written for it.
#[test]
fn held_lists_reach_the_store_and_not_the_snapshot() {
    use umsh_ulcp::{frame, ids::prop};
    static DEFAULTS: [[u8; 32]; 1] = [[0x5A; 32]];
    let mut saved = [0; SNAPSHOT_MAX];
    let len = session("Saved radio").encode_snapshot(&mut saved).unwrap();
    let saved = &saved[..len];
    let link: &'static DeviceLink<NoopRawMutex> = Box::leak(Box::new(DeviceLink::new()));
    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        device: Some(link),
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let input = rt.input;
    let events = Rc::new(RefCell::new(std::vec::Vec::new()));
    let env = Env {
        events: events.clone(),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session = session("Device change");
    session.hold_lists(&DEFAULTS, None);
    let mut storage = [0; SNAPSHOT_MAX];
    let mut run = core::pin::pin!(run_with_storage(
        &mut session,
        &mut storage,
        Some(saved),
        Some([0x55; 32]),
        rt,
        env
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(run.as_mut().poll(&mut cx).is_pending());
    events.borrow_mut().clear();

    let mut buf = [0u8; 64];
    let len = frame::prop_insert(&mut buf, 1, prop::DEV_PEERS, &[0xD0; 32]).unwrap();
    assert!(
        input
            .try_send(InEvent::Device(FrameBuf::from_slice(&buf[..len]).unwrap()))
            .is_ok()
    );
    assert!(run.as_mut().poll(&mut cx).is_pending());
    let events = events.borrow();
    assert!(!events.contains(&Event::SnapshotPersisted));
    let mut record = std::vec![1];
    record.extend_from_slice(&[0xD0; 32]);
    record.push(1);
    record.extend_from_slice(&[0x5A; 32]);
    assert!(events.contains(&Event::ListsPersisted(Some(record))));
}

/// The device's own interface is answered on its link and nowhere else,
/// hears every publication the host hears, hears what the host changes,
/// and is told when it fell too far behind to hear them all. What it
/// changes reaches the host as a change the host did not make.
#[test]
fn the_device_interface_is_answered_on_its_link_and_hears_every_publication() {
    use umsh_ulcp::{Frame, PropPayload, frame, ids::prop};
    let link: &'static DeviceLink<NoopRawMutex> = Box::leak(Box::new(DeviceLink::new()));
    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        device: Some(link),
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let input = rt.input;
    let out = rt.out;
    let env = Env {
        events: Rc::new(RefCell::new(std::vec::Vec::new())),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session = session("Device link");
    let mut storage = [0; SNAPSHOT_MAX];
    let mut run = core::pin::pin!(run_with_storage(
        &mut session,
        &mut storage,
        None,
        Some([0x55; 32]),
        rt,
        env
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let mut step = |event: Option<InEvent>| {
        if let Some(event) = event {
            assert!(input.try_send(event).is_ok());
        }
        assert!(run.as_mut().poll(&mut cx).is_pending());
    };
    step(None);
    let parse = |bytes: &[u8]| {
        let parsed = Frame::parse(bytes).unwrap();
        let payload = PropPayload::parse(parsed.payload).unwrap();
        (parsed.header.tid(), payload.key, payload.value.to_vec())
    };

    // With no host attached, a publication still reaches the interface.
    step(Some(InEvent::Toggle(Setting::Bluetooth)));
    let Some(DeviceFrame::Frame(published)) = link.try_receive() else {
        panic!("the toggle was not published to the interface");
    };
    assert_eq!(parse(&published), (0, prop::BLE_ENABLED, vec![0]));

    // A host attaches. The interface's request is answered on the link
    // alone, under its own TID.
    step(Some(InEvent::Attached(Transport::Usb)));
    while out.wired.try_receive().is_ok() {}
    let mut buf = [0u8; 64];
    let len = frame::prop_set(&mut buf, 3, prop::DEV_NAME, b"Pocket").unwrap();
    step(Some(InEvent::Device(
        FrameBuf::from_slice(&buf[..len]).unwrap(),
    )));
    let Some(DeviceFrame::Frame(answer)) = link.try_receive() else {
        panic!("the request was not answered");
    };
    assert_eq!(parse(&answer), (3, prop::DEV_NAME, b"Pocket".to_vec()));
    assert!(link.try_receive().is_none(), "exactly one answer");
    let told = out.wired.try_receive().expect("the host hears the change");
    assert_eq!(parse(&told.frame), (0, prop::DEV_NAME, b"Pocket".to_vec()));
    assert!(out.wired.try_receive().is_err(), "the host hears no answer");

    // The host's own frames are still the host's: the exchange was not an
    // attach, and displaced nothing.
    let len = frame::prop_get(&mut buf, 2, prop::DEV_NAME).unwrap();
    step(Some(InEvent::Frame(
        Transport::Usb,
        FrameBuf::from_slice(&buf[..len]).unwrap(),
    )));
    let reply = out.wired.try_receive().expect("the host is still served");
    assert_eq!(parse(&reply.frame), (2, prop::DEV_NAME, b"Pocket".to_vec()));
    assert!(
        link.try_receive().is_none(),
        "the host's answer is the host's"
    );

    // What the host changes, the interface hears; the status that closes
    // a refused write is the host's alone.
    let len = frame::prop_set(&mut buf, 4, prop::DEV_NAME, b"Mine").unwrap();
    step(Some(InEvent::Frame(
        Transport::Usb,
        FrameBuf::from_slice(&buf[..len]).unwrap(),
    )));
    let reply = out.wired.try_receive().expect("the host is answered");
    assert_eq!(parse(&reply.frame), (4, prop::DEV_NAME, b"Mine".to_vec()));
    let Some(DeviceFrame::Frame(told)) = link.try_receive() else {
        panic!("the interface was not told of the host's change");
    };
    assert_eq!(parse(&told), (0, prop::DEV_NAME, b"Mine".to_vec()));
    let len = frame::prop_set(&mut buf, 5, prop::PHY_LORA_SF, &[99]).unwrap();
    step(Some(InEvent::Frame(
        Transport::Usb,
        FrameBuf::from_slice(&buf[..len]).unwrap(),
    )));
    let reply = out.wired.try_receive().expect("the host is answered");
    assert_eq!(parse(&reply.frame).1, prop::LAST_STATUS);
    assert!(link.try_receive().is_none(), "a refusal is not a change");

    // A publication reaches both.
    step(Some(InEvent::Toggle(Setting::Bluetooth)));
    let to_host = out.wired.try_receive().expect("published to the host");
    assert_eq!(parse(&to_host.frame), (0, prop::BLE_ENABLED, vec![1]));
    let Some(DeviceFrame::Frame(to_device)) = link.try_receive() else {
        panic!("not published to the interface");
    };
    assert_eq!(parse(&to_device), (0, prop::BLE_ENABLED, vec![1]));

    // An interface that stops reading loses publications, never blocks
    // the driver, and is told after the ones that were kept.
    for _ in 0..DEVICE_LINK_DEPTH + 2 {
        step(Some(InEvent::Toggle(Setting::Bluetooth)));
        while out.wired.try_receive().is_ok() {}
    }
    let mut kept = 0;
    let mut overrun = false;
    while let Some(frame) = link.try_receive() {
        match frame {
            DeviceFrame::Frame(_) => {
                assert!(!overrun, "the overrun follows the frames kept");
                kept += 1;
            }
            DeviceFrame::Overrun => {
                assert!(!overrun, "the overrun is reported once");
                overrun = true;
            }
        }
    }
    assert_eq!(kept, DEVICE_LINK_DEPTH);
    assert!(overrun);
}

/// Node messaging through the driver: the claims reach the node's side of
/// the mirror, a held message goes to the host only once it listens, and
/// a host whose session starts over is handed it again, flagged, once it
/// listens again.
#[cfg(feature = "node-msg")]
#[test]
fn node_messages_wait_for_a_host_that_listens() {
    use crate::node_msg::{self, Inbox, Message};
    use umsh_ulcp::frame::StreamPayload;
    use umsh_ulcp::node_msg::{Kind, RecvMeta, Source};
    use umsh_ulcp::{
        Frame, frame,
        ids::{prop, stream},
    };

    let _alone = node_msg::TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    node_msg::INBOX.lock(|inbox| *inbox.borrow_mut() = Inbox::new());
    node_msg::publish_claims([]);

    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        device: None,
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let input = rt.input;
    let out = rt.out;
    let env = Env {
        events: Rc::new(RefCell::new(std::vec::Vec::new())),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session: TestSession = Session::new(
        SessionConfig {
            mac_node: true,
            node_msg: Some(node_msg::CONFIG),
            ..config("Node messages")
        },
        Status::RESET_POWER_ON,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    );
    let mut storage = [0; SNAPSHOT_MAX];
    let mut run = core::pin::pin!(run_with_storage(
        &mut session,
        &mut storage,
        None,
        Some([0x55; 32]),
        rt,
        env
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let mut step = |event: Option<InEvent>| {
        if let Some(event) = event {
            assert!(input.try_send(event).is_ok());
        }
        assert!(run.as_mut().poll(&mut cx).is_pending());
    };
    let from_host =
        |bytes: &[u8]| InEvent::Frame(Transport::Usb, FrameBuf::from_slice(bytes).unwrap());
    let drain = || while out.wired.try_receive().is_ok() {};
    // The node messages among what the host was sent since the last look,
    // each as its payload and whether it is flagged as delivered before.
    // Whatever else the driver published in between is not this test's.
    let received = || {
        let mut messages = std::vec::Vec::new();
        while let Ok(queued) = out.wired.try_receive() {
            let parsed = Frame::parse(&queued.frame).unwrap();
            if parsed.command() != Some(umsh_ulcp::Cmd::StrRecv) {
                continue;
            }
            let payload = StreamPayload::parse(parsed.payload).unwrap();
            assert_eq!(payload.stream, stream::NODE_MSG);
            let meta = RecvMeta::parse(payload.metadata).unwrap();
            messages.push((payload.data.to_vec(), meta.redelivered));
        }
        messages
    };
    step(None);
    step(Some(InEvent::Attached(Transport::Usb)));
    drain();

    // A claim the host writes is the node's to act on at once.
    let mut buf = [0u8; 64];
    let len = frame::prop_set(&mut buf, 1, prop::NODE_MSG_TYPES, &[3]).unwrap();
    step(Some(from_host(&buf[..len])));
    drain();
    assert!(node_msg::claimed(3), "the claim reached the receive tap");
    assert!(!node_msg::claimed(4));

    // A message arrives while the host is not listening: it waits.
    let stored = node_msg::INBOX.lock(|inbox| {
        inbox.borrow_mut().store(Message {
            kind: Kind::Unicast,
            source: Source::Key([0xAA; 32]),
            channel: None,
            sender_auth: true,
            acked: true,
            rssi_dbm: None,
            snr_cb: None,
            trace: heapless::Vec::new(),
            payload: heapless::Vec::from_slice(&[3, 7]).unwrap(),
        })
    });
    assert!(stored);
    step(Some(InEvent::NodeMsgPending));
    assert_eq!(received(), [], "nobody is listening");

    // The host listens, and has it, once.
    let len = frame::prop_set(&mut buf, 2, prop::NODE_MSG_LISTEN, &[1]).unwrap();
    step(Some(from_host(&buf[..len])));
    assert_eq!(received(), [(vec![3, 7], false)]);
    step(Some(InEvent::NodeMsgPending));
    assert_eq!(received(), [], "delivered once");

    // Its session starts over. Listening is session state, so the message
    // waits again, for this host and no other link.
    let len = frame::session_start(&mut buf, 3).unwrap();
    step(Some(from_host(&buf[..len])));
    drain();
    step(Some(InEvent::NodeMsgPending));
    assert_eq!(received(), [], "not listening yet");
    let len = frame::prop_set(&mut buf, 4, prop::NODE_MSG_LISTEN, &[1]).unwrap();
    step(Some(from_host(&buf[..len])));
    assert_eq!(received(), [(vec![3, 7], true)]);
}

/// The window reaches the UART link task at boot, before any host, and
/// again when the host on the wired UART sets it. A host on BLE is not
/// on the UART and is refused. The link task also hears of each frame
/// from the UART once it is acted on, and of no other.
#[cfg(feature = "uart-link")]
#[test]
fn the_uart_window_is_published_for_the_link_task() {
    use crate::uart_link::WINDOW;
    use umsh_ulcp::{frame, ids::prop};
    use umsh_ulcp_device::UartLinks;

    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        device: None,
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let input = rt.input;
    let env = Env {
        events: Rc::new(RefCell::new(std::vec::Vec::new())),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session: TestSession = Session::new(
        SessionConfig {
            uart_links: UartLinks {
                wired_host: true,
                device: false,
            },
            ..config("UART window")
        },
        Status::RESET_POWER_ON,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    );
    let mut storage = [0; SNAPSHOT_MAX];
    let mut run = core::pin::pin!(run_with_storage(
        &mut session,
        &mut storage,
        None,
        Some([0x55; 32]),
        rt,
        env
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let mut step = |event: Option<InEvent>| {
        if let Some(event) = event {
            assert!(input.try_send(event).is_ok());
        }
        assert!(run.as_mut().poll(&mut cx).is_pending());
    };
    let set_window = |transport: Transport, window: u16| {
        let mut buf = [0u8; 16];
        let len = frame::prop_set(&mut buf, 1, prop::UART_WINDOW, &window.to_le_bytes()).unwrap();
        InEvent::Frame(transport, FrameBuf::from_slice(&buf[..len]).unwrap())
    };

    let _alone = UART_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    step(None);
    assert_eq!(WINDOW.get(), Some(0));
    let before = WINDOW.acted();
    step(Some(InEvent::Attached(Transport::Ble)));
    step(Some(set_window(Transport::Ble, 16)));
    assert_eq!(WINDOW.get(), Some(0));
    step(Some(InEvent::Attached(Transport::Usb)));
    assert_eq!(WINDOW.acted(), before, "nothing from the UART yet");
    step(Some(set_window(Transport::Usb, 32)));
    assert_eq!(WINDOW.get(), Some(32));
    assert_eq!(WINDOW.acted(), before.wrapping_add(1));
}

/// The UART link tests share the board's one window.
#[cfg(feature = "uart-link")]
static UART_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An application wired to the device's own interface is on a serial
/// link: a frame lost on its UART ends its session, which owes it the
/// notice and nothing else, publications included, until it starts the
/// next one. The host is untouched.
#[cfg(feature = "uart-link")]
#[test]
fn a_lost_frame_ends_the_application_s_session() {
    use umsh_ulcp::{Cmd, Frame, frame};
    use umsh_ulcp_device::UartLinks;

    let _alone = UART_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let link: &'static DeviceLink<NoopRawMutex> = Box::leak(Box::new(DeviceLink::wire()));
    let rt = DeviceRuntime {
        input: Box::leak(Box::new(InputChannel::<NoopRawMutex>::new())),
        radio: Box::leak(Box::new(Channels::<NoopRawMutex, 1, 1>::new())),
        ctl: Box::leak(Box::new(DeviceControl::new())),
        out: Box::leak(Box::new(TransportChannels::new())),
        session_gen: Box::leak(Box::new(AtomicU32::new(0))),
        device: Some(link),
        snapshot: Box::leak(Box::new(SnapshotControl::new())),
    };
    let input = rt.input;
    let out = rt.out;
    let env = Env {
        events: Rc::new(RefCell::new(std::vec::Vec::new())),
        older: None,
        restore_gate: Box::leak(Box::new(Signal::new())),
        name_gate: None,
        dfu_result: Err(Status::UNIMPLEMENTED),
    };
    let mut session: TestSession = Session::new(
        SessionConfig {
            uart_links: UartLinks {
                wired_host: false,
                device: true,
            },
            ..config("Application")
        },
        Status::RESET_POWER_ON,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    );
    let mut storage = [0; SNAPSHOT_MAX];
    let mut run = core::pin::pin!(run_with_storage(
        &mut session,
        &mut storage,
        None,
        Some([0x55; 32]),
        rt,
        env
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let mut step = |event: Option<InEvent>| {
        if let Some(event) = event {
            assert!(input.try_send(event).is_ok());
        }
        assert!(run.as_mut().poll(&mut cx).is_pending());
    };
    let from_application = |bytes: &[u8]| InEvent::Device(FrameBuf::from_slice(bytes).unwrap());
    let next = || match link.try_receive() {
        Some(DeviceFrame::Frame(frame)) => Some(frame),
        Some(DeviceFrame::Overrun) => panic!("a wire never hears an overrun"),
        None => None,
    };
    let command = |bytes: &[u8]| Frame::parse(bytes).unwrap().command();
    let mut buf = [0u8; 16];

    step(None);
    step(Some(InEvent::Attached(Transport::Usb)));
    while out.wired.try_receive().is_ok() {}
    let len = frame::nop(&mut buf, 1).unwrap();
    step(Some(from_application(&buf[..len])));
    assert!(next().is_some(), "the application is answered");

    step(Some(InEvent::DeviceFrameLost));
    let notice = next().expect("the application is told");
    let parsed = Frame::parse(&notice).unwrap();
    assert_eq!(parsed.command(), Some(Cmd::SessionDidEnd));
    assert_eq!(
        frame::parse_session_did_end(parsed.payload),
        Ok(SessionEndReason::FrameLost)
    );

    // Nothing more until it starts over: no answer, no publication.
    let len = frame::nop(&mut buf, 2).unwrap();
    step(Some(from_application(&buf[..len])));
    step(Some(InEvent::Toggle(Setting::Bluetooth)));
    assert!(next().is_none());
    assert!(
        out.wired.try_receive().is_ok(),
        "the host still hears the change"
    );

    let len = frame::session_start(&mut buf, 3).unwrap();
    step(Some(from_application(&buf[..len])));
    assert_eq!(command(&next().unwrap()), Some(Cmd::SessionDidStart));
    step(Some(InEvent::Toggle(Setting::Bluetooth)));
    assert_eq!(command(&next().unwrap()), Some(Cmd::PropIs));
}
