//! The model over a [`LocalExchange`], against the soft device's real
//! session through the device's own interface.

use umsh_ulcp::Frame;
use umsh_ulcp::frame::Cmd;
use umsh_ulcp::ids::{cap, prop, saved};
use umsh_ulcp::profiles;
use umsh_ulcp_admin::{
    Event, Freshness, LocalExchange, LocalPort, Model, PortBusy, PortFrame, Refusal, WriteOutcome,
};
use umsh_ulcp_simdev::{
    AlertConfig, BatteryFields, DutyLedger, GnssConfig, RadioSettings, SessionConfig,
    SimulatedDevice, TimeConfig,
};

fn config() -> SessionConfig {
    SessionConfig {
        dev_version: "umsh-ulcp-admin-test/0.1",
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
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: true,
        }),
        alert: Some(AlertConfig::DEFAULT),
        time: Some(TimeConfig),
        gnss: Some(GnssConfig::DEFAULT),
        display_motion_wake: false,
        display: None,
        keyboard: false,
        sound: false,
        illuminance: false,
        temperatures: false,
        ble: true,
        ble_pairing: true,
        ble_pin: true,
        reboot: true,
        dev_identity: true,
        messaging: false,
        stats: None,
        // A simulated device has no node, so it cannot forward.
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

/// The soft device's own interface, as a [`LocalPort`]. It answers as
/// soon as it is asked, so what this exercises is the model's handling of
/// what a session says, not of when it says it.
struct Port {
    sim: SimulatedDevice,
    /// Every request handed over, in order.
    sent: Vec<Vec<u8>>,
    /// Report a dropped publication before the next frame.
    overrun: bool,
}

impl LocalPort for Port {
    fn send(&mut self, frame: &[u8]) -> Result<(), PortBusy> {
        self.sent.push(frame.to_vec());
        self.sim.device_request(frame, 1_000);
        Ok(())
    }

    fn receive(&mut self, out: &mut [u8]) -> Option<PortFrame> {
        if core::mem::take(&mut self.overrun) {
            return Some(PortFrame::Overrun);
        }
        let frame = self.sim.take_device_frame()?;
        out[..frame.len()].copy_from_slice(&frame);
        Some(PortFrame::Frame(frame.len()))
    }
}

fn device() -> (Model, LocalExchange<Port>) {
    let mut sim = SimulatedDevice::new(config());
    sim.open_device_interface();
    let mut exchange = LocalExchange::new(Port {
        sim,
        sent: Vec::new(),
        overrun: false,
    });
    let mut model = Model::new();
    model.refresh();
    model.pump(&mut exchange, 1_000);
    while model.next_event().is_some() {}
    exchange.port_mut().sent.clear();
    (model, exchange)
}

fn events(model: &mut Model) -> Vec<Event> {
    core::iter::from_fn(|| model.next_event()).collect()
}

fn commands(exchange: &LocalExchange<Port>) -> Vec<Cmd> {
    exchange
        .port()
        .sent
        .iter()
        .map(|frame| Frame::parse(frame).unwrap().command().unwrap())
        .collect()
}

#[test]
fn one_bundle_fills_the_cache() {
    let mut sim = SimulatedDevice::new(config());
    sim.open_device_interface();
    let mut exchange = LocalExchange::new(Port {
        sim,
        sent: Vec::new(),
        overrun: false,
    });
    let mut model = Model::new();
    model.refresh();
    model.pump(&mut exchange, 1_000);

    // Everything covered went out together, and nothing asked whether the
    // device could take that.
    assert_eq!(commands(&exchange), [Cmd::PropMultiGet]);
    assert!(!model.busy());

    assert_eq!(model.device_name(), Some("Pocket"));
    assert_eq!(model.tx_power_dbm(), Some(14));
    let radio = model.radio().unwrap();
    assert_eq!(radio.profile().map(|p| p.id), Some("meshcore-us-ca"));
    // A soft device has no identity until one is provisioned, and reports
    // the key empty.
    assert_eq!(model.raw(prop::DEV_KEY), Some(&[][..]));
    assert_eq!(model.device_key(), None);
    assert_eq!(model.has_cap(cap::DEV_IDENTITY), Some(true));
    assert_eq!(model.has_cap(cap::REPEATER), Some(false));
    assert_eq!(
        model.freshness(prop::PHY_TX_POWER),
        Freshness::Fresh { at_ms: 1_000 }
    );
    assert_eq!(model.peers().count(), 0);

    // A property the device does not have says so, once.
    assert!(matches!(
        model.freshness(prop::MAC_REPEATER_ENABLED),
        Freshness::Unavailable(_)
    ));
    let events = events(&mut model);
    assert!(events.contains(&Event::Changed(prop::DEV_NAME)));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Unavailable { key, .. } if *key == prop::MAC_REPEATER_ENABLED))
    );

    // Once the capabilities are known, a refresh leaves out what the
    // device lacks and the constant it already has.
    exchange.port_mut().sent.clear();
    model.refresh();
    model.pump(&mut exchange, 2_000);
    let request = Frame::parse(&exchange.port().sent[0]).unwrap();
    let asked: Vec<u32> = umsh_ulcp::frame::MultiGetKeys::new(request.payload)
        .map(Result::unwrap)
        .collect();
    assert!(!asked.contains(&prop::CAPS));
    assert!(!asked.contains(&prop::MAC_REPEATER_ENABLED));
    assert!(asked.contains(&prop::PHY_TX_POWER));
}

#[test]
fn a_write_reports_what_the_device_applied() {
    let (mut model, mut exchange) = device();

    let name = model.set_device_name("Trail").unwrap();
    // Pending until answered: the cache still shows what the device said.
    assert_eq!(model.pending(prop::DEV_NAME), Some(&b"Trail"[..]));
    assert_eq!(model.device_name(), Some("Pocket"));
    model.pump(&mut exchange, 2_000);
    assert_eq!(model.pending(prop::DEV_NAME), None);
    assert_eq!(model.device_name(), Some("Trail"));

    // Beyond what the radio reaches, the device clamps.
    let power = model.set_tx_power_dbm(30).unwrap();
    model.pump(&mut exchange, 2_000);
    assert_eq!(model.tx_power_dbm(), Some(22));

    assert_eq!(
        events(&mut model),
        [
            Event::Changed(prop::DEV_NAME),
            Event::Written {
                id: name,
                key: prop::DEV_NAME,
                outcome: WriteOutcome::Applied
            },
            Event::Changed(prop::PHY_TX_POWER),
            Event::Written {
                id: power,
                key: prop::PHY_TX_POWER,
                outcome: WriteOutcome::Adjusted
            },
        ]
    );
}

#[test]
fn writes_the_device_cannot_take_never_leave() {
    let (mut model, exchange) = device();
    assert_eq!(model.set_forwarding(true), Err(Refusal::Unsupported));
    assert_eq!(
        model.set(prop::PHY_LORA_SW, &[0x12, 0x34]),
        Err(Refusal::WrongAccess)
    );
    assert_eq!(
        model.set(prop::DEV_PEERS, &[0; 32]),
        Err(Refusal::WrongAccess)
    );
    assert_eq!(
        model.set_device_name(&"x".repeat(65)),
        Err(Refusal::BadLength)
    );
    assert_eq!(
        model.insert(prop::DEV_PEERS, &[0; 16]),
        Err(Refusal::BadLength)
    );
    assert_eq!(model.set(prop::ALERT, &[1]), Err(Refusal::NotCovered));
    assert!(!model.busy());
    assert!(exchange.port().sent.is_empty());
}

#[test]
fn a_profile_goes_out_as_one_request() {
    let (mut model, mut exchange) = device();
    let profile = profiles::by_id("umsh-us-ca").unwrap();
    let id = model.set_profile(profile).unwrap();
    model.pump(&mut exchange, 2_000);
    assert_eq!(commands(&exchange), [Cmd::PropMultiSet]);
    assert_eq!(model.radio().unwrap().profile(), Some(profile));

    let outcomes: Vec<(u32, WriteOutcome)> = events(&mut model)
        .into_iter()
        .filter_map(|event| match event {
            Event::Written {
                id: written,
                key,
                outcome,
            } if written == id => Some((key, outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            (prop::PHY_FREQ, WriteOutcome::Applied),
            (prop::PHY_LORA_BW, WriteOutcome::Applied),
            (prop::PHY_LORA_SF, WriteOutcome::Applied),
            (prop::PHY_LORA_CR, WriteOutcome::Applied),
            // The profile is vetted for 30 dBm; this radio reaches 22.
            (prop::PHY_TX_POWER, WriteOutcome::Adjusted),
            (prop::PHY_DUTY_LIMIT, WriteOutcome::Applied),
        ]
    );
}

#[test]
fn a_refused_write_stops_its_sequence_and_leaves_the_cache() {
    let (mut model, mut exchange) = device();
    let id = model
        .set_many(&[(prop::PHY_LORA_SF, &[13]), (prop::PHY_TX_POWER, &[5])])
        .unwrap();
    model.pump(&mut exchange, 2_000);
    assert_eq!(model.radio().unwrap().sf, 7);
    assert_eq!(model.tx_power_dbm(), Some(14));
    let events = events(&mut model);
    assert!(matches!(
        events[0],
        Event::Written {
            id: written,
            key: prop::PHY_LORA_SF,
            outcome: WriteOutcome::Refused(_),
        } if written == id
    ));
    assert_eq!(
        events[1],
        Event::Written {
            id,
            key: prop::PHY_TX_POWER,
            outcome: WriteOutcome::Skipped
        }
    );
    assert_eq!(events.len(), 2);
}

#[test]
fn tables_change_an_item_at_a_time() {
    let (mut model, mut exchange) = device();
    let peer = [0x42; 32];
    let channel = [0x17; 32];
    model.save_peer(&peer).unwrap();
    model.join_channel(&channel).unwrap();
    model.pump(&mut exchange, 2_000);
    assert_eq!(model.peers().collect::<Vec<_>>(), [&peer]);
    // A channel is reported by its identifier, never its key.
    let channels: Vec<&[u8; 16]> = model.channels().collect();
    assert_eq!(channels.len(), 1);
    assert_ne!(&channels[0][..], &channel[..16]);

    model.forget_peer(&peer).unwrap();
    model.pump(&mut exchange, 3_000);
    assert_eq!(model.peers().count(), 0);
    assert_eq!(
        commands(&exchange),
        [Cmd::PropInsert, Cmd::PropInsert, Cmd::PropRemove]
    );
    assert!(events(&mut model).iter().all(|event| !matches!(
        event,
        Event::Written {
            outcome: WriteOutcome::Refused(_) | WriteOutcome::Unknown,
            ..
        }
    )));
}

#[test]
fn a_save_is_followed_by_what_it_saved() {
    let (mut model, mut exchange) = device();
    model.set_device_name("Trail").unwrap();
    model.pump(&mut exchange, 2_000);
    assert_eq!(model.saved(), Some(saved::NONE));

    let id = model.save().unwrap();
    model.pump(&mut exchange, 3_000);
    assert_eq!(commands(&exchange)[1..], [Cmd::Save, Cmd::PropGet]);
    assert_eq!(model.saved(), Some(saved::CURRENT));
    assert!(events(&mut model).contains(&Event::Saved { id, result: Ok(()) }));
}

#[test]
fn lost_publications_leave_everything_to_read_again() {
    let (mut model, mut exchange) = device();
    exchange.port_mut().overrun = true;
    model.pump(&mut exchange, 5_000);
    assert_eq!(commands(&exchange), [Cmd::PropMultiGet]);
    assert_eq!(events(&mut model)[0], Event::Resync);
    assert_eq!(
        model.freshness(prop::PHY_TX_POWER),
        Freshness::Fresh { at_ms: 5_000 }
    );
}

#[test]
fn a_switch_turned_at_the_device_is_taken_in_without_asking() {
    let (mut model, mut exchange) = device();
    let was = model.bluetooth_enabled().expect("read with the rest");
    exchange.port_mut().sim.toggle_ble();
    model.pump(&mut exchange, 2_000);
    assert_eq!(events(&mut model), [Event::Changed(prop::BLE_ENABLED)]);
    assert_eq!(model.bluetooth_enabled(), Some(!was));
    assert!(exchange.port().sent.is_empty());
}
