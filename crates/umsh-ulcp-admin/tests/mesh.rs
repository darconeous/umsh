//! The model across the mesh: node-mgmt's administrator engine on one
//! side, a device running the real ULCP session behind node-mgmt's device
//! engine on the other, as node-mgmt's own binding tests set them up.
//!
//! The air between them is the test's. A response arrives a latency after
//! its request, and only once the test moves the clock past it, so every
//! request here is one the model must leave pending and come back to. The
//! test can also lose responses, and lose the device.

use std::collections::VecDeque;

use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_node_mgmt::admin::{self, Outcome, RESPONSE_WAIT_MIN_MS, Reassembly, Step};
use umsh_node_mgmt::device::{DeviceEngine, Dispatch, Ingress};
use umsh_ulcp::frame::{self, Cmd, Frame};
use umsh_ulcp::ids::{cap, prop, saved};
use umsh_ulcp::status::Status;
use umsh_ulcp_admin::{
    Arrival, Busy, Event, Exchange, Freshness, Model, Request, Ticket, WriteOutcome,
};
use umsh_ulcp_device::{
    AlertConfig, BatteryFields, DutyLedger, Effect, GnssConfig, MULTI_MAX, RadioSettings, Session,
    SessionConfig, TimeConfig,
};

/// One Node Management payload on this link, the nRF responder's ceiling.
const PAYLOAD: usize = 180;

/// A radio that carries less, so a reply runs out of room.
const SMALL_PAYLOAD: usize = 96;

/// The largest request the administrator's engine holds.
const REQUEST_MAX: usize = 192;

/// The largest reassembled answer.
const ANSWER_MAX: usize = 1024;

/// How long a request takes to reach the device and its answer to come
/// back.
const LATENCY_MS: u64 = 3_000;

const ADMIN_KEY: [u8; 32] = [0xA1; 32];

// ─── The device ──────────────────────────────────────────────────────────

struct Device<const PAYLOAD: usize> {
    session: Session<SoftwareAes, SoftwareSha256>,
    engine: DeviceEngine<PAYLOAD, { 2 * MULTI_MAX }, 2>,
    /// Requests the session actually ran, as opposed to those answered
    /// from the retained response.
    executed: u32,
}

impl<const PAYLOAD: usize> Device<PAYLOAD> {
    fn new() -> Self {
        let config = SessionConfig {
            dev_version: "umsh-ulcp-admin-mesh/0.1",
            dev_model: Some("Simulated Repeater"),
            default_device_name: "Ridgeline",
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
                level: false,
                charge_state: true,
            }),
            alert: Some(AlertConfig::DEFAULT),
            time: Some(TimeConfig),
            gnss: Some(GnssConfig::DEFAULT),
            display_motion_wake: false,
            display: None,
            keyboard: false,
            illuminance: false,
            temperatures: false,
            ble: true,
            ble_pairing: true,
            ble_pin: true,
            reboot: true,
            dev_identity: true,
            messaging: false,
            stats: None,
            mac_node: true,
            meshcore_forwarder: false,
            lan_bearer: umsh_ulcp_device::LanBearerRole::None,
            wifi: None,
            ip: None,
            bridge_client: false,
            i2c_buses: &[],
            i2c_devices: &[],
        };
        let mut session = Session::new(
            config,
            Status::RESET_POWER_ON,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        session.attach(false);
        Self {
            session,
            engine: DeviceEngine::new(0x5AA5),
            executed: 0,
        }
    }

    /// One Node Management Request in, its response out, as the
    /// firmware's responder does it. The sender is the administrator;
    /// authorization is node-mgmt's to test, not this crate's.
    fn deliver(&mut self, payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        let mut out = [0u8; PAYLOAD];
        let len = match self.engine.begin(&ADMIN_KEY, payload, now_ms, &mut out) {
            Ingress::Drop(_) => return None,
            Ingress::Respond { len } => Some(len),
            Ingress::Dispatch(dispatch) => {
                self.executed += 1;
                let reply = self.serve(&dispatch, now_ms);
                self.engine.complete(&reply, &mut out).expect("complete")
            }
        };
        len.map(|len| out[..len].to_vec())
    }

    fn serve(&mut self, dispatch: &Dispatch<'_>, now_ms: u64) -> Vec<u8> {
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut pending = self.session.handle_admin_frame(
            dispatch.frame,
            now_ms,
            dispatch.budget,
            &mut |bytes: &[u8]| emitted.push(bytes.to_vec()),
        );
        while let Some(effect) = pending.take() {
            if let Effect::SaveSnapshot { tid } = effect {
                self.session.respond_save(tid, Ok(()), &mut |bytes: &[u8]| {
                    emitted.push(bytes.to_vec())
                });
            }
            pending = self
                .session
                .resume_multi(now_ms, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        }
        self.session.end_admin_exchange();
        assert!(emitted.len() <= 1, "one frame answers an exchange");
        emitted.pop().unwrap_or_default()
    }

    /// Read a property over the tethered binding, to see what a remote
    /// write did.
    fn local_get(&mut self, key: u32) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 6, key).unwrap();
        let mut emitted = Vec::new();
        self.session
            .handle_frame(&buf[..len], 0, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        let parsed = Frame::parse(&emitted[0]).unwrap();
        let (_, consumed) = umsh_ulcp::pui::decode(parsed.payload).unwrap();
        parsed.payload[consumed..].to_vec()
    }
}

// ─── The administrator's link ────────────────────────────────────────────

/// One exchange at a time with one device, over air the test drives.
struct Mesh<const PAYLOAD: usize> {
    device: Device<PAYLOAD>,
    now_ms: u64,
    /// The exchange in flight, and the ticket it answers.
    current: Option<(Ticket, admin::Exchange<REQUEST_MAX>)>,
    reassembly: Vec<u8>,
    reassembled: usize,
    /// Responses on their way back, and when each lands.
    air: VecDeque<(u64, Vec<u8>)>,
    /// Lose this many of the next responses.
    lose_responses: u32,
    /// The device is out of reach: no attempt is acknowledged.
    unreachable: bool,
    next_ticket: u32,
    /// The token counter carried across exchanges.
    counter: u16,
    /// Payloads sent, retransmissions and continuations included.
    sent: u32,
    /// The ULCP command of each exchange begun, in order.
    commands: Vec<Cmd>,
}

impl<const PAYLOAD: usize> Mesh<PAYLOAD> {
    fn new(device: Device<PAYLOAD>) -> Self {
        Self {
            device,
            now_ms: 0,
            current: None,
            reassembly: vec![0; ANSWER_MAX],
            reassembled: 0,
            air: VecDeque::new(),
            lose_responses: 0,
            unreachable: false,
            next_ticket: 0,
            counter: 0x1000,
            sent: 0,
            commands: Vec::new(),
        }
    }

    /// Put one attempt on the air. The MAC acknowledges whatever reaches
    /// the device, answered or not.
    fn attempt(&mut self, payload: &[u8]) {
        let Some((_, exchange)) = self.current.as_mut() else {
            return;
        };
        self.sent += 1;
        if self.unreachable {
            exchange.undelivered();
            return;
        }
        exchange.acknowledged(self.now_ms);
        let Some(response) = self.device.deliver(payload, self.now_ms) else {
            return;
        };
        if self.lose_responses > 0 {
            self.lose_responses -= 1;
        } else {
            self.air.push_back((self.now_ms + LATENCY_MS, response));
        }
    }

    /// The exchange in flight is over.
    fn finish(&mut self) -> Ticket {
        let (ticket, exchange) = self.current.take().unwrap();
        self.counter = exchange.counter().wrapping_add(1);
        ticket
    }

    /// Move the clock.
    fn advance(&mut self, ms: u64) {
        self.now_ms += ms;
    }
}

impl<const PAYLOAD: usize> Exchange for Mesh<PAYLOAD> {
    const ANSWER_MAX: usize = ANSWER_MAX;

    fn submit(&mut self, request: &Request<'_>) -> Result<Ticket, Busy> {
        if self.current.is_some() {
            return Err(Busy::Full);
        }
        // An administrator's frames go under TID 0: the token correlates.
        let mut frame = [0u8; REQUEST_MAX];
        let len = request.encode(0, &mut frame).map_err(|_| Busy::TooLarge)?;
        let exchange = admin::Exchange::new(&frame[..len], self.counter, self.now_ms)
            .map_err(|_| Busy::TooLarge)?;
        self.commands
            .push(Frame::parse(&frame[..len]).unwrap().command().unwrap());
        let ticket = Ticket(self.next_ticket);
        self.next_ticket += 1;
        self.current = Some((ticket, exchange));
        self.reassembled = 0;
        Ok(ticket)
    }

    fn receive<'b>(&mut self, out: &'b mut [u8]) -> Option<Arrival<'b>> {
        loop {
            let (ticket, exchange) = self.current.as_mut()?;
            let ticket = *ticket;
            let mut wire = [0u8; PAYLOAD];
            let landed = self.air.front().is_some_and(|(at, _)| *at <= self.now_ms);
            let step = if landed {
                let (_, response) = self.air.pop_front().unwrap();
                let mut reassembly = Reassembly::resume(&mut self.reassembly, self.reassembled);
                let step = exchange.receive(&response, &mut reassembly, self.now_ms, &mut wire);
                self.reassembled = reassembly.len();
                // A late answer to an exchange already over carries a
                // token nobody holds now.
                let Some(step) = step else {
                    continue;
                };
                step
            } else {
                exchange.poll(self.now_ms, &mut wire)
            };
            match step {
                // The first attempt, a retransmission, or a continuation.
                Step::Send { len } => self.attempt(&wire[..len]),
                Step::Done(Outcome::Replied { len }) => {
                    self.finish();
                    out[..len].copy_from_slice(&self.reassembly[..len]);
                    return Some(Arrival::Answer {
                        ticket,
                        frame: &out[..len],
                    });
                }
                Step::Done(_) => {
                    return Some(Arrival::Lost {
                        ticket: self.finish(),
                    });
                }
                Step::Wait { .. } | Step::Delivering => {
                    if !landed {
                        return None;
                    }
                }
            }
        }
    }
}

fn mesh<const PAYLOAD: usize>() -> (Model, Mesh<PAYLOAD>) {
    let mut link = Mesh::new(Device::<PAYLOAD>::new());
    let mut model = Model::new();
    model.refresh();
    settle(&mut model, &mut link);
    while model.next_event().is_some() {}
    link.commands.clear();
    link.sent = 0;
    (model, link)
}

/// Pump until nothing is left to wait for, moving the clock a latency at
/// a time.
fn settle<const PAYLOAD: usize>(model: &mut Model, link: &mut Mesh<PAYLOAD>) {
    pump(model, link);
    for _ in 0..1_000 {
        if !model.busy() {
            return;
        }
        link.advance(LATENCY_MS);
        pump(model, link);
    }
    panic!("the model never settled");
}

fn pump<const PAYLOAD: usize>(model: &mut Model, link: &mut Mesh<PAYLOAD>) {
    let now_ms = link.now_ms;
    model.pump(link, now_ms);
}

fn events(model: &mut Model) -> Vec<Event> {
    core::iter::from_fn(|| model.next_event()).collect()
}

// ─── The tests ───────────────────────────────────────────────────────────

#[test]
fn a_distant_device_fills_the_cache_without_being_waited_on() {
    let mut link = Mesh::new(Device::<PAYLOAD>::new());
    let mut model = Model::new();
    model.refresh();
    model.pump(&mut link, 0);

    // Asked, and not yet answered: the model went on its way.
    assert_eq!(link.commands, [Cmd::PropMultiGet]);
    assert!(model.busy());
    assert_eq!(model.device_name(), None);
    assert_eq!(model.freshness(prop::DEV_NAME), Freshness::Unknown);
    assert_eq!(model.next_event(), None);

    settle(&mut model, &mut link);
    assert_eq!(model.device_name(), Some("Ridgeline"));
    assert_eq!(model.forwarding(), Some(false));
    assert_eq!(model.has_cap(cap::REPEATER), Some(true));
    assert_eq!(model.tx_power_dbm(), Some(14));
    assert!(matches!(
        model.freshness(prop::PHY_TX_POWER),
        Freshness::Fresh { at_ms } if at_ms >= LATENCY_MS
    ));
    // Every exchange after the first only asked for what an earlier
    // answer had no room for.
    assert!(
        link.commands
            .iter()
            .all(|command| matches!(command, Cmd::PropMultiGet | Cmd::PropGet))
    );
}

#[test]
fn an_answer_too_large_for_one_payload_arrives_in_pieces() {
    let mut link = Mesh::new(Device::<SMALL_PAYLOAD>::new());
    let mut model = Model::new();
    model.refresh();
    settle(&mut model, &mut link);
    // A small radio's payload cannot carry the whole answer, so the device
    // ran the read once and the engine fetched it in fragments: one
    // request as far as the model knows, and nothing lost.
    assert_eq!(link.commands, [Cmd::PropMultiGet]);
    assert_eq!(link.device.executed, 1);
    assert!(link.sent > 1);
    assert_eq!(model.device_name(), Some("Ridgeline"));
    assert_eq!(model.radio().unwrap().sf, 7);
    assert_eq!(model.duty_limit(), Some(0xFFFF));
    assert_eq!(model.share_location(), Some(false));
    assert_eq!(model.peers().count(), 0);
}

#[test]
fn a_write_stays_pending_until_its_answer_lands() {
    let (mut model, mut link) = mesh::<PAYLOAD>();
    let id = model.set_tx_power_dbm(30).unwrap();
    pump(&mut model, &mut link);
    assert_eq!(model.pending(prop::PHY_TX_POWER), Some(&[30][..]));
    assert_eq!(model.tx_power_dbm(), Some(14));
    assert_eq!(model.next_event(), None);

    // The device has already applied it; the administrator does not know
    // yet.
    assert_eq!(link.device.local_get(prop::PHY_TX_POWER), [22]);

    link.advance(LATENCY_MS);
    pump(&mut model, &mut link);
    assert_eq!(model.pending(prop::PHY_TX_POWER), None);
    assert_eq!(model.tx_power_dbm(), Some(22));
    assert_eq!(
        events(&mut model),
        [
            Event::Changed(prop::PHY_TX_POWER),
            Event::Written {
                id,
                key: prop::PHY_TX_POWER,
                outcome: WriteOutcome::Adjusted
            }
        ]
    );
}

#[test]
fn requests_made_while_one_is_out_wait_their_turn() {
    let (mut model, mut link) = mesh::<PAYLOAD>();
    let name = model.set_device_name("Saddle").unwrap();
    let forwarding = model.set_forwarding(true).unwrap();
    model.read(prop::PHY_DUTY_NOW);
    pump(&mut model, &mut link);
    assert_eq!(model.in_flight(), 1);

    settle(&mut model, &mut link);
    assert_eq!(
        link.commands,
        [Cmd::PropSet, Cmd::PropSet, Cmd::PropGet],
        "in the order made, one exchange at a time"
    );
    let written: Vec<(u32, WriteOutcome)> = events(&mut model)
        .into_iter()
        .filter_map(|event| match event {
            Event::Written { id, key, outcome } if id == name || id == forwarding => {
                Some((key, outcome))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        written,
        [
            (prop::DEV_NAME, WriteOutcome::Applied),
            (prop::MAC_REPEATER_ENABLED, WriteOutcome::Applied),
        ]
    );
    assert_eq!(link.device.local_get(prop::DEV_NAME), b"Saddle");
    assert_eq!(model.forwarding(), Some(true));
}

#[test]
fn a_lost_answer_is_recovered_without_writing_twice() {
    let (mut model, mut link) = mesh::<PAYLOAD>();
    let peer = [0x42; 32];
    link.lose_responses = 1;
    let id = model.save_peer(&peer).unwrap();
    pump(&mut model, &mut link);
    let executed = link.device.executed;

    // The answer never comes. The engine waits out its deadline and asks
    // again under the same token; the device answers from what it kept.
    link.advance(RESPONSE_WAIT_MIN_MS);
    pump(&mut model, &mut link);
    assert_eq!(link.sent, 2);
    assert!(model.busy());
    link.advance(LATENCY_MS);
    pump(&mut model, &mut link);

    assert_eq!(link.device.executed, executed, "answered, not run again");
    assert_eq!(model.peers().collect::<Vec<_>>(), [&peer]);
    assert!(events(&mut model).contains(&Event::Written {
        id,
        key: prop::DEV_PEERS,
        outcome: WriteOutcome::Applied
    }));
}

#[test]
fn a_device_out_of_reach_leaves_the_write_unknown() {
    let (mut model, mut link) = mesh::<PAYLOAD>();
    link.unreachable = true;
    let id = model.set_device_name("Saddle").unwrap();
    settle(&mut model, &mut link);

    assert_eq!(
        events(&mut model),
        [Event::Written {
            id,
            key: prop::DEV_NAME,
            outcome: WriteOutcome::Unknown
        }]
    );
    // Whether it took is unknown, so what the cache shows is stale, and
    // nothing is asked of a device that cannot be reached.
    assert_eq!(model.freshness(prop::DEV_NAME), Freshness::Stale);
    assert_eq!(model.device_name(), Some("Ridgeline"));
    assert_eq!(model.pending(prop::DEV_NAME), None);
    assert!(!model.busy());
    assert_eq!(link.sent, 1);

    // Back in reach, a read settles it.
    link.unreachable = false;
    model.read(prop::DEV_NAME);
    settle(&mut model, &mut link);
    assert_eq!(model.device_name(), Some("Ridgeline"));
    assert!(matches!(
        model.freshness(prop::DEV_NAME),
        Freshness::Fresh { .. }
    ));
}

#[test]
fn a_save_across_the_mesh_reads_back_what_it_saved() {
    let (mut model, mut link) = mesh::<PAYLOAD>();
    assert_eq!(model.saved(), Some(saved::NONE));
    let id = model.save().unwrap();
    settle(&mut model, &mut link);
    assert_eq!(link.commands, [Cmd::Save, Cmd::PropGet]);
    assert_eq!(model.saved(), Some(saved::CURRENT));
    assert!(events(&mut model).contains(&Event::Saved { id, result: Ok(()) }));
}
