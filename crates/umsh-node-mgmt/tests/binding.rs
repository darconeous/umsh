//! Two nodes, one binding: an administrator and a device that runs the
//! real ULCP session, talking to each other over a simulated link.
//!
//! The device half here is what the firmware's responder does, in the
//! order it does it — authorization first, then [`DeviceEngine::begin`],
//! then the session, then [`produce`] and [`DeviceEngine::complete`] — so
//! this is the binding's semantics under test rather than a paraphrase of
//! them. The administrator half is the shipping [`Exchange`] engine.
//!
//! Nothing here is timed by the wall clock and nothing is random: the
//! virtual clock only advances where a test says so, and both engines take
//! their nonces as parameters.

use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_node_mgmt::admin::{Exchange, Outcome, RETRY_MS, Reassembly, Step};
use umsh_node_mgmt::device::{DeviceEngine, Ingress};
use umsh_node_mgmt::fragment::{continuable, produce};
use umsh_ulcp::frame::{Cmd, Frame, MultiEntries};
use umsh_ulcp::ids::prop;
use umsh_ulcp::status::Status;
use umsh_ulcp::{frame, pui};
use umsh_ulcp_device::{
    AlertConfig, BatteryFields, DutyLedger, Effect, GnssConfig, MULTI_MAX, RadioSettings, Session,
    SessionConfig, TimeConfig,
};

/// What one Node Management payload carries on this simulated link,
/// matching the nRF responder's derived ceiling.
const PAYLOAD: usize = 180;

/// A device whose radio carries less — a narrower bandwidth, a longer
/// preamble, anything that shrinks the MAC's payload. Used where a test
/// needs a budget small enough to run out of on purpose.
const SMALL_PAYLOAD: usize = 96;

const ADMIN_KEY: [u8; 32] = [0xA1; 32];
const STRANGER_KEY: [u8; 32] = [0x5F; 32];

// ─── The device ──────────────────────────────────────────────────────────

/// A device as the mesh sees it: an authorization list, the binding's
/// device engine, and a real session behind them.
struct Device<const PAYLOAD: usize> {
    session: Session<SoftwareAes, SoftwareSha256>,
    engine: DeviceEngine<PAYLOAD, 2>,
    /// The mirrored `PROP_DEV_ADMINS`, as the firmware's receive path
    /// mirrors it: authorization happens before the session is reached.
    admins: Vec<[u8; 32]>,
    /// How many requests were actually executed, as opposed to answered
    /// from the retained response. The at-most-once property is measured
    /// here.
    executed: u32,
    /// Requests refused before the engine saw them.
    unauthorized: u32,
}

impl<const PAYLOAD: usize> Device<PAYLOAD> {
    fn new() -> Self {
        let config = SessionConfig {
            dev_version: "sim-dev/0.1",
            dev_model: Some("Simulated Board"),
            default_device_name: "Simulated Device",
            mtu: 255,
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
            battery: Some(BatteryFields {
                voltage: true,
                level: false,
                charge_state: true,
            }),
            alert: Some(AlertConfig::DEFAULT),
            time: Some(TimeConfig),
            gnss: Some(GnssConfig::DEFAULT),
            illuminance: true,
            ble: true,
            mac_node: true,
        };
        let mut session = Session::new(
            config,
            Status::RESET_POWER_ON,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        // No host is attached: an administrator does not need one, which
        // is the point of the binding.
        session.attach(false);
        Self {
            session,
            engine: DeviceEngine::new(0x5AA5),
            admins: Vec::new(),
            executed: 0,
            unauthorized: 0,
        }
    }

    /// Provision an administrator the way a bench-attached host does, and
    /// mirror the resulting list the way the device-domain sync does.
    fn provision_admin(&mut self, key: &[u8; 32]) {
        let mut buf = [0u8; 64];
        let len = frame::prop_insert(&mut buf, 5, prop::DEV_ADMINS, key).unwrap();
        let mut emitted = Vec::new();
        // Provisioning key material needs a secure local link.
        self.session.attach(true);
        self.session
            .handle_frame(&buf[..len], 0, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        self.session.attach(false);
        assert_eq!(
            Frame::parse(&emitted[0]).unwrap().command(),
            Some(Cmd::PropInserted),
            "the administrator was not accepted"
        );

        let len = frame::prop_get(&mut buf, 5, prop::DEV_ADMINS).unwrap();
        let mut emitted = Vec::new();
        self.session
            .handle_frame(&buf[..len], 0, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        let listed = value_of(&emitted[0]);
        self.admins = listed
            .chunks_exact(32)
            .map(|k| k.try_into().unwrap())
            .collect();
    }

    /// Persist the device domain over the local link, the way
    /// commissioning ends.
    fn save(&mut self) {
        let mut buf = [0u8; 16];
        let len = frame::save(&mut buf, 5).unwrap();
        let effect = self
            .session
            .handle_frame(&buf[..len], 0, &mut |_bytes: &[u8]| {});
        let Some(Effect::SaveSnapshot { tid }) = effect else {
            panic!("expected a snapshot to save");
        };
        self.session
            .respond_save(tid, Ok(()), &mut |_bytes: &[u8]| {});
    }

    /// Add a peer over the local link, to give the device state worth
    /// reading remotely.
    fn provision_peer(&mut self, key: &[u8; 32]) {
        let mut buf = [0u8; 64];
        let len = frame::prop_insert(&mut buf, 5, prop::DEV_PEERS, key).unwrap();
        self.session.attach(true);
        self.session
            .handle_frame(&buf[..len], 0, &mut |_bytes: &[u8]| {});
        self.session.attach(false);
    }

    /// Deliver one Node Management Request payload and return the
    /// response payload, or `None` where the device says nothing at all.
    fn deliver(&mut self, from: &[u8; 32], payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        // Authorization, exactly as the receive path applies it: an
        // unlisted sender is dropped with accounting and no response.
        if !self.admins.iter().any(|listed| listed == from) {
            self.unauthorized += 1;
            return None;
        }
        let generation = self.session.dev_domain_version() as u16;
        let mut out = [0u8; PAYLOAD];
        let mut cut = [0u8; PAYLOAD];
        let len = match self
            .engine
            .begin(from, payload, generation, now_ms, &mut out)
        {
            Ingress::Drop(_) => return None,
            Ingress::Respond { len } => Some(len),
            Ingress::Dispatch(dispatch) => {
                self.executed += 1;
                let reply = self.serve(&dispatch, now_ms);
                let produced = produce(&reply, &dispatch, &mut cut);
                self.engine.complete(produced, &mut out).expect("complete")
            }
        };
        len.map(|len| out[..len].to_vec())
    }

    /// Run one frame through the session, serving the deferred platform
    /// round trips the way the driver's event loop does.
    fn serve(&mut self, dispatch: &umsh_node_mgmt::device::Dispatch<'_>, now_ms: u64) -> Vec<u8> {
        let reply_budget = match dispatch.command() {
            Some(cmd) if continuable(cmd) => MULTI_MAX,
            _ => dispatch.budget,
        };
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut pending = self.session.handle_admin_frame(
            dispatch.frame,
            now_ms,
            reply_budget,
            &mut |bytes: &[u8]| emitted.push(bytes.to_vec()),
        );
        while let Some(effect) = pending.take() {
            match effect {
                Effect::SampleBattery { tid } => self.session.respond_battery(
                    tid,
                    Ok(umsh_ulcp::BatteryStatus::default()),
                    &mut |bytes: &[u8]| emitted.push(bytes.to_vec()),
                ),
                Effect::ReadTime { tid } => {
                    self.session
                        .respond_time(tid, Some(1_700_000_000), &mut |bytes: &[u8]| {
                            emitted.push(bytes.to_vec())
                        })
                }
                Effect::SampleIlluminance { tid } => {
                    self.session
                        .respond_illuminance(tid, Some(1234), &mut |bytes: &[u8]| {
                            emitted.push(bytes.to_vec())
                        })
                }
                Effect::SampleRssi { tid } => {
                    self.session
                        .respond_rssi(tid, Err(()), &mut |bytes: &[u8]| {
                            emitted.push(bytes.to_vec())
                        })
                }
                Effect::SaveSnapshot { tid } => {
                    self.session.respond_save(tid, Ok(()), &mut |bytes: &[u8]| {
                        emitted.push(bytes.to_vec())
                    })
                }
                // Radio and platform effects with no reply of their own.
                _ => {}
            }
            pending = self
                .session
                .resume_multi(now_ms, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        }
        self.session.end_admin_exchange();
        assert!(
            emitted.len() <= 1,
            "an administrative exchange answers with at most one frame"
        );
        emitted.pop().unwrap_or_default()
    }

    /// Read a property over the local binding, for checking what a
    /// remote write actually did.
    fn local_get(&mut self, key: u32) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 6, key).unwrap();
        let mut emitted = Vec::new();
        self.session
            .handle_frame(&buf[..len], 0, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
        value_of(&emitted[0])
    }
}

// ─── The administrator ───────────────────────────────────────────────────

/// How a conversation ended, and everything the administrator learned.
struct Conversation {
    outcome: Outcome,
    reply: Vec<u8>,
    /// Payloads the administrator sent, including retransmissions.
    requests: u32,
}

/// Run one exchange to completion against `device`, dropping the
/// responses whose ordinal appears in `drop_responses`.
fn converse_lossy<const PAYLOAD: usize>(
    device: &mut Device<PAYLOAD>,
    key: &[u8; 32],
    request: &[u8],
    seed: u16,
    drop_responses: &[u32],
) -> Conversation {
    let mut exchange = Exchange::<192>::new(request, seed, 0).expect("begin");
    let mut storage = [0u8; 4096];
    let mut reassembly = Reassembly::new(&mut storage);
    let mut wire = [0u8; PAYLOAD];
    let mut now = 0u64;
    let mut requests = 0;
    let mut responses = 0;

    let mut step = exchange.poll(now, &mut wire);
    loop {
        match step {
            Step::Send { len } => {
                requests += 1;
                let response = device.deliver(key, &wire[..len].to_vec(), now);
                let Some(response) = response else {
                    if !exchange.expects_response() {
                        // A reset: the MAC acknowledgment is what
                        // completes it.
                        step = exchange.delivered();
                        continue;
                    }
                    // Nothing came back. Wait out the retry deadline.
                    now += RETRY_MS;
                    step = exchange.poll(now, &mut wire);
                    continue;
                };
                responses += 1;
                if drop_responses.contains(&responses) {
                    now += RETRY_MS;
                    step = exchange.poll(now, &mut wire);
                    continue;
                }
                step = match exchange.receive(&response, &mut reassembly, now, &mut wire) {
                    Some(step) => step,
                    None => panic!("the device answered someone else's token"),
                };
            }
            Step::Wait { deadline_ms } => {
                now = deadline_ms;
                step = exchange.poll(now, &mut wire);
            }
            Step::Done(outcome) => {
                return Conversation {
                    outcome,
                    reply: reassembly.frame().to_vec(),
                    requests,
                };
            }
        }
    }
}

fn converse<const PAYLOAD: usize>(
    device: &mut Device<PAYLOAD>,
    request: &[u8],
    seed: u16,
) -> Conversation {
    converse_lossy(device, &ADMIN_KEY, request, seed, &[])
}

// ─── Frame readers ───────────────────────────────────────────────────────

/// The value of a `CMD_PROP_IS`.
fn value_of(frame: &[u8]) -> Vec<u8> {
    let parsed = Frame::parse(frame).unwrap();
    assert_eq!(parsed.command(), Some(Cmd::PropIs));
    let (_, consumed) = pui::decode(parsed.payload).unwrap();
    parsed.payload[consumed..].to_vec()
}

fn status_of(frame: &[u8]) -> Status {
    let parsed = Frame::parse(frame).unwrap();
    let (key, consumed) = pui::decode(parsed.payload).unwrap();
    assert_eq!(key, prop::LAST_STATUS);
    Status(pui::decode(&parsed.payload[consumed..]).unwrap().0)
}

fn entries_of(frame: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let parsed = Frame::parse(frame).unwrap();
    assert_eq!(parsed.command(), Some(Cmd::PropAre));
    MultiEntries::new(parsed.payload)
        .map(|entry| entry.unwrap())
        .map(|entry| (entry.key, entry.value.to_vec()))
        .collect()
}

/// A commissioned device: an administrator provisioned over the bench
/// link, and the device domain saved — which is what makes the
/// administrator survive the resets the administrator itself can order.
fn managed() -> Device<PAYLOAD> {
    let mut device = Device::new();
    device.provision_admin(&ADMIN_KEY);
    device.save();
    device
}

// ─── The tests ───────────────────────────────────────────────────────────

#[test]
fn an_administrator_reads_and_writes_the_device_domain() {
    let mut device = managed();
    let mut buf = [0u8; 64];

    let len = frame::prop_get(&mut buf, 0, prop::DEV_MODEL).unwrap();
    let read = converse(&mut device, &buf[..len], 1);
    assert!(matches!(read.outcome, Outcome::Replied { .. }));
    assert_eq!(value_of(&read.reply), b"Simulated Board\0");

    // Uptime is ungated and not on the admin deny-list, so a distant
    // administrator can ask a repeater how long it has been up. The
    // harness owns the clock, so this asserts reachability and width
    // rather than a particular reading.
    let len = frame::prop_get(&mut buf, 0, prop::UPTIME).unwrap();
    let uptime = converse(&mut device, &buf[..len], 3);
    assert!(matches!(uptime.outcome, Outcome::Replied { .. }));
    assert_eq!(value_of(&uptime.reply).len(), 4);

    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Ridgeline Repeater").unwrap();
    let write = converse(&mut device, &buf[..len], 2);
    assert!(matches!(write.outcome, Outcome::Replied { .. }));
    assert_eq!(value_of(&write.reply), b"Ridgeline Repeater");
    assert_eq!(device.local_get(prop::DEV_NAME), b"Ridgeline Repeater");
}

/// Placing a node is the case this whole surface exists for: an
/// administrator several hops away writes where a repeater is, and the
/// device advertises it. Refused while the device is maintaining the
/// position from its own fixes, so a write cannot be silently reverted by
/// the next one.
#[test]
fn an_administrator_places_a_node_that_cannot_place_itself() {
    let mut device = managed();
    let mut buf = [0u8; 64];

    let cell = [0x12, 0x34, 0x56, 0x78, 0x9A];
    let len = frame::prop_set(&mut buf, 0, prop::IDENT_LOCATION, &cell).unwrap();
    let placed = converse(&mut device, &buf[..len], 1);
    assert!(matches!(placed.outcome, Outcome::Replied { .. }));
    assert_eq!(value_of(&placed.reply), cell);
    assert_eq!(device.local_get(prop::IDENT_LOCATION), cell);

    // A padded altitude is understood and reported back minimally, which
    // is the encoding that goes back over the air.
    let len = frame::prop_set(&mut buf, 0, prop::IDENT_ALTITUDE, &[0xC8, 0, 0, 0]).unwrap();
    let altitude = converse(&mut device, &buf[..len], 2);
    assert_eq!(value_of(&altitude.reply), [0xC8, 0x00]);

    // Handing the position to the receiver takes it away from the
    // administrator, who is told so rather than ignored.
    let len = frame::prop_set(&mut buf, 0, prop::GNSS_IDENT_UPDATE, &[1]).unwrap();
    converse(&mut device, &buf[..len], 3);
    let len = frame::prop_set(&mut buf, 0, prop::IDENT_LOCATION, &cell).unwrap();
    let refused = converse(&mut device, &buf[..len], 4);
    assert_eq!(status_of(&refused.reply), Status::INVALID_STATE);
}

/// What one management screen costs: the properties it shows, asked for
/// together and answered in one exchange.
///
/// The design the phone's category screens are built on — a device several
/// flood hops away answers slowly and at everyone's expense, so a screen
/// asks for its own handful rather than the device whole. A property the
/// device does not implement comes back as a refusal in its own position
/// rather than costing the rest of the answer.
#[test]
fn one_screens_worth_of_properties_is_one_exchange() {
    let mut device = managed();
    let mut buf = [0u8; 128];
    let identity = [
        prop::DEV_NAME,
        prop::IDENT_ROLE,
        prop::IDENT_MOBILE,
        prop::IDENT_LOCATION,
        prop::IDENT_ALTITUDE,
        prop::GNSS_IDENT_UPDATE,
    ];
    let len = frame::prop_multi_get(&mut buf, 0, &identity).unwrap();

    let read = converse(&mut device, &buf[..len], 1);
    assert!(matches!(read.outcome, Outcome::Replied { .. }));
    let entries = entries_of(&read.reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        identity,
        "every property answered, in the order it was asked for"
    );
    assert!(
        entries
            .iter()
            .find(|(key, _)| *key == prop::IDENT_LOCATION)
            .is_some_and(|(_, value)| value.is_empty()),
        "a device advertising no position says so with an empty value"
    );
}

/// The radio screen, which asks for the most of any of them.
#[test]
fn a_radio_screen_is_one_exchange_too() {
    let mut device = managed();
    let mut buf = [0u8; 128];
    let radio = [
        prop::PHY_ENABLED,
        prop::PHY_FREQ,
        prop::PHY_TX_POWER,
        prop::PHY_LORA_BW,
        prop::PHY_LORA_SF,
        prop::PHY_LORA_CR,
        prop::PHY_DUTY_NOW,
        prop::PHY_DUTY_LIMIT,
    ];
    let len = frame::prop_multi_get(&mut buf, 0, &radio).unwrap();

    let read = converse(&mut device, &buf[..len], 1);
    assert!(matches!(read.outcome, Outcome::Replied { .. }));
    assert_eq!(
        entries_of(&read.reply)
            .iter()
            .map(|(key, _)| *key)
            .collect::<Vec<_>>(),
        radio,
        "all eight in one answer — the screen costs one round trip, not eight"
    );
}

#[test]
fn an_administrator_inserts_and_removes_table_entries() {
    let mut device = managed();
    let mut buf = [0u8; 64];
    let peer = [0x33u8; 32];

    let len = frame::prop_insert(&mut buf, 0, prop::DEV_PEERS, &peer).unwrap();
    let inserted = converse(&mut device, &buf[..len], 1);
    assert!(matches!(inserted.outcome, Outcome::Replied { .. }));
    assert_eq!(
        Frame::parse(&inserted.reply).unwrap().command(),
        Some(Cmd::PropInserted)
    );
    assert_eq!(device.local_get(prop::DEV_PEERS), peer.to_vec());

    let len = frame::prop_remove(&mut buf, 0, prop::DEV_PEERS, &peer).unwrap();
    let removed = converse(&mut device, &buf[..len], 2);
    assert_eq!(
        Frame::parse(&removed.reply).unwrap().command(),
        Some(Cmd::PropRemoved)
    );
    assert!(device.local_get(prop::DEV_PEERS).is_empty());
}

/// An unlisted node learns nothing — not even that the device declined to
/// answer. From its side the exchange is indistinguishable from a device
/// that is not there.
#[test]
fn an_unlisted_node_is_answered_by_silence() {
    let mut device = managed();
    let mut buf = [0u8; 16];
    let len = frame::prop_get(&mut buf, 0, prop::DEV_MODEL).unwrap();

    let refused = converse_lossy(&mut device, &STRANGER_KEY, &buf[..len], 1, &[]);
    assert_eq!(
        refused.outcome,
        Outcome::Failed(umsh_node_mgmt::admin::Failure::TimedOut)
    );
    assert_eq!(device.unauthorized, refused.requests);
    assert_eq!(device.executed, 0, "nothing was executed for a stranger");
}

/// The at-most-once property. A retransmission under the same token is
/// answered from the retained response, byte for byte, without the
/// request running a second time.
#[test]
fn a_retransmission_is_answered_without_executing_again() {
    let mut device = managed();
    let mut buf = [0u8; 64];
    // A write, so a second execution would be observable even if the two
    // responses happened to match.
    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Saddle Peak").unwrap();

    let mut exchange = Exchange::<192>::new(&buf[..len], 3, 0).expect("begin");
    let mut wire = [0u8; PAYLOAD];
    let Step::Send { len } = exchange.poll(0, &mut wire) else {
        panic!("expected a request");
    };
    let request = wire[..len].to_vec();

    let first = device.deliver(&ADMIN_KEY, &request, 0).expect("a response");
    assert_eq!(device.executed, 1);

    // The identical payload again: the same token, the same everything.
    let again = device
        .deliver(&ADMIN_KEY, &request, RETRY_MS)
        .expect("a response");
    assert_eq!(again, first, "the retained response is repeated verbatim");
    assert_eq!(device.executed, 1, "the request did not run twice");
}

/// The other face of at-most-once, and why a token may never be issued
/// twice: a *different* request arriving under an already-answered token
/// is indistinguishable from a retransmission. The device replays the
/// retained answer, the new request never runs, and the administrator
/// walks away holding the old exchange's values as if they answered the
/// new one.
#[test]
fn a_reused_token_replays_the_past_and_runs_nothing() {
    let mut device = managed();
    let mut buf = [0u8; 64];

    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    let read = converse(&mut device, &buf[..len], 7);
    assert_eq!(value_of(&read.reply), b"Simulated Device");
    assert_eq!(device.executed, 1);

    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Windy Gap").unwrap();
    let collided = converse(&mut device, &buf[..len], 7);
    assert!(matches!(collided.outcome, Outcome::Replied { .. }));
    assert_eq!(device.executed, 1, "the write never ran");
    assert_eq!(
        value_of(&collided.reply),
        b"Simulated Device",
        "and what came back was the old read's answer"
    );
    assert_eq!(device.local_get(prop::DEV_NAME), b"Simulated Device");
}

/// A lost response costs a round trip and nothing else: the retry finds
/// the retained answer waiting.
#[test]
fn a_lost_response_is_recovered_by_the_retry() {
    let mut device = managed();
    let mut buf = [0u8; 64];
    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Cold Spring").unwrap();

    let recovered = converse_lossy(&mut device, &ADMIN_KEY, &buf[..len], 4, &[1]);
    assert!(matches!(recovered.outcome, Outcome::Replied { .. }));
    assert_eq!(value_of(&recovered.reply), b"Cold Spring");
    assert_eq!(recovered.requests, 2, "one retransmission");
    assert_eq!(device.executed, 1, "the write happened once");
}

#[test]
fn a_multi_read_round_trips_in_one_payload() {
    let mut device = managed();
    let mut buf = [0u8; 64];
    let keys = [prop::PROTOCOL_VERSION, prop::DEV_MODEL, prop::DEV_NAME];
    let len = frame::prop_multi_get(&mut buf, 0, &keys).unwrap();

    let read = converse(&mut device, &buf[..len], 1);
    assert!(matches!(read.outcome, Outcome::Replied { .. }));
    let entries = entries_of(&read.reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys
    );
    assert_eq!(entries[1].1, b"Simulated Board\0");
}

/// A read whose answer does not fit one payload is carried across
/// several, and the administrator reassembles a frame identical to the
/// one a single payload would have carried.
#[test]
fn a_large_multi_read_is_continued_across_fragments() {
    let mut device = managed();
    // A peer table is what makes a device's state outgrow a payload, so
    // that is what this reads.
    for index in 0..4u8 {
        device.provision_peer(&[0xD0 | index; 32]);
    }
    let keys = [
        prop::PROTOCOL_VERSION,
        prop::DEV_VERSION,
        prop::DEV_MODEL,
        prop::DEV_NAME,
        prop::CAPS,
        prop::DEV_KEY,
        prop::DEV_ADMINS,
        prop::PHY_FREQ,
        prop::PHY_LORA_BW,
        prop::PHY_LORA_SF,
        prop::PHY_LORA_CR,
        prop::PHY_TX_POWER,
        prop::PHY_MTU,
        prop::PHY_ENABLED,
        prop::DEV_PEERS,
    ];
    let mut buf = [0u8; 128];
    let len = frame::prop_multi_get(&mut buf, 0, &keys).unwrap();

    let read = converse(&mut device, &buf[..len], 1);
    assert!(matches!(read.outcome, Outcome::Replied { .. }));
    assert!(
        read.reply.len() > PAYLOAD,
        "this read is meant to need more than one payload, got {}",
        read.reply.len()
    );
    assert!(
        read.requests > 1,
        "a continued read takes more than one exchange"
    );

    // Every slot is present, in order, and the reassembled frame is a
    // well-formed ARE.
    let entries = entries_of(&read.reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys
    );
}

/// The budget rule: a write sequence whose reply would overflow the
/// payload stops before executing the entry that would not fit, and the
/// administrator reissues the remainder as a new exchange.
#[test]
fn a_write_sequence_stops_for_space_and_the_remainder_is_reissued() {
    // A write sequence's reply reports each property's resulting value,
    // which for a table is close in size to what was written — so the
    // request and the reply are nearly the same size, and the overflow
    // window on a full-size payload is narrow. A device with a smaller
    // payload shows the rule plainly, and the rule is the same either way.
    let mut device: Device<SMALL_PAYLOAD> = Device::new();
    device.provision_admin(&ADMIN_KEY);

    // Two peers as a whole-table write, then a name, then a radio
    // setting: the table alone very nearly fills the reply.
    let mut peers = [0x71u8; 64];
    peers[32..].fill(0x72);
    let entries: Vec<(u32, &[u8])> = vec![
        (prop::DEV_PEERS, peers.as_slice()),
        (prop::DEV_NAME, b"Cold Spring"),
        (prop::PHY_LORA_SF, &[9]),
    ];
    let mut buf = [0u8; 300];
    let len = frame::prop_multi_set(&mut buf, 0, &entries).unwrap();

    let write = converse(&mut device, &buf[..len], 1);
    assert!(matches!(write.outcome, Outcome::Replied { .. }));
    let answered = entries_of(&write.reply);
    assert!(
        answered.len() < entries.len(),
        "this write is meant to overflow the payload"
    );
    assert!(
        write.reply.len() <= SMALL_PAYLOAD,
        "a write sequence is never continued, so it must fit"
    );
    // What it did execute stands...
    assert_eq!(device.local_get(prop::DEV_PEERS), peers.to_vec());
    // ...and what it stopped before did not happen at all: the radio
    // still has its post-reset spreading factor.
    assert_eq!(device.local_get(prop::PHY_LORA_SF), vec![7]);

    // The administrator reissues what was left over, which now fits.
    let remainder = &entries[answered.len()..];
    let len = frame::prop_multi_set(&mut buf, 0, remainder).unwrap();
    let rest = converse(&mut device, &buf[..len], 2);
    assert!(matches!(rest.outcome, Outcome::Replied { .. }));
    assert_eq!(entries_of(&rest.reply).len(), remainder.len());
    assert_eq!(device.local_get(prop::DEV_NAME), b"Cold Spring");
    assert_eq!(device.local_get(prop::PHY_LORA_SF), vec![9]);
}

/// A reset is answered by no response payload at all; the administrator
/// completes on the MAC acknowledgment. It also takes the retained
/// responses with it, so a request repeated across it runs again.
#[test]
fn a_reset_is_answered_by_nothing() {
    let mut device = managed();
    let mut buf = [0u8; 64];
    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Before").unwrap();
    let write = converse(&mut device, &buf[..len], 1);
    assert!(matches!(write.outcome, Outcome::Replied { .. }));

    let len = frame::reset(&mut buf, 0).unwrap();
    let reset = converse(&mut device, &buf[..len], 2);
    assert_eq!(reset.outcome, Outcome::NoResponse);
    assert_eq!(reset.requests, 1, "a reset is not retransmitted");
    // The reset dropped the unsaved name and came back up on the saved
    // snapshot, which is the observable proof it ran...
    assert_eq!(device.local_get(prop::DEV_NAME), b"Simulated Device");
    // ...and the same snapshot is what carries the administrator across
    // it. A device managed before it was saved would not answer its
    // administrator again.
    assert_eq!(device.local_get(prop::DEV_ADMINS), ADMIN_KEY.to_vec());
}

/// What the binding does not reach, checked from the far end of the link
/// rather than at the session's door.
#[test]
fn the_host_domain_is_out_of_reach_over_the_mesh() {
    let mut device = managed();
    let mut buf = [0u8; 64];

    let len = frame::prop_get(&mut buf, 0, prop::HOST_KEY).unwrap();
    let refused = converse(&mut device, &buf[..len], 1);
    assert_eq!(status_of(&refused.reply), Status::PROP_NOT_FOUND);

    let len = frame::queue_drain(&mut buf, 0).unwrap();
    let refused = converse(&mut device, &buf[..len], 2);
    assert_eq!(status_of(&refused.reply), Status::INVALID_COMMAND);
}
