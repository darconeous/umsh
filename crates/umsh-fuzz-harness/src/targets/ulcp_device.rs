//! The production device session over its whole surface: host, radio,
//! device interface, and administrators, on a platform whose storage can
//! fail, in any order.
//!
//! Bytes from the host pass a decoder the size of firmware's, so the session
//! sees only what a board would hand it.

use umsh_ulcp::frame::{self, Cmd, FRAME_IN_MAX, FRAME_OUT_MAX, Frame};
use umsh_ulcp::ids::prop;
use umsh_ulcp::items::PeerKeyEntry;
use umsh_ulcp::{Status, hdlc};
use umsh_ulcp_device::{MULTI_MAX, TxOutcome};
use umsh_ulcp_simdev::RadioRxInfo;
use umsh_ulcp_simdev::soft::SoftDevice;

use crate::device::{self, FaultyPlatform, StorageFault};
use crate::fixup::{self, cast};
use crate::script::{Fields, Record, records};

pub const OP_CONFIG: u8 = 0;
pub const OP_BYTES: u8 = 1;
pub const OP_FRAME: u8 = 2;
pub const OP_RADIO: u8 = 3;
pub const OP_ATTACH: u8 = 4;
pub const OP_DETACH: u8 = 5;
pub const OP_TICK: u8 = 6;
pub const OP_TX: u8 = 7;
pub const OP_DEVICE: u8 = 8;
pub const OP_ADMIN: u8 = 9;
pub const OP_FAULT: u8 = 10;
const OPS: u8 = 11;

/// In an `OP_CONFIG` body: come up attached and provisioned, with the keys
/// the fixup seals under. The fuzzer would not find the sequence by itself,
/// and the radio path does nothing until it has run.
pub const CONFIG_PROVISIONED: u8 = 0x01;
/// In an `OP_CONFIG` body: the device has a settings interface of its own.
pub const CONFIG_INTERFACE: u8 = 0x02;

/// What a firmware driver stages for one session call.
const EMITS_PER_CALL: usize = 2;
const PROBE_TID: u8 = 7;
/// Room to see a frame past firmware's limit, rather than fail to decode it.
const WIRE_MAX: usize = 4096;

/// The sequence a host runs before it hands the radio its receive path,
/// under the keys the fixup seals with.
pub fn provisioning() -> Vec<Vec<u8>> {
    let cast = cast();
    let mut frames = Vec::new();
    let mut buf = [0u8; FRAME_IN_MAX];
    let mut push = |len: usize, buf: &[u8]| frames.push(buf[..len].to_vec());

    let len = frame::prop_set(&mut buf, 1, prop::PHY_ENABLED, &[1]).expect("it fits");
    push(len, &buf);
    let len = frame::prop_set(&mut buf, 1, prop::HOST_KEY, &cast.local_key.0).expect("it fits");
    push(len, &buf);
    let channel = cast.channel_key.0;
    let len = frame::prop_insert(&mut buf, 1, prop::HOST_CHANNEL_KEYS, &channel).expect("it fits");
    push(len, &buf);
    for party in &cast.parties {
        let entry = PeerKeyEntry {
            public_key: party.key.0,
            k_enc: party.keys.k_enc,
            k_mic: party.keys.k_mic,
        };
        let mut item = [0u8; PeerKeyEntry::WIRE_LEN];
        entry.encode(&mut item).expect("it fits");
        let len = frame::prop_insert(&mut buf, 1, prop::HOST_PEER_KEYS, &item).expect("it fits");
        push(len, &buf);
    }
    let len = frame::prop_set(&mut buf, 1, prop::HOST_AUTO_ACK, &[1]).expect("it fits");
    push(len, &buf);
    frames
}

struct Harness {
    device: SoftDevice<FaultyPlatform>,
    faults: StorageFault,
    front: hdlc::Decoder<FRAME_IN_MAX>,
    now_ms: u64,
    interface: bool,
    /// Whether nothing has happened that ends an attachment.
    expect_attached: bool,
    /// Whether this step did something that restarts the host's session.
    reset_allowed: bool,
}

impl Harness {
    fn new(config: &[u8]) -> Self {
        let flags = Fields::new(config).u8();
        let (mut device, faults) = device::soft_device();
        device.defer_tx();
        let interface = flags & CONFIG_INTERFACE != 0;
        if interface {
            device.open_device_interface();
        }
        let mut harness = Self {
            device,
            faults,
            front: hdlc::Decoder::new(),
            now_ms: 1,
            interface,
            expect_attached: false,
            reset_allowed: false,
        };
        if flags & CONFIG_PROVISIONED != 0 {
            harness.provision();
        }
        harness
    }

    fn attach(&mut self) {
        self.front.reset();
        self.device.attach();
        self.expect_attached = true;
        self.reset_allowed = true;
        self.audit();
    }

    fn provision(&mut self) {
        self.attach();
        for request in provisioning() {
            self.host_frame(&request);
        }
    }

    fn note(&mut self, frame: &[u8]) {
        match Frame::parse(frame).ok().and_then(|frame| frame.command()) {
            Some(Cmd::Reset | Cmd::Restore) => self.reset_allowed = true,
            Some(Cmd::Reboot | Cmd::FactoryReset) => self.expect_attached = false,
            _ => {}
        }
    }

    /// A frame a host's link delivered whole.
    fn host_frame(&mut self, frame: &[u8]) {
        // Firmware's decoder stops at its limit, and nothing reaches a
        // session with no host.
        if frame.len() > FRAME_IN_MAX || !self.device.session().is_attached() {
            return;
        }
        self.note(frame);
        let parses = Frame::parse(frame).is_ok();
        let version = self.device.session().dev_domain_version();
        let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
        let len = hdlc::encode_frame(frame, &mut wire).expect("worst-case size");
        self.device
            .ingest(&wire[..len], self.now_ms)
            .expect("its own encoding decodes");
        if !parses {
            assert!(
                self.device.take_outbound().is_none(),
                "a frame that does not parse was answered"
            );
            assert_eq!(
                self.device.session().dev_domain_version(),
                version,
                "a frame that does not parse changed the device"
            );
        }
        self.audit();
    }

    fn host_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let frame = match self.front.push(byte) {
                Some(Ok(frame)) => frame.to_vec(),
                _ => continue,
            };
            self.host_frame(&frame);
        }
    }

    fn radio(&mut self, body: &[u8]) {
        let mut fields = Fields::new(body);
        let selector = fields.u8();
        let rssi = -i16::from(fields.u8());
        let snr = i16::from(fields.u8() as i8);
        let flags = fields.u8();
        let frame = fixup::apply(fields.rest(), selector);
        let info = if flags & 1 != 0 {
            RadioRxInfo::self_transmitted()
        } else {
            RadioRxInfo::measured(rssi, snr, None)
        };
        self.device.inject_radio_rx(&frame, &info, self.now_ms);
        self.audit();
    }

    fn device_frame(&mut self, frame: &[u8]) {
        if self.interface {
            self.note(frame);
            self.device.device_request(frame, self.now_ms);
        }
        self.audit();
    }

    fn admin(&mut self, body: &[u8]) {
        let mut fields = Fields::new(body);
        let budget = usize::from(fields.u16()).clamp(16, MULTI_MAX);
        let frame = fields.rest();
        self.note(frame);
        for answer in self.device.admin_request(frame, budget, self.now_ms) {
            assert!(answer.len() <= FRAME_OUT_MAX, "an oversized admin answer");
            assert!(Frame::parse(&answer).is_ok(), "an admin answer is a frame");
        }
        self.audit();
    }

    /// What holds after every step.
    fn audit(&mut self) {
        assert!(
            self.device.emit_high_water() <= EMITS_PER_CALL,
            "one session call emitted more than firmware stages"
        );
        while let Some(wire) = self.device.take_outbound() {
            self.check_outbound(&wire);
        }
        while let Some(frame) = self.device.take_device_frame() {
            assert!(frame.len() <= FRAME_OUT_MAX, "an oversized device frame");
        }
        let _ = self.device.take_transmitted();
        let _ = self.device.take_announcements();
        if self.expect_attached {
            assert!(
                self.device.session().is_attached(),
                "an attachment ended with nothing to end it"
            );
        }
        self.reset_allowed = false;
    }

    fn check_outbound(&mut self, wire: &[u8]) {
        for frame in decoded(wire) {
            assert!(
                frame.len() <= FRAME_OUT_MAX,
                "an oversized frame for firmware"
            );
            if Frame::parse(&frame).is_ok_and(|frame| frame.command() == Some(Cmd::SessionReset)) {
                assert!(
                    self.reset_allowed,
                    "the host's session was reset with no cause"
                );
            }
        }
    }

    fn step(&mut self, record: Record<'_>) {
        match record.op % OPS {
            OP_BYTES => self.host_bytes(record.body),
            OP_FRAME => self.host_frame(record.body),
            OP_RADIO => self.radio(record.body),
            OP_ATTACH => self.attach(),
            OP_DETACH => {
                self.front.reset();
                self.device.detach();
                self.expect_attached = false;
                self.audit();
            }
            OP_TICK => {
                self.now_ms += u64::from(Fields::new(record.body).u16()) * 8;
                self.device.tick(self.now_ms);
                self.audit();
            }
            OP_TX => {
                let outcome = match Fields::new(record.body).u8() % 3 {
                    0 => TxOutcome::Sent,
                    1 => TxOutcome::ChannelBusy,
                    _ => TxOutcome::Failed,
                };
                self.device.complete_tx(outcome, self.now_ms);
                self.audit();
            }
            OP_DEVICE => self.device_frame(record.body),
            OP_ADMIN => self.admin(record.body),
            OP_FAULT => self.faults.set(Fields::new(record.body).u8() & 1 != 0),
            _ => {}
        }
    }

    /// Whatever came before, a host that speaks up is answered, once.
    fn check_answer(&mut self) {
        self.faults.set(false);
        if !self.device.session().is_attached() {
            self.attach();
        }
        self.device
            .ingest(&[hdlc::FLAG], self.now_ms)
            .expect("a lone flag decodes");
        let mut request = [0u8; 8];
        let len = frame::nop(&mut request, PROBE_TID).expect("it fits");
        let mut wire = [0u8; 32];
        let len = hdlc::encode_frame(&request[..len], &mut wire).expect("it fits");
        self.device
            .ingest(&wire[..len], self.now_ms)
            .expect("its own encoding decodes");
        let mut answers = 0;
        while let Some(outbound) = self.device.take_outbound() {
            for frame in decoded(&outbound) {
                let Ok(parsed) = Frame::parse(&frame) else {
                    continue;
                };
                if parsed.header.tid() != PROBE_TID {
                    continue;
                }
                let mut ok = [0u8; 16];
                let len = frame::last_status(&mut ok, PROBE_TID, Status::OK).expect("it fits");
                assert_eq!(frame, &ok[..len], "the probe's answer was not OK");
                answers += 1;
            }
        }
        assert_eq!(answers, 1, "a host's probe was not answered once");
    }
}

fn decoded(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut decoder = hdlc::Decoder::<WIRE_MAX>::new();
    let mut frames = Vec::new();
    for &byte in wire {
        if let Some(frame) = decoder.push(byte) {
            frames.push(frame.expect("the device encodes what it sends").to_vec());
        }
    }
    frames
}

pub fn run(data: &[u8]) {
    let mut steps = records(data).peekable();
    let config = match steps.peek() {
        Some(Record {
            op: OP_CONFIG,
            body,
        }) => {
            let body = *body;
            steps.next();
            body
        }
        _ => &[],
    };
    let mut harness = Harness::new(config);
    for record in steps {
        harness.step(record);
    }
    harness.check_answer();
}
