//! The MeshCore forwarder: everything it emits is a well-formed packet
//! carrying a payload it received. It relays, and originates nothing.

use umsh_hal::Snr;
use umsh_meshcore_forwarder::packet::{Packet, payload_type};
use umsh_meshcore_forwarder::{Environment, Forwarder, Heard, RegionPolicy, Settings, Verdict};

use crate::script::{Fields, records};

struct Env {
    draw: u32,
}

impl Environment for Env {
    fn airtime_ms(&self, len: usize) -> u32 {
        4 * len as u32
    }

    fn random_u32(&mut self) -> u32 {
        self.draw
    }
}

fn check_forward(forwarder: &mut Forwarder<8>, frame: &[u8]) {
    let sent = forwarder.pop_due(u64::MAX).expect("a scheduled forward");
    let sent = Packet::parse(&sent).expect("forwards are well formed");
    let received = Packet::parse(frame).expect("what was forwarded parsed");
    let relayed = sent.payload() == received.payload()
        // A multipart acknowledgment goes on as the one it carries.
        || (received.payload_type() == payload_type::MULTIPART
            && sent.payload() == &received.payload()[1..]);
    assert!(relayed, "{frame:02x?}");
}

pub fn run(data: &[u8]) {
    let mut fields = Fields::new(data);
    let settings = Settings {
        region_policy: RegionPolicy::Ignore,
        ..Settings::default()
    };
    let key = [fields.u8(); 32];
    let mut forwarder = Forwarder::<8>::new(key, settings);
    let mut env = Env {
        draw: 0x8000_0000 | u32::from(fields.u8()),
    };
    let mut now_ms = 0u64;
    for record in records(fields.rest()) {
        let mut fields = Fields::new(record.body);
        now_ms += u64::from(fields.u16());
        let heard = match record.op % 3 {
            0 => Heard::Air {
                rssi: -i16::from(fields.u8()),
                snr: Snr::from_centibels(i16::from(fields.u8() as i8) * 10),
            },
            1 => Heard::Backhaul,
            _ => Heard::LocalTx,
        };
        let frame = fields.rest();
        if let Verdict::Scheduled { .. } = forwarder.receive(frame, heard, now_ms, &mut env) {
            check_forward(&mut forwarder, frame);
        }
    }
}
