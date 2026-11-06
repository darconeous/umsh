//! The web debugger's engine, parsing whatever a device sends a browser.

use umsh_ulcp::frame::{Frame, Header, TID_MAX};
use umsh_ulcp::{gatt, hdlc};
use umsh_ulcp_web_engine::{DebuggerEngine, Transport, property_specs};

use crate::script::{Fields, records};

pub const OP_INGEST: u8 = 0;
pub const OP_ANSWER: u8 = 1;
pub const OP_TICK: u8 = 2;
pub const OP_GET: u8 = 3;
pub const OP_SET: u8 = 4;
pub const OP_COMMAND: u8 = 5;
pub const OP_DISCONNECT: u8 = 6;
const OPS: u8 = 7;

const COMMANDS: [&str; 6] = ["reset", "nop", "queue_drain", "save", "clear", "restore"];

fn answer(engine: &mut DebuggerEngine, transport: Transport, tid: u8, frame: &[u8]) {
    let mut frame = frame.to_vec();
    if let (Some(first), Some(header)) = (frame.first_mut(), Header::new(tid)) {
        *first = header.to_byte();
    }
    match transport {
        Transport::SerialHdlc => {
            let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
            if let Ok(len) = hdlc::encode_frame(&frame, &mut wire) {
                engine.ingest(&wire[..len]);
            }
        }
        Transport::BleSar => {
            for segment in gatt::segments(&frame, 20) {
                let mut encoded = vec![0; segment.payload().len() + 1];
                if let Ok(len) = segment.write_to(&mut encoded) {
                    engine.ingest(&encoded[..len]);
                }
            }
        }
    }
}

pub fn run(data: &[u8]) {
    let mut steps = records(data);
    let transport = match steps.clone().next().map(|record| record.op) {
        Some(1) => Transport::BleSar,
        _ => Transport::SerialHdlc,
    };
    let _ = steps.next();
    let specs = property_specs();
    let mut engine = DebuggerEngine::new(transport);
    let _ = engine.attach();
    let mut tid = 1;
    let mut now_ms = 0;
    for record in steps {
        let mut fields = Fields::new(record.body);
        match record.op % OPS {
            OP_INGEST => engine.ingest(record.body),
            OP_ANSWER => answer(&mut engine, transport, tid, record.body),
            OP_TICK => {
                now_ms += u64::from(fields.u16()) * 8;
                engine.tick(now_ms);
            }
            OP_GET => {
                let _ = engine.prop_get(specs[usize::from(fields.u8()) % specs.len()].key);
            }
            OP_SET => {
                let key = specs[usize::from(fields.u8()) % specs.len()].key;
                let _ = engine.prop_set(key, fields.rest());
            }
            OP_COMMAND => {
                let _ = engine.command(COMMANDS[usize::from(fields.u8()) % COMMANDS.len()]);
            }
            _ => engine.disconnected("fuzz"),
        }
        while let Some(outbound) = engine.take_outbound() {
            if let Some(frame) = decoded(transport, &outbound)
                && let Ok(parsed) = Frame::parse(&frame)
                && (1..=TID_MAX).contains(&parsed.header.tid())
            {
                tid = parsed.header.tid();
            }
        }
        while engine.take_event().is_some() {}
    }
}

fn decoded(transport: Transport, wire: &[u8]) -> Option<Vec<u8>> {
    match transport {
        Transport::SerialHdlc => {
            let mut decoder = hdlc::Decoder::<4096>::new();
            wire.iter()
                .find_map(|&byte| decoder.push(byte).and_then(Result::ok).map(<[u8]>::to_vec))
        }
        Transport::BleSar => wire.get(1..).map(<[u8]>::to_vec),
    }
}
