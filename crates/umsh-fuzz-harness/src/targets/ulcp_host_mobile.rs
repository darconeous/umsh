//! The phone's ULCP session and the inspectors behind its screens, against
//! a radio that answers whatever it likes.

use std::sync::Arc;

use umsh_mobile_core::{
    MobileGattReassembler, MobileHdlcDecoder, MobileUlcpSession, UlcpSessionUpdateRecord,
    describe_ulcp_frame, inspect_ulcp_alert, inspect_ulcp_battery, inspect_ulcp_battery_diagnostic,
    inspect_ulcp_device_card, inspect_ulcp_properties, inspect_ulcp_property_frame,
    inspect_ulcp_status, inspect_ulcp_sync, inspect_ulcp_wifi_scan_result, ulcp_property_record,
};
use umsh_ulcp::frame::Header;

use crate::script::{Fields, records};

pub const OP_CONSUME: u8 = 0;
pub const OP_ANSWER: u8 = 1;
pub const OP_CALL: u8 = 2;
pub const OP_TRANSPORT: u8 = 3;
pub const OP_INSPECT: u8 = 4;
pub const OP_RECORDS: u8 = 5;
const OPS: u8 = 6;

const HOST_KEY: [u8; 32] = [0x4C; 32];

/// Hand the session a frame under a transaction it is waiting on. Anything
/// else is a stray, refused before it is read.
fn answer(
    session: &MobileUlcpSession,
    pending: &[u8],
    body: &[u8],
) -> Option<UlcpSessionUpdateRecord> {
    let (&which, frame) = body.split_first()?;
    let tid = *pending.get(usize::from(which) % pending.len().max(1))?;
    let mut frame = frame.to_vec();
    *frame.first_mut()? = Header::new(tid)?.to_byte();
    session.consume(frame).ok()
}

fn call(session: &MobileUlcpSession, which: u8) -> Option<UlcpSessionUpdateRecord> {
    match which % 8 {
        0 => session.begin(Some(HOST_KEY.to_vec())).ok(),
        1 => session.claim(HOST_KEY.to_vec()).ok(),
        2 => session.release().ok(),
        3 => session.refresh().ok(),
        4 => session.begin_save().ok(),
        5 => session.drain_queue().ok(),
        6 => session.set_host_auto_ack(true).ok(),
        _ => Some(session.reset()),
    }
}

fn inspect(kind: u8, key: u32, value: &[u8]) {
    let value = value.to_vec();
    match kind % 7 {
        0 => drop(inspect_ulcp_status(value)),
        1 => drop(inspect_ulcp_property_frame(value)),
        2 => drop(inspect_ulcp_battery(value)),
        3 => drop(inspect_ulcp_alert(value)),
        4 => drop(inspect_ulcp_wifi_scan_result(value)),
        5 => drop(inspect_ulcp_battery_diagnostic(key, value)),
        _ => drop(describe_ulcp_frame(value)),
    }
}

/// Each screen's reading of a set of properties.
fn inspect_records(body: &[u8]) {
    let mut records = Vec::new();
    let mut rest = body;
    while let [key_hi, key_lo, len, tail @ ..] = rest {
        let len = usize::from(*len).min(tail.len());
        let key = u32::from(u16::from_be_bytes([*key_hi, *key_lo]));
        records.push(ulcp_property_record(key, tail[..len].to_vec()));
        rest = &tail[len..];
    }
    let _ = inspect_ulcp_sync(records.clone());
    let _ = inspect_ulcp_device_card(records.clone());
    let _ = inspect_ulcp_properties(records);
}

pub fn run(data: &[u8]) {
    let session: Arc<MobileUlcpSession> = MobileUlcpSession::new();
    let hdlc = MobileHdlcDecoder::new();
    let gatt = MobileGattReassembler::new();
    let mut pending = session
        .begin(None)
        .map(|update| update.pending_control_transactions)
        .unwrap_or_default();
    for record in records(data) {
        let mut fields = Fields::new(record.body);
        let update = match record.op % OPS {
            OP_CONSUME => session.consume(record.body.to_vec()).ok(),
            OP_ANSWER => answer(&session, &pending, record.body),
            OP_CALL => call(&session, fields.u8()),
            OP_TRANSPORT => {
                for frame in hdlc.push(record.body.to_vec()) {
                    let _ = session.consume(frame);
                }
                if let Ok(Some(frame)) = gatt.push(record.body.to_vec()) {
                    let _ = session.consume(frame);
                }
                None
            }
            OP_INSPECT => {
                let kind = fields.u8();
                let key = fields.u32();
                inspect(kind, key, fields.rest());
                None
            }
            _ => {
                inspect_records(record.body);
                None
            }
        };
        if let Some(update) = update {
            pending = update.pending_control_transactions;
        }
    }
}
