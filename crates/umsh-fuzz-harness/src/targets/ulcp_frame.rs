//! ULCP frames and the payload grammars their commands select.

use umsh_ulcp::frame::{FrameWriter, MultiEntries, MultiGetKeys, parse_session_reset};
use umsh_ulcp::host::PropertyNotification;
use umsh_ulcp::{Frame, FrameDescription, PropPayload, StreamPayload, reply};

fn payloads(data: &[u8], payload: &[u8]) {
    let _ = PropPayload::parse(payload);
    let _ = StreamPayload::parse(payload);
    let _ = parse_session_reset(payload);
    let _ = PropertyNotification::parse(data);
    let _ = MultiGetKeys::new(payload).count();
    let _ = MultiEntries::new(payload).count();
    let _ = reply::status_of(data);
}

pub fn run(data: &[u8]) {
    let _ = FrameDescription(data).to_string();
    let Ok(frame) = Frame::parse(data) else {
        return;
    };
    payloads(data, frame.payload);

    let Some(command) = frame.command() else {
        return;
    };
    let mut out = vec![0u8; data.len() + 8];
    let Ok(mut writer) = FrameWriter::new(&mut out, frame.header.tid(), command) else {
        return;
    };
    writer.write_bytes(frame.payload).expect("sized to fit");
    let len = writer.finish();
    assert_eq!(
        Frame::parse(&out[..len]),
        Ok(frame),
        "changed by a round trip"
    );
}
