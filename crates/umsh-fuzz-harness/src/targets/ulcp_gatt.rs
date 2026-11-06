//! BLE segmentation and reassembly.

use umsh_ulcp::gatt::{MAX_FRAME, Reassembler, SAR_COMPLETE, segments};

use crate::script::{Fields, records};

pub fn run(data: &[u8]) {
    let mut fields = Fields::new(data);
    let seg_payload = usize::from(fields.u8()).max(1);
    let script = fields.rest();

    let mut reassembler = Reassembler::<MAX_FRAME>::new();
    for record in records(script) {
        if let Some(Ok(frame)) = reassembler.push(record.body) {
            assert!(frame.len() <= MAX_FRAME);
        }
    }

    // A complete segment stands alone, whatever came before it.
    let probe = [SAR_COMPLETE << 6, 0x80, 0x01];
    assert!(matches!(reassembler.push(&probe), Some(Ok(frame)) if frame == &probe[1..]));

    // Whatever is segmented comes back whole.
    let frame = &script[..script.len().min(MAX_FRAME)];
    if !frame.is_empty() {
        let mut fresh = Reassembler::<MAX_FRAME>::new();
        let mut out = None;
        for segment in segments(frame, seg_payload) {
            let mut wire = [0u8; 300];
            let len = segment.write_to(&mut wire).expect("a payload byte at most");
            assert!(out.is_none(), "segments past the end of the frame");
            out = fresh.push(&wire[..len]).map(|r| r.map(<[u8]>::to_vec));
        }
        assert_eq!(out.expect("a final segment").expect("reassembled"), frame);
    }
}
