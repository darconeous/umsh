//! HDLC-Lite: any byte stream, and resynchronization after it.

use umsh_ulcp::hdlc::{Decoder, FILL, TEXT_MARKER, encode_frame, max_encoded_len};

/// What firmware decodes into: the frame limit plus the FCS is inside it.
const CAPACITY: usize = umsh_ulcp::frame::FRAME_IN_MAX;
const FLAG: u8 = 0x7E;

fn encoded(payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0; max_encoded_len(payload.len())];
    let len = encode_frame(payload, &mut wire).expect("sized by max_encoded_len");
    wire.truncate(len);
    wire
}

fn feed(decoder: &mut Decoder<CAPACITY>, wire: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for &byte in wire {
        if let Some(Ok(frame)) = decoder.push(byte) {
            frames.push(frame.to_vec());
        }
    }
    frames
}

pub fn run(data: &[u8]) {
    let mut decoder = Decoder::<CAPACITY>::new();
    for frame in feed(&mut decoder, data) {
        assert!(frame.len() + 2 <= CAPACITY, "past the decoder's capacity");
        // Whatever decoded survives its own encoding. An escaped leading
        // octet decodes to a frame the ULCP rules would skip on the way
        // back in, so it goes through the plain decoder.
        let mut fresh = Decoder::<CAPACITY>::plain();
        assert_eq!(feed(&mut fresh, &encoded(&frame)), [frame]);
    }

    // Garbage costs what it was: a flag and a good frame still get through.
    let probe = [0x80, 0x01, 0x02, 0x03];
    let mut wire = vec![FLAG];
    wire.extend_from_slice(&encoded(&probe));
    assert_eq!(
        feed(&mut decoder, &wire).last().map(Vec::as_slice),
        Some(&probe[..])
    );

    if data.len() + 2 <= CAPACITY {
        // Outside ULCP any octet may begin a frame.
        let mut plain = Decoder::<CAPACITY>::plain();
        assert_eq!(feed(&mut plain, &encoded(data)), [data.to_vec()]);

        // Under ULCP a frame beginning with marked text or fill is skipped,
        // and every other frame survives.
        let mut fresh = Decoder::<CAPACITY>::new();
        let decoded = feed(&mut fresh, &encoded(data));
        match data.first() {
            Some(&(TEXT_MARKER | FILL)) => assert!(decoded.is_empty()),
            _ => assert_eq!(decoded, [data.to_vec()]),
        }
    }
}
