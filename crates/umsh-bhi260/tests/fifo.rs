use umsh_bhi260::fifo::{Decoder, Error};

#[test]
fn fragments_keep_timestamps_and_event_payloads_together() {
    let stream = [247, 0x00, 0x10, 0, 0, 0, 77, 245, 0x20, 1, 1, 0, 2, 0, 3, 0];
    for chunk_size in 1..=stream.len() {
        let mut decoder = Decoder::new();
        decoder.register(77, 1).unwrap();
        decoder.register(1, 7).unwrap();
        let mut events = Vec::new();
        for chunk in stream.chunks(chunk_size) {
            for byte in chunk {
                if let Some(event) = decoder.push(*byte).unwrap() {
                    events.push(event);
                }
            }
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, 77);
        assert_eq!(events[0].ticks, Some(4096));
        assert!(events[0].payload().is_empty());
        assert_eq!(events[1].ticks, Some(4128));
        assert_eq!(events[1].payload(), [1, 0, 2, 0, 3, 0]);
    }
}

#[test]
fn overflow_and_reset_invalidate_the_clock() {
    for kind in [11, 12, 16, 19] {
        let mut decoder = Decoder::new();
        decoder.register(77, 1).unwrap();
        for b in [247, 1, 0, 0, 0, 0, 248, kind, 0] {
            decoder.push(b).unwrap();
        }
        let meta = decoder.push(0).unwrap().unwrap();
        assert!(meta.discontinuity());
        assert_eq!(meta.ticks, None);
        decoder.push(245).unwrap();
        decoder.push(10).unwrap();
        assert_eq!(decoder.push(77).unwrap().unwrap().ticks, None);
        for b in [247, 20, 0, 0, 0, 0] {
            decoder.push(b).unwrap();
        }
        assert_eq!(decoder.push(77).unwrap().unwrap().ticks, Some(20));
    }
}

#[test]
fn independent_fifos_do_not_share_timestamp_deltas() {
    let mut wake = Decoder::new();
    let mut nonwake = Decoder::new();
    wake.register(77, 1).unwrap();
    nonwake.register(77, 1).unwrap();
    for byte in [247, 100, 0, 0, 0, 0] {
        wake.push(byte).unwrap();
    }
    for byte in [253, 200, 0, 0, 0, 0] {
        nonwake.push(byte).unwrap();
    }
    for byte in [246, 0xff, 1] {
        wake.push(byte).unwrap();
    }
    assert_eq!(wake.push(77).unwrap().unwrap().ticks, Some(611));
    assert_eq!(nonwake.push(77).unwrap().unwrap().ticks, Some(200));
}

#[test]
fn full_timestamp_rollover_extends_the_clock() {
    let mut decoder = Decoder::new();
    decoder.register(77, 1).unwrap();
    for byte in [247, 0xff, 0xff, 0xff, 0xff, 0xff] {
        decoder.push(byte).unwrap();
    }
    for byte in [247, 5, 0, 0, 0, 0] {
        decoder.push(byte).unwrap();
    }
    assert_eq!(
        decoder.push(77).unwrap().unwrap().ticks,
        Some((1 << 40) + 5)
    );
}

#[test]
fn backwards_timestamp_is_not_mistaken_for_a_198_day_rollover() {
    let mut decoder = Decoder::new();
    decoder.register(77, 1).unwrap();
    for byte in [247, 100, 0, 0, 0, 0, 247, 99, 0, 0, 0] {
        decoder.push(byte).unwrap();
    }
    assert_eq!(decoder.push(0), Err(Error::Discontinuity));
    assert_eq!(decoder.push(77), Err(Error::Discontinuity));
    decoder.reset();
    assert_eq!(decoder.push(77).unwrap().unwrap().ticks, None);
}

#[test]
fn unknown_frames_require_explicit_reset_instead_of_guessing_alignment() {
    let mut decoder = Decoder::new();
    decoder.register(77, 1).unwrap();
    assert_eq!(decoder.push(123), Err(Error::UnsupportedEvent(123)));
    assert_eq!(decoder.push(77), Err(Error::Discontinuity));
    decoder.reset();
    assert_eq!(decoder.push(77).unwrap().unwrap().ticks, None);
}
