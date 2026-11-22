//! `fixup::authenticates` is the noninterference oracle's own judge of a raw
//! frame, so it must say yes to a sealed frame and no to a spoiled one.

use umsh_core::PacketBuilder;
use umsh_fuzz_harness::fixup;

/// A blind unicast sealed for party 2, built the way `gen_seeds` builds its
/// stranger frame.
fn sealed_blind_unicast() -> Vec<u8> {
    let cast = fixup::cast();
    let mut buf = [0u8; 255];
    let blind = PacketBuilder::new(&mut buf)
        .blind_unicast(cast.channel.channel_id, cast.local_key.hint())
        .source_full(&cast.parties[2].key)
        .frame_counter(1)
        .payload(&[0x01, b'h', b'i'])
        .build()
        .expect("a blind unicast")
        .as_bytes()
        .to_vec();
    fixup::apply(&blind, 2)
}

#[test]
fn a_sealed_frame_authenticates_and_a_spoiled_one_does_not() {
    let frame = sealed_blind_unicast();
    assert!(fixup::authenticates(&frame), "a sealed blind unicast");

    for at in [1, 8, 30, 44, frame.len() - 1] {
        let mut spoiled = frame.clone();
        spoiled[at] ^= 0x01;
        assert!(!fixup::authenticates(&spoiled), "byte {at} spoiled");
    }
    assert!(!fixup::authenticates(&[]));
}
