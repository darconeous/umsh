//! A repeater forwards an `EMERGENCY` multicast ahead of its other forwards
//! (UEP-0021), and nothing else: the frame must be a multicast with the
//! group's hint, unencrypted, carrying its full source address, under a MIC
//! the group's key verifies.

use super::*;

fn repeater() -> CryptoMac {
    let mut mac = make_crypto_mac();
    mac.repeater_config_mut().mode = RepeaterMode::On;
    let _ = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac
}

fn emergency_key(mac: &CryptoMac) -> ChannelKey {
    mac.crypto()
        .derive_named_channel_key(crate::EMERGENCY_CHANNEL_NAME)
        .unwrap()
}

fn sealing_keys(mac: &CryptoMac, key: &ChannelKey) -> PairwiseKeys {
    let derived = mac.crypto().derive_channel_keys(key);
    PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    }
}

/// How a test frame departs from a qualifying `EMERGENCY` multicast.
#[derive(Clone, Copy, Default)]
struct Multicast {
    encrypted: bool,
    source_hint: bool,
}

/// A flood multicast from the node with key byte `source`, carrying
/// `channel_id` and sealed under `key`.
fn multicast(
    mac: &CryptoMac,
    channel_id: ChannelId,
    key: &ChannelKey,
    source: u8,
    shape: Multicast,
) -> std::vec::Vec<u8> {
    let source = DummyIdentity::new([source; 32]);
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf).multicast(channel_id);
    let builder = if shape.source_hint {
        builder.source_hint(source.public_key().hint())
    } else {
        builder.source_full(source.public_key())
    };
    let builder = builder.frame_counter(11).flood_hops(4);
    let builder = if shape.encrypted {
        builder.encrypted()
    } else {
        builder
    };
    let mut packet = builder.payload(b"help").build().unwrap();
    mac.crypto()
        .seal_packet(&mut packet, &sealing_keys(mac, key))
        .unwrap();
    packet.as_bytes().to_vec()
}

/// The `EMERGENCY` multicast that qualifies.
fn emergency(mac: &CryptoMac, source: u8) -> std::vec::Vec<u8> {
    let key = emergency_key(mac);
    multicast(
        mac,
        crate::EMERGENCY_CHANNEL_ID,
        &key,
        source,
        Multicast::default(),
    )
}

/// The priority a repeater queues its forward of `frame` at.
fn forward_priority(frame: &[u8]) -> TxPriority {
    let mut mac = repeater();
    mac.radio_mut().queue_received_frame(frame);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(mac.tx_queue().len(), 1, "the frame is forwarded");
    mac.tx_queue_mut().pop_next().unwrap().priority
}

#[test]
fn the_emergency_hint_is_derived_from_its_name() {
    let mac = make_crypto_mac();
    assert_eq!(
        mac.crypto().derive_channel_id(&emergency_key(&mac)),
        crate::EMERGENCY_CHANNEL_ID
    );
}

#[test]
fn an_emergency_multicast_in_the_clear_with_its_full_source_is_prioritized() {
    let mac = make_crypto_mac();
    assert_eq!(
        forward_priority(&emergency(&mac, 0xA1)),
        TxPriority::EmergencyForward
    );
}

#[test]
fn an_encrypted_emergency_multicast_is_not() {
    let mac = make_crypto_mac();
    let key = emergency_key(&mac);
    let shape = Multicast {
        encrypted: true,
        ..Multicast::default()
    };
    let frame = multicast(&mac, crate::EMERGENCY_CHANNEL_ID, &key, 0xA1, shape);
    assert_eq!(forward_priority(&frame), TxPriority::Forward);
}

#[test]
fn an_emergency_multicast_from_a_source_hint_is_not() {
    let mac = make_crypto_mac();
    let key = emergency_key(&mac);
    let shape = Multicast {
        source_hint: true,
        ..Multicast::default()
    };
    let frame = multicast(&mac, crate::EMERGENCY_CHANNEL_ID, &key, 0xA1, shape);
    assert_eq!(forward_priority(&frame), TxPriority::Forward);
}

#[test]
fn an_emergency_multicast_with_a_bad_mic_is_not() {
    let mac = make_crypto_mac();
    let mut frame = emergency(&mac, 0xA1);
    *frame.last_mut().unwrap() ^= 0x01;
    assert_eq!(forward_priority(&frame), TxPriority::Forward);
}

/// Another group that only shares the hint is another group.
#[test]
fn a_group_sharing_the_hint_is_not() {
    let mac = make_crypto_mac();
    let other = ChannelKey([0x5A; 32]);
    let frame = multicast(
        &mac,
        crate::EMERGENCY_CHANNEL_ID,
        &other,
        0xA1,
        Multicast::default(),
    );
    assert_eq!(forward_priority(&frame), TxPriority::Forward);
}

#[test]
fn a_group_unicast_in_emergency_is_not() {
    let mac = make_crypto_mac();
    let channel_keys = mac.crypto().derive_channel_keys(&emergency_key(&mac));
    let pairwise = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let blind_keys = mac.crypto().derive_blind_keys(&pairwise, &channel_keys);
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .blind_unicast(channel_keys.channel_id, test_pubkey(0xAB).hint())
        .source_full(DummyIdentity::new([0xA1; 32]).public_key())
        .frame_counter(11)
        .flood_hops(4)
        .payload(b"help")
        .build()
        .unwrap();
    mac.crypto()
        .seal_blind_packet(&mut packet, &blind_keys, &channel_keys)
        .unwrap();
    assert_eq!(forward_priority(packet.as_bytes()), TxPriority::Forward);
}

/// A qualifying forward airs ahead of one queued before it, and still
/// waits out its own contention delay.
#[test]
fn an_emergency_forward_airs_ahead_of_an_earlier_forward() {
    let mut mac = repeater();
    let ordinary = ChannelKey([0x5A; 32]);
    let ordinary_id = mac.crypto().derive_channel_id(&ordinary);
    let first = multicast(&mac, ordinary_id, &ordinary, 0xA1, Multicast::default());
    let second = emergency(&mac, 0xA2);
    for frame in [&first, &second] {
        mac.radio_mut().queue_received_frame(frame);
        let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    }
    assert_eq!(mac.tx_queue().len(), 2);
    assert!(
        !mac.tx_queue().has_ready(123),
        "the contention delay still applies"
    );

    mac.clock().advance_ms(1_000);
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    let aired: std::vec::Vec<_> = mac
        .radio()
        .transmitted
        .iter()
        .map(|frame| PacketHeader::parse(frame.as_slice()).unwrap().channel)
        .collect();
    assert_eq!(
        aired,
        [Some(crate::EMERGENCY_CHANNEL_ID), Some(ordinary_id)]
    );
}
