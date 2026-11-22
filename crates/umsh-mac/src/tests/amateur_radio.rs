//! Amateur radio operation (UEP-0017): what a node's one operating mode does
//! to the packets it receives and forwards, and to its MAC acks.

use super::*;

const KZ2X: &[u8] = &[0x48, 0xED, 0x96, 0x00];
const KZ2Y: &[u8] = &[0x48, 0xED, 0x9C, 0x40];
const N0CALL: &[u8] = &[0x5B, 0xBB, 0x08, 0x2C];

fn callsign(text: &str) -> HamAddr {
    HamAddr::try_from_callsign(text).unwrap()
}

fn keys() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    }
}

/// A repeater in `mode`, with `station` as its station callsign.
fn relay(mode: AmateurRadioMode, station: Option<&str>) -> TestMac {
    let mut mac = make_mac();
    mac.repeater_config_mut().mode = RepeaterMode::On;
    mac.repeater_config_mut().station_callsign = station.map(callsign);
    mac.operating_policy_mut().amateur_radio_mode = mode;
    mac.add_identity(DummyIdentity::new([0x30; 32])).unwrap();
    mac
}

/// A flooded unicast between two other nodes, carrying `options`.
fn unicast(options: &[(OptionNumber, &[u8])], encrypted: bool) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut builder = PacketBuilder::new(&mut buf)
        .unicast(NodeHint([0x77, 0x66, 0x55]))
        .source_hint(NodeHint([0x12, 0x34, 0x56]))
        .frame_counter(7)
        .flood_hops(4);
    if encrypted {
        builder = builder.encrypted();
    }
    for &(number, value) in options {
        builder = builder.option(number, value);
    }
    builder
        .payload(b"hello")
        .build()
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// What `mac` transmits after hearing `frame`, if anything.
fn forward(mac: &mut TestMac, frame: &[u8]) -> Option<Vec<u8>> {
    mac.radio_mut().queue_received_frame(frame);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    mac.tx_queue_mut()
        .pop_next()
        .map(|queued| queued.frame.iter().copied().collect())
}

/// Each option in `frame`, in order.
fn options(frame: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let header = PacketHeader::parse(frame).unwrap();
    iter_options(frame, header.options_range)
        .map(|entry| {
            entry
                .map(|(number, value)| (number, value.to_vec()))
                .unwrap()
        })
        .collect()
}

fn station_callsigns(frame: &[u8]) -> Vec<Vec<u8>> {
    options(frame)
        .into_iter()
        .filter(|(number, _)| *number == OptionNumber::StationCallsign.as_u16())
        .map(|(_, value)| value)
        .collect()
}

#[test]
fn a_licensed_only_node_discards_encrypted_packets_unopened() {
    let receive = |mode: AmateurRadioMode| {
        let mut mac = make_mac();
        mac.operating_policy_mut().amateur_radio_mode = mode;
        mac.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
        let local = DummyIdentity::new([0x10; 32]);
        let local_hint = local.public_key().hint();
        let local_id = mac.add_identity(local).unwrap();
        let remote = DummyIdentity::new([0xAB; 32]);
        let peer_id = mac.add_peer(*remote.public_key()).unwrap();
        mac.install_pairwise_keys(local_id, peer_id, keys())
            .unwrap();
        let channel_key = ChannelKey([0x5A; 32]);
        mac.add_channel(channel_key).unwrap();

        let request = build_received_unicast_frame(
            &remote,
            &keys(),
            &local_hint,
            b"hello",
            true,
            None,
            None,
            None,
        );
        mac.radio_mut().queue_received_frame(&request);
        let mut events = 0;
        let unicast = block_on(mac.receive_one(|_, _| events += 1)).unwrap();

        let channel_id = mac.crypto().derive_channel_id(&channel_key);
        let derived = mac.crypto().derive_channel_keys(&channel_key);
        let channel_keys = PairwiseKeys {
            k_enc: derived.k_enc,
            k_mic: derived.k_mic,
        };
        mac.radio_mut()
            .queue_received_multicast(&remote, channel_id, &channel_keys, b"group");
        let multicast = block_on(mac.receive_one(|_, _| events += 1)).unwrap();
        let queued = mac.tx_queue_mut().pop_next().is_some();
        let peer = mac.peer_registry().get(peer_id).unwrap();
        // What the node learned from the two packets: an accepted frame in the
        // sender's replay window, the sender's liveness, a route, and its transmitter.
        let learned = (
            mac.rx_windows()
                .get(remote.public_key())
                .is_some_and(|window| !window.replay_window.recent_mics.is_empty()),
            peer.last_seen_ms != 0,
            peer.route.is_some(),
            !mac.transmitter_observations().is_empty(),
        );
        (unicast, multicast, events, queued, mac.counters(), learned)
    };

    let (unicast, multicast, events, acked, counters, learned) =
        receive(AmateurRadioMode::LicensedOnly);
    assert!(!unicast && !multicast);
    assert_eq!(events, 0, "nothing is delivered");
    assert!(!acked, "nothing is acknowledged");
    assert_eq!(learned, (false, false, false, false), "nothing is learned");
    assert_eq!(counters.rx_encrypted_discarded, 2);

    for mode in [AmateurRadioMode::Hybrid, AmateurRadioMode::Unlicensed] {
        let (unicast, multicast, events, acked, counters, learned) = receive(mode);
        assert!(unicast && multicast, "{mode:?}");
        assert!(events >= 2, "{mode:?}");
        assert!(acked, "{mode:?}");
        assert!(learned.0 && learned.1, "{mode:?} learns the sender");
        assert_eq!(counters.rx_encrypted_discarded, 0, "{mode:?}");
    }
}

#[test]
fn a_licensed_only_repeater_forwards_only_unencrypted_packets_with_an_operator_callsign() {
    let mut mac = relay(AmateurRadioMode::LicensedOnly, Some("N0CALL"));
    let forwarded = forward(
        &mut mac,
        &unicast(&[(OptionNumber::OperatorCallsign, KZ2X)], false),
    )
    .expect("forwarded under amateur authority");
    assert_eq!(station_callsigns(&forwarded), [N0CALL]);

    let mut mac = relay(AmateurRadioMode::LicensedOnly, Some("N0CALL"));
    let declined = [
        unicast(&[(OptionNumber::OperatorCallsign, KZ2X)], true),
        unicast(&[], false),
        // A malformed Operator Callsign is not one.
        unicast(&[(OptionNumber::OperatorCallsign, &KZ2X[..3])], false),
        unicast(&[(OptionNumber::OperatorCallsign, &[0, 0])], false),
    ];
    for frame in declined {
        assert_eq!(forward(&mut mac, &frame), None);
    }

    // Without a station callsign it forwards nothing.
    let mut mac = relay(AmateurRadioMode::LicensedOnly, None);
    let frame = unicast(&[(OptionNumber::OperatorCallsign, KZ2X)], false);
    assert_eq!(forward(&mut mac, &frame), None);
}

#[test]
fn a_hybrid_repeater_sets_its_station_callsign_only_under_amateur_authority() {
    let mut mac = relay(AmateurRadioMode::Hybrid, Some("N0CALL"));
    let frame = unicast(&[(OptionNumber::OperatorCallsign, KZ2X)], false);
    let forwarded = forward(&mut mac, &frame).expect("forwarded");
    assert_eq!(station_callsigns(&forwarded), [N0CALL]);

    let mut mac = relay(AmateurRadioMode::Hybrid, Some("N0CALL"));
    let frame = unicast(
        &[
            (OptionNumber::OperatorCallsign, KZ2X),
            (OptionNumber::StationCallsign, KZ2Y),
        ],
        true,
    );
    let forwarded = forward(&mut mac, &frame).expect("forwarded");
    assert!(station_callsigns(&forwarded).is_empty(), "removed");
}

#[test]
fn a_hybrid_repeater_without_a_station_callsign_forwards_everything_unlicensed() {
    let mut mac = relay(AmateurRadioMode::Hybrid, None);
    let frame = unicast(
        &[
            (OptionNumber::OperatorCallsign, KZ2X),
            (OptionNumber::StationCallsign, KZ2Y),
        ],
        false,
    );
    let forwarded = forward(&mut mac, &frame).expect("forwarded under unlicensed authority");
    assert!(station_callsigns(&forwarded).is_empty());
}

#[test]
fn a_forward_carries_exactly_one_station_callsign_or_none() {
    let frame = unicast(
        &[
            (OptionNumber::OperatorCallsign, KZ2X),
            (OptionNumber::StationCallsign, KZ2Y),
            (OptionNumber::StationCallsign, KZ2X),
        ],
        false,
    );
    let mut mac = relay(AmateurRadioMode::LicensedOnly, Some("N0CALL"));
    let forwarded = forward(&mut mac, &frame).expect("forwarded");
    assert_eq!(station_callsigns(&forwarded), [N0CALL]);

    let mut mac = relay(AmateurRadioMode::Unlicensed, None);
    let forwarded = forward(&mut mac, &frame).expect("forwarded");
    assert!(station_callsigns(&forwarded).is_empty());
}

#[test]
fn a_malformed_station_callsign_is_not_forwarded() {
    for value in [&N0CALL[..3], &[0, 0][..], &[0x5B; 10][..]] {
        let frame = unicast(
            &[
                (OptionNumber::OperatorCallsign, KZ2X),
                (OptionNumber::StationCallsign, KZ2Y),
                (OptionNumber::StationCallsign, value),
            ],
            false,
        );
        for mode in [
            AmateurRadioMode::Unlicensed,
            AmateurRadioMode::LicensedOnly,
            AmateurRadioMode::Hybrid,
        ] {
            let mut mac = relay(mode, Some("N0CALL"));
            assert_eq!(forward(&mut mac, &frame), None, "{mode:?} {value:02X?}");
        }
    }
}

/// The Station Callsign follows an inserted Region Code, so the two
/// together still encode in order.
#[test]
fn a_set_station_callsign_follows_an_inserted_region_code() {
    let mut mac = relay(AmateurRadioMode::LicensedOnly, Some("N0CALL"));
    mac.repeater_config_mut().default_region = Some([0x78, 0x53]);
    let frame = unicast(&[(OptionNumber::OperatorCallsign, KZ2X)], false);
    let forwarded = forward(&mut mac, &frame).expect("forwarded");
    let numbers: Vec<u16> = options(&forwarded).iter().map(|(n, _)| *n).collect();
    assert_eq!(numbers, [4, 11, 15]);
    assert_eq!(mac.counters().forward_dropped_oversize, 0);
}

#[test]
fn a_verbatim_ack_carries_the_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().operator_callsign = Some(callsign("N0CALL"));
    mac.queue_mac_ack([0xA5; 8]).unwrap();
    let ack: Vec<u8> = mac
        .tx_queue_mut()
        .pop_next()
        .unwrap()
        .frame
        .iter()
        .copied()
        .collect();
    assert_eq!(options(&ack), [(4, N0CALL.to_vec())]);
    assert_eq!(ack[ack.len() - 8..], [0xA5; 8]);
}

#[test]
fn a_licensed_only_node_without_an_operator_callsign_sends_no_ack() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_id = mac.add_peer(test_pubkey(0xAB)).unwrap();
    assert_eq!(
        mac.queue_mac_ack([0xA5; 8]),
        Err(SendError::PolicyViolation)
    );
    assert_eq!(
        mac.queue_mac_ack_for_peer(local_id, peer_id, [0xA5; 8], false),
        Err(SendError::PolicyViolation)
    );
    assert!(mac.tx_queue_mut().pop_next().is_none());
}

/// UEP-0017 Appendix A, Station Callsign Edit: a Licensed-Only repeater with
/// hint `30 30` and station callsign `N0CALL` forwards a flood hop and a
/// routed hop, each heard at −1 dBm and 0 dB. With real keys the repeater's
/// hint is not `30 30`, so it is written where the vectors carry it.
#[test]
fn station_callsign_edit_vectors() {
    // Each frame, and where in it the repeater's hint stands.
    type Frame<'a> = (&'a [u8], &'a [usize]);
    let vectors: [(Frame, Frame); 2] = [
        (
            (
                &[
                    0xD9, 0x20, 0x20, 0x20, 0x20, 0x10, 0x10, 0x10, 0x60, 0x0A, 0x09, 0x08, 0x07,
                    0x44, 0x48, 0xED, 0x96, 0x00, 0x30, 0xFF, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x57,
                    0x8D, 0x58, 0xFF, 0x1B, 0x55, 0x23, 0x78, 0x05, 0x99, 0x85, 0x01, 0x71, 0x65,
                    0x8E, 0xE5,
                ],
                &[],
            ),
            (
                &[
                    0xD9, 0x11, 0x20, 0x20, 0x20, 0x10, 0x10, 0x10, 0x60, 0x0A, 0x09, 0x08, 0x07,
                    0x44, 0x48, 0xED, 0x96, 0x00, 0x34, 0x30, 0x30, 0x01, 0x00, 0x84, 0x5B, 0xBB,
                    0x08, 0x2C, 0xFF, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x57, 0x8D, 0x58, 0xFF, 0x1B,
                    0x55, 0x23, 0x78, 0x05, 0x99, 0x85, 0x01, 0x71, 0x65, 0x8E, 0xE5,
                ],
                &[19],
            ),
        ),
        (
            (
                &[
                    0xC8, 0x32, 0x30, 0x30, 0x14, 0x48, 0xED, 0x9C, 0x40, 0x30, 0x57, 0x8D, 0x58,
                    0xFF, 0xA0, 0x93, 0xF7, 0x44,
                ],
                &[2],
            ),
            (
                &[
                    0xC8, 0x30, 0x14, 0x48, 0xED, 0x9C, 0x40, 0x34, 0x30, 0x30, 0x01, 0x00, 0x84,
                    0x5B, 0xBB, 0x08, 0x2C, 0x57, 0x8D, 0x58, 0xFF, 0xA0, 0x93, 0xF7, 0x44,
                ],
                &[8],
            ),
        ),
    ];
    let hint = DummyIdentity::new([0x30; 32]).public_key().router_hint().0;
    let place = |(frame, at): Frame| {
        let mut frame = frame.to_vec();
        for &at in at {
            frame[at..at + 2].copy_from_slice(&hint);
        }
        frame
    };
    for (received, forwarded) in vectors {
        let (received, forwarded) = (place(received), place(forwarded));
        let mut mac = relay(AmateurRadioMode::LicensedOnly, Some("N0CALL"));
        mac.radio_mut().rx_rssi = -1;
        mac.radio_mut().rx_snr = Snr::from_centibels(0);
        assert_eq!(
            forward(&mut mac, &received),
            Some(forwarded),
            "{received:02X?}"
        );
    }
}

/// The MAC's own answers and probes start from encrypted options. A
/// Licensed-Only node sends them in the clear instead of refusing them.
#[test]
fn a_licensed_only_node_answers_an_echo_request_in_the_clear() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
    let local = DummyIdentity::new([0x10; 32]);
    let local_hint = local.public_key().hint();
    let local_id = mac.add_identity(local).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_id = mac.add_peer(*remote.public_key()).unwrap();
    mac.install_pairwise_keys(local_id, peer_id, keys())
        .unwrap();

    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(local_hint)
        .source_full(remote.public_key())
        .frame_counter(7)
        .option(OptionNumber::OperatorCallsign, KZ2Y)
        .payload(&encode_echo_command_payload(4, &[9, 8, 7, 6]))
        .build()
        .unwrap();
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys())
        .unwrap();
    mac.radio_mut().queue_received_frame(packet.as_bytes());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let response = mac.tx_queue_mut().pop_next().expect("echo response queued");
    let frame = response.frame.as_slice();
    let header = PacketHeader::parse(frame).unwrap();
    assert!(!header.sec_info.unwrap().scf.encrypted());
    assert!(options(frame).contains(&(OptionNumber::OperatorCallsign.as_u16(), KZ2X.to_vec())));
    assert_eq!(
        &frame[header.body_range.clone()],
        encode_echo_command_payload(5, &[9, 8, 7, 6]).as_slice()
    );
}
