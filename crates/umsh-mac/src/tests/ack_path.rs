//! An acknowledgment reports how the frame that carried it arrived: how it
//! was heard, the hops it took, and its trace. A ping is an acknowledged
//! No-Op, so the acknowledgment is all it has to measure the path by.

use super::*;

/// MAC command 9, which asks nothing of its destination.
const NO_OP: u8 = 9;

fn keys() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    }
}

/// What an `AckReceived` said of the frame that carried it.
struct Arrival {
    rx: RxMetadata,
    hop_count: Option<u8>,
    /// `None` when the frame carried no trace.
    hints: Option<std::vec::Vec<RouterHint>>,
    signals: std::vec::Vec<HopSignal>,
}

/// Receive one frame, which has to acknowledge `expected`.
fn receive_ack(mac: &mut TestMac, expected: SendReceipt) -> Arrival {
    let mut arrival = None;
    block_on(mac.receive_one(|_, event| {
        if let MacEventRef::AckReceived {
            receipt,
            rx,
            hop_count,
            trace,
            ..
        } = event
        {
            assert_eq!(receipt, expected);
            arrival = Some(Arrival {
                rx,
                hop_count,
                hints: trace.map(|trace| trace.entries().map(|entry| entry.hint).collect()),
                signals: trace
                    .iter()
                    .flat_map(|trace| trace.entries().filter_map(|entry| entry.signal))
                    .collect(),
            });
        }
    }))
    .unwrap();
    arrival.expect("the frame acknowledged the send")
}

#[test]
fn a_direct_ack_reports_one_hop_and_how_it_was_heard() {
    let remote = DummyIdentity::new([0xAB; 32]);
    let (mut mac, _, receipt, trailer) = pending_request_to(&remote, &keys());
    mac.radio_mut().rx_rssi = -93;
    mac.radio_mut().rx_snr = Snr::from_centibels(-45);
    mac.radio_mut().queue_received_mac_ack(trailer);

    let arrival = receive_ack(&mut mac, receipt);
    assert_eq!(arrival.hop_count, Some(1));
    assert_eq!(arrival.hints, None);
    assert_eq!(arrival.rx.rssi(), Some(-93));
    assert_eq!(arrival.rx.snr(), Some(Snr::from_centibels(-45)));
    assert!(arrival.rx.received_at_ms().is_some());
}

#[test]
fn a_traced_ack_reports_the_repeaters_it_crossed() {
    let remote = DummyIdentity::new([0xAB; 32]);
    let repeaters = [RouterHint([0x11, 0x22]), RouterHint([0x33, 0x44])];

    let (mut mac, _, receipt, trailer) = pending_request_to(&remote, &keys());
    mac.radio_mut()
        .queue_received_mac_ack_with_signal(trailer, &repeaters, &[40, -20]);
    let arrival = receive_ack(&mut mac, receipt);
    assert_eq!(arrival.hop_count, Some(3));
    assert_eq!(arrival.hints.as_deref(), Some(repeaters.as_slice()));
    assert_eq!(arrival.signals, snr_signals(&[40, -20]));

    // A trace that kept only its hints still names the path.
    let (mut mac, _, receipt, trailer) = pending_request_to(&remote, &keys());
    mac.radio_mut()
        .queue_received_mac_ack_with_trace(trailer, &repeaters);
    let arrival = receive_ack(&mut mac, receipt);
    assert_eq!(arrival.hop_count, Some(3));
    assert_eq!(arrival.hints.as_deref(), Some(repeaters.as_slice()));
    assert!(arrival.signals.is_empty());
}

/// An acknowledgment that rides on a packet, as an Ack MIC option, reports
/// that packet.
#[test]
fn an_ack_riding_on_a_packet_reports_that_packet() {
    let remote = DummyIdentity::new([0xAB; 32]);
    let (mut mac, local_id, receipt, trailer) = pending_request_to(&remote, &keys());
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    mac.radio_mut().rx_rssi = -88;
    mac.radio_mut().queue_received_reply_acking(
        &remote,
        &keys(),
        &dst_hint,
        trailer[..4].try_into().unwrap(),
    );

    let arrival = receive_ack(&mut mac, receipt);
    assert_eq!(arrival.hop_count, Some(1));
    assert_eq!(arrival.rx.rssi(), Some(-88));
}

/// A ping is an acknowledged No-Op. Padded to the size it wants to test, it
/// draws the destination's MAC ack and nothing else, and that ack is its
/// answer.
#[test]
fn an_acked_no_op_draws_one_ack_and_nothing_else() {
    let mut scenario = build_modeled_line_scenario(2);
    install_endpoint_pairwise_keys(&mut scenario);
    for (node, other) in [(0, 1), (1, 0)] {
        let mut mac = scenario.macs[node].borrow_mut();
        let (peer_id, _) = mac
            .peer_registry()
            .lookup_by_key(&scenario.keys[other])
            .unwrap();
        mac.peer_registry_mut()
            .update_route(peer_id, CachedRoute::Direct);
    }
    let mut ping = std::vec![PayloadType::MacCommand as u8, NO_OP];
    ping.extend([0xA5; 6]);
    let receipt = scenario.macs[0]
        .borrow_mut()
        .queue_unicast(
            scenario.identity_ids[0],
            &scenario.keys[1],
            &ping,
            &SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(10),
        )
        .unwrap()
        .unwrap();

    let mut delivered = std::vec::Vec::new();
    let mut answers = std::vec::Vec::new();
    // Long past the acknowledgment deadline, so a retry or a second answer
    // would show.
    for _ in 0..6_000 {
        for (node, mac) in scenario.macs.iter().enumerate() {
            let mut mac = mac.borrow_mut();
            block_on(mac.poll_cycle(|_, event| match event {
                MacEventRef::AckReceived {
                    receipt: actual,
                    hop_count,
                    rx,
                    ..
                } => {
                    assert_eq!(node, 0);
                    assert_eq!(actual, receipt);
                    answers.push((hop_count, rx.rssi().is_some()));
                }
                MacEventRef::AckTimeout { .. } => panic!("the ping timed out"),
                MacEventRef::Received(packet) => {
                    assert_eq!(node, 1);
                    delivered.push(packet.payload_bytes().to_vec());
                }
                _ => {}
            }))
            .unwrap();
        }
        scenario.network.advance_ms(5);
    }

    assert_eq!(answers, [(Some(1), true)]);
    assert_eq!(delivered, [ping]);
    for mac in &scenario.macs {
        let mac = mac.borrow();
        // One frame each: the ping from one end, its ack from the other.
        assert_eq!(mac.counters().tx_frames, 1);
        assert!(mac.tx_queue().is_empty());
    }
}
