//! Forwarding confirmation at a repeater: a source-routed hop listens for
//! the next hop to carry its forward onward and retries on silence, and a
//! flood hop never does (repeater-operation.md § Forwarding Confirmation).

use super::*;
use crate::coordinator::{forward_slots, tracked_forward_slots};

/// The repeater named after this one in the routes these tests send.
const NEXT_HOP_SEED: u8 = 0x30;

fn next_hop_hint() -> RouterHint {
    DummyIdentity::new([NEXT_HOP_SEED; 32])
        .public_key()
        .router_hint()
}

/// A sealed unicast from a stranger to a stranger, carrying `route`.
fn routed_unicast(
    payload: &[u8],
    ack_requested: bool,
    flood_hops: Option<(u8, u8)>,
    route: &[RouterHint],
) -> heapless::Vec<u8, 256> {
    build_received_unicast_frame(
        &DummyIdentity::new([0xAB; 32]),
        &PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        },
        &umsh_core::NodeHint([0x77, 0x66, 0x55]),
        payload,
        ack_requested,
        flood_hops,
        None,
        Some(route),
    )
}

/// `frame` received and queued for forwarding.
fn receive(mac: &mut TestMac, frame: &[u8]) {
    mac.radio_mut().queue_received_frame(frame);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
}

/// Run the transmit path once, returning what went on the air.
fn transmit(mac: &mut TestMac) -> Option<std::vec::Vec<u8>> {
    let before = mac.radio().transmitted.len();
    block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    (mac.radio().transmitted.len() > before)
        .then(|| mac.radio().transmitted.last().unwrap().to_vec())
}

/// Let a confirmation window and the longest retry delay after it run out.
fn wait_out_a_rung(mac: &TestMac) {
    mac.clock()
        .advance_ms(u64::from(mac.radio().t_frame_ms()).saturating_mul(10));
}

fn awaiting(mac: &TestMac) -> usize {
    mac.tx_queue()
        .iter()
        .filter(|entry| entry.forward_watch.has_aired())
        .count()
}

/// The next hop named in the route carries the forward on, and that is the
/// end of it.
#[test]
fn a_forward_heard_carried_onward_is_not_retried() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"onward",
        false,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    let aired = transmit(&mut mac).expect("the forward airs");
    assert_eq!(awaiting(&mac), 1, "and waits on its next hop");

    let (onward, hint) = forward_through(NEXT_HOP_SEED, &aired);
    assert_eq!(hint, next_hop_hint());
    receive(&mut mac, &onward);
    assert!(
        mac.tx_queue().is_empty(),
        "hearing it carried on settles it"
    );

    wait_out_a_rung(&mac);
    assert_eq!(transmit(&mut mac), None);
    assert_eq!(mac.counters().forward_retried, 0);
    assert_eq!(mac.counters().forward_unconfirmed, 0);
}

/// Silence earns three retries of the same bytes, through CAD like any
/// frame, and then the repeater stops listening. The forward aired, so a
/// later copy of the packet is still a duplicate here.
#[test]
fn a_forward_heard_by_no_one_retries_three_times_then_stops() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"silence",
        false,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    let aired = transmit(&mut mac).expect("the forward airs");

    // A copy from behind—the previous hop retrying—confirms nothing and
    // does not reopen the forwarding decision.
    let due_ms = mac.tx_queue().iter().next().unwrap().not_before_ms;
    receive(&mut mac, &frame);
    assert_eq!(awaiting(&mac), 1);
    assert_eq!(mac.tx_queue().iter().next().unwrap().not_before_ms, due_ms);
    assert_eq!(transmit(&mut mac), None, "not before the window ends");

    let cad_before = mac.radio().cad_calls;
    for retry in 1..=crate::MAX_FORWARD_RETRIES {
        wait_out_a_rung(&mac);
        assert_eq!(
            transmit(&mut mac).as_deref(),
            Some(aired.as_slice()),
            "retry {retry} is the same frame"
        );
    }
    assert_eq!(
        mac.radio().cad_calls - cad_before,
        u32::from(crate::MAX_FORWARD_RETRIES),
        "each retry contends for the channel"
    );
    assert_eq!(awaiting(&mac), 1, "the last retry is still listened for");

    wait_out_a_rung(&mac);
    assert_eq!(transmit(&mut mac), None);
    assert!(mac.tx_queue().is_empty());
    assert_eq!(
        mac.counters().forward_retried,
        u32::from(crate::MAX_FORWARD_RETRIES)
    );
    assert_eq!(mac.counters().forward_unconfirmed, 1);

    receive(&mut mac, &frame);
    assert!(mac.tx_queue().is_empty(), "the packet was carried once");
}

/// A flood hop has no next hop to hear, and that includes the hop that
/// floods a packet whose route a repeater before it emptied.
#[test]
fn a_flood_forward_is_never_retried() {
    let mut mac = make_repeater_mac();
    let flood = build_passing_unar(false);
    receive(&mut mac, &flood);
    let emptied = routed_unicast(b"emptied", true, Some((3, 0)), &[]);
    receive(&mut mac, &emptied);
    assert_eq!(mac.tx_queue().len(), 2);
    assert!(
        mac.tx_queue()
            .iter()
            .all(|entry| entry.forward_watch == crate::send::ForwardWatch::None)
    );

    mac.clock().advance_ms(60_000);
    assert!(transmit(&mut mac).is_some());
    assert!(transmit(&mut mac).is_some());
    assert!(mac.tx_queue().is_empty());
    wait_out_a_rung(&mac);
    assert_eq!(transmit(&mut mac), None);
    assert_eq!(mac.counters().forward_retried, 0);
}

/// The hop that empties the route of a packet asking for no acknowledgment
/// has nothing that could answer it, whether it hands the packet to its
/// destination or to a flood.
#[test]
fn the_last_hop_of_an_unacknowledged_packet_airs_once() {
    for flood_hops in [None, Some((3, 0))] {
        let mut mac = make_repeater_mac();
        let frame = routed_unicast(b"last", false, flood_hops, &[repeater_hint(&mac)]);
        receive(&mut mac, &frame);
        assert!(transmit(&mut mac).is_some());
        assert!(mac.tx_queue().is_empty(), "{flood_hops:?}");
    }
}

/// At the end of the route the destination's acknowledgment is the answer.
#[test]
fn the_last_hop_of_an_acknowledged_packet_is_confirmed_by_its_ack() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(b"last", true, None, &[repeater_hint(&mac)]);
    receive(&mut mac, &frame);
    let aired = transmit(&mut mac).expect("the forward airs");
    assert_eq!(awaiting(&mac), 1, "and waits on the destination");

    mac.radio_mut()
        .queue_received_mac_ack(overheard_trailer(&aired));
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(mac.tx_queue().is_empty(), "the ack settles it");

    wait_out_a_rung(&mac);
    assert_eq!(transmit(&mut mac), None);
    assert_eq!(mac.counters().forward_retried, 0);
    assert_eq!(mac.counters().forward_unconfirmed, 0);
}

/// A routed MAC ack is listened for like any routed packet, with the
/// single retry an ack gets.
#[test]
fn a_routed_ack_forward_retries_once() {
    let mut mac = make_repeater_mac();
    let mut buf = [0u8; 256];
    let ack = PacketBuilder::new(&mut buf)
        .mac_ack([0xA5; 8])
        .source_route(&[repeater_hint(&mac), next_hop_hint()])
        .build()
        .unwrap();
    let ack: heapless::Vec<u8, 256> = ack.iter().copied().collect();
    receive(&mut mac, &ack);
    assert!(transmit(&mut mac).is_some());
    wait_out_a_rung(&mac);
    assert!(transmit(&mut mac).is_some(), "one retry");
    wait_out_a_rung(&mac);
    assert_eq!(transmit(&mut mac), None);
    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.counters().forward_retried, 1);
    assert_eq!(mac.counters().forward_unconfirmed, 1);
}

/// Forwards waiting on their next hops never take more than the forwards'
/// share of the queue, and only a few of them wait at once: a newer one
/// pushes the oldest out.
#[test]
fn retries_stay_inside_the_forwards_share_of_the_queue() {
    const TX: usize = 16;
    let tracked = tracked_forward_slots(TX);
    let share = forward_slots(TX);
    assert!(tracked > 0 && tracked < share);

    let mut mac = make_repeater_mac();
    let route = [repeater_hint(&mac), next_hop_hint()];
    for index in 0..tracked {
        receive(
            &mut mac,
            &routed_unicast(&[0x40, index as u8], false, None, &route),
        );
        assert!(transmit(&mut mac).is_some());
    }
    assert_eq!(awaiting(&mac), tracked);

    // New forwards fill the rest of the share, and no further.
    let mut index = tracked;
    while mac.counters().forward_queue_full == 0 {
        receive(
            &mut mac,
            &routed_unicast(&[0x40, index as u8], false, None, &route),
        );
        index += 1;
    }
    let forwards = |mac: &TestMac| {
        mac.tx_queue()
            .iter()
            .filter(|entry| entry.priority == TxPriority::Forward)
            .count()
    };
    assert_eq!(forwards(&mac), share);

    // The node's own traffic keeps the rest of the queue.
    for own in 0..TX - share {
        mac.tx_queue_mut()
            .enqueue(TxPriority::Application, &[0xF0, own as u8], None, None)
            .unwrap();
    }

    // A new forward airing pushes out the one that aired first.
    assert!(transmit(&mut mac).is_some());
    assert_eq!(awaiting(&mac), tracked);
    assert_eq!(mac.counters().forward_unconfirmed, 1);
    assert!(forwards(&mac) <= share);
    assert_eq!(mac.tx_queue().len(), TX - 1);
}

/// An overheard ack before the forward airs cuts its channel-access budget
/// (§ Overheard Acknowledgments). On a clear channel it airs once and is
/// not listened for: the ack already answered it.
#[test]
fn an_ack_hinted_forward_airs_once_and_is_not_retried() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"hinted",
        true,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    mac.radio_mut()
        .queue_received_mac_ack(overheard_trailer(&frame));
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(mac.tx_queue().iter().all(ack_hinted));
    assert_eq!(mac.counters().forward_cancelled, 1);

    assert!(transmit(&mut mac).is_some(), "a clear channel carries it");
    assert!(mac.tx_queue().is_empty());
    wait_out_a_rung(&mac);
    assert_eq!(transmit(&mut mac), None);
    assert_eq!(mac.counters().forward_retried, 0);
}

/// On a busy channel the hinted forward gives way at once. It never aired,
/// so it releases its packet and is not counted as unconfirmed.
#[test]
fn an_ack_hinted_forward_still_yields_to_a_busy_channel() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"hinted",
        true,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    mac.radio_mut()
        .queue_received_mac_ack(overheard_trailer(&frame));
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    mac.radio_mut().cad_responses.push_back(true).unwrap();
    assert_eq!(transmit(&mut mac), None);
    assert!(mac.tx_queue().is_empty(), "one busy channel ends it");
    assert_eq!(mac.counters().tx_abandoned, 1);
    assert_eq!(mac.counters().forward_unconfirmed, 0);

    receive(&mut mac, &frame);
    assert_eq!(mac.tx_queue().len(), 1, "the next copy is carried");
    assert!(!mac.tx_queue().iter().any(ack_hinted));
}

/// A retry the channel never lets out ends the wait, and the packet keeps
/// its duplicate entry: it aired once already.
#[test]
fn a_retry_lost_to_a_busy_channel_keeps_its_packet() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"busy",
        false,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    assert!(transmit(&mut mac).is_some());

    wait_out_a_rung(&mac);
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
        assert_eq!(transmit(&mut mac), None);
        mac.clock().advance_ms(60_000);
    }
    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.counters().forward_unconfirmed, 1);

    receive(&mut mac, &frame);
    assert!(mac.tx_queue().is_empty(), "still a duplicate");
}

/// A frame carrying the forward's MIC over other contents is not the
/// packet carried onward: it confirms nothing and is counted, as it is for
/// a send of this node's own.
#[test]
fn a_frame_that_only_shares_the_key_confirms_nothing() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"impostor",
        false,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    let aired = transmit(&mut mac).expect("the forward airs");

    let (mut onward, _) = forward_through(NEXT_HOP_SEED, &aired);
    let header = PacketHeader::parse(&onward).unwrap();
    onward[header.body_range.start] ^= 0x01;
    receive(&mut mac, &onward);
    assert_eq!(awaiting(&mac), 1);
    assert_eq!(mac.counters().forward_echo_mismatched, 1);
}

/// A forward waiting to hear its next hop stays queued for several frame
/// times. It must not keep `next_event` from returning: the caller handles
/// what each wake delivered only once the call ends, and until then holds
/// the MAC from everyone else.
#[test]
fn a_forward_waiting_on_its_next_hop_does_not_hold_next_event() {
    let mut mac = make_repeater_mac();
    let frame = routed_unicast(
        b"waiting",
        false,
        None,
        &[repeater_hint(&mac), next_hop_hint()],
    );
    receive(&mut mac, &frame);
    transmit(&mut mac).expect("the forward airs");
    assert_eq!(awaiting(&mac), 1);

    // Any wake will do; a copy from behind settles nothing.
    mac.radio_mut().queue_received_frame(&frame);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let ended = {
        let mut wake = core::pin::pin!(mac.next_event(|_, _| {}));
        matches!(wake.as_mut().poll(&mut cx), Poll::Ready(Ok(())))
    };
    assert!(ended, "the wake ends the call");
    assert_eq!(awaiting(&mac), 1, "with the forward still waiting");
}
