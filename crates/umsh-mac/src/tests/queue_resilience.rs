//! Congestion and cancellation: a full transmit queue, a transmit that never
//! completed, and a forward that never aired must each cost one frame at
//! most, never a slot held forever or an error out of the event loop.

use super::*;

/// An identity with one keyed peer, ready for acknowledged unicasts.
fn keyed_mac() -> (TestMac, LocalIdentityId, PublicKey) {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        },
    )
    .unwrap();
    (mac, local_id, peer_key)
}

/// Fill every free transmit-queue slot with a frame that is not yet due.
fn fill_queue(mac: &mut TestMac) {
    let mut filler = 0u8;
    while mac
        .tx_queue_mut()
        .enqueue_with_state(
            TxPriority::Application,
            &[0xF0, filler],
            None,
            None,
            u64::MAX,
            0,
            0,
        )
        .is_ok()
    {
        filler = filler.wrapping_add(1);
    }
}

#[test]
fn a_retry_that_finds_the_queue_full_is_deferred_not_lost() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let route = [RouterHint([1, 2])];
    let options = SendOptions::default()
        .with_ack_requested(true)
        .try_with_source_route(&route)
        .unwrap();
    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next();
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.ack_deadline_ms = u64::MAX;
    pending.state = AckState::AwaitingForward {
        confirm_deadline_ms: 0,
    };
    fill_queue(&mut mac);

    mac.service_pending_ack_timeouts(|_, _| {});

    assert_eq!(mac.counters().retry_enqueue_deferred, 1);
    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert_eq!(pending.retries, 0, "the rung is given back");
    let now_ms = mac.clock().now_ms();
    assert!(matches!(
        pending.state,
        AckState::AwaitingForward { confirm_deadline_ms } if confirm_deadline_ms > now_ms
    ));

    // Room again, and the deferral has run out: the retry goes in.
    mac.tx_queue_mut()
        .remove_all_matching(|entry| entry.priority == TxPriority::Application);
    mac.clock().advance_ms(1_000);
    mac.service_pending_ack_timeouts(|_, _| {});
    let retry = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(retry.priority, TxPriority::Retry);
    assert_eq!(retry.receipt, Some(receipt));
}

#[test]
fn a_send_whose_frame_vanished_is_retired_as_abandoned() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let options = SendOptions::default().with_ack_requested(true);
    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    // The frame is out of the queue and the entry is still `Queued`. A
    // cancelled transmit no longer leaves this behind (see below), but the
    // sweep stays as the backstop for anything else that does.
    mac.tx_queue_mut().pop_next();

    let mut abandoned = None;
    mac.service_pending_ack_timeouts(|_, event| {
        if let MacEventRef::TxAbandoned { receipt, .. } = event {
            abandoned = receipt;
        }
    });

    assert_eq!(abandoned, Some(receipt));
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
    assert_eq!(mac.counters().tx_orphans_reclaimed, 1);
}

/// Start one `transmit_next`, let the radio take the frame, and drop the
/// future while the radio is still sending: what a driver losing a
/// `select!` race does.
fn cancel_mid_transmit(mac: &mut TestMac) {
    mac.radio_mut().hold_transmit = true;
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut on_event =
        |_, event: MacEventRef<'_>| panic!("a cancelled transmit reports nothing: {event:?}");
    {
        let mut transmit = pin!(mac.transmit_next(&mut on_event));
        assert!(transmit.as_mut().poll(&mut cx).is_pending());
    }
    mac.radio_mut().hold_transmit = false;
}

#[test]
fn a_cancelled_transmit_keeps_the_retry_ladder() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let options = SendOptions::default().with_ack_requested(true);
    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    let sequence = mac.tx_queue().iter().next().unwrap().sequence;

    cancel_mid_transmit(&mut mac);

    let queued = mac.tx_queue().iter().next().unwrap();
    assert_eq!(
        queued.sequence, sequence,
        "the frame keeps its place in line"
    );
    assert_eq!(queued.receipt, Some(receipt));
    mac.service_pending_ack_timeouts(|_, event| panic!("nothing is lost: {event:?}"));
    assert_eq!(mac.counters().tx_orphans_reclaimed, 0);

    let sent = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    assert_eq!(sent, Some(receipt));
    assert_eq!(mac.radio().transmitted.len(), 1);
    assert!(mac.tx_queue().is_empty());
    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert_eq!(pending.retries, 0);
    let AckState::AwaitingForward {
        confirm_deadline_ms,
    } = pending.state
    else {
        panic!("the send waits for a repeat: {:?}", pending.state);
    };

    // No repeat is heard, and the ladder's first rung is there.
    let now_ms = mac.clock().now_ms();
    mac.clock().advance_ms(confirm_deadline_ms - now_ms);
    mac.service_pending_ack_timeouts(|_, _| {});
    assert!(
        mac.tx_queue()
            .iter()
            .any(|entry| entry.priority == TxPriority::Retry && entry.receipt == Some(receipt))
    );
}

#[test]
fn a_forward_cancelled_mid_transmit_keeps_suppressing_its_packet() {
    let mut mac = make_repeater_mac();
    let unar = build_passing_unar(false);
    mac.radio_mut().queue_received_frame(unar.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);
    mac.clock().advance_ms(60_000);

    cancel_mid_transmit(&mut mac);

    // Still queued, and its key still marks the packet as one this
    // repeater is carrying.
    assert_eq!(mac.tx_queue().len(), 1);
    let key = crate::forward_id::forwarding_dup_key(unar.as_slice()).unwrap();
    let now_ms = mac.clock().now_ms();
    assert!(mac.dup_cache().contains(&key, now_ms));

    block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    assert_eq!(mac.radio().transmitted.len(), 1);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn a_broadcast_cancelled_mid_transmit_still_airs() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let receipt = mac
        .queue_broadcast(local_id, b"hello", &SendOptions::default())
        .unwrap();

    cancel_mid_transmit(&mut mac);
    assert_eq!(mac.tx_queue().len(), 1);

    let mut transmitted = None;
    block_on(mac.transmit_next(&mut |_, event| {
        if let MacEventRef::Transmitted { receipt, .. } = event {
            transmitted = receipt;
        }
    }))
    .unwrap();
    assert_eq!(transmitted, Some(receipt));
    assert_eq!(mac.radio().transmitted.len(), 1);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn a_queued_send_is_not_mistaken_for_an_orphan() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let options = SendOptions::default().with_ack_requested(true);
    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();

    mac.service_pending_ack_timeouts(|_, _| panic!("nothing has happened yet"));

    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_some()
    );
    assert_eq!(mac.counters().tx_orphans_reclaimed, 0);
}

#[test]
fn the_counter_reservation_is_durable_before_the_first_frame_airs() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let context = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .0
        .to_vec();
    mac.counter_store()
        .loaded
        .borrow_mut()
        .insert(context.clone(), 128);
    block_on(mac.load_persisted_counter(local_id)).unwrap();

    mac.queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default())
        .unwrap();
    assert!(
        mac.counter_store().stored.borrow().is_empty(),
        "queueing only schedules the reservation"
    );

    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

    assert_eq!(mac.radio().transmitted.len(), 1);
    let stored = mac.counter_store().stored.borrow();
    assert_eq!(stored.as_slice(), &[(context, 256)]);
    assert!(mac.counter_store().flushes.get() >= 1);
}

#[test]
fn a_frame_waits_for_its_counter_reservation_and_others_go_ahead() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let context = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .0
        .to_vec();
    mac.counter_store()
        .loaded
        .borrow_mut()
        .insert(context.clone(), 128);
    block_on(mac.load_persisted_counter(local_id)).unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    // A frame that carries no counter of this identity's.
    mac.queue_mac_ack([0x11; 8]).unwrap();
    mac.counter_store().failing_stores.set(u32::MAX);

    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

    assert_eq!(mac.radio().transmitted.len(), 1, "only the ack aired");
    let header = PacketHeader::parse(&mac.radio().transmitted[0]).unwrap();
    assert_eq!(header.packet_type(), PacketType::MacAck);
    assert_eq!(mac.counters().tx_counter_holds, 1);
    let held = mac.tx_queue().iter().next().unwrap();
    assert_eq!(held.receipt, Some(receipt));
    assert_eq!(held.frame_counter, Some(128));

    // The store recovers; when the frame comes due again its reservation
    // commits and it goes.
    mac.counter_store().failing_stores.set(0);
    mac.clock().advance_ms(1_000);
    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

    assert_eq!(mac.radio().transmitted.len(), 2);
    assert!(mac.tx_queue().is_empty());
    assert_eq!(
        mac.counter_store().stored.borrow().as_slice(),
        &[(context, 256)]
    );
}

#[test]
fn a_frame_whose_reservation_never_commits_is_abandoned() {
    let (mut mac, local_id, peer_key) = keyed_mac();
    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    mac.counter_store().failing_stores.set(u32::MAX);

    let mut abandoned = None;
    for _ in 0..=crate::coordinator::MAX_COUNTER_HOLDS {
        block_on(mac.drain_tx_queue(&mut |_, event| {
            if let MacEventRef::TxAbandoned { receipt, .. } = event {
                abandoned = receipt;
            }
        }))
        .unwrap();
        mac.clock().advance_ms(1_000);
    }

    assert_eq!(abandoned, Some(receipt));
    assert!(mac.tx_queue().is_empty());
    assert!(mac.radio().transmitted.is_empty(), "it never aired");
    assert_eq!(mac.counters().tx_abandoned, 1);
    assert_eq!(
        mac.counters().tx_counter_holds,
        u32::from(crate::coordinator::MAX_COUNTER_HOLDS)
    );
}

#[test]
fn a_forward_abandoned_on_a_busy_channel_stops_suppressing_its_packet() {
    let mut mac = make_repeater_mac();
    let unar = build_passing_unar(false);
    mac.radio_mut().queue_received_frame(unar.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
    }
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.clock().advance_ms(60_000);
        block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    }
    assert!(mac.tx_queue().is_empty(), "the forward was abandoned");
    assert!(mac.radio().transmitted.is_empty());

    // The sender's identical retransmission is carried this time.
    mac.radio_mut().queue_received_frame(unar.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(mac.tx_queue().len(), 1);
}

#[test]
fn forwards_leave_room_in_the_queue_for_acknowledgements() {
    let mut mac = make_repeater_mac();
    let mut filler = 0u8;
    while mac
        .tx_queue()
        .count_matching(|entry| entry.priority == TxPriority::Forward)
        < crate::coordinator::forward_slots(16)
    {
        mac.tx_queue_mut()
            .enqueue_with_state(
                TxPriority::Forward,
                &[0xF1, filler],
                None,
                None,
                u64::MAX,
                0,
                0,
            )
            .unwrap();
        filler = filler.wrapping_add(1);
    }

    let unar = build_passing_unar(false);
    mac.radio_mut().queue_received_frame(unar.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(mac.counters().forward_queue_full, 1);
    assert_eq!(mac.tx_queue().len(), crate::coordinator::forward_slots(16));

    // The reserved slots are still there for this node's own traffic.
    mac.queue_mac_ack([0x11; 8]).unwrap();
}

#[test]
fn the_forward_reserve_scales_with_the_queue() {
    use crate::coordinator::forward_slots;
    // The shallowest queues the firmware builds still forward through most
    // of their slots.
    assert_eq!(forward_slots(4), 3);
    assert_eq!(forward_slots(8), 6);
    assert_eq!(forward_slots(16), 12);
    assert_eq!(forward_slots(1), 1);
}
