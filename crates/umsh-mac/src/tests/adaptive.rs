//! Adaptive forwarding (repeater-operation.md § Adaptive Forwarding): a
//! forwarder that honors every source-routed hop and floods only what no
//! ordinary repeater was heard carrying.

use super::*;

/// The dummy radio's frame time, which every delay here is a share of.
const T_FRAME_MS: u64 = 100;
const START_MS: u64 = 123;

fn make_adaptive_mac() -> TestMac {
    let mut mac = make_mac();
    mac.repeater_config_mut().mode = RepeaterMode::Adaptive;
    mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    assert_eq!(u64::from(mac.radio().t_frame_ms()), T_FRAME_MS);
    mac
}

fn flood_broadcast(payload: &[u8]) -> heapless::Vec<u8, 256> {
    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let frame = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(4)
        .payload(payload)
        .build()
        .unwrap();
    frame.iter().copied().collect()
}

fn receive(mac: &mut TestMac, frame: &[u8]) {
    mac.radio_mut().queue_received_frame(frame);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
}

/// Wait out every contention delay and send what is queued.
fn transmit(mac: &mut TestMac) -> bool {
    mac.clock().advance_ms(T_FRAME_MS * 3);
    let before = mac.radio().transmitted.len();
    block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    mac.radio().transmitted.len() > before
}

/// An ordinary repeater's window closes at `W_max + 2 × W_jitter`. The
/// dummy radio's reception is strong, so the window proper sits at its
/// maximum and only the jitter varies.
#[test]
fn an_adaptive_flood_forward_waits_out_every_ordinary_repeater() {
    let mut mac = make_adaptive_mac();
    receive(&mut mac, &flood_broadcast(b"late"));

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::Forward);
    let offset = T_FRAME_MS * 70 / 100;
    assert!(queued.not_before_ms >= START_MS + offset + 50);
    assert!(queued.not_before_ms <= START_MS + offset + 60);
    // The whole wait, plus a frame's airtime, still ends inside the
    // sender's confirmation window.
    assert!(offset + 60 + T_FRAME_MS < T_FRAME_MS * 295 / 100);
}

#[test]
fn an_adaptive_forward_gives_way_to_the_first_carry() {
    let mut mac = make_adaptive_mac();
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
    receive(&mut mac, &flood_broadcast(b"carried"));
    let carried = pending_forward_frame(&mut mac);

    receive(&mut mac, &carried);
    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// The originator sending again shows that nobody carried the packet,
/// which is when an adaptive forwarder is wanted.
#[test]
fn an_originators_retry_leaves_the_pending_forward_alone() {
    let mut mac = make_adaptive_mac();
    let frame = flood_broadcast(b"again");
    receive(&mut mac, &frame);
    let not_before_ms = mac.tx_queue_mut().pop_next().unwrap().not_before_ms;
    receive(&mut mac, &frame);
    assert!(mac.tx_queue().is_empty(), "popped above, and not re-queued");

    let mut mac = make_adaptive_mac();
    receive(&mut mac, &frame);
    receive(&mut mac, &frame);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.forward_deferrals, 0);
    assert_eq!(queued.not_before_ms, not_before_ms);
}

/// A flood forward that airs was needed. The traffic coming back for
/// whoever it was carried for arrives as other repeaters' forwards, so for
/// a while the node tolerates as many of those as an ordinary repeater.
#[test]
fn airing_a_flood_forward_engages_the_forwarder_for_the_hold() {
    let mut mac = make_adaptive_mac();
    receive(&mut mac, &flood_broadcast(b"needed"));
    assert!(transmit(&mut mac));
    assert_eq!(mac.repeater_state(), RepeaterState::Engaged);

    receive(&mut mac, &flood_broadcast(b"coming back"));
    let carried = pending_forward_frame(&mut mac);
    receive(&mut mac, &carried);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.forward_deferrals, 1);
    // Deferred, and still behind the ordinary repeaters.
    assert!(queued.not_before_ms >= mac.clock().now_ms() + T_FRAME_MS * 70 / 100);

    mac.clock()
        .advance_ms(mac.repeater_config().adaptive_engaged_hold_ms);
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// A source-routed hop is forwarded at once and engages nothing: being
/// named says the route's owner chose this node, not that the
/// neighborhood lacks repeaters.
#[test]
fn a_source_routed_hop_is_forwarded_without_delay() {
    let mut mac = make_adaptive_mac();
    let frame = routed_through(&mac);
    receive(&mut mac, &frame);

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.not_before_ms, START_MS);
    mac.tx_queue_mut().enqueue_entry(queued).unwrap();
    assert!(transmit(&mut mac));
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// A busy channel with repeaters about: a packet nobody was heard carrying
/// is more likely lost to the congestion than to a gap in coverage.
#[test]
fn a_busy_well_served_channel_withholds_floods_but_not_routed_hops() {
    let mut mac = make_adaptive_mac();
    mac.repeater_config_mut().adaptive_gate_repeaters = 0;
    mac.set_rx_duty(mac.repeater_config().adaptive_gate_rx_duty);
    assert_eq!(mac.repeater_state(), RepeaterState::Withheld);

    receive(&mut mac, &flood_broadcast(b"too busy"));
    assert!(mac.tx_queue().is_empty());

    let frame = routed_through(&mac);
    receive(&mut mac, &frame);
    assert_eq!(mac.tx_queue().len(), 1);
}

/// Busy alone is not enough: with no repeaters about, this node may be the
/// only one that can carry the packet.
#[test]
fn a_busy_channel_without_repeaters_still_floods() {
    let mut mac = make_adaptive_mac();
    mac.set_rx_duty(u16::MAX);
    assert_eq!(mac.repeaters_heard(), 0);
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);

    receive(&mut mac, &flood_broadcast(b"only me"));
    assert_eq!(mac.tx_queue().len(), 1);
}

#[test]
fn an_ordinary_repeater_is_unaffected_by_the_gate() {
    let mut mac = make_adaptive_mac();
    mac.repeater_config_mut().mode = RepeaterMode::On;
    mac.repeater_config_mut().adaptive_gate_repeaters = 0;
    mac.set_rx_duty(u16::MAX);
    assert_eq!(mac.repeater_state(), RepeaterState::Forwarding);

    receive(&mut mac, &flood_broadcast(b"always"));
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert!(queued.not_before_ms <= START_MS + 60);
}

/// A unicast for someone else, source-routed through `mac`'s own hint.
fn routed_through(mac: &TestMac) -> heapless::Vec<u8, 256> {
    let repeater_hint = mac
        .identity(LocalIdentityId(0))
        .unwrap()
        .identity()
        .public_key()
        .router_hint();
    build_received_unicast_frame(
        &DummyIdentity::new([0xAB; 32]),
        &PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        },
        &umsh_core::NodeHint([0x77, 0x66, 0x55]),
        b"routed",
        false,
        Some((4, 0)),
        None,
        Some(&[repeater_hint]),
    )
}

/// One sender and three forwarders, everyone in range of everyone, with
/// `modes` for the forwarders. Returns how many frames each of the four
/// put on the air for one flooded broadcast.
fn frames_sent_for_one_flood(modes: [RepeaterMode; 3]) -> [u32; 4] {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    let mut macs = Vec::new();
    let mut radio_ids = Vec::new();
    let mut sender = None;
    for index in 0..4 {
        let radio = network.add_radio_with_config(256, 200);
        radio_ids.push(radio.id());
        let mut mac = crate::test_support::make_modeled_test_mac(radio, clock.clone());
        if index > 0 {
            mac.repeater_config_mut().mode = modes[index - 1];
        }
        let id = mac
            .add_identity(crate::test_support::DummyIdentity::new(
                [0x50u8.wrapping_add(index as u8); 32],
            ))
            .unwrap();
        sender.get_or_insert(id);
        macs.push(RefCell::new(mac));
    }
    // Each forwarder hears the sender at its own strength, so the
    // contention window ranks them, and nothing is in flight long enough
    // for a forward to start between a channel falling quiet and the copy
    // that occupied it being delivered.
    for left in 0..4 {
        for right in (left + 1)..4 {
            connect_modeled_bidirectional_with_profile(
                &network,
                radio_ids[left],
                radio_ids[right],
                crate::test_support::ModeledLinkProfile {
                    connected: true,
                    base_rssi: -92 + 7 * (left + right) as i16,
                    base_snr: Snr::from_decibels(15),
                    rssi_jitter_dbm: 0,
                    snr_jitter_centibels: 0,
                    propagation_delay_ms: 0,
                    drop_per_thousand: 0,
                },
            );
        }
    }

    macs[0]
        .borrow_mut()
        .queue_broadcast(
            sender.unwrap(),
            b"anyone?",
            &SendOptions::default().with_flood_hops(1),
        )
        .unwrap();
    // Long enough for the sender's whole retry ladder, had nobody carried
    // the packet. A frame this short is delivered between two polls, so
    // "nothing queued, nothing on the air" is true before anyone has seen it.
    let steps = Cell::new(0u32);
    pump_modeled_until(
        &network,
        &macs,
        1,
        5000,
        |_, _, _| {},
        || {
            steps.set(steps.get() + 1);
            steps.get() > 4000
        },
        "the exchange to run its course",
    );

    core::array::from_fn(|index| macs[index].borrow().counters().tx_frames)
}

/// Beside an ordinary repeater, adaptive forwarders add nothing: the
/// repeater's window closes before theirs opens, and its forward is the
/// carry they give way to.
#[test]
fn adaptive_forwarders_stay_silent_beside_a_repeater() {
    let sent = frames_sent_for_one_flood([
        RepeaterMode::On,
        RepeaterMode::Adaptive,
        RepeaterMode::Adaptive,
    ]);
    assert_eq!(sent, [1, 1, 0, 0]);
}

/// With no repeater about, one adaptive forwarder carries the packet, the
/// rest give way to it, and the sender hears its packet carried in time:
/// it sends once.
#[test]
fn one_adaptive_forwarder_carries_what_no_repeater_does() {
    let sent = frames_sent_for_one_flood([RepeaterMode::Adaptive; 3]);
    assert_eq!(
        sent[0], 1,
        "the adaptive forward lands inside the sender's window"
    );
    assert_eq!(sent[1..].iter().sum::<u32>(), 1);
}
