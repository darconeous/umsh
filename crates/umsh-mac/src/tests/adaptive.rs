//! Adaptive forwarding (repeater-operation.md § Adaptive Forwarding): a
//! forwarder that honors every source-routed hop and floods only where it
//! hears no other forwarder.

use super::*;

/// The dummy radio's frame time, which every delay here is a share of.
const T_FRAME_MS: u64 = 100;
const START_MS: u64 = 123;
/// The weakest signal a transmitter standing beside a node is heard at.
const BESIDE_RSSI_DBM: i16 = -65;
/// A transmitter too far off to be beside the node, and still strong
/// enough to put the contention window at its maximum.
const FAR_RSSI_DBM: i16 = -70;

fn make_adaptive_mac() -> TestMac {
    let mut mac = make_mac();
    assert_eq!(
        mac.repeater_config().adaptive_beside_rssi_dbm,
        BESIDE_RSSI_DBM
    );
    mac.radio_mut().rx_rssi = FAR_RSSI_DBM;
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

/// `frame` as a neighboring repeater forwards it: one flood hop spent.
fn forwarded_once(frame: &[u8]) -> heapless::Vec<u8, 256> {
    let mut repeater = make_mac();
    repeater.repeater_config_mut().mode = RepeaterMode::On;
    repeater
        .add_identity(DummyIdentity::new([0x20; 32]))
        .unwrap();
    receive(&mut repeater, frame);
    pending_forward_frame(&mut repeater)
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

/// A flood that arrives already forwarded is carried on when no other
/// forwarder is heard: in a mesh of adaptive nodes this one may be the only
/// way further. Carrying it shows nothing about a neighbor, so it does not
/// engage.
#[test]
fn standby_carries_a_forwarded_flood_no_one_else_is_heard_sending() {
    let mut mac = make_adaptive_mac();
    receive(&mut mac, &forwarded_once(&flood_broadcast(b"second tier")));
    assert_eq!(mac.tx_queue().len(), 1);
    assert!(transmit(&mut mac));
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// Among repeaters the same flood arrives from several of them. Every one
/// of them holds it already, so none carries it further, and silence
/// further on would say nothing; the second repeater's copy is what shows
/// the neighborhood served.
#[test]
fn a_sibling_copy_of_a_forwarded_flood_ends_the_forward() {
    let mut mac = make_adaptive_mac();
    let frame = forwarded_once(&flood_broadcast(b"well served"));
    receive(&mut mac, &frame);
    assert_eq!(mac.tx_queue().len(), 1);
    receive(&mut mac, &frame);
    assert!(mac.tx_queue().is_empty());
}

/// A sibling's copy of a flood heard from its originator is the carry the
/// adaptive forward gives way to.
#[test]
fn a_repeaters_copy_of_an_originators_flood_is_a_carry() {
    let mut mac = make_adaptive_mac();
    let frame = flood_broadcast(b"served");
    receive(&mut mac, &frame);
    receive(&mut mac, &forwarded_once(&frame));
    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// Carrying a flood for the node that originated it shows a neighbor
/// nobody else serves. What comes back for it arrives as several
/// repeaters' copies, so for a while the node tolerates as many of those as
/// an ordinary repeater does. A flood from its originator gets no such
/// tolerance: another forwarder's copy of that is all that was wanted.
#[test]
fn carrying_an_originators_flood_engages_the_forwarder_for_the_hold() {
    let mut mac = make_adaptive_mac();
    receive(&mut mac, &flood_broadcast(b"needed"));
    assert!(transmit(&mut mac));
    assert_eq!(mac.repeater_state(), RepeaterState::Engaged);

    receive(&mut mac, &forwarded_once(&flood_broadcast(b"coming back")));
    let carried = pending_forward_frame(&mut mac);
    receive(&mut mac, &carried);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.forward_deferrals, 1);
    // Deferred, and still behind the ordinary repeaters.
    assert!(queued.not_before_ms >= mac.clock().now_ms() + T_FRAME_MS * 70 / 100);

    // Still engaged, a flood from its originator ends on the first copy.
    let frame = flood_broadcast(b"another of its own");
    receive(&mut mac, &frame);
    receive(&mut mac, &forwarded_once(&frame));
    assert!(mac.tx_queue().is_empty());

    mac.clock()
        .advance_ms(mac.repeater_config().adaptive_engaged_hold_ms);
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// Only the neighbor's own floods renew the hold. What the node forwards
/// for the rest of the mesh would otherwise keep it engaged for as long as
/// the mesh had traffic.
#[test]
fn forwarding_for_the_rest_of_the_mesh_does_not_renew_the_hold() {
    let mut mac = make_adaptive_mac();
    receive(&mut mac, &flood_broadcast(b"needed"));
    assert!(transmit(&mut mac));
    let hold_ms = mac.repeater_config().adaptive_engaged_hold_ms;

    mac.clock().advance_ms(hold_ms - T_FRAME_MS * 10);
    receive(&mut mac, &forwarded_once(&flood_broadcast(b"passing")));
    assert!(transmit(&mut mac));
    assert_eq!(mac.repeater_state(), RepeaterState::Engaged);

    mac.clock().advance_ms(T_FRAME_MS * 10);
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// An ordinary repeater counts every overheard copy, the previous hop's
/// among them.
#[test]
fn an_ordinary_repeater_counts_a_copy_from_behind() {
    let mut mac = make_adaptive_mac();
    mac.repeater_config_mut().mode = RepeaterMode::On;
    let frame = flood_broadcast(b"again");
    receive(&mut mac, &frame);
    receive(&mut mac, &frame);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.forward_deferrals, 1);
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

/// Every frame off the air holds the channel for as long as the radio
/// says a frame its length does, whoever it was for.
#[test]
fn receptions_fill_the_occupancy_window() {
    let mut mac = make_adaptive_mac();
    assert_eq!(mac.rx_duty(), 0);
    let frame = flood_broadcast(b"heard");
    let airtime_ms = u64::from(mac.radio().airtime_ms(frame.len()));
    assert!(airtime_ms > 0);
    for _ in 0..20 {
        receive(&mut mac, &frame);
    }
    let expected = 20 * airtime_ms * 65_535 / crate::occupancy::RX_OCCUPANCY_WINDOW_MS;
    assert_eq!(u64::from(mac.rx_duty()), expected);

    mac.clock()
        .advance_ms(crate::occupancy::RX_OCCUPANCY_WINDOW_MS);
    assert_eq!(mac.rx_duty(), 0);
}

/// A low battery is the owner's before it is the mesh's: nothing is
/// forwarded, a routed hop included, until it has recovered past the
/// resume level.
#[test]
fn a_low_battery_forwards_nothing_until_it_recovers() {
    let mut mac = make_adaptive_mac();
    mac.set_battery_percent(Some(10));
    assert_eq!(mac.repeater_state(), RepeaterState::Withheld);
    receive(&mut mac, &flood_broadcast(b"not mine"));
    let frame = routed_through(&mac);
    receive(&mut mac, &frame);
    assert!(mac.tx_queue().is_empty());

    // Between the two levels nothing changes, whichever side it came from.
    mac.set_battery_percent(Some(14));
    assert_eq!(mac.repeater_state(), RepeaterState::Withheld);
    mac.set_battery_percent(Some(15));
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
    mac.set_battery_percent(Some(11));
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);

    // No battery to run down: external power, or none measured.
    mac.set_battery_percent(Some(3));
    mac.set_battery_percent(None);
    assert_eq!(mac.repeater_state(), RepeaterState::Standby);
}

/// A flood from a transmitter standing beside this node is left alone: a
/// copy from here would cover the ground the original did.
#[test]
fn a_flood_from_beside_is_left_alone() {
    let mut mac = make_adaptive_mac();
    mac.radio_mut().rx_rssi = BESIDE_RSSI_DBM;
    receive(&mut mac, &flood_broadcast(b"right here"));
    assert!(mac.tx_queue().is_empty());

    mac.radio_mut().rx_rssi = BESIDE_RSSI_DBM - 1;
    receive(&mut mac, &flood_broadcast(b"further off"));
    assert_eq!(mac.tx_queue().len(), 1);
}

/// A route that names this node was chosen by its owner, however close
/// the previous hop stands.
#[test]
fn a_routed_hop_from_beside_is_still_forwarded() {
    let mut mac = make_adaptive_mac();
    mac.radio_mut().rx_rssi = BESIDE_RSSI_DBM + 20;
    let frame = routed_through(&mac);
    receive(&mut mac, &frame);
    assert_eq!(mac.tx_queue().len(), 1);
}

/// One flood from each of `neighbors` nodes, heard at `rssi_dbm`.
fn hear_neighbors(mac: &mut TestMac, neighbors: u8, rssi_dbm: i16) {
    mac.radio_mut().rx_rssi = rssi_dbm;
    for neighbor in 0..neighbors {
        let source = DummyIdentity::new([0x60 + neighbor; 32]);
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_full(source.public_key())
            .flood_hops(4)
            .payload(b"here")
            .build()
            .unwrap();
        mac.radio_mut().queue_received_frame(frame);
        let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
        let _ = mac.tx_queue_mut().pop_next();
    }
}

/// How many of 400 distinct floods heard from far off `mac` queues.
fn floods_carried(mac: &mut TestMac) -> usize {
    mac.radio_mut().rx_rssi = FAR_RSSI_DBM;
    let mut carried = 0;
    for packet in 0..400u16 {
        receive(mac, &flood_broadcast(&packet.to_be_bytes()));
        if mac.tx_queue_mut().pop_next().is_some() {
            carried += 1;
        }
    }
    carried
}

/// A node standing in a group shares a flood from elsewhere with the
/// nodes beside it: each draws, and about three of the group carry it.
#[test]
fn a_group_standing_together_shares_a_flood_from_elsewhere() {
    let mut mac = make_adaptive_mac();
    hear_neighbors(&mut mac, 29, BESIDE_RSSI_DBM + 10);
    assert_eq!(mac.neighbors_beside(), 29);
    // Three chances in thirty.
    let carried = floods_carried(&mut mac);
    assert!((5..=100).contains(&carried), "{carried} of 400");
}

/// A group no larger than the number wanted all carry it, and neighbors
/// heard from far off are not beside this node however many they are.
#[test]
fn a_spread_out_team_shares_nothing() {
    let mut mac = make_adaptive_mac();
    hear_neighbors(&mut mac, 2, BESIDE_RSSI_DBM + 10);
    assert_eq!(floods_carried(&mut mac), 400);

    let mut mac = make_adaptive_mac();
    hear_neighbors(&mut mac, 29, FAR_RSSI_DBM);
    assert_eq!(mac.neighbors_beside(), 0);
    assert_eq!(floods_carried(&mut mac), 400);
}

#[test]
fn an_ordinary_repeater_is_unaffected_by_what_holds_an_adaptive_one_back() {
    let mut mac = make_adaptive_mac();
    mac.repeater_config_mut().mode = RepeaterMode::On;
    hear_neighbors(&mut mac, 29, BESIDE_RSSI_DBM + 10);
    mac.set_battery_percent(Some(1));
    assert_eq!(mac.repeater_state(), RepeaterState::Forwarding);

    for packet in 0..20u8 {
        receive(&mut mac, &flood_broadcast(&[b'a', packet]));
        assert!(mac.tx_queue_mut().pop_next().is_some(), "packet {packet}");
    }
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

/// Node 0 floods one broadcast with `flood_hops` to spend, among nodes
/// forwarding as `modes` says and hearing each other along `links`, each
/// at the RSSI it names. Returns how many frames each node put on the air
/// and how many it received.
fn flood_once(
    modes: &[RepeaterMode],
    links: &[(usize, usize, i16)],
    flood_hops: u8,
) -> Vec<(u32, u32)> {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    let mut macs = Vec::new();
    let mut radio_ids = Vec::new();
    let mut sender = None;
    for (index, mode) in modes.iter().enumerate() {
        let radio = network.add_radio_with_config(256, 200);
        radio_ids.push(radio.id());
        let mut mac = crate::test_support::make_modeled_test_mac(radio, clock.clone());
        mac.repeater_config_mut().mode = *mode;
        let id = mac
            .add_identity(crate::test_support::DummyIdentity::new(
                [0x50u8.wrapping_add(index as u8); 32],
            ))
            .unwrap();
        sender.get_or_insert(id);
        macs.push(RefCell::new(mac));
    }
    // Each link has its own strength, so the contention window ranks the
    // forwarders that share a reception, and nothing is in flight long
    // enough for a forward to start between a channel falling quiet and
    // the copy that occupied it being delivered.
    for &(left, right, base_rssi) in links {
        connect_modeled_bidirectional_with_profile(
            &network,
            radio_ids[left],
            radio_ids[right],
            crate::test_support::ModeledLinkProfile {
                connected: true,
                base_rssi,
                base_snr: Snr::from_decibels(15),
                rssi_jitter_dbm: 0,
                snr_jitter_centibels: 0,
                propagation_delay_ms: 0,
                drop_per_thousand: 0,
            },
        );
    }

    macs[0]
        .borrow_mut()
        .queue_broadcast(
            sender.unwrap(),
            b"anyone?",
            &SendOptions::default().with_flood_hops(flood_hops),
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

    macs.iter()
        .map(|mac| {
            let mac = mac.borrow();
            (mac.counters().tx_frames, mac.counters().rx_frames)
        })
        .collect()
}

/// One sender and three forwarders, everyone in range of everyone, with
/// `modes` for the forwarders. Returns how many frames each of the four
/// put on the air for one flooded broadcast.
/// Links that each have their own strength, by the nodes they join.
fn ranked(links: &[(usize, usize)]) -> Vec<(usize, usize, i16)> {
    links
        .iter()
        .map(|&(left, right)| (left, right, -90 + 3 * (left + right) as i16))
        .collect()
}

fn frames_sent_for_one_flood(modes: [RepeaterMode; 3]) -> [u32; 4] {
    let all = [RepeaterMode::Off, modes[0], modes[1], modes[2]];
    let links = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
    let sent = flood_once(&all, &ranked(&links), 1);
    core::array::from_fn(|index| sent[index].0)
}

/// A team with no repeater among them, strung out so each hears only the
/// next: every node carries the packet one hop on, once, and it reaches
/// the far end.
#[test]
fn a_chain_of_adaptive_forwarders_carries_a_flood_end_to_end() {
    let nodes = flood_once(
        &[RepeaterMode::Adaptive; 5],
        &ranked(&[(0, 1), (1, 2), (2, 3), (3, 4)]),
        3,
    );
    let sent: Vec<u32> = nodes.iter().map(|node| node.0).collect();
    assert_eq!(sent, [1, 1, 1, 1, 0]);
    assert!(nodes[4].1 >= 1, "the far end heard it");
}

/// Two adaptive forwarders among three repeaters, out of the sender's
/// earshot. The packet reaches them already forwarded and nobody carries
/// it further, because every repeater has it; the second repeater's copy
/// is what keeps them quiet.
#[test]
fn adaptive_forwarders_stay_silent_among_repeaters_they_hear_second_hand() {
    let nodes = flood_once(
        &[
            RepeaterMode::Off,
            RepeaterMode::On,
            RepeaterMode::On,
            RepeaterMode::On,
            RepeaterMode::Adaptive,
            RepeaterMode::Adaptive,
        ],
        &ranked(&[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (1, 4),
            (2, 4),
            (3, 4),
            (1, 5),
            (2, 5),
            (3, 5),
            (4, 5),
        ]),
        3,
    );
    assert!(nodes[4].1 >= 1 && nodes[5].1 >= 1, "both heard it");
    assert_eq!((nodes[4].0, nodes[5].0), (0, 0));
}

/// The same two behind a single repeater hear no second copy, so one of
/// them carries the packet a hop further and the other gives way to it.
/// That is what a repeater standing there would do.
#[test]
fn one_adaptive_forwarder_extends_a_lone_repeater() {
    let nodes = flood_once(
        &[
            RepeaterMode::Off,
            RepeaterMode::On,
            RepeaterMode::Adaptive,
            RepeaterMode::Adaptive,
        ],
        // The two hear the repeater at different strengths, which is
        // what ranks them.
        &[(0, 1, -80), (1, 2, -75), (1, 3, -95), (2, 3, -80)],
        3,
    );
    assert_eq!(nodes[2].0 + nodes[3].0, 1);
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

/// A link between nodes far apart, spread across the range the contention
/// window ranks.
fn weak_link_rssi(left: usize, right: usize) -> i16 {
    -98 + ((left * 7 + right * 13) % 27) as i16
}

/// A link between nodes in one hall, from across a table to across the
/// floor.
fn hall_link_rssi(left: usize, right: usize) -> i16 {
    -40 - ((left * 7 + right * 13) % 25) as i16
}

/// How the nodes of a survey stand to one another.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Shape {
    /// A line, each hearing `reach` either side over weak links.
    Line,
    /// Everyone beside everyone.
    Hall,
    /// A hall, and a last node far off that hears only the hall's second
    /// node.
    HallWithOutsider,
    /// A hall between a first and a last node far off, which hear the
    /// whole hall weakly and not each other.
    HallBetween,
    /// A hall whose links run from across a table to through a crowd, with
    /// `repeaters` ordinary repeaters nearby that hear all of it. The first
    /// and last nodes stand far outside: they hear only the repeaters, and
    /// reach each other through them. Only `talkers` of the hall send.
    Conference,
}

/// A link between nodes in one hall with bodies and bags in the way: some
/// beside each other, most not.
fn crowded_hall_link_rssi(left: usize, right: usize) -> i16 {
    -45 - ((left * 7 + right * 13) % 48) as i16
}

/// `nodes` adaptive forwarders on one modeled channel, `left` and `right`
/// in earshot of each other where `linked(left, right)` says so, asked
/// with `left` the lower.
fn build_linked_group(
    nodes: usize,
    linked: impl Fn(usize, usize) -> bool,
    rssi: impl Fn(usize, usize) -> i16,
    t_frame_ms: u32,
    configure: impl Fn(&mut RepeaterConfig),
) -> (
    crate::test_support::ModeledNetwork,
    Vec<RefCell<DeepModeledMac>>,
    Vec<LocalIdentityId>,
) {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    let mut macs = Vec::new();
    let mut ids = Vec::new();
    let mut radio_ids = Vec::new();
    for index in 0..nodes {
        let radio = network.add_radio_with_airtime_by_length(256, t_frame_ms);
        radio_ids.push(radio.id());
        let mut mac: DeepModeledMac =
            crate::test_support::make_modeled_test_mac(radio, clock.clone());
        mac.repeater_config_mut().mode = RepeaterMode::Adaptive;
        configure(mac.repeater_config_mut());
        // Each node's generator starts somewhere of its own.
        mac.rng_mut().0 = (index as u8).wrapping_mul(37);
        ids.push(
            mac.add_identity(crate::test_support::DummyIdentity::new(
                [0x50u8.wrapping_add(index as u8); 32],
            ))
            .unwrap(),
        );
        macs.push(RefCell::new(mac));
    }
    for left in 0..nodes {
        for right in (left + 1)..nodes {
            if !linked(left, right) {
                continue;
            }
            connect_modeled_bidirectional_with_profile(
                &network,
                radio_ids[left],
                radio_ids[right],
                crate::test_support::ModeledLinkProfile {
                    connected: true,
                    base_rssi: rssi(left, right),
                    base_snr: Snr::from_decibels(15),
                    rssi_jitter_dbm: 0,
                    snr_jitter_centibels: 0,
                    propagation_delay_ms: 0,
                    drop_per_thousand: 0,
                },
            );
        }
    }
    (network, macs, ids)
}

/// How a node spaces the packets it originates when it hears a busy
/// channel. Forwards, acknowledgments and the MAC's own retries are never
/// held.
#[derive(Clone, Copy, Debug)]
enum Throttle {
    None,
    /// A gap between a node's own packets that grows from nothing where
    /// others hold the channel 5% of the time to this where they hold it
    /// 25%.
    Scaled(u64),
}

#[derive(Clone, Copy, Debug)]
struct Survey {
    nodes: usize,
    reach: usize,
    hops: u8,
    /// Each node offers a flood on its own, at random, this far apart on
    /// average.
    mean_ms: u64,
    mode: RepeaterMode,
    throttle: Throttle,
    /// How long a transmission is on the air before a channel check can
    /// see it. Zero is the model's own check, instant.
    blind_ms: u64,
    /// How many checks in a thousand miss a collided transmission.
    miss_per_thousand: u16,
    /// The stronger of two colliding frames survives.
    capture: bool,
    shape: Shape,
    /// `adaptive_beside_rssi_dbm`. `i16::MAX` puts nobody beside anybody.
    beside_rssi: i16,
    /// `adaptive_beside_forwarders`.
    beside_forwarders: u8,
    /// [`Shape::Conference`]: ordinary repeaters near the hall.
    repeaters: usize,
    /// [`Shape::Conference`]: how many of the hall send anything.
    talkers: usize,
    /// Which run of the same survey this is; each draws differently.
    run: u8,
}

/// What the group did with the floods offered once it had settled.
#[derive(Clone, Copy, Debug, Default)]
struct Outcome {
    /// Offered floods the originator never sent: its backlog overflowed.
    shed_percent: u32,
    /// Of every (flood, other node) pair, those where the node got it.
    reached_percent: u32,
    /// The same, of the floods that were sent.
    reached_of_sent_percent: u32,
    /// Of the floods the first and last nodes sent, those the other got.
    last_reached_percent: u32,
    /// Frames on the air per flood sent, the original included, in
    /// hundredths.
    frames_per_sent_x100: u32,
    occupancy_percent: u32,
    /// Of the receptions the frames on the air should have made, those
    /// that arrived; the rest were lost to collisions.
    heard_percent: u32,
    /// Frames given up after every channel check found it busy.
    abandoned: u32,
    /// Forwards sent again because nobody was heard carrying them on.
    forward_retries: u32,
    /// From a flood being offered to anyone first hearing it, on average.
    delay_ms: u64,
}

fn run_survey(survey: Survey) -> Outcome {
    const STEP_MS: u64 = 2;
    const T_FRAME_MS: u32 = 800;
    const LENGTHS: [usize; 8] = [8, 24, 12, 60, 16, 140, 32, 20];
    const MINUTES: u64 = 14;
    // Counted from when the occupancy window has been full for a whole
    // window, and stopped early enough for the last floods to finish.
    const FROM_MS: u64 = 7 * 60_000;
    const TO_MS: u64 = 13 * 60_000;
    // What an application would hold before giving up on the oldest.
    const BACKLOG: usize = 4;

    struct Flood {
        created_ms: u64,
        from: usize,
        sent: bool,
        first_heard_ms: Option<u64>,
        reached: [u64; 4],
    }

    let Survey {
        nodes,
        reach,
        hops,
        mean_ms,
        mode,
        throttle,
        blind_ms,
        miss_per_thousand,
        capture,
        shape,
        beside_rssi,
        beside_forwarders,
        repeaters,
        talkers,
        run,
    } = survey;
    let last = nodes - 1;
    // A conference's repeaters come after its hall, before the last node.
    let first_repeater = last - repeaters;
    let repeater = move |node: usize| (first_repeater..last).contains(&node);
    let linked = |left: usize, right: usize| match shape {
        Shape::Line => right - left <= reach,
        Shape::Hall => true,
        Shape::HallWithOutsider => right != last || left == 1,
        Shape::HallBetween => !(left == 0 && right == last),
        Shape::Conference if left == 0 => repeater(right),
        Shape::Conference if right == last => repeater(left),
        Shape::Conference => true,
    };
    let rssi = |left: usize, right: usize| match shape {
        Shape::Line => weak_link_rssi(left, right),
        Shape::Hall => hall_link_rssi(left, right),
        Shape::HallWithOutsider if right == last => -100,
        Shape::HallBetween if left == 0 || right == last => -104 + ((left + right) % 8) as i16,
        Shape::HallWithOutsider | Shape::HallBetween => hall_link_rssi(left, right),
        Shape::Conference if left == 0 || right == last => -100 + ((left + right) % 6) as i16,
        Shape::Conference if repeater(left) => -80,
        // From the hall to a repeater on a roof nearby.
        Shape::Conference if repeater(right) => -72 - ((left * 5) % 22) as i16,
        Shape::Conference => crowded_hall_link_rssi(left, right),
    };
    let (network, macs, ids) = build_linked_group(nodes, linked, rssi, T_FRAME_MS, |config| {
        config.mode = mode;
        config.adaptive_beside_rssi_dbm = beside_rssi;
        config.adaptive_beside_forwarders = beside_forwarders;
    });
    for (node, mac) in macs.iter().enumerate() {
        let mut mac = mac.borrow_mut();
        if shape == Shape::Conference {
            if repeater(node) {
                mac.repeater_config_mut().mode = RepeaterMode::On;
            } else if node == 0 || node == last {
                mac.repeater_config_mut().mode = RepeaterMode::Off;
            }
        }
        let draws = mac.rng_mut().0.wrapping_add(run.wrapping_mul(101));
        mac.rng_mut().0 = draws;
    }
    let talks = |node: usize| {
        shape != Shape::Conference || node == 0 || node == last || (1..=talkers).contains(&node)
    };
    network.set_carrier_sense(crate::test_support::ModeledCarrierSense {
        blind_ms,
        miss_per_thousand,
    });
    if capture {
        // The usual figure for two frames on one spreading factor, and
        // about the part of a preamble a receiver can still switch in.
        network.set_capture(crate::test_support::ModeledCapture {
            margin_db: 6,
            lock_ms: 15,
        });
    }
    // 5% and 25% of the receive window.
    let (low, high) = (3277u64, 16384u64);

    let mut floods: Vec<Flood> = Vec::new();
    let mut backlogs = vec![std::collections::VecDeque::<u32>::new(); nodes];
    let mut last_own_ms = vec![None::<u64>; nodes];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(run).wrapping_mul(0x2545_f491_4f6c_dd1d);
    let mut wait_ms = |mean_ms: u64| -> u64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let unit = ((seed >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
        (-unit.ln() * mean_ms as f64) as u64
    };
    let mut next_ms: Vec<u64> = (0..nodes).map(|_| wait_ms(mean_ms)).collect();
    let totals = || -> (u32, u32, u32, u32) {
        macs.iter().fold((0, 0, 0, 0), |sum, mac| {
            let counters = mac.borrow().counters();
            (
                sum.0 + counters.tx_frames,
                sum.1 + counters.rx_frames,
                sum.2 + counters.tx_abandoned,
                sum.3 + counters.forward_retried,
            )
        })
    };
    let (mut before, mut after) = ((0, 0, 0, 0), (0, 0, 0, 0));
    let mut occupancy = (0u32, 0u32);

    for step in 0..(MINUTES * 60_000 / STEP_MS) {
        let now_ms = step * STEP_MS;
        if now_ms == FROM_MS {
            before = totals();
        }
        if now_ms == TO_MS {
            after = totals();
        }
        let mut offer = |from: usize, floods: &mut Vec<Flood>| {
            let packet = floods.len() as u32;
            floods.push(Flood {
                created_ms: now_ms,
                from,
                sent: false,
                first_heard_ms: None,
                reached: [0; 4],
            });
            if backlogs[from].len() == BACKLOG {
                backlogs[from].pop_front();
            }
            backlogs[from].push_back(packet);
        };
        for from in 0..nodes {
            if talks(from) && now_ms >= next_ms[from] {
                next_ms[from] = now_ms + wait_ms(mean_ms).max(STEP_MS);
                offer(from, &mut floods);
            }
        }
        for (node, mac) in macs.iter().enumerate() {
            let mut mac = mac.borrow_mut();
            if let Some(&packet) = backlogs[node].front() {
                let rx_duty = u64::from(mac.rx_duty());
                let gap_ms = match throttle {
                    Throttle::None => 0,
                    Throttle::Scaled(max_ms) => {
                        max_ms * rx_duty.clamp(low, high).saturating_sub(low) / (high - low)
                    }
                };
                let due = last_own_ms[node].is_none_or(|last_ms| now_ms >= last_ms + gap_ms);
                if due {
                    let mut payload = [b'c'; 140];
                    payload[1..5].copy_from_slice(&packet.to_be_bytes());
                    let len = LENGTHS[packet as usize % LENGTHS.len()];
                    let queued = mac.queue_broadcast(
                        ids[node],
                        &payload[..len],
                        &SendOptions::default().with_flood_hops(hops),
                    );
                    // A full transmit queue leaves it in the backlog.
                    if queued.is_ok() {
                        backlogs[node].pop_front();
                        last_own_ms[node] = Some(now_ms);
                        floods[packet as usize].sent = true;
                    }
                }
            }
            block_on(mac.poll_cycle(|_, event| {
                if let crate::MacEventRef::Received(packet) = event {
                    let bytes = packet.payload_bytes();
                    if bytes.len() >= 5 && bytes[0] == b'c' {
                        let id = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
                        let flood = &mut floods[id as usize];
                        flood.reached[node / 64] |= 1 << (node % 64);
                        flood.first_heard_ms.get_or_insert(now_ms);
                    }
                }
            }))
            .unwrap();
        }
        network.advance_ms(STEP_MS);
        if (FROM_MS..TO_MS).contains(&now_ms) && now_ms.is_multiple_of(30_000) {
            occupancy.0 += macs
                .iter()
                .map(|mac| u32::from(mac.borrow().rx_duty()) * 100 / 65_535)
                .sum::<u32>()
                / nodes as u32;
            occupancy.1 += 1;
        }
    }

    let counted: Vec<&Flood> = floods
        .iter()
        .filter(|flood| (FROM_MS..TO_MS).contains(&flood.created_ms))
        .collect();
    let offered = (counted.len() as u64).max(1);
    let sent = (counted.iter().filter(|flood| flood.sent).count() as u64).max(1);
    let others = nodes as u64 - 1;
    let reached: u64 = counted
        .iter()
        .map(|flood| {
            let mut reached = flood.reached;
            reached[flood.from / 64] &= !(1 << (flood.from % 64));
            reached
                .iter()
                .map(|word| u64::from(word.count_ones()))
                .sum::<u64>()
        })
        .sum();
    let delays: Vec<u64> = counted
        .iter()
        .filter_map(|flood| Some(flood.first_heard_ms? - flood.created_ms))
        .collect();
    let frames = u64::from(after.0 - before.0);
    let links: u64 = (0..nodes)
        .flat_map(|left| ((left + 1)..nodes).map(move |right| (left, right)))
        .filter(|&(left, right)| linked(left, right))
        .count() as u64
        * 2;
    // From the first node to the last and back: the two that stand
    // furthest apart.
    let to_last: Vec<bool> = counted
        .iter()
        .filter(|flood| flood.sent && (flood.from == 0 || flood.from == last))
        .map(|flood| {
            let to = last - flood.from;
            flood.reached[to / 64] & (1 << (to % 64)) != 0
        })
        .collect();
    Outcome {
        shed_percent: ((offered - sent.min(offered)) * 100 / offered) as u32,
        reached_percent: (reached * 100 / (offered * others)) as u32,
        reached_of_sent_percent: (reached * 100 / (sent * others)) as u32,
        last_reached_percent: (to_last.iter().filter(|&&got| got).count() * 100
            / to_last.len().max(1)) as u32,
        frames_per_sent_x100: (frames * 100 / sent) as u32,
        occupancy_percent: occupancy.0 / occupancy.1.max(1),
        heard_percent: (u64::from(after.1 - before.1) * 100
            / (frames * links / nodes as u64).max(1)) as u32,
        abandoned: after.2 - before.2,
        forward_retries: after.3 - before.3,
        delay_ms: delays.iter().sum::<u64>() / (delays.len() as u64).max(1),
    }
}

fn print_survey_heading() {
    println!(
        "{:<22} {:>5} {:>8} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>7}",
        "policy",
        "shed%",
        "reached%",
        "of sent%",
        "across",
        "frames",
        "occ%",
        "heard%",
        "gave up",
        "delay s"
    );
}

fn print_survey_row(policy: &str, outcome: Outcome) {
    println!(
        "{:<22} {:>5} {:>8} {:>8} {:>6} {:>6.2} {:>6} {:>6} {:>6} {:>7.1}",
        policy,
        outcome.shed_percent,
        outcome.reached_percent,
        outcome.reached_of_sent_percent,
        outcome.last_reached_percent,
        f64::from(outcome.frames_per_sent_x100) / 100.0,
        outcome.occupancy_percent,
        outcome.heard_percent,
        outcome.abandoned,
        outcome.delay_ms as f64 / 1000.0,
    );
}

/// Not a test: what turns a room's forwards into a storm. The same crowd
/// with the channel check's blind spell and the stronger frame's survival
/// each switched on and off.
/// `cargo test --release -p umsh-mac --lib survey_what -- --ignored --nocapture`
#[test]
#[ignore = "a survey that prints a table, not a check"]
fn survey_what_makes_a_room_storm() {
    for mean_s in [300u64, 60] {
        for (blind_ms, miss_per_thousand, capture) in [
            (0, 0, false),
            (15, 0, false),
            (0, 50, false),
            (15, 50, false),
            (15, 50, true),
        ] {
            println!(
                "\n50 nodes in one room, each sending every {mean_s} s; blind spell {blind_ms} ms, misses {miss_per_thousand}/1000, capture {capture}"
            );
            print_survey_heading();
            for (policy, mode) in [
                ("forwarding off", RepeaterMode::Off),
                ("forwarding on", RepeaterMode::On),
                ("adaptive", RepeaterMode::Adaptive),
            ] {
                let outcome = run_survey(Survey {
                    nodes: 50,
                    reach: 50,
                    hops: 4,
                    mean_ms: mean_s * 1000,
                    mode,
                    throttle: Throttle::None,
                    blind_ms,
                    miss_per_thousand,
                    capture,
                    shape: Shape::Line,
                    beside_rssi: i16::MAX,
                    beside_forwarders: 3,
                    repeaters: 0,
                    talkers: 0,
                    run: 0,
                });
                print_survey_row(policy, outcome);
                assert_eq!(
                    outcome.forward_retries, 0,
                    "a flood forward is never retried"
                );
            }
        }
    }
}

/// Not a test: how much the storm depends on the length of the blind
/// spell, which is an estimate.
/// `cargo test --release -p umsh-mac --lib survey_the_blind -- --ignored --nocapture`
#[test]
#[ignore = "a survey that prints a table, not a check"]
fn survey_the_blind_spell() {
    for blind_ms in [2, 4, 8, 16, 32] {
        println!(
            "\n50 nodes in one room, each sending every 300 s; blind spell {blind_ms} ms, no misses, capture"
        );
        print_survey_heading();
        for (policy, mode) in [
            ("forwarding on", RepeaterMode::On),
            ("adaptive", RepeaterMode::Adaptive),
        ] {
            print_survey_row(
                policy,
                run_survey(Survey {
                    nodes: 50,
                    reach: 50,
                    hops: 4,
                    mean_ms: 300_000,
                    mode,
                    throttle: Throttle::None,
                    blind_ms,
                    miss_per_thousand: 0,
                    capture: true,
                    shape: Shape::Line,
                    beside_rssi: i16::MAX,
                    beside_forwarders: 3,
                    repeaters: 0,
                    talkers: 0,
                    run: 0,
                }),
            );
        }
    }
}

/// One way of forwarding to compare.
#[derive(Clone, Copy)]
struct Strategy {
    name: &'static str,
    mode: RepeaterMode,
    throttle: Throttle,
    beside_rssi: i16,
    beside_forwarders: u8,
}

const STRATEGIES: [Strategy; 8] = [
    Strategy {
        name: "forwarding off",
        mode: RepeaterMode::Off,
        throttle: Throttle::None,
        beside_rssi: BESIDE_RSSI_DBM,
        beside_forwarders: 3,
    },
    Strategy {
        name: "forwarding on",
        mode: RepeaterMode::On,
        throttle: Throttle::None,
        beside_rssi: BESIDE_RSSI_DBM,
        beside_forwarders: 3,
    },
    Strategy {
        name: "adaptive",
        mode: RepeaterMode::Adaptive,
        throttle: Throttle::None,
        beside_rssi: BESIDE_RSSI_DBM,
        beside_forwarders: 3,
    },
    Strategy {
        name: "nobody beside anybody",
        mode: RepeaterMode::Adaptive,
        throttle: Throttle::None,
        beside_rssi: i16::MAX,
        beside_forwarders: 3,
    },
    Strategy {
        name: "beside rule, no draw",
        mode: RepeaterMode::Adaptive,
        throttle: Throttle::None,
        beside_rssi: BESIDE_RSSI_DBM,
        // More than a node can count beside it.
        beside_forwarders: u8::MAX,
    },
    Strategy {
        name: "2 of a group forward",
        mode: RepeaterMode::Adaptive,
        throttle: Throttle::None,
        beside_rssi: BESIDE_RSSI_DBM,
        beside_forwarders: 2,
    },
    Strategy {
        name: "5 of a group forward",
        mode: RepeaterMode::Adaptive,
        throttle: Throttle::None,
        beside_rssi: BESIDE_RSSI_DBM,
        beside_forwarders: 5,
    },
    Strategy {
        name: "adaptive + send gap",
        mode: RepeaterMode::Adaptive,
        throttle: Throttle::Scaled(120_000),
        beside_rssi: BESIDE_RSSI_DBM,
        beside_forwarders: 3,
    },
];

fn survey_strategies(heading: &str, survey: Survey) {
    println!("\n{heading}");
    print_survey_heading();
    for strategy in STRATEGIES {
        print_survey_row(
            strategy.name,
            run_survey(Survey {
                mode: strategy.mode,
                throttle: strategy.throttle,
                beside_rssi: strategy.beside_rssi,
                beside_forwarders: strategy.beside_forwarders,
                ..survey
            }),
        );
    }
}

const STRATEGY_SURVEY: Survey = Survey {
    nodes: 50,
    reach: 50,
    hops: 4,
    mean_ms: 300_000,
    mode: RepeaterMode::Adaptive,
    throttle: Throttle::None,
    blind_ms: 16,
    miss_per_thousand: 0,
    capture: true,
    shape: Shape::Line,
    beside_rssi: BESIDE_RSSI_DBM,
    beside_forwarders: 3,
    repeaters: 0,
    talkers: 0,
    run: 0,
};

/// Not a test: the strategies where forwards are needed. Teams strung out
/// over several hops on weak links, and a camp with one member far off.
/// `cargo test --release -p umsh-mac --lib survey_strategies_for_a_team -- --ignored --nocapture`
#[test]
#[ignore = "a survey that prints a table, not a check"]
fn survey_strategies_for_a_team() {
    for (nodes, reach) in [(8, 2), (12, 3), (16, 4)] {
        survey_strategies(
            &format!(
                "{nodes} spread in a line, each hearing {reach} either side weakly, each sending every 60 s"
            ),
            Survey {
                nodes,
                reach,
                mean_ms: 60_000,
                ..STRATEGY_SURVEY
            },
        );
    }
    survey_strategies(
        "8 camped together and one far off that hears only one of them, each sending every 60 s",
        Survey {
            nodes: 9,
            mean_ms: 60_000,
            shape: Shape::HallWithOutsider,
            ..STRATEGY_SURVEY
        },
    );
}

/// Not a test: the strategies in a hall of fifty, everyone beside
/// everyone.
/// `cargo test --release -p umsh-mac --lib survey_strategies_for_a_hall -- --ignored --nocapture`
#[test]
#[ignore = "a survey that prints a table, not a check"]
fn survey_strategies_for_a_hall() {
    for mean_s in [300u64, 60] {
        survey_strategies(
            &format!("50 in a hall, each sending every {mean_s} s"),
            Survey {
                mean_ms: mean_s * 1000,
                shape: Shape::Hall,
                ..STRATEGY_SURVEY
            },
        );
    }
}

/// Not a test: the same hall with a far node on either side that needs
/// the hall to carry for it.
/// `cargo test --release -p umsh-mac --lib survey_strategies_through_a_hall -- --ignored --nocapture`
#[test]
#[ignore = "a survey that prints a table, not a check"]
fn survey_strategies_through_a_hall() {
    for mean_s in [300u64, 60] {
        survey_strategies(
            &format!(
                "50 in a hall between two far nodes that hear the hall weakly and not each other, each sending every {mean_s} s"
            ),
            Survey {
                nodes: 52,
                mean_ms: mean_s * 1000,
                shape: Shape::HallBetween,
                ..STRATEGY_SURVEY
            },
        );
    }
}

/// Not a test: a hall of fifty as one is likely to be found. Links from
/// across a table to through a crowd, one or two ordinary repeaters
/// nearby, and a pair far outside that reaches each other only through
/// those repeaters, whose "across" figure is what the hall costs the mesh
/// around it. Either everyone sends now and then or a few send often.
/// `cargo test --release -p umsh-mac --lib survey_a_conference -- --ignored --nocapture`
#[test]
#[ignore = "a survey that prints a table, not a check"]
fn survey_a_conference() {
    const HALL: usize = 50;
    const RUNS: u8 = 5;
    let mut tables = Vec::new();
    for repeaters in [0usize, 1, 2] {
        for (talkers, mean_s) in [(HALL, 300u64), (10, 60)] {
            let heading = format!(
                "{HALL} in a crowded hall, {repeaters} repeaters nearby, {talkers} of the hall sending every {mean_s} s"
            );
            let rows: Vec<_> = STRATEGIES[..5]
                .iter()
                .map(|strategy| {
                    let workers: Vec<_> = (0..RUNS)
                        .map(|run| {
                            let survey = Survey {
                                nodes: HALL + repeaters + 2,
                                mean_ms: mean_s * 1000,
                                shape: Shape::Conference,
                                mode: strategy.mode,
                                throttle: strategy.throttle,
                                beside_rssi: strategy.beside_rssi,
                                beside_forwarders: strategy.beside_forwarders,
                                repeaters,
                                talkers,
                                run,
                                ..STRATEGY_SURVEY
                            };
                            std::thread::Builder::new()
                                .stack_size(64 << 20)
                                .spawn(move || run_survey(survey))
                                .unwrap()
                        })
                        .collect();
                    (strategy.name, workers)
                })
                .collect();
            tables.push((heading, rows));
        }
    }
    for (heading, rows) in tables {
        println!("\n{heading}; {RUNS} runs each");
        println!(
            "{:<24} {:>8} {:>20} {:>8}",
            "policy", "reached%", "frames mean (range)", "heard%"
        );
        for (name, workers) in rows {
            let outcomes: Vec<Outcome> = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect();
            let runs = outcomes.len() as u32;
            let frames: Vec<u32> = outcomes
                .iter()
                .map(|outcome| outcome.frames_per_sent_x100)
                .collect();
            println!(
                "{:<24} {:>8} {:>7.2} ({:>4.2}-{:>5.2}) {:>8}",
                name,
                outcomes
                    .iter()
                    .map(|outcome| outcome.reached_percent)
                    .sum::<u32>()
                    / runs,
                f64::from(frames.iter().sum::<u32>() / runs) / 100.0,
                f64::from(*frames.iter().min().unwrap()) / 100.0,
                f64::from(*frames.iter().max().unwrap()) / 100.0,
                outcomes
                    .iter()
                    .map(|outcome| outcome.heard_percent)
                    .sum::<u32>()
                    / runs,
            );
        }
    }
}
