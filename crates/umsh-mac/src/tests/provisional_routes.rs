//! Provisional routes: what an unsigned beacon may suggest about the way to
//! its source, and the one kind of send that tries it.

use super::*;
use crate::{PROVISIONAL_ROUTE_LIFETIME_MS, PROVISIONAL_ROUTE_SUPPRESSION_MS, PROVISIONAL_ROUTES};

const R1: RouterHint = RouterHint([0x01, 0x02]);
const R2: RouterHint = RouterHint([0x03, 0x04]);
const R9: RouterHint = RouterHint([0x09, 0x09]);

/// How a test beacon names its source.
#[derive(Clone, Copy)]
enum Source<'a> {
    Hint(&'a PublicKey),
    Full(&'a PublicKey),
}

/// An unsigned beacon (no payload) from `source`, with `flood_hops` if
/// given, a Source Route option naming `source_route` if given, and a
/// Trace option holding `trace` if given.
fn beacon(
    source: Source<'_>,
    flood_hops: Option<u8>,
    source_route: Option<&[RouterHint]>,
    trace: Option<&[u8]>,
) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf).broadcast();
    let builder = match source {
        Source::Hint(key) => builder.source_hint(key.hint()),
        Source::Full(key) => builder.source_full(key),
    };
    let builder = match flood_hops {
        Some(hops) => builder.flood_hops(hops),
        None => builder,
    };
    let builder = match source_route {
        Some(route) => builder.source_route(route),
        None => builder,
    };
    let builder = match trace {
        Some(value) => builder.option(OptionNumber::Trace, value),
        None => builder,
    };
    builder.build().unwrap().to_vec()
}

/// A flooded beacon that crossed `hops`, nearest first.
fn traced_beacon(source: Source<'_>, hops: &[RouterHint]) -> std::vec::Vec<u8> {
    let (value, len) = encode_trace(hops);
    beacon(source, Some(3), None, Some(&value[..len]))
}

fn hear(mac: &mut TestMac, frame: &[u8]) {
    mac.radio_mut().queue_received_frame(frame);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
}

fn provisional(mac: &TestMac, peer_id: PeerId) -> Option<CachedRoute> {
    mac.peer_registry()
        .provisional_route(peer_id, mac.clock().now_ms())
        .cloned()
}

fn source_route(hints: &[RouterHint]) -> CachedRoute {
    CachedRoute::source(hints).unwrap()
}

/// The flood hops, source route and trace a queued frame went out with.
struct Shape {
    flood_hops: Option<u8>,
    source_route: Option<std::vec::Vec<u8>>,
    trace: bool,
    route_retry: bool,
}

fn shape_of(frame: &[u8]) -> Shape {
    let header = PacketHeader::parse(frame).unwrap();
    let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();
    Shape {
        flood_hops: header.flood_hops.map(|hops| hops.remaining()),
        source_route: options.source_route.map(|range| frame[range].to_vec()),
        trace: options.trace.is_some(),
        route_retry: options.route_retry,
    }
}

fn acked() -> SendOptions {
    SendOptions::default().with_ack_requested(true)
}

/// Send `options` to `peer_key` and return the queued frame's shape and
/// receipt.
fn send(
    mac: &mut TestMac,
    local_id: LocalIdentityId,
    peer_key: &PublicKey,
    options: &SendOptions,
) -> (Shape, Option<SendReceipt>) {
    let receipt = mac
        .queue_unicast(local_id, peer_key, b"hello", options)
        .unwrap();
    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    (shape_of(queued.frame.as_slice()), receipt)
}

/// An unsigned beacon from a peer this node holds no route to suggests its
/// path, and only an acknowledged unicast this node originates follows it:
/// a source route, the margin past its end, and a trace. Nothing else sees
/// a route, and the beacon touches nothing kept for the peer.
#[test]
fn an_unsigned_beacon_suggests_a_route_only_acked_sends_follow() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));

    let peer = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(peer.route, None, "an unsigned beacon teaches no route");
    assert_eq!(peer.last_seen_ms, 0, "nor refreshes the peer");
    assert!(!peer.trace_owed);
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R1, R2])));

    let (shape, _) = send(&mut mac, local_id, &peer_key, &acked());
    assert_eq!(shape.source_route.as_deref(), Some(&[1, 2, 3, 4][..]));
    assert_eq!(
        shape.flood_hops,
        Some(crate::ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS),
        "the margin past the route's end"
    );
    assert!(shape.trace);

    let (shape, _) = send(&mut mac, local_id, &peer_key, &SendOptions::default());
    assert_eq!(shape.source_route, None, "a send with no ack floods");
    assert_eq!(shape.flood_hops, Some(5));

    let (shape, _) = send(&mut mac, local_id, &peer_key, &acked().as_reply());
    assert_eq!(shape.source_route, None, "a reply floods");
    assert_eq!(shape.flood_hops, Some(5));

    mac.queue_mac_ack_for_peer(local_id, peer_id, [0xA5; 8], false)
        .unwrap();
    let ack = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(
        shape_of(ack.frame.as_slice()).source_route,
        None,
        "a MAC ack never follows a provisional route"
    );
}

/// A beacon with no flood hops and no trace came off its source's own
/// transmitter, and suggests a direct route: an acknowledged send then
/// carries the margin as its only flood hops.
#[test]
fn an_unflooded_beacon_suggests_a_direct_route() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    hear(&mut mac, &beacon(Source::Full(&peer_key), None, None, None));
    assert_eq!(provisional(&mac, peer_id), Some(CachedRoute::Direct));

    let (shape, _) = send(&mut mac, local_id, &peer_key, &acked());
    assert_eq!(shape.source_route, None);
    assert_eq!(
        shape.flood_hops,
        Some(crate::ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS)
    );
    assert!(shape.trace);
}

/// A flooded beacon arrives as several copies, each traced differently.
/// The first suggestion stands until it is older than the forwarding cache
/// lifetime, and a provisional route expires an hour after it was
/// suggested.
#[test]
fn the_first_copy_of_a_beacon_suggests_and_the_suggestion_expires() {
    let (mut mac, _, peer_key, peer_id) = mac_with_keyed_peer();
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R9]));
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R1, R2])));

    mac.clock().advance_ms(crate::DUP_CACHE_TTL_MS);
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R9]));
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R9])));

    mac.clock().advance_ms(PROVISIONAL_ROUTE_LIFETIME_MS - 1);
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R9])));
    mac.clock().advance_ms(1);
    assert_eq!(provisional(&mac, peer_id), None);
}

/// A beacon for a peer this node holds a route to suggests nothing. A
/// differing source or direct route is put in doubt and kept; the same
/// path, or a flood distance, is left alone. Only a beacon's first copy
/// counts: the others came the many ways a flood goes.
#[test]
fn a_beacon_for_a_routed_peer_doubts_a_differing_route() {
    let (mut mac, _, peer_key, peer_id) = mac_with_keyed_peer();
    let held = source_route(&[R9]);
    mac.peer_registry_mut().update_route(peer_id, held.clone());

    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R9]));
    let peer = mac.peer_registry().get(peer_id).unwrap();
    assert!(!peer.route_doubted, "the same path is no doubt");
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    let peer = mac.peer_registry().get(peer_id).unwrap();
    assert!(
        !peer.route_doubted,
        "a later copy of the beacon is no doubt"
    );

    mac.clock().advance_ms(crate::DUP_CACHE_TTL_MS);
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    let peer = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(peer.route, Some(held), "the route is kept");
    assert!(peer.route_doubted, "but held in doubt");
    assert_eq!(provisional(&mac, peer_id), None);
    mac.peer_registry_mut().clear_route(peer_id);
    assert_eq!(
        provisional(&mac, peer_id),
        None,
        "nothing was suggested while the route was held"
    );

    let flood = CachedRoute::flood(2, &[]).unwrap();
    mac.peer_registry_mut().update_route(peer_id, flood.clone());
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    let peer = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(peer.route, Some(flood));
    assert!(!peer.route_doubted, "a flood distance is not put in doubt");
}

/// A send along a provisional route that goes unacknowledged drops the
/// route, takes no suggestion for the peer for the suppression period, and
/// earns the Route Retry an assumed route gets.
#[test]
fn a_failed_provisional_send_is_dropped_suppressed_and_route_retried() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    let (_, receipt) = send(&mut mac, local_id, &peer_key, &acked());
    let receipt = receipt.unwrap();

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    // The failure comes well after the beacon, so its suppression outlasts
    // the window in which the beacon's copies count as one.
    mac.clock().advance_ms(60_000);
    let mut timed_out = false;
    mac.service_pending_ack_timeouts(|_, event| {
        timed_out |= matches!(event, MacEventRef::AckTimeout { .. });
    });
    assert!(!timed_out, "the send is retried, not abandoned");

    let retry = shape_of(mac.tx_queue_mut().pop_next().unwrap().frame.as_slice());
    assert!(retry.route_retry);
    assert_eq!(retry.source_route, None);
    assert_eq!(retry.flood_hops, Some(5));
    assert!(retry.trace);
    assert_eq!(provisional(&mac, peer_id), None);

    mac.clock().advance_ms(PROVISIONAL_ROUTE_SUPPRESSION_MS - 1);
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R9]));
    assert_eq!(provisional(&mac, peer_id), None, "still suppressed");
    // That copy counted, so the next beacon to count is a later one.
    mac.clock().advance_ms(crate::DUP_CACHE_TTL_MS);
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R9]));
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R9])));
}

/// An acknowledgment of a send along a provisional route does not make it
/// a learned route. An ack that teaches nothing leaves it provisional and
/// in use; one that teaches a route replaces it.
#[test]
fn an_acknowledged_provisional_route_is_not_promoted() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    let (_, receipt) = send(&mut mac, local_id, &peer_key, &acked());
    let receipt = receipt.unwrap();

    // Flooded, with a truncated trace: an ack that teaches no route.
    let trailer = mac.ack_trailer_for_test(local_id, &receipt);
    let mut buf = [0u8; 64];
    let ack = PacketBuilder::new(&mut buf)
        .mac_ack(trailer)
        .flood_hops(2)
        .option(OptionNumber::Trace, &[0xFF, 1, 1, 2, 2])
        .build()
        .unwrap()
        .to_vec();
    let mut acknowledged = false;
    mac.radio_mut().queue_received_frame(&ack);
    block_on(mac.receive_one(|_, event| {
        acknowledged |= matches!(event, MacEventRef::AckReceived { .. });
    }))
    .unwrap();
    assert!(acknowledged);
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, None);
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R1, R2])));

    let (shape, receipt) = send(&mut mac, local_id, &peer_key, &acked());
    assert_eq!(shape.source_route.as_deref(), Some(&[1, 2, 3, 4][..]));

    // An ack heard straight off the peer teaches a direct route, which
    // supersedes the provisional one.
    let trailer = mac.ack_trailer_for_test(local_id, &receipt.unwrap());
    mac.radio_mut().queue_received_mac_ack(trailer);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Direct)
    );
    mac.peer_registry_mut().clear_route(peer_id);
    assert_eq!(provisional(&mac, peer_id), None);
}

/// Beacons that do not qualify suggest nothing: from a mobile peer, under
/// a hint two peers share, replayed from storage, a copy of this node's own
/// transmission, under this node's own hint, with a truncated trace, with a
/// Source Route option, or flooded with no trace.
#[test]
fn beacons_that_do_not_qualify_suggest_nothing() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    let (value, len) = encode_trace(&[R1]);
    let traced = &value[..len];
    let cases: [(&str, std::vec::Vec<u8>); 3] = [
        (
            "truncated trace",
            beacon(Source::Hint(&peer_key), Some(3), None, Some(&[0xFF, 1, 1])),
        ),
        (
            "source route",
            beacon(Source::Hint(&peer_key), Some(3), Some(&[R9]), Some(traced)),
        ),
        (
            "flood with no trace",
            beacon(Source::Hint(&peer_key), Some(3), None, None),
        ),
    ];
    for (case, frame) in cases {
        hear(&mut mac, &frame);
        assert_eq!(provisional(&mac, peer_id), None, "{case}");
    }

    let good = traced_beacon(Source::Hint(&peer_key), &[R1]);

    mac.radio_mut().rx_buffered = Some(RxBuffered {
        age_s: 30,
        acked: false,
    });
    hear(&mut mac, &good);
    assert_eq!(provisional(&mac, peer_id), None, "buffered");
    mac.radio_mut().rx_buffered = None;

    mac.radio_mut().rx_origin = RxOrigin::LocalTx;
    hear(&mut mac, &good);
    assert_eq!(provisional(&mac, peer_id), None, "own transmission");
    mac.radio_mut().rx_origin = RxOrigin::default();

    mac.peer_registry_mut().set_mobile(peer_id, true);
    hear(&mut mac, &good);
    assert_eq!(provisional(&mac, peer_id), None, "mobile");
    mac.peer_registry_mut().set_mobile(peer_id, false);

    // A second peer under the same hint makes the hint name nobody. Only
    // the hint matters here, so the registry takes the key unchecked.
    let mut twin = peer_key;
    twin.0[31] ^= 0xFF;
    let twin_id = mac
        .peer_registry_mut()
        .try_insert_or_update(twin, PeerHolder::Application)
        .unwrap();
    hear(&mut mac, &good);
    assert_eq!(provisional(&mac, peer_id), None, "ambiguous hint");
    assert_eq!(provisional(&mac, twin_id), None, "ambiguous hint");
    // Named by full key, the peer is no longer ambiguous.
    hear(&mut mac, &traced_beacon(Source::Full(&peer_key), &[R1]));
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R1])));

    // A peer sharing this node's hint, named by that hint.
    let mut own = *mac.identity(local_id).unwrap().identity().public_key();
    own.0[31] ^= 0xFF;
    let own_hint_peer = mac
        .peer_registry_mut()
        .try_insert_or_update(own, PeerHolder::Application)
        .unwrap();
    hear(&mut mac, &traced_beacon(Source::Hint(&own), &[R1]));
    assert_eq!(provisional(&mac, own_hint_peer), None, "own hint");
}

/// A suppression in force is never given up to make room for another
/// peer's suggestion: a full table of them takes no suggestion at all,
/// which is what bounds a forger to one failed send per peer per period.
#[test]
fn a_suppression_in_force_is_never_evicted() {
    let mut mac = make_mac();
    let now = mac.clock().now_ms();
    let peers: std::vec::Vec<(PeerId, PublicKey)> = (0..=PROVISIONAL_ROUTES as u8)
        .map(|seed| {
            let key = test_pubkey(0x40 + seed);
            (mac.add_peer(key).unwrap(), key)
        })
        .collect();
    let registry = mac.peer_registry_mut();
    for (peer_id, key) in &peers[..PROVISIONAL_ROUTES] {
        assert!(registry.hear_beacon(*peer_id, CachedRoute::Direct, now, &[]));
        registry.fail_provisional_route(key, now);
    }
    let (newcomer, _) = peers[PROVISIONAL_ROUTES];
    assert!(!registry.hear_beacon(newcomer, CachedRoute::Direct, now, &[]));
    for (peer_id, _) in &peers[..PROVISIONAL_ROUTES] {
        assert!(!registry.hear_beacon(*peer_id, CachedRoute::Direct, now, &[]));
    }

    let later = now + PROVISIONAL_ROUTE_SUPPRESSION_MS;
    assert!(registry.hear_beacon(newcomer, CachedRoute::Direct, later, &[]));
    assert_eq!(
        registry.provisional_route(newcomer, later),
        Some(&CachedRoute::Direct)
    );
}

/// One send along a peer's provisional route is in flight at a time: a
/// forged route costs one failure before its suppression, however many
/// acknowledged sends were waiting. Those go as if there were no route.
#[test]
fn one_provisional_send_is_in_flight_per_peer() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));

    let (shape, _) = send(&mut mac, local_id, &peer_key, &acked());
    assert_eq!(shape.source_route.as_deref(), Some(&[1, 2, 3, 4][..]));

    let (shape, _) = send(&mut mac, local_id, &peer_key, &acked());
    assert_eq!(shape.source_route, None, "the first is still in flight");
    assert_eq!(shape.flood_hops, Some(5));
    assert!(shape.trace);
    assert_eq!(provisional(&mac, peer_id), Some(source_route(&[R1, R2])));
}

/// A provisional route is followed only with a trace. A frame too large to
/// carry one goes as if there were no such route.
#[test]
fn a_frame_too_large_for_a_trace_does_not_follow_a_provisional_route() {
    let mut followed = false;
    let mut fell_back = false;
    for len in (64..=255).rev() {
        let (mut mac, local_id, peer_key, _) = mac_with_keyed_peer();
        hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
        let payload = std::vec![0x55; len];
        if mac
            .queue_unicast(local_id, &peer_key, &payload, &acked())
            .is_err()
        {
            continue;
        }
        let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
        let shape = shape_of(queued.frame.as_slice());
        if shape.source_route.is_some() {
            assert!(shape.trace, "{len} octets followed the route untraced");
            followed = true;
        } else {
            assert_eq!(shape.flood_hops, Some(5), "{len} octets");
            fell_back = true;
        }
    }
    assert!(followed && fell_back);
}

/// A learned route that just failed is not taken up again as a provisional
/// route while its holdoff lasts.
#[test]
fn a_failed_route_is_not_suggested_during_its_holdoff() {
    let (mut mac, _, peer_key, peer_id) = mac_with_keyed_peer();
    let route = source_route(&[R1, R2]);
    mac.peer_registry_mut().update_route(peer_id, route.clone());
    let revision = mac.peer_registry().get(peer_id).unwrap().route_revision;
    let now = mac.clock().now_ms();
    mac.peer_registry_mut().fail_route(&peer_key, revision, now);
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, None);

    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    assert_eq!(provisional(&mac, peer_id), None);

    mac.clock().advance_ms(crate::DUP_CACHE_TTL_MS);
    hear(&mut mac, &traced_beacon(Source::Hint(&peer_key), &[R1, R2]));
    assert_eq!(provisional(&mac, peer_id), Some(route));
}

/// An entry whose peer has a send along its provisional route in flight is
/// never given up for another peer's suggestion, and a beacon from a peer
/// holding a route gives up no live provisional route.
#[test]
fn pinned_and_live_entries_are_kept() {
    let mut mac = make_mac();
    let now = mac.clock().now_ms();
    let peers: std::vec::Vec<PeerId> = (0..PROVISIONAL_ROUTES as u8 + 2)
        .map(|seed| mac.add_peer(test_pubkey(0x40 + seed)).unwrap())
        .collect();
    let registry = mac.peer_registry_mut();
    for (at, peer_id) in peers[..PROVISIONAL_ROUTES].iter().enumerate() {
        assert!(registry.hear_beacon(*peer_id, CachedRoute::Direct, now + at as u64, &[]));
    }

    let later = now + PROVISIONAL_ROUTES as u64;
    let newcomer = peers[PROVISIONAL_ROUTES];
    assert!(registry.hear_beacon(newcomer, CachedRoute::Direct, later, &peers[..1]));
    assert!(
        registry.provisional_route(peers[0], later).is_some(),
        "pinned"
    );
    assert!(
        registry.provisional_route(peers[1], later).is_none(),
        "oldest"
    );

    let routed = peers[PROVISIONAL_ROUTES + 1];
    registry.update_route(routed, source_route(&[R9]));
    assert!(!registry.hear_beacon(routed, CachedRoute::Direct, later, &[]));
    assert!(!registry.get(routed).unwrap().route_doubted, "no room");
    for peer_id in [peers[0], peers[2], peers[3], newcomer] {
        assert!(registry.provisional_route(peer_id, later).is_some());
    }
}

/// The MAC forwards a repeated beacon again once ten minutes have passed,
/// while its first-copy acceptance cache refuses a repeated unsigned
/// multicast for an hour.
#[test]
fn the_mac_forwards_again_at_ten_minutes_and_accepts_again_at_an_hour() {
    let mut mac = make_repeater_mac();
    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let frame = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .build()
        .unwrap()
        .to_vec();
    let forwarded = |mac: &mut TestMac| {
        mac.radio_mut().queue_received_frame(&frame);
        let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
        mac.tx_queue_mut().pop_next().is_some()
    };
    assert!(forwarded(&mut mac));
    mac.clock().advance_ms(crate::DUP_CACHE_TTL_MS - 1);
    assert!(!forwarded(&mut mac));
    mac.clock().advance_ms(1);
    assert!(forwarded(&mut mac));

    let mut mac = make_mac();
    let _ = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key).unwrap();
    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    let delivered = |mac: &mut TestMac| {
        mac.radio_mut()
            .queue_received_multicast(&source, channel_id, &keys, b"group");
        let mut delivered = false;
        let _ = block_on(mac.receive_one(|_, event| {
            delivered |= is_received_type(&event, PacketType::Multicast);
        }))
        .unwrap();
        delivered
    };
    assert!(delivered(&mut mac));
    mac.clock().advance_ms(crate::DUP_CACHE_TTL_MS);
    assert!(!delivered(&mut mac));
    mac.clock()
        .advance_ms(crate::FIRST_COPY_CACHE_TTL_MS - crate::DUP_CACHE_TTL_MS - 1);
    assert!(!delivered(&mut mac));
    mac.clock().advance_ms(1);
    assert!(delivered(&mut mac));
}
