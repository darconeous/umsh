//! Receptions from a bearer (lan-bearer.md § Forwarding Across Bearers,
//! § Channel Access). A bearer is fed in as a reception and hears what the
//! radio transmits, as backhaul does; what the MAC decides is whether its
//! repeater carries a bearer reception onto the radio, and how.

use super::*;
use umsh_hal::BearerId;

type BearerMac = Mac<DummyPlatform, 4, 16, 8, 16, 16, 256, 64, 0>;

const LAN: BearerId = BearerId::LAN;

/// A node with an identity (so it has a router hint to forward under),
/// and the repeater as given.
fn make_bearer_mac(repeater: bool) -> BearerMac {
    let mut mac = Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(DummyAes, DummySha),
        DummyClock {
            now_ms: Cell::new(123),
        },
        DummyRng(7),
        DummyCounterStore::default(),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    );
    mac.repeater_config_mut().enabled = repeater;
    mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac
}

fn flood_broadcast(hops: u8) -> heapless::Vec<u8, 256> {
    flood_broadcast_carrying(hops, b"bridge me")
}

fn flood_broadcast_carrying(hops: u8, payload: &[u8]) -> heapless::Vec<u8, 256> {
    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let frame = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(hops)
        .payload(payload)
        .build()
        .unwrap();
    frame.iter().copied().collect()
}

fn receive(mac: &mut BearerMac, frame: &[u8], origin: RxOrigin) {
    mac.radio_mut().rx_origin = origin;
    mac.radio_mut().queue_received_frame(frame);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
}

/// Carrying a bearer reception onto the radio is the repeater's decision,
/// like any other forward; a bearer makes the node a participant, not a
/// forwarder.
#[test]
fn a_bearer_reception_is_repeated_only_by_a_repeater() {
    let mut mac = make_bearer_mac(false);
    receive(&mut mac, &flood_broadcast(4), RxOrigin::Bearer(LAN));
    assert!(mac.tx_queue().is_empty());

    let mut mac = make_bearer_mac(true);
    receive(&mut mac, &flood_broadcast(4), RxOrigin::Bearer(LAN));
    assert!(mac.tx_queue_mut().pop_next().is_some());
}

/// Every radio on the bearer heard the datagram, so they contend for the
/// channel—with nothing measured to rank them, uniformly over the window.
#[test]
fn bearer_receptions_contend_over_the_whole_window() {
    let t_frame_ms = 100;
    let mut min_seen = u64::MAX;
    let mut max_seen = 0;
    for seed in 0..64 {
        let mut mac = make_bearer_mac(true);
        *mac.rng_mut() = DummyRng(seed);
        {
            let repeater = mac.repeater_config_mut();
            repeater.flood_contention_min_window_percent = 20;
            repeater.flood_contention_max_window_percent = 60;
            repeater.flood_contention_jitter_percent = 10;
        }
        let now_ms = mac.clock().now_ms();
        receive(&mut mac, &flood_broadcast(4), RxOrigin::Bearer(LAN));
        let delay = mac.tx_queue_mut().pop_next().unwrap().not_before_ms - now_ms;
        min_seen = min_seen.min(delay);
        max_seen = max_seen.max(delay);
    }
    assert!(min_seen >= t_frame_ms * 20 / 100, "{min_seen}");
    assert!(max_seen <= t_frame_ms * 70 / 100, "{max_seen}");
    assert!(max_seen > min_seen, "the window is sampled, not fixed");
}

/// Only a copy heard on the radio channel says anything about who will
/// hear this node's repeat on it.
#[test]
fn only_an_over_the_air_copy_defers_a_pending_repeat() {
    for origin in [RxOrigin::Bearer(LAN), RxOrigin::Backhaul] {
        let mut mac = make_bearer_mac(true);
        let frame = flood_broadcast(4);
        receive(&mut mac, &frame, RxOrigin::Air);
        let scheduled = mac.tx_queue_mut().pop_next().unwrap();
        mac.tx_queue_mut()
            .enqueue_with_state(
                scheduled.priority,
                scheduled.frame.as_slice(),
                None,
                None,
                scheduled.not_before_ms,
                0,
                0,
            )
            .unwrap();

        mac.clock().advance_ms(5);
        receive(&mut mac, &frame, origin);
        let pending = mac.tx_queue_mut().pop_next().unwrap();
        assert_eq!(pending.forward_deferrals, 0, "{origin:?} deferred");
        assert_eq!(pending.not_before_ms, scheduled.not_before_ms);
    }
}

fn unicast_mac() -> (BearerMac, LocalIdentityId, PublicKey) {
    let mut mac = make_bearer_mac(false);
    let local_id = LocalIdentityId(0);
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

/// A copy from a bearer is a frame some radio transmitted, so it shows
/// the send was carried.
#[test]
fn a_bearer_copy_confirms_a_forwarded_send_as_backhaul_does() {
    let (mut mac, local_id, peer_key) = unicast_mac();
    let route = [RouterHint([1, 2])];
    let options = SendOptions::default()
        .with_ack_requested(true)
        .try_with_source_route(&route)
        .unwrap();
    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    let original = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    let forwarded = rewrite_forwarded_fixture(original.as_slice());

    receive(&mut mac, &forwarded, RxOrigin::Bearer(LAN));
    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert_eq!(pending.state, AckState::AwaitingAck);
}
